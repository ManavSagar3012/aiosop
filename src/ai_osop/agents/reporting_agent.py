"""
Reporting Agent
Responsible for compiling evidence, generating risk narratives, and exporting
assessment results into structured deliverables.
"""

import os
from datetime import datetime
from typing import Any, Dict

import structlog

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType, settings
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task
from ai_osop.core.safe_paths import safe_component
from ai_osop.reporting.exporters import ReportExporter

logger = structlog.get_logger(__name__)


class ReportingAgent(BaseAgent):
    """
    Compiles findings from Graph Memory, integrates audit logs from Session Memory,
    and uses the LLM to generate executive summaries and structured reports.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.REPORTING

    async def _setup_resources(self) -> None:
        """Initialize reporting templates and exporters."""
        template_dir = os.path.join(os.path.dirname(__file__), "..", "reporting", "templates")
        self.exporter = ReportExporter(template_dir)
        self.generated_reports: Dict[str, Dict[str, Any]] = {}

    DETERMINISTIC_TASK_TYPES: frozenset = frozenset({
        "generate_report", "generate_yield_report", "compile_evidence",
    })

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute reporting task."""
        task_type = task.type
        payload = task.payload

        if task_type == "generate_report":
            return await self._generate_report(payload)
        elif task_type == "generate_yield_report":
            return await self._generate_yield_report(payload)
        elif task_type == "compile_evidence":
            return await self._compile_evidence(payload)
        else:
            raise AgentException(f"Unknown reporting task type: {task_type}")

    async def _generate_report(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate full assessment report."""
        engagement_id = self.ctx.current_task.engagement_id
        version = payload.get("version", "v1.0")

        # 1. Gather real data from memories (no mocks — OSOP-P0-02 anti-fabrication).
        # graph_stats: live per-engagement asset/endpoint counts from Neo4j.
        graph_stats = await self.ctx.graph_memory.get_graph_stats(engagement_id)

        # Real vulnerability nodes for this engagement, fetched from the graph below.
        findings = []
        try:
            vuln_nodes = await self.ctx.graph_memory.get_vulnerabilities_by_engagement(
                engagement_id
            )
            logger.info(
                "report_vuln_fetch", engagement_id=repr(engagement_id), vuln_count=len(vuln_nodes)
            )

            # Best-effort traceability: map vulnerability id -> audit event_id with a
            # single query (not one per finding). This MUST be fully isolated — any
            # failure here (missing method, DB hiccup, no events written yet) must
            # never abort the findings loop. A prior bug called a non-existent method
            # (find_audit_events), raising AttributeError that dropped every finding
            # even when vulnerabilities existed (report findings_included=0).
            audit_event_by_target: Dict[str, str] = {}
            try:
                audit_events = await self.ctx.session_memory.query_audit_log(
                    engagement_id=engagement_id,
                    event_types=["vulnerability_discovered"],
                )
                for ev in audit_events:
                    ctx_data = ev.context or {}
                    tgt = ctx_data.get("vulnerability_id") or ctx_data.get("target_id")
                    if tgt:
                        audit_event_by_target.setdefault(tgt, ev.event_id)
            except Exception as audit_err:  # noqa: BLE001 - traceability is non-critical
                logger.debug("audit_event_lookup_skipped", error=str(audit_err))

            for n in vuln_nodes:
                # Use actual evidence from the vulnerability node; never fabricate.
                raw_evidence = n.get("evidence", [])
                evidence_str = ""
                if isinstance(raw_evidence, list) and raw_evidence:
                    evidence_parts = []
                    for ev in raw_evidence:
                        if isinstance(ev, dict):
                            ev_type = ev.get("type", "unknown")
                            ev_payload = ev.get("payload", "")
                            ev_response = ev.get("response", "")
                            ev_provenance = ev.get("provenance", "")
                            parts = [f"Type: {ev_type}"]
                            if ev_payload:
                                parts.append(f"Payload: {ev_payload}")
                            if ev_response:
                                parts.append(f"Response: {ev_response}")
                            if ev_provenance:
                                parts.append(f"Provenance: {ev_provenance}")
                            evidence_parts.append("\n".join(parts))
                        else:
                            evidence_parts.append(str(ev))
                    evidence_str = "\n\n---\n\n".join(evidence_parts)
                elif isinstance(raw_evidence, str):
                    evidence_str = raw_evidence
                if not evidence_str:
                    evidence_str = "No evidence recorded for this finding."

                # Hash over the FULL evidence (integrity of the real, complete artifact).
                evidence_hash = self.exporter.hash_evidence(evidence_str)

                # AIOSOP-REPORT-TRUNC-001: truncate the RENDERED evidence so a single
                # finding's 200KB+ raw request/response body can't bloat the report to
                # multi-MB. Full evidence remains in the graph/vault; the hash above still
                # covers the complete text so integrity/traceability is preserved.
                _max = settings.report_evidence_max_chars
                display_evidence = evidence_str
                if _max and len(evidence_str) > _max:
                    display_evidence = (
                        evidence_str[:_max]
                        + f"\n\n...[truncated {len(evidence_str) - _max} chars — "
                        "full evidence in the evidence vault; sha256 above covers the complete artifact]"
                    )

                # Resolve event_id from the pre-built audit map; default if absent.
                event_id = audit_event_by_target.get(n.get("id"), "no-audit-event")

                # AIOSOP-TAXONOMY-001: enrich each finding with ATT&CK / OWASP /
                # CVSS / remediation so the technical report carries standard
                # identifiers and actionable remediation for every entry.
                from ai_osop.core.attack_taxonomy import enrich_finding
                from ai_osop.core.bounty_report import _CVSS, _REMEDIATION

                sev_key = str(n.get("severity", "info")).strip().lower()
                vuln_type = n.get("vuln_type", "unknown")

                finding = enrich_finding(
                    {
                        "id": n.get("id"),
                        "title": n.get("title", "Unknown"),
                        "severity": n.get("severity", "INFO"),
                        "vuln_type": vuln_type,
                        "target": n.get("endpoint_id", "unknown"),
                        "description": n.get("description", "No description provided."),
                        "evidence": display_evidence,
                        "evidence_hash": evidence_hash,
                        "event_id": event_id,
                    }
                )
                finding["cvss"] = _CVSS.get(sev_key, _CVSS.get("info", "0.0 (Informational)"))
                finding["remediation"] = _REMEDIATION.get(
                    vuln_type, "Apply input validation and least-privilege controls."
                )
                findings.append(finding)
        except Exception as e:
            logger.warning("could_not_fetch_findings_from_graph", error=str(e))

        # 2. Generate Risk Narrative via LLM
        # AIOSOP-REPORT-SEVCASE-001: severities are stored lowercase (nuclei emits
        # "info"/"high"/...), but the counts previously compared against uppercase
        # literals ("HIGH"/"CRITICAL") — so high_count/critical_count were ALWAYS 0,
        # silently hiding the most important findings AND causing the LLM narrative
        # (fed from these counts) to falsely assert "no high-severity findings".
        # Normalize case and count every bucket.
        def _sev(f: Dict[str, Any]) -> str:
            return str(f.get("severity", "info")).strip().upper()

        stats = {
            "assets_count": graph_stats.get("assets", 0),
            "endpoints_count": graph_stats.get("endpoints", 0),
            "critical_count": sum(1 for f in findings if _sev(f) == "CRITICAL"),
            "high_count": sum(1 for f in findings if _sev(f) == "HIGH"),
            "medium_count": sum(1 for f in findings if _sev(f) == "MEDIUM"),
            "low_count": sum(1 for f in findings if _sev(f) == "LOW"),
            "info_count": sum(1 for f in findings if _sev(f) == "INFO"),
            "total_findings": len(findings),
        }

        top_titled = [f"{f.get('title', 'Unknown')} [{_sev(f)}]" for f in findings[:5]]
        context = (
            f"Engagement {engagement_id}. Finding counts: {stats}. "
            f"Top findings: {top_titled}. "
            "Base the narrative strictly on these counts and severities; do not state "
            "there are no high/critical findings if the counts show otherwise."
        )
        messages = [
            {
                "role": "system",
                "content": "You are a Senior Security Consultant. Write a 2-paragraph executive risk narrative based on the provided findings context. Classify as CONFIDENTIAL.",
            },
            {"role": "user", "content": context},
        ]
        risk_narrative = await self.ctx.llm_client.complete(messages)

        # 3. Render Templates
        report_context = {
            "engagement_id": engagement_id,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "version": version,
            "risk_narrative": risk_narrative,
            "stats": stats,
            "top_findings": findings[:5],
            "findings": findings,
        }

        try:
            exec_md = self.exporter.generate_markdown("executive.md.j2", report_context)
            tech_md = self.exporter.generate_markdown("technical.md.j2", report_context)
            full_md = exec_md + "\n\n" + tech_md
            html_report = self.exporter.markdown_to_html(full_md)
        except Exception as e:
            logger.error("template_rendering_failed", error=str(e))
            raise AgentException(f"Template rendering failed: {e}")

        # 4. Generate Attack Graph Visualization
        graph_data = {"nodes": [], "edges": []}
        try:
            nodes = await self.ctx.graph_memory.get_all_nodes_for_engagement(engagement_id)
            edges = await self.ctx.graph_memory.get_all_edges_for_engagement(engagement_id)
            for n in nodes:
                graph_data["nodes"].append(
                    {"id": n.get("id") or "unknown", "labels": list(n.get("labels") or [])}
                )
            for e in edges:
                graph_data["edges"].append(
                    {
                        "source": e.get("source") or "unknown",
                        "target": e.get("target") or "unknown",
                        "type": e.get("type") or "unknown",
                    }
                )
        except Exception as e:
            logger.warning("attack_graph_compilation_failed", error=str(e))

        graph_html = self.exporter.render_attack_graph(graph_data, engagement_id)

        # 4.5. Generate Mission Quality Certificate (Sprint 11)
        try:
            from ai_osop.core.findings_quality import FindingCertificationEngine

            await FindingCertificationEngine.generate_mission_certificate(
                engagement_id, self.ctx.session_memory, self.ctx.graph_memory
            )
        except Exception as e:
            logger.warning("mission_certificate_generation_failed", error=str(e))

        # 4.6. Generate Attack Surface Coverage Certificate (Sprint 12)
        try:
            from ai_osop.core.findings_quality import AttackSurfaceCertifier

            await AttackSurfaceCertifier.generate_attack_surface_certificate(
                engagement_id, self.ctx.session_memory, self.ctx.graph_memory
            )
        except Exception as e:
            logger.warning("attack_surface_certificate_generation_failed", error=str(e))

        # 5. Save generated assets — in-memory AND on disk so the report
        # survives restart and operators can inspect drafts before approval.
        report_id = f"report-{engagement_id}-{version}"
        json_blob = self.exporter.export_json(report_context)
        self.generated_reports[report_id] = {
            "markdown": full_md,
            "html": html_report,
            "graph_html": graph_html,
            "json": json_blob,
        }

        import os

        reports_dir = os.path.join("reports", safe_component(engagement_id))
        os.makedirs(reports_dir, exist_ok=True)
        artifacts: Dict[str, str] = {}
        for ext, content in (
            ("md", full_md),
            ("html", html_report),
            ("graph.html", graph_html),
            ("json", json_blob),
        ):
            path = os.path.join(reports_dir, f"{report_id}.{ext}")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            artifacts[ext] = os.path.abspath(path)

        return {
            "status": "success",
            "report_id": report_id,
            "version": version,
            "findings_included": len(findings),
            "requires_approval": True,
            "report_paths": artifacts,
            "report_path": artifacts["json"],
            "message": "Report drafts persisted to disk; awaiting operator sign-off before final export.",
        }

    async def _generate_yield_report(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate findings conversion and yield report (Sprint 14)."""
        from ai_osop.core.findings_quality import FindingConversionEngine

        engagement_id = self.ctx.current_task.engagement_id

        # 1. Fetch Findings (already fetched in _generate_report or here)
        # Mocking finding fetch for this demonstration
        # 1. Fetch Findings (already fetched in _generate_report or here)
        # Fetch outcomes from finding_corpus (Sprint 15)
        outcomes = []
        try:
            from sqlalchemy import text

            async with self.ctx.session_memory._async_session() as session:
                res = await session.execute(
                    text(
                        "SELECT original_finding_id AS finding_id, outcome AS status FROM finding_corpus WHERE engagement_id = :eid"
                    ),
                    {"engagement_id": engagement_id},
                )
                outcomes = [dict(r._mapping) for r in res.all()]
        except Exception as e:
            logger.warning("failed_fetch_outcomes", error=str(e))

        # 2. Calculate Yield
        stats = FindingConversionEngine.calculate_yield(
            discovery_inputs=payload.get("discovery_inputs", 100),
            raw_findings=len(outcomes),
            certified_findings=len([o for o in outcomes if o["status"] == "accepted"]),
        )

        heatmap = FindingConversionEngine.generate_yield_heatmap(
            [{"id": o["finding_id"], "certification": {"status": o["status"]}} for o in outcomes]
        )

        # 3. Save Report
        md_content = f"""# FINDING YIELD INTELLIGENCE REPORT
**Engagement ID:** `{engagement_id}`

## 1. Finding Conversion Ratio (FCR)
| Metric | Value |
|---|---|
| **Raw Conversion** | {stats['raw_conversion']:.2f} |
| **Validation Conversion** | {stats['certification_conversion']:.2f} |
| **Finding Conversion Ratio** | {stats['finding_conversion_ratio']:.2f} |

## 2. Yield Heatmap
| Privilege Level | Finding Count |
|---|---|
| Anonymous | {heatmap['anonymous']} |
| Authenticated | {heatmap['authenticated']} |
| Admin | {heatmap['admin']} |
"""
        reports_dir = os.path.join("reports", safe_component(engagement_id))
        os.makedirs(reports_dir, exist_ok=True)
        report_path = os.path.join(reports_dir, "FINDING_YIELD_REPORT.md")
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(md_content)

        return {"status": "success", "report_path": os.path.abspath(report_path)}

    async def _compile_evidence(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Compile and hash evidence for chain of custody."""
        evidence_list = payload.get("evidence", [])
        compiled = []
        for ev in evidence_list:
            hashed = self.exporter.hash_evidence(ev)
            compiled.append({"content": ev, "sha256": hashed})

        return {"status": "success", "compiled_evidence": compiled}

    async def _cleanup_resources(self) -> None:
        """Cleanup report resources."""
        self.generated_reports.clear()
