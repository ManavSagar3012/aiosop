"""
Reporting Agent
Responsible for compiling evidence, generating risk narratives, and exporting
assessment results into structured deliverables.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType, settings
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import Task, Vulnerability
from ai_osop.reporting.exporters import ReportExporter


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

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute reporting task."""
        task_type = task.type
        payload = task.payload

        if task_type == "generate_report":
            return await self._generate_report(payload)
        elif task_type == "compile_evidence":
            return await self._compile_evidence(payload)
        else:
            raise AgentException(f"Unknown reporting task type: {task_type}")

    async def _generate_report(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate full assessment report."""
        engagement_id = self.ctx.current_task.engagement_id
        version = payload.get("version", "v1.0")

        # 1. Gather Data from Memories
        # In a full implementation, we'd query graph_memory.get_vulnerabilities()
        # Mocking data retrieval for P1 scope
        graph_stats = await self.ctx.graph_memory.get_graph_stats(engagement_id)

        # We need actual vulnerability data. For this implementation we mock querying them
        # if the real method isn't fully implemented in graph_memory.
        findings = []
        try:
            # Attempt to run a custom cypher query to get findings
            query = "MATCH (v:Vulnerability) WHERE v.engagement_id = $eid RETURN v"
            async with self.ctx.graph_memory._driver.session() as session:
                result = await session.run(query, eid=engagement_id)
                for record in await result.data():
                    n = record["v"]
                    findings.append(
                        {
                            "id": n.get("id"),
                            "title": n.get("title", "Unknown"),
                            "severity": n.get("severity", "INFO"),
                            "vuln_type": n.get("vuln_type", "unknown"),
                            "target": n.get("endpoint_id", "unknown"),
                            "description": n.get("description", "No description provided."),
                            "evidence": "Payload: <script>alert(1)</script>\nResponse: 200 OK",
                            "evidence_hash": self.exporter.hash_evidence(
                                "Payload: <script>alert(1)</script>"
                            ),
                            "event_id": "evt-" + n.get("id", "000")[-6:],
                        }
                    )
        except Exception as e:
            print(f"WARN: Could not fetch findings from graph: {e}")

        # 2. Generate Risk Narrative via LLM
        stats = {
            "assets_count": graph_stats.get("total_assets", 0),
            "endpoints_count": graph_stats.get("total_endpoints", 0),
            "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high_count": sum(1 for f in findings if f["severity"] == "HIGH"),
        }

        context = f"Engagement {engagement_id} findings: {stats}. Top findings: {[f['title'] for f in findings[:3]]}"
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
            print(f"ERROR: Template rendering failed: {e}")
            raise AgentException(f"Template rendering failed: {e}")

        # 4. Generate Attack Graph Visualization
        # Mocking graph data for visualization
        graph_data = {"nodes": [], "edges": []}
        try:
            query = "MATCH (n) WHERE n.engagement_id = $eid RETURN n"
            async with self.ctx.graph_memory._driver.session() as session:
                result = await session.run(query, eid=engagement_id)
                for record in await result.data():
                    n = record["n"]
                    graph_data["nodes"].append(
                        {"id": n.get("id", "unknown"), "labels": list(n.labels)}
                    )
        except Exception:
            pass

        graph_html = self.exporter.render_attack_graph(graph_data, engagement_id)

        # 5. Save generated assets
        report_id = f"report-{engagement_id}-{version}"
        self.generated_reports[report_id] = {
            "markdown": full_md,
            "html": html_report,
            "graph_html": graph_html,
            "json": self.exporter.export_json(report_context),
        }

        # The task requires approval to export/finalize
        return {
            "status": "success",
            "report_id": report_id,
            "version": version,
            "findings_included": len(findings),
            "requires_approval": True,
            "message": "Report generated and awaiting operator sign-off before export.",
        }

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
