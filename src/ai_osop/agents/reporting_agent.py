"""Evidence-grounded, review-only security assessment reporting.

Reports reflect persisted graph-marked vulnerabilities with recorded evidence.
The graph's validated flag does not authenticate the source. Even a signed
draft preserves that UNKNOWN evidence-origin boundary; only independent
durable source verification can qualify a release candidate.
Never synthesize an exploit payload, response status, severity or audit event.
"""

import hashlib
import html
import json
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import EvidenceArtifact, Task
from ai_osop.reporting.artifact_store import publish_report_bundle
from ai_osop.reporting.attestation import (
    ReportAttestationError,
    hash_evidence_snapshot,
    sign_report_attestation,
)
from ai_osop.reporting.exporters import ReportExporter
from ai_osop.safety.approval_binding import task_payload_sha256

_SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_.-]{1,128}$")
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_MAX_REPORT_FINDINGS = 200
_MAX_CANDIDATE_REFS_PER_FINDING = 12
_SHA256_LOWER = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_BINDING_FIELDS = (
    "source_task_id",
    "source_task_sha256",
    "flow_id",
    "flow_revision",
    "authorization_version",
    "authorization_sha256",
    "source_event_id",
    "provider_receipt_sha256",
)
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(bearer|basic)\s+[a-z0-9._~+/-]{8,}"),
    re.compile(r"(?i)\b(password|api[_-]?key|secret|token|authorization)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)\b(?:gh[pousr]_[a-z0-9]{20,}|sk-(?:live|test)-[a-z0-9]{12,})\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
)


def _safe_text(value: Any, limit: int = 200) -> str:
    """Keep concise display metadata, not credentials or executable markup."""
    if not isinstance(value, str):
        return ""
    value = value[:4096]
    for secret_pattern in _SECRET_PATTERNS:
        value = secret_pattern.sub("[REDACTED]", value)
    value = "".join(char if char.isprintable() else " " for char in value).strip()
    # Escape both embedded HTML and Markdown control characters, because the
    # existing exporter converts Markdown to HTML without sanitizing HTML.
    value = html.escape(value[:limit], quote=True)
    for mark in ("\\", "`", "*", "_", "[", "]", "<", ">"):
        value = value.replace(mark, "\\" + mark)
    return value


def _evidence_digest(raw: Any) -> str:
    """Hash actual saved evidence deterministically, never a sample payload."""
    return hash_evidence_snapshot(raw)


def _node_value(node: Any, key: str) -> Any:
    """Neo4j Node and test fixtures use mapping/get lookup."""
    return node.get(key) if callable(getattr(node, "get", None)) else None


def _raw_evidence(node: Any) -> Any:
    value = _node_value(node, "evidence")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return None
    try:
        hash_evidence_snapshot(value)
    except ReportAttestationError:
        return None
    return value


def _validated_finding(node: Any, engagement_id: str) -> Dict[str, Any] | None:
    if _node_value(node, "engagement_id") != engagement_id:
        return None
    if _node_value(node, "validated") is not True:
        return None
    identifier = _node_value(node, "id")
    if not isinstance(identifier, str) or not _SAFE_IDENTIFIER.fullmatch(identifier):
        return None
    severity = _node_value(node, "severity")
    if not isinstance(severity, str) or severity.upper() not in _VALID_SEVERITIES:
        return None
    raw_evidence = _raw_evidence(node)
    if raw_evidence is None:
        return None
    title = _safe_text(_node_value(node, "title"), limit=160)
    if not title:
        return None
    evidence_hash = _evidence_digest(raw_evidence)
    # Do not copy potentially sensitive HTTP headers, payloads, credentials,
    # reflection fragments or copied secret values into any report artifact.
    # The SHA256 is over the source evidence as stored in Neo4j; this says
    # nothing about who created it or whether a target produced those bytes.
    event_ids = [
        item.get("event_id")
        for item in raw_evidence
        if isinstance(item.get("event_id"), str)
        and re.fullmatch(r"evt-[A-Za-z0-9-]{1,80}", item["event_id"])
    ]
    # Include a bounded graph *claim* of source lineage in the signed report
    # JSON so it cannot be attached/changed after signing. Its presence does
    # not authenticate the claim: the release API must verify independent PG
    # Task/Flow/signed provider receipt evidence before senior signoff.
    binding = {key: _node_value(node, key) for key in _SOURCE_BINDING_FIELDS}
    source_binding = None
    if (
        isinstance(binding["source_task_id"], str)
        and re.fullmatch(r"task-[A-Za-z0-9._-]{1,78}", binding["source_task_id"])
        and isinstance(binding["flow_id"], str)
        and re.fullmatch(r"flow-[A-Za-z0-9._-]{1,78}", binding["flow_id"])
        and isinstance(binding["source_event_id"], str)
        and re.fullmatch(r"evt-[A-Za-z0-9._-]{1,60}", binding["source_event_id"])
        and all(
            isinstance(binding[name], str) and re.fullmatch(r"[0-9a-f]{64}", binding[name])
            for name in (
                "source_task_sha256",
                "authorization_sha256",
                "provider_receipt_sha256",
            )
        )
        and type(binding["flow_revision"]) is int
        and binding["flow_revision"] >= 0
        and type(binding["authorization_version"]) is int
        and binding["authorization_version"] > 0
    ):
        source_binding = binding
    return {
        "id": identifier,
        "title": title,
        "severity": severity.upper(),
        "vuln_type": _safe_text(_node_value(node, "vuln_type"), limit=80) or "Not recorded",
        "target": _safe_text(_node_value(node, "endpoint_id"), limit=120) or "Not recorded",
        "description": (
            "Marked validated in the engagement graph (unattributed record). "
            "Evidence origin and target-side authenticity are UNKNOWN; "
            "a graph flag or digest does not constitute independent proof. "
            "Original bytes remain restricted; this draft excludes raw bodies."
        ),
        "evidence": "Recorded evidence SHA-256: " + evidence_hash,
        "evidence_hash": evidence_hash,
        "event_id": event_ids[0] if event_ids else "Not recorded",
        # Neo4j's Boolean indicates a graph review only; exposing it as
        # validated=true in a public report promoted the claim across a trust
        # boundary. Preserve the graph fact under an explicitly scoped name.
        "validated": False,
        "graph_validated": True,
        "source_authenticity_verified": False,
        "source_provenance_status": "UNKNOWN_graph_flag_only",
        "source_binding": source_binding,
    }


class ReportingAgent(BaseAgent):
    """Create reproducible, evidence-only report drafts for operator approval."""

    @property
    def agent_type(self) -> AgentType:
        return AgentType.REPORTING

    async def _setup_resources(self) -> None:
        template_dir = os.path.join(os.path.dirname(__file__), "..", "reporting", "templates")
        self.exporter = ReportExporter(template_dir)
        self.generated_reports: Dict[str, Dict[str, Any]] = {}

    async def _execute(self, task: Task) -> Dict[str, Any]:
        if task.type == "generate_report":
            return await self._generate_report(task.payload)
        if task.type == "compile_evidence":
            return await self._compile_evidence(task.payload)
        raise AgentException(f"Unknown reporting task type: {task.type}")

    async def _attach_current_candidate_artifact_references(
        self,
        engagement_id: str,
        task: Task,
        findings: List[Dict[str, Any]],
        generation_binding: Dict[str, Any],
    ) -> None:
        """Attach 0024 metadata hashes to matching signed *draft* findings only.

        This is a bounded READ, not a graph-validated or independent target-side
        effect. Never copy a URL, replay recipe, provider receipt, HTTP header,
        raw request/response, or unverifiable value into a report. Existing
        v2 report signing covers these extra JSON fields as exact artifact bytes.
        """
        from ai_osop.memory.session_memory import SessionMemory, _checked_evidence_artifact

        memory = self.ctx.session_memory
        if not isinstance(memory, SessionMemory):
            return
        if not hasattr(memory, "_async_session"):
            # SessionMemory.__new__ from offline legacy signed-unit fixtures
            # has NO production PostgreSQL and must not fabricate evidence.
            return
        if not callable(memory._async_session):
            raise AgentException("Signed report candidate evidence store unavailable")
        if not findings:
            return

        expected_version = generation_binding["authorization_version"]
        expected_policy = generation_binding["authorization_sha256"]
        flow_id = generation_binding.get("flow_id")
        flow_revision = generation_binding.get("flow_revision")

        async def check_report_authority() -> None:
            signed = await memory.assert_signed_authorization(
                engagement_id,
                expected_version=expected_version,
            )
            generating = await memory.load_task_authoritative(task.id)
            if (
                getattr(signed, "version", None) != expected_version
                or getattr(signed, "policy_sha256", None) != expected_policy
                or generating is None
                or generating.id != task.id
                or generating.engagement_id != engagement_id
                or generating.status != "running"
                or generating.type != "generate_report"
                or generating.agent_type != AgentType.REPORTING
                or generating.assigned_agent_id != self.ctx.agent_id
                or generating.flow_id != task.flow_id
                or generating.subtask_id != task.subtask_id
                or generating.payload != task.payload
                or generating.approval_required is not True
            ):
                raise ValueError("Report generating Task or signed authority changed")
            if flow_id is not None:
                flow = await memory.load_flow(flow_id)
                if (
                    flow is None
                    or flow.id != flow_id
                    or flow.engagement_id != engagement_id
                    or flow.status not in {"pending", "running"}
                    or type(flow.revision) is not int
                    or flow.revision != flow_revision
                ):
                    raise ValueError("Report generating Flow revision is stale")

        try:
            await check_report_authority()
            for finding in findings:
                finding_id = finding["id"]
                # No evidence is invented or inferred from Neo4j properties.
                await check_report_authority()
                artifacts = await memory.list_finding_evidence(engagement_id, finding_id)
                if (
                    not isinstance(artifacts, list)
                    or len(artifacts) > _MAX_CANDIDATE_REFS_PER_FINDING
                ):
                    raise ValueError("Evidence artifacts are unavailable or unbounded")
                refs: List[Dict[str, Any]] = []
                seen = set()
                for artifact in artifacts:
                    if not isinstance(artifact, EvidenceArtifact):
                        raise ValueError("Immutable evidence artifact type is invalid")
                    _checked_evidence_artifact(artifact)
                    recipe = artifact.replay_recipe
                    source_id = recipe.get("source_task_id")
                    if (
                        artifact.engagement_id != engagement_id
                        or artifact.finding_id != finding_id
                        or artifact.source_tool != "signed_browser_provider_summary"
                        or not isinstance(source_id, str)
                        or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,59}", source_id)
                        or not _SHA256_LOWER.fullmatch(artifact.merkle_leaf_hash)
                        or recipe.get("replayable") is not False
                        or recipe.get("finding_verified") is not False
                        or recipe.get("target_effect_verified") is not False
                        or artifact.merkle_leaf_hash in seen
                    ):
                        raise ValueError("Candidate artifact linkage is invalid")
                    seen.add(artifact.merkle_leaf_hash)
                    source = await memory.load_task_authoritative(source_id)
                    provider_event = (
                        source.result.get("provider_evidence")
                        if source is not None and isinstance(source.result, dict)
                        else None
                    )
                    if (
                        source is None
                        or source.id != source_id
                        or source.engagement_id != engagement_id
                        or source.type != "navigate"
                        or source.status != "completed"
                        or not source.approval_required
                        or not isinstance(source.payload, dict)
                        or source.payload.get("_authorization_version") != expected_version
                        or type(source.payload.get("_flow_revision")) is not int
                        or not isinstance(source.payload.get("url"), str)
                        or source.payload.get("method", "GET") != "GET"
                        or source.payload.get("operator_approved") is not True
                        or source.payload.get("approval_id") != artifact.approval_id
                        or not isinstance(artifact.approval_id, str)
                        or not isinstance(source.flow_id, str)
                        or (flow_id is not None and source.flow_id != flow_id)
                        or hashlib.sha256(source.payload["url"].encode("utf-8")).hexdigest()
                        != recipe.get("original_url_sha256")
                        or not isinstance(source.result, dict)
                        or source.result.get("status") != "success"
                        or source.result.get("verification_status") != "provider_testimony_only"
                        or source.result.get("remote_effect_verified") is not False
                        or source.result.get("authorization_violation_verified") is not False
                        or source.result.get("findings_count") != 0
                        or source.result.get("redirected") is not False
                        or source.result.get("http_status_code") != artifact.response_status
                        or not isinstance(provider_event, dict)
                        or provider_event.get("source_authenticity_verified") is not False
                        or provider_event.get("target_effect_verified") is not False
                        or provider_event.get("finding_verified") is not False
                        or not isinstance(provider_event.get("provider_event_id"), str)
                        or not re.fullmatch(
                            r"evt-[A-Za-z0-9._-]{1,80}",
                            provider_event["provider_event_id"],
                        )
                        or not isinstance(provider_event.get("provider_receipt_sha256"), str)
                        or not _SHA256_LOWER.fullmatch(provider_event["provider_receipt_sha256"])
                    ):
                        raise ValueError("Signed navigation candidate source is stale")
                    flow = await memory.load_flow(source.flow_id)
                    if (
                        flow is None
                        or flow.id != source.flow_id
                        or flow.engagement_id != engagement_id
                        or flow.status not in {"pending", "running"}
                        or flow.revision != source.payload["_flow_revision"]
                    ):
                        raise ValueError("Signed navigation Flow changed")
                    if not await memory.is_task_approved(
                        source.id,
                        engagement_id,
                        artifact.approval_id,
                    ):
                        raise ValueError("Signed navigation human approval is not current")
                    # Fresh authority and source readback after the awaited
                    # Flow/approval calls; no post-factum graph claim upgrade.
                    fresh = await memory.load_task_authoritative(source_id)
                    if fresh is None or fresh.model_dump(mode="json") != source.model_dump(
                        mode="json"
                    ):
                        raise ValueError("Signed navigation source changed during read")
                    fresh_source_flow = await memory.load_flow(source.flow_id)
                    if (
                        fresh_source_flow is None
                        or fresh_source_flow.id != source.flow_id
                        or fresh_source_flow.engagement_id != engagement_id
                        or fresh_source_flow.status not in {"pending", "running"}
                        or fresh_source_flow.revision != source.payload["_flow_revision"]
                    ):
                        raise ValueError("Signed navigation Flow changed after source reads")
                    await check_report_authority()
                    refs.append(
                        {
                            "schema": "ai-osop.candidate-artifact-reference.v1",
                            "merkle_leaf_sha256": artifact.merkle_leaf_hash,
                            "source_task_id_sha256": hashlib.sha256(
                                b"ai-osop-report-navigation-source-v1\0"
                                + engagement_id.encode("utf-8")
                                + b"\0"
                                + source_id.encode("utf-8")
                            ).hexdigest(),
                            "verification_state": "candidate_unverified",
                            "independent_target_effect_verified": False,
                        }
                    )
                finding["candidate_evidence_artifacts"] = sorted(
                    refs,
                    key=lambda item: item["merkle_leaf_sha256"],
                )
                await check_report_authority()
            await check_report_authority()
        except Exception as exc:
            raise AgentException(
                "Current signed candidate evidence provenance unavailable"
            ) from exc

    async def _generate_report(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        task = self.ctx.current_task
        if task is None or not task.engagement_id or task.engagement_id == "api-bootstrap":
            raise AgentException("Reporting requires a persisted engagement task")
        engagement_id = task.engagement_id
        require_attestation = payload.get("require_attestation", False)
        if type(require_attestation) is not bool:
            raise AgentException("Report attestation must be requested explicitly")
        signer_key_id = payload.get("signer_key_id")
        if (signer_key_id is not None and not require_attestation) or (
            require_attestation and (not isinstance(signer_key_id, str) or not signer_key_id)
        ):
            raise AgentException("Signed reports require an explicit trusted signer key ID")
        version = payload.get("version", "v-" + uuid.uuid4().hex)
        if (
            not isinstance(version, str)
            or not _SAFE_IDENTIFIER.fullmatch(version)
            or not _SAFE_IDENTIFIER.fullmatch(engagement_id)
        ):
            raise AgentException("Unsafe report identifier")

        # An in-memory AgentContext is not a proof of engagement authorization.
        # Load the current durable scope before opening graph/report assets.
        try:
            engagement = await self.ctx.session_memory.load_session_state(engagement_id)
        except Exception as exc:
            raise AgentException("Cannot verify current report engagement") from exc
        if (
            engagement is None
            or engagement.session_id != engagement_id
            or engagement.phase in {"halted", "completed"}
            or not engagement.scope.authorization_ref
            or not (engagement.scope.domains or engagement.scope.ips)
        ):
            raise AgentException("Reporting engagement is not currently authorized")

        generation_binding = None
        if require_attestation:
            # A v2 signed artifact must be bound to an actual verified ROE
            # and immutable persisted generating Task. Fake/offline stores
            # keep the legacy v1 draft-only format, never release-certified.
            from ai_osop.memory.session_memory import SessionMemory

            if isinstance(self.ctx.session_memory, SessionMemory):
                try:
                    signed = await self.ctx.session_memory.assert_signed_authorization(
                        engagement_id,
                        expected_version=task.payload.get("_authorization_version"),
                    )
                    persisted = await self.ctx.session_memory.load_task_authoritative(task.id)
                    if (
                        persisted is None
                        or persisted.engagement_id != engagement_id
                        or persisted.type != "generate_report"
                        or persisted.agent_type != AgentType.REPORTING
                        or persisted.id != task.id
                        or persisted.flow_id != task.flow_id
                        or persisted.subtask_id != task.subtask_id
                        or persisted.status != "running"
                        or persisted.started_at is None
                        or persisted.assigned_agent_id != self.ctx.agent_id
                        or not persisted.approval_required
                        or persisted.payload != task.payload
                        or task.payload.get("require_attestation") is not True
                        or type(task.payload.get("_authorization_version")) is not int
                        or task.payload["_authorization_version"] != signed.version
                    ):
                        raise ValueError("Generating Task is not durably admitted")
                    generation_binding = {
                        "task_id": task.id,
                        "authorization_version": signed.version,
                        "authorization_sha256": signed.policy_sha256,
                        "task_payload_sha256": task_payload_sha256(persisted.payload),
                    }
                    if task.flow_id is not None:
                        flow = await self.ctx.session_memory.load_flow(task.flow_id)
                        if (
                            flow is None
                            or flow.id != task.flow_id
                            or flow.engagement_id != engagement_id
                            or flow.status not in {"pending", "running"}
                            or type(flow.revision) is not int
                            or flow.revision < 0
                        ):
                            raise ValueError("Signed report Flow is no longer executable")
                        generation_binding.update(
                            {
                                "flow_id": flow.id,
                                "flow_revision": flow.revision,
                            }
                        )
                except Exception as exc:
                    raise AgentException(
                        "Trusted report generating Task authorization unavailable"
                    ) from exc

        # Graph failures are unknown-data failures, never a misleading
        # "zero findings" success. Graph validated + evidenced records are
        # eligible for clearly non-certified DRAFTS only. The release route
        # independently gates their signed durable source chain.
        try:
            graph_stats = await self.ctx.graph_memory.get_graph_stats(engagement_id)
            driver = self.ctx.graph_memory._driver
            if driver is None:
                raise RuntimeError("Graph memory unavailable")
            query = (
                "MATCH (v:Vulnerability {engagement_id: $eid}) "
                "WHERE v.validated = true RETURN v ORDER BY v.id LIMIT $limit"
            )
            async with driver.session() as session:
                result = await session.run(query, eid=engagement_id, limit=_MAX_REPORT_FINDINGS + 1)
                rows = await result.data()
        except Exception as exc:
            raise AgentException("Verified findings could not be read from graph memory") from exc
        if not isinstance(rows, list) or len(rows) > _MAX_REPORT_FINDINGS:
            # A silently truncated list would misstate critical/high counts.
            raise AgentException("Verified findings exceed the bounded report capacity")
        if not isinstance(graph_stats, dict) or any(
            type(graph_stats.get(key)) is not int or graph_stats[key] < 0
            for key in ("assets", "endpoints")
        ):
            raise AgentException("Authoritative engagement graph statistics are unavailable")

        unique: Dict[str, Dict[str, Any]] = {}
        for record in rows:
            if not isinstance(record, dict):
                continue
            finding = _validated_finding(record.get("v"), engagement_id)
            if finding is not None:
                identifier = finding["id"]
                if require_attestation and identifier in unique and unique[identifier] != finding:
                    raise AgentException("Conflicting signed report evidence records")
                unique[finding["id"]] = finding
        findings = [unique[key] for key in sorted(unique)]
        # A nonempty signed draft must at least carry each finding's exact
        # bounded source lineage; otherwise the independent 0022 verification
        # and final release pipeline have nothing trustworthy to revalidate.
        # This checks shape/current signed scope ONLY, not 0022 proof or release.
        if require_attestation and findings:
            if generation_binding is None:
                raise AgentException("Signed nonempty report requires durable generation admission")
            if any(
                finding.get("source_binding") is None
                or finding["source_binding"]["authorization_version"]
                != generation_binding["authorization_version"]
                or finding["source_binding"]["authorization_sha256"]
                != generation_binding["authorization_sha256"]
                or (
                    "flow_id" in generation_binding
                    and (
                        finding["source_binding"]["flow_id"] != generation_binding["flow_id"]
                        or finding["source_binding"]["flow_revision"]
                        != generation_binding["flow_revision"]
                    )
                )
                for finding in findings
            ):
                raise AgentException(
                    "Signed nonempty report source binding is missing or stale; "
                    "independent 0022 source verification remains UNKNOWN"
                )

        if require_attestation and generation_binding is not None and findings:
            # The immutable 0024 ledger is separate from graph source claims.
            # A failure to fetch/revalidate it aborts signing; a legacy
            # synthetic unit memory without any durable PostgreSQL has no
            # artifact references and must not invent them.
            await self._attach_current_candidate_artifact_references(
                engagement_id,
                task,
                findings,
                generation_binding,
            )

        def graph_count(key: str) -> int:
            value = graph_stats.get(key) if isinstance(graph_stats, dict) else None
            return value if type(value) is int and value >= 0 else 0

        stats = {
            "assets_count": graph_count("assets"),
            "endpoints_count": graph_count("endpoints"),
            "critical_count": sum(item["severity"] == "CRITICAL" for item in findings),
            "high_count": sum(item["severity"] == "HIGH" for item in findings),
        }
        if findings:
            risk_narrative = (
                f"{len(findings)} graph-marked finding(s) have stored evidence "
                "fingerprints, but source authenticity is UNKNOWN. These are "
                "uncertified observations, not independently verified "
                "vulnerabilities. Severity labels are graph claims, not "
                "independently reassessed. Signed release requires durable "
                "source provenance plus separate human review; even a signed "
                "provider outcome cannot prove exploitation or business impact."
            )
        else:
            risk_narrative = (
                "No graph-marked vulnerabilities with recorded evidence "
                "were available for this engagement at report generation time. "
                "This does not demonstrate that the assessed systems are secure "
                "or that all testing was completed."
            )
        report_context = {
            "engagement_id": engagement_id,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "version": version,
            "risk_narrative": risk_narrative,
            "stats": stats,
            "top_findings": findings[:5],
            "findings": findings,
            "verification_status": "verified_findings_only" if findings else "no_verified_findings",
            # Keep legacy verification_status for the existing strict signed
            # attestation schema: its scope states graph_validated_flag_only.
            # Never use that field to infer source authenticity.
            "source_authenticity_verified": False,
            "independent_target_effect_verified": False,
            "finding_source_assurance": "UNKNOWN_graph_flag_only" if findings else "NO_FINDINGS",
            "signature_status": "ed25519_signed" if require_attestation else "not_signed",
            "requires_approval": True,
        }
        try:
            exec_md = self.exporter.generate_markdown("executive.md.j2", report_context)
            tech_md = self.exporter.generate_markdown("technical.md.j2", report_context)
            # Existing templates hardcode "Verified Vulnerabilities" and
            # "Critical/High Vulnerabilities" for the graph flag. Templates
            # are prime/out-of-scope here: neutralize the misleading headings
            # in the concrete signed output before hashing/export.
            tech_md = tech_md.replace(
                "## Verified Vulnerabilities",
                "## Graph-Marked Findings (Target Verification UNKNOWN)",
            )
            exec_md = exec_md.replace(
                "Critical Vulnerabilities:",
                "Critical Graph-Marked Candidates:",
            ).replace(
                "High Vulnerabilities:",
                "High Graph-Marked Candidates:",
            )
            if not findings:
                tech_md += (
                    "\n\nNo graph-marked, evidence-backed findings "
                    "were available at the time of this draft.\n"
                )
            full_md = exec_md + "\n\n" + tech_md
            html_report = self.exporter.markdown_to_html(full_md)
            # No verified exploit edges were retrieved. Rendering a synthetic
            # attack path from unverified nodes would misrepresent the evidence.
            graph_html = self.exporter.render_attack_graph(
                {"nodes": [], "edges": []}, engagement_id
            )
            json_blob = self.exporter.export_json(report_context)
        except Exception as exc:
            raise AgentException("Report template rendering failed") from exc

        report_id = f"report-{engagement_id}-{version}"
        contents = {
            "md": full_md,
            "html": html_report,
            "graph.html": graph_html,
            "json": json_blob,
        }
        digests = {
            extension: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for extension, content in contents.items()
        }
        manifest = {
            "engagement_id": engagement_id,
            "report_id": report_id,
            "hash_algorithm": "sha256",
            "signature_status": "ed25519_signed" if require_attestation else "not_signed",
            "artifacts": digests.copy(),
        }
        if require_attestation:
            try:
                envelope = sign_report_attestation(
                    engagement_id=engagement_id,
                    report_id=report_id,
                    signer_key_id=signer_key_id,
                    artifacts={key: content.encode("utf-8") for key, content in contents.items()},
                    evidence_provenance=[
                        {
                            "finding_id": finding["id"],
                            "source_type": "validated_engagement_graph",
                            "evidence_sha256": finding["evidence_hash"],
                        }
                        for finding in findings
                    ],
                    generation_binding=generation_binding,
                )
            except ReportAttestationError as exc:
                # A signed report request must never silently become an
                # unsigned report when a signing secret/key is unavailable.
                raise AgentException("Trusted report attestation unavailable") from exc
            contents["attestation"] = json.dumps(
                envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            manifest["attestation_sha256"] = hashlib.sha256(
                contents["attestation"].encode("utf-8")
            ).hexdigest()
            digests["attestation"] = manifest["attestation_sha256"]
        # Unsigned reports retain their existing draft manifest and status.
        # Signed reports include a detached Ed25519 signature over the exact
        # artifacts/evidence fingerprints. Neither proves operator approval.
        contents["manifest"] = json.dumps(
            manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        digests["manifest"] = hashlib.sha256(contents["manifest"].encode("utf-8")).hexdigest()
        reports_root = Path(os.environ.get("OSOP_ATTESTED_REPORT_ROOT", "reports"))
        if os.environ.get("OSOP_ENV", "development") == "production" and (
            not os.environ.get("OSOP_ATTESTED_REPORT_ROOT") or not reports_root.is_absolute()
        ):
            raise AgentException("Production report storage requires a configured absolute root")
        try:
            artifacts = publish_report_bundle(reports_root, engagement_id, report_id, contents)
        except OSError as exc:
            raise AgentException("Report draft could not be persisted") from exc

        self.generated_reports[report_id] = {
            "markdown": full_md,
            "html": html_report,
            "graph_html": graph_html,
            "json": json_blob,
            "sha256": digests,
            "signature_status": report_context["signature_status"],
            "verification_status": (
                "graph_marked_candidates_unverified" if findings else "no_verified_findings"
            ),
            "finding_source_assurance": report_context["finding_source_assurance"],
        }
        return {
            "status": "success",
            "report_id": report_id,
            "version": version,
            "findings_included": len(findings),
            "verification_status": (
                "graph_marked_candidates_unverified" if findings else "no_verified_findings"
            ),
            "finding_source_assurance": report_context["finding_source_assurance"],
            "signature_status": report_context["signature_status"],
            "artifact_sha256": digests,
            "requires_approval": True,
            "report_paths": artifacts,
            "report_path": artifacts["json"],
            "message": (
                "Evidence snapshot cryptographically attested; source authenticity, "
                "exploit success and operator sign-off remain unverified."
                if require_attestation
                else "Evidence-only draft saved; hashes are not signatures. Operator sign-off is required."
            ),
        }

    async def _compile_evidence(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        evidence_list = payload.get("evidence", [])
        if not isinstance(evidence_list, list) or len(evidence_list) > 100:
            raise AgentException("Evidence must be a bounded list")
        compiled = []
        for value in evidence_list:
            if not isinstance(value, str) or len(value) > 65536:
                raise AgentException("Evidence entry must be a bounded text string")
            compiled.append(
                {
                    "content": _safe_text(value, limit=2000),
                    "sha256": self.exporter.hash_evidence(value),
                }
            )
        return {"status": "success", "compiled_evidence": compiled}

    async def _cleanup_resources(self) -> None:
        self.generated_reports.clear()
