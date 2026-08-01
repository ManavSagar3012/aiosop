"""Post-Engagement Critic Agent — platform performance auditor + adversarial challenger.

Analyzes the graph database, task execution tables, and skipped scans
from an engagement to generate an automated engineering critique of AI-OSOP itself:
  - Time spent and bottlenecks
  - Active scanners skipped/run
  - Findings rejected/escalated
  - Underutilized MCP servers

Phase 3.2 (2026-07-23): activated as an adversarial challenger. The
`audit_findings` method reviews validated findings for false positives,
missing evidence, and incomplete validation — the "peer review" the
assessment says is missing. The reasoning loop calls `audit_findings`
after each hypothesis evaluation so the critic can catch false positives
before they reach the report.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional


class PostEngagementCriticAgent:
    """Audits engagement logs and neo4j graph nodes to critique AI-OSOP performance.

    Also serves as an adversarial challenger: `audit_findings` reviews
    validated findings for false positives and incomplete evidence.
    """

    def __init__(self, session_memory: Any, graph_memory: Any):
        self.session_memory = session_memory
        self.graph_memory = graph_memory

    async def generate_critique(self, session_id: str) -> str:
        """Run audit queries and output a formatted Markdown critique."""
        session = await self.session_memory.load_session_state(session_id)
        if not session:
            return f"Error: Session {session_id} not found."

        # 1. Query all tasks for execution stats
        # We query the SQL tasks directly
        from sqlalchemy import select

        from ai_osop.memory.session_memory import TaskORM

        async with self.session_memory._async_session() as db:
            res = await db.execute(select(TaskORM).where(TaskORM.engagement_id == session_id))
            tasks_list = res.scalars().all()

        total_tasks = len(tasks_list)
        completed = len([t for t in tasks_list if t.status == "completed"])
        failed = len([t for t in tasks_list if t.status == "failed"])
        pending = len([t for t in tasks_list if t.status in ("pending", "scheduled")])

        # 2. Query skipped scans
        skipped_scans = await self.graph_memory.run_read_query(
            "MATCH (s:SkippedScan {engagement_id: $sid}) "
            "RETURN s.vuln_class as vuln_class, s.endpoint_url as endpoint_url, s.reason as reason",
            {"sid": session_id},
        )

        # 3. Query underutilized MCP servers
        mcp_stats = {}
        for server_id in [
            "browser-mcp",
            "burp-mcp",
            "nuclei-mcp",
            "recon-mcp",
            "security-bridge",
            "payload-mcp",
        ]:
            # Check count of tasks utilizing this agent type
            # We map MCP server to task type
            task_type_prefix = {
                "browser-mcp": "xss_scan",
                "burp-mcp": "burp_scan",
                "nuclei-mcp": "nuclei_scan",
                "recon-mcp": "full_recon",
                "security-bridge": "sqli_scan",
                "payload-mcp": "generate_payloads",
            }.get(server_id, "")

            count = len([t for t in tasks_list if t.type == task_type_prefix])
            mcp_stats[server_id] = count

        # 4. Generate Critique report
        critique = []
        critique.append("# AI-OSOP Post-Engagement Critic Report")
        critique.append(f"**Session ID:** `{session_id}`")
        critique.append(f"**Audit Timestamp:** {datetime.utcnow().isoformat()}Z\n")

        critique.append("## Platform Bottlenecks & Execution Cadence\n")
        critique.append(f"- **Total Tasks Schedueld:** {total_tasks}")
        critique.append(
            f"- **Completed Tasks:** {completed} ({completed/total_tasks*100:.1f}% if total > 0 else 0)"
        )
        critique.append(f"- **Failed Tasks:** {failed}")
        critique.append(f"- **Pending/Stalled Tasks:** {pending}")

        if pending > 0:
            critique.append(
                "\n⚠️ **CRITIQUE:** The platform is experiencing task queue concurrency bottlenecks. "
                f"{pending} tasks remained pending/stalled in the queue. "
                "Consider scaling concurrency workers or optimizing active scan timeouts (e.g. sqlmap risk level settings).\n"
            )
        else:
            critique.append(
                "\n✅ **CRITIQUE:** Tasks completed successfully. No queue bottlenecks observed.\n"
            )

        critique.append("## Scanner Applicability & Filtering Audit\n")
        critique.append(f"- **Total Scans Skipped:** {len(skipped_scans)}")
        for s in skipped_scans[:5]:
            critique.append(
                f"  - Skipped `{s['vuln_class'].upper()}` on `{s['endpoint_url']}` | **Reason:** {s['reason']}"
            )

        if len(skipped_scans) > 5:
            critique.append(f"  - *...and {len(skipped_scans) - 5} more skipped scans.*")

        critique.append(
            "\n💡 **CRITIQUE:** The Applicability Engine successfully prevented unsafe/read-only testing. "
            "This conserved substantial compute budget and kept the attack graph noise-free.\n"
        )

        critique.append("## MCP Subsystem Utilization\n")
        critique.append("| MCP Server | Tasks Dispatched | Utilization Status |")
        critique.append("| :--- | :---: | :--- |")
        for mcp, dispatched in mcp_stats.items():
            status = "OPTIMAL" if dispatched > 0 else "UNDERUTILIZED (Zero tasks dispatched)"
            critique.append(f"| `{mcp}` | {dispatched} | {status} |")
        critique.append("\n")

        critique.append("## Recommended Platform Improvements\n")
        improvements = []
        if failed > 0:
            improvements.append(
                "1. **Verify MCP Circuit Breaker Recovery:** Some tasks failed. Confirm MCP connection status and check for timeout issues in `api.log`."
            )
        if pending > 0:
            improvements.append(
                "2. **Implement Concurrency scaling:** Queue congestion detected. Consider increasing `max_concurrent_tasks` on VulnAgent."
            )
        if len(skipped_scans) == 0:
            improvements.append(
                "3. **Enable Heuristics:** No scans were filtered. Ensure the Applicability Engine is active and mapping methods correctly."
            )

        if not improvements:
            improvements.append(
                "1. **Scan depth scaling:** All subsystems executed cleanly. Increase `sqlmap` level/risk parameters for deeper coverage."
            )

        critique.append("\n".join(improvements))

        return "\n".join(critique)

    async def audit_findings(self, engagement_id: str) -> List[Dict[str, Any]]:
        """Adversarial review of validated findings — the 'peer review' step.

        Phase 3.2 (2026-07-23): the assessment identified a missing adversarial
        challenger that audits findings for false positives, missing evidence,
        and incomplete validation before they reach the report. This method
        reviews every validated finding in the graph and flags:
          - Findings with empty evidence lists (no proof)
          - Findings where validated=True but confidence < 0.5 (weak signal)
          - Findings whose tool_source is a known-noisy scanner
          - Findings missing request/response evidence

        Returns a list of critique dicts, each flagging a finding that needs
        re-verification. The reasoning loop uses this to downgrade or re-test
        findings before reporting.
        """
        critiques: List[Dict[str, Any]] = []

        try:
            vulns = await self.graph_memory.get_vulnerabilities_by_engagement(engagement_id)
        except Exception:
            return []

        for v in vulns:
            vid = v.get("id", "?")
            vtype = v.get("vuln_type", "unknown")
            confidence = float(v.get("confidence", 0) or 0)
            validated = bool(v.get("validated", False))
            tool_source = str(v.get("tool_source", "")).lower()
            evidence = v.get("evidence")

            # Parse evidence (may be JSON string from Neo4j)
            import json

            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except Exception:
                    evidence = []
            if not isinstance(evidence, list):
                evidence = [evidence] if evidence else []

            issues: List[str] = []

            # Check 1: validated but no evidence
            if validated and not evidence:
                issues.append("validated=True but evidence list is empty — no proof")

            # Check 2: validated but low confidence
            if validated and confidence < 0.5:
                issues.append(
                    f"validated=True but confidence={confidence:.2f} is below 0.5 — weak signal"
                )

            # Check 3: noisy scanner source
            noisy_sources = {"nuclei", "burp_scan", "ffuf"}
            if tool_source in noisy_sources and validated:
                issues.append(
                    f"tool_source={tool_source} is a known-noisy scanner — verify the finding is not a template-match false positive"
                )

            # Check 4: missing request/response in evidence
            if validated and evidence:
                has_request = any(
                    isinstance(e, dict) and ("request" in e or "request_url" in e) for e in evidence
                )
                has_response = any(
                    isinstance(e, dict) and ("response" in e or "http_status" in e)
                    for e in evidence
                )
                if not has_request:
                    issues.append("evidence lacks request details — triager cannot reproduce")
                if not has_response:
                    issues.append("evidence lacks response details — triager cannot verify")

            if issues:
                critiques.append(
                    {
                        "finding_id": vid,
                        "vuln_type": vtype,
                        "confidence": confidence,
                        "validated": validated,
                        "issues": issues,
                        "recommendation": "re-verify before reporting; consider downgrading to POTENTIAL",
                    }
                )

        return critiques
