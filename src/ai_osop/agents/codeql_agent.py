"""
CodeQL Intelligence Agent
Integrates static analysis findings (SARIF) into the Attack Graph.
"""

import json
from typing import Any, Dict, List

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Severity, Task, Vulnerability


class CodeQLAgent(BaseAgent):
    """
    CodeQL & SAST Intelligence Agent
    Parses SARIF results and maps them to Runtime Endpoints in the Attack Graph.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.SAST_ANALYSIS

    async def _setup_resources(self) -> None:
        """Initialize SAST resources."""
        self.findings_cache: List[Dict[str, Any]] = []

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute SAST analysis task."""
        task_type = task.type
        payload = task.payload

        if task_type == "ingest_sarif":
            return await self._ingest_sarif(payload)
        elif task_type == "map_sast_to_graph":
            return await self._map_to_graph(payload)
        else:
            return {"status": "error", "message": f"Unknown task type {task_type}"}

    async def _ingest_sarif(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses SARIF (Static Analysis Results Interchange Format) data.
        Extracts sinks, sources, and dataflow paths.
        """
        sarif_data = payload.get("sarif_json")
        if isinstance(sarif_data, str):
            try:
                sarif_data = json.loads(sarif_data)
            except json.JSONDecodeError:
                return {"status": "error", "message": "Invalid JSON in sarif_json"}

        runs = sarif_data.get("runs", [])
        extracted_findings = []

        for run in runs:
            results = run.get("results", [])
            for res in results:
                rule_id = res.get("ruleId")
                message = res.get("message", {}).get("text", "")

                # Extract locations (Sinks)
                locations = res.get("locations", [])
                primary_loc = locations[0] if locations else {}
                phys_loc = primary_loc.get("physicalLocation", {})
                file_path = phys_loc.get("artifactLocation", {}).get("uri", "unknown")
                region = phys_loc.get("region", {})
                line = region.get("startLine", 0)

                finding = {
                    "rule_id": rule_id,
                    "message": message,
                    "file_path": file_path,
                    "line": line,
                    "severity": res.get("level", "warning"),
                    "type": "codeql_finding",
                }
                extracted_findings.append(finding)

        self.findings_cache.extend(extracted_findings)

        # Log discovery
        await self.think(
            f"Ingested {len(extracted_findings)} CodeQL findings from SARIF. Detecting potential sinks in {list(set([f['file_path'] for f in extracted_findings]))}.",
            ["sast_analysis", "codeql_procedures"],
        )

        return {
            "status": "success",
            "count": len(extracted_findings),
            "findings": extracted_findings[:5],  # Return sample
        }

    async def _map_to_graph(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Bridges the gap between Static Source and Runtime Graph.
        Searches Attack Graph for Endpoints that likely map to these files/routes.
        """
        mapped_count = 0
        import uuid


        for finding in self.findings_cache:
            file_path = finding["file_path"]

            # Search for endpoints matching the source file/route

            records = await self.ctx.graph_memory.run_read_query(
                """
                MATCH (e:Endpoint)
                WHERE e.url CONTAINS $path OR e.metadata CONTAINS $path
                RETURN e.id as id
                """,
                {"path": file_path.split("/")[-1]},
            )
            for record in records:
                endpoint_id = record.get("id")

                # Create Vulnerability node from SAST finding
                vuln = Vulnerability(
                    id=f"vuln-sast-{uuid.uuid4().hex[:6]}",
                    title=f"SAST: {finding['rule_id']} in {finding['file_path']}",
                    description=finding["message"],
                    vuln_type="sast_sink",
                    severity=(Severity.HIGH if finding["severity"] == "error" else Severity.MEDIUM),
                    confidence=0.9,
                    endpoint_id=endpoint_id,
                    tool_source="CodeQL",
                    engagement_id=self.ctx.session_id,
                    evidence=[{"file": file_path, "line": finding["line"]}],
                )

                await self.ctx.graph_memory.add_vulnerability(vuln)
                mapped_count += 1

        return {"status": "success", "mapped_findings": mapped_count}

    async def _cleanup_resources(self) -> None:
        self.findings_cache.clear()
