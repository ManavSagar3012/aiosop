"""
JS Analysis Agent
Analyzes client-side JavaScript for endpoints, secrets, and routes.
"""


import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Asset, Endpoint, EvidenceProvenance, Task, Vulnerability


class JSAnalyzerAgent(BaseAgent):
    """
    JS Analysis Agent
    Extracts high-value information from client-side JavaScript bundles.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.VULN_ANALYSIS

    def supports_task_type(self, task_type: str) -> bool:
        return task_type in ["analyze_js", "extract_endpoints_from_js", "detect_secrets_in_js"]

    async def _setup_resources(self) -> None:
        """Initialize JS resources."""
        self.discovered_endpoints: List[str] = []

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute JS analysis task."""
        task_type = task.type
        payload = task.payload

        if task_type == "analyze_js":
            return await self._analyze_js(payload)
        else:
            return {"status": "error", "message": f"Unknown task type {task_type}"}

    async def _analyze_js(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes a JS bundle for interesting patterns.
        """
        js_url = payload.get("url", "unknown")
        js_content = payload.get("content", "")

        if not js_content and js_url:
            # Simulate fetching
            js_content = "const API_BASE = '/api/v2'; fetch(`${API_BASE}/user/delete`);"

        # 1. Extract Endpoints
        endpoints = re.findall(r"['\"](/[a-zA-Z0-9/_\-\.]+)['\"]", js_content)
        unique_endpoints = list(set(endpoints))
        # 2. Look for Secrets (AWS AKIA pattern)
        matches = re.finditer(r"(AKIA[0-9A-Z]{16})", js_content)

        findings_ids = []
        from ai_osop.core.models import EvidenceProvenance

        for m in matches:
            key = m.group(1)
            # Capture context: 50 chars before and after
            start = max(0, m.start() - 50)
            end = min(len(js_content), m.end() + 50)
            context_snippet = js_content[start:end]

            await self.think(
                f"Secret Match: {key}. Context: ...{context_snippet}...",
                ["js_analysis", "secret_validation"],
            )

            vuln = Vulnerability(
                id=f"vuln-js-{uuid.uuid4().hex[:6]}",
                title="Hardcoded AWS Access Key in Javascript",
                description=f"A likely valid AWS Access Key ({key[:8]}...) was found in {js_url}.",
                severity=Severity.CRITICAL,
                vuln_type=VulnClass.OSINT_LEAK,
                confidence=0.95,
                tool_source=self.ctx.agent_id,
                engagement_id=self.ctx.session_id,
                provenance=EvidenceProvenance.LIVE,
                evidence=[
                    {"type": "js_match", "file": js_url, "match": key, "context": context_snippet}
                ],
            )
            vid = await self.ctx.graph_memory.add_vulnerability(vuln)
            findings_ids.append(vid)

        await self.think(
            f"Analyzed JS at {js_url}. Found {len(unique_endpoints)} potential endpoints and {len(findings_ids)} potential AWS keys.",
            ["js_analysis", "secret_discovery"],
        )

        return {
            "status": "success",
            "endpoints_found": len(unique_endpoints),
            "vulnerabilities_created": len(findings_ids),
            "finding_ids": findings_ids,
        }

    async def _cleanup_resources(self) -> None:
        pass
