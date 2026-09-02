import json
import logging
from typing import Any, Dict, List, Optional
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.memory.graph_memory import GraphMemory

logger = logging.getLogger(__name__)

class ImpactQuantificationEngine:
    """
    Analyzes validated attack chains and calculates composite severity scores (CVSS)
    and business impact narratives.
    """

    def __init__(self, graph_memory: GraphMemory, llm_client: Optional[LiteLLMClient] = None):
        self.graph_memory = graph_memory
        self.llm_client = llm_client or LiteLLMClient()

    async def _fetch_chain_nodes(self, chain_id: str) -> List[Dict[str, Any]]:
        """Fetch the sequence of vulnerabilities/primitives that make up the chain."""
        # The chain connects primitives. We need their details to understand the impact.
        cypher = """
        MATCH (c:AttackChain {id: $chain_id})-[:INCLUDES_PRIMITIVE]->(p)
        RETURN p
        """
        records = await self.graph_memory.run_read_query(cypher, {"chain_id": chain_id})
        nodes = [r.get("p", {}) for r in records]
        # Sort by whatever order they might have if present, else just return
        # A real implementation would follow the graph edges (e.g., LEADS_TO)
        return nodes
        
    async def quantify_chain_impact(self, chain_id: str, context: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluates the full attack chain to produce a CVSS score and a business impact narrative.
        """
        nodes = await self._fetch_chain_nodes(chain_id)
        if not nodes:
            return {
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "cvss_score": 0.0,
                "severity": "informational",
                "narrative": "Empty or invalid attack chain."
            }
            
        # Build prompt for LLM
        nodes_desc = "\n".join([f"- Step: {n.get('title', 'Unknown')} (Type: {n.get('type', 'Unknown')})\n  Details: {n.get('description', '')}" for n in nodes])
        
        system_prompt = (
            "You are a senior Application Security Engineer. You are analyzing a validated attack chain. "
            "Based on the sequence of vulnerabilities, provide a composite CVSS v3.1 vector, numerical score, "
            "and a concise, one-sentence business impact narrative explaining the worst-case scenario for the target organization. "
            "Return valid JSON ONLY with the keys: 'cvss_vector', 'cvss_score', 'severity' (critical, high, medium, low), and 'narrative'."
        )
        
        user_prompt = f"Attack Chain:\n{nodes_desc}\n\nAdditional Context: {context or 'None'}"
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            response = await self.llm_client.complete(messages, max_tokens=300, temperature=0.2)
            content = response.get("content", "{}") if isinstance(response, dict) else str(response)
            
            # Clean JSON if wrapped in markdown
            if content.startswith("```json"):
                content = content.replace("```json", "").replace("```", "").strip()
                
            result = json.loads(content)
            return {
                "cvss_vector": result.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
                "cvss_score": float(result.get("cvss_score", 0.0)),
                "severity": result.get("severity", "informational").lower(),
                "narrative": result.get("narrative", "Unable to determine impact narrative.")
            }
        except Exception as e:
            logger.error(f"Impact quantification failed: {e}")
            return {
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "cvss_score": 0.0,
                "severity": "informational",
                "narrative": f"Impact assessment failed due to error: {e}"
            }

