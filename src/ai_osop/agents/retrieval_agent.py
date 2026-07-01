import json
import os
from typing import Any, Dict, List, Optional
from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.findings_knowledge import FindingsKnowledge, VectorMemoryFindingsStore
from ai_osop.core.models import Task

class RetrievalAgent(BaseAgent):
    """Retrieval Agent for querying bug bounty methodology knowledge.

    Two retrieval modes:
      - keyword methodology lookup over knowledge/bug_bounty/*.json (original), and
      - semantic recall of *past confirmed findings* via FindingsKnowledge (P2
        learning brain) so a new engagement is informed by earlier ones.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.RETRIEVAL

    async def _setup_resources(self) -> None:
        self.knowledge_base_path = "src/ai_osop/knowledge/bug_bounty/"
        # Semantic findings memory (durable via the pgvector-backed VectorMemory
        # when available; optional so the agent still works without it).
        self.findings_kb: Optional[FindingsKnowledge] = None
        vm = getattr(self.ctx, "vector_memory", None)
        llm = getattr(self.ctx, "llm_client", None)
        if vm is not None and llm is not None and hasattr(llm, "get_embedding"):
            self.findings_kb = FindingsKnowledge(
                embed_fn=llm.get_embedding, store=VectorMemoryFindingsStore(vm)
            )

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute retrieval task."""
        if task.type == "recall_findings":
            return await self._recall_findings(task)
        if task.type == "record_finding":
            return await self._record_finding(task)

        vulnerability_class = task.payload.get("vulnerability_class")
        if not vulnerability_class:
            return {"status": "error", "error": "Missing vulnerability_class in payload"}

        results = self.search(vulnerability_class)
        return {"status": "completed", "results": results}

    async def _recall_findings(self, task: Task) -> Dict[str, Any]:
        """Semantic recall of past confirmed findings similar to a query."""
        if self.findings_kb is None:
            return {"status": "error", "error": "findings knowledge base unavailable"}
        query = task.payload.get("query") or task.payload.get("vulnerability_class")
        if not query:
            return {"status": "error", "error": "recall_findings requires 'query'"}
        limit = int(task.payload.get("limit", 5))
        min_score = float(task.payload.get("min_score", 0.0))
        hits = await self.findings_kb.recall_similar(query, limit=limit, min_score=min_score)
        return {
            "status": "completed",
            "query": query,
            "results": [
                {"score": round(h.score, 4), "document": h.document, "metadata": h.metadata}
                for h in hits
            ],
        }

    async def _record_finding(self, task: Task) -> Dict[str, Any]:
        """Record a confirmed finding into semantic memory for future recall."""
        if self.findings_kb is None:
            return {"status": "error", "error": "findings knowledge base unavailable"}
        finding = task.payload.get("finding")
        if not finding:
            return {"status": "error", "error": "record_finding requires 'finding'"}
        stored = await self.findings_kb.record_finding(finding)
        return {"status": "completed", "recorded": stored}

    async def _cleanup_resources(self) -> None:
        """Cleanup retrieval resources."""
        pass

    def search(self, vulnerability_class: str) -> List[Dict[str, Any]]:
        """Scan knowledge/bug_bounty/ JSON files for methodology matches."""
        matches = []
        if not os.path.exists(self.knowledge_base_path):
            return matches
        
        for filename in os.listdir(self.knowledge_base_path):
            if filename.endswith(".json"):
                file_path = os.path.join(self.knowledge_base_path, filename)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for item in data:
                            if item.get("class", "").lower() == vulnerability_class.lower():
                                matches.append(item)
                except (json.JSONDecodeError, IOError):
                    continue
        return matches
