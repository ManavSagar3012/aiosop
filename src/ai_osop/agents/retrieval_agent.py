import json
import os
from typing import Any, Dict, List
from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task

class RetrievalAgent(BaseAgent):
    """Retrieval Agent for querying bug bounty methodology knowledge."""

    @property
    def agent_type(self) -> AgentType:
        return AgentType.RETRIEVAL

    async def _setup_resources(self) -> None:
        self.knowledge_base_path = "src/ai_osop/knowledge/bug_bounty/"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute retrieval task."""
        vulnerability_class = task.payload.get("vulnerability_class")
        if not vulnerability_class:
            return {"status": "error", "error": "Missing vulnerability_class in payload"}
        
        results = self.search(vulnerability_class)
        return {"status": "completed", "results": results}

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
