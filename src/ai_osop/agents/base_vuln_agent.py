from abc import abstractmethod
from typing import Any, Dict

from ai_osop.agents.base import BaseAgent
from ai_osop.core.models import Task, Vulnerability


class BaseVulnerabilityAgent(BaseAgent):
    """
    Base class for all vulnerability scanner agents, providing
    standardized finding persistence and error handling.
    """

    async def persist_finding(self, vuln: Vulnerability) -> None:
        """Persist a vulnerability finding to the Graph Memory."""
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            self.logger.error(f"Failed to add vulnerability {vuln.id} to graph: {e}")

    @abstractmethod
    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Specific scanner logic."""
        pass

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass
