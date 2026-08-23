from typing import Any, Dict, Optional, Protocol

from ai_osop.core.config import EngagementPhase
from ai_osop.core.models import ApprovalRequest, SessionState, Task


class ITaskScheduler(Protocol):
    async def schedule_task(self, task: Task) -> Task: ...


class IApprovalCoordinator(Protocol):
    async def request_approval(self, request: ApprovalRequest) -> ApprovalRequest: ...
    async def resolve_approval(
        self, request_id: str, decision: str, operator_id: str, notes: Optional[str] = None
    ) -> ApprovalRequest: ...


class IPhaseMonitor(Protocol):
    async def _on_phase_enter(self, session: SessionState, phase: EngagementPhase) -> None: ...
    async def _auto_advance_phase(self, session: SessionState) -> None: ...
