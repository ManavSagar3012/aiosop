"""Local MCP-style adapter for session memory operations."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from ai_osop.core.exceptions import MCPException, MCPTimeoutError
from ai_osop.core.models import AuditEvent, SessionState
from ai_osop.memory.session_memory import SessionMemory


class SessionMemoryMCPAdapter:
    """Expose SessionMemory through a timeout-bound adapter."""

    def __init__(self, session_memory: SessionMemory, timeout_seconds: float = 30.0):
        self.session_memory = session_memory
        self.timeout_seconds = timeout_seconds

    async def store_session(self, session: SessionState) -> Dict[str, Any]:
        """Persist a session state."""
        await self._run(self.session_memory.store_session_state(session))
        await self._run(self.session_memory.persist_session_state(session))
        return {"status": "success", "session_id": session.session_id}

    async def query_audit_log(
        self,
        engagement_id: str,
        event_types: Optional[List[str]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return serialized audit events."""
        events = await self._run(
            self.session_memory.query_audit_log(
                engagement_id=engagement_id, event_types=event_types, limit=limit
            )
        )
        return [event.dict() if isinstance(event, AuditEvent) else dict(event) for event in events]

    async def write_audit_event(self, event: AuditEvent) -> Dict[str, Any]:
        """Write an audit event."""
        await self._run(self.session_memory.write_audit_event(event))
        return {"status": "success", "event_id": event.event_id}

    async def _run(self, awaitable: Any) -> Any:
        try:
            return await asyncio.wait_for(awaitable, timeout=self.timeout_seconds)
        except asyncio.TimeoutError as exc:
            raise MCPTimeoutError("Session memory MCP operation timed out") from exc
        except MCPException:
            raise
        except Exception as exc:
            raise MCPException(f"Session memory MCP operation failed: {exc}") from exc
