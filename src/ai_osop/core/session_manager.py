"""
V4.2A Session Intelligence Layer
Manages multi-user sessions, token rotation, and drift detection.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ai_osop.core.models import BrowserSession
from ai_osop.memory.session_memory import SessionMemory


class SessionManager:
    """
    Dedicated subsystem for managing session lifecycles and identities.
    """

    def __init__(self, session_memory: SessionMemory):
        self.session_memory = session_memory
        self._active_sessions: Dict[str, BrowserSession] = {}

    async def create_session(
        self,
        engagement_id: str,
        user_label: str,
        role: str,
        user_agent: str,
        initial_tokens: Optional[Dict[str, str]] = None,
        ttl_minutes: int = 60,
    ) -> BrowserSession:
        """
        Create and track a new session.
        """
        session = BrowserSession(
            user_label=user_label,
            role=role,
            tokens=initial_tokens or {},
            user_agent=user_agent,
            engagement_id=engagement_id,
            expiry=datetime.utcnow() + timedelta(minutes=ttl_minutes),
        )

        # Store in hot memory (Redis) if available
        try:
            await self.session_memory.store_hot(f"session:{session.id}", session.dict())
        except Exception as e:
            print(f"DEBUG: Session store_hot failed (likely mock/test environment): {e}")

        self._active_sessions[session.id] = session

        return session

    async def get_session(self, session_id: str) -> Optional[BrowserSession]:
        """
        Retrieve a session from hot memory.
        """
        if session_id in self._active_sessions:
            return self._active_sessions[session_id]

        data = await self.session_memory.retrieve_hot(f"session:{session_id}")
        if data:
            session = BrowserSession(**data)
            self._active_sessions[session_id] = session
            return session
        return None

    async def update_session(self, session: BrowserSession) -> None:
        """
        Update session state (tokens, cookies, storage).
        """
        session.last_active = datetime.utcnow()
        await self.session_memory.store_hot(f"session:{session.id}", session.dict())
        self._active_sessions[session.id] = session

    async def check_drift(self, session_id: str, current_state: Dict[str, Any]) -> bool:
        """
        Compare observed state with recorded session state.
        Returns True if drift is detected.
        """
        session = await self.get_session(session_id)
        if not session:
            return False

        # Simplified drift check: check if critical tokens changed
        for key, val in current_state.get("tokens", {}).items():
            if session.tokens.get(key) != val:
                return True
        return False

    async def rotate_tokens(self, session_id: str, new_tokens: Dict[str, str]) -> None:
        """
        Handle token rotation.
        """
        session = await self.get_session(session_id)
        if session:
            session.tokens.update(new_tokens)
            await self.update_session(session)
