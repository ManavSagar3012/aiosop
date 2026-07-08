import json
from datetime import datetime
from typing import Any, Dict, Optional

from ai_osop.memory.session_memory import SessionMemory


class HeartbeatManager:
    def __init__(self, session_memory: SessionMemory):
        self.sm = session_memory

    async def update(self, agent_id: str, state: Dict[str, Any]) -> None:
        state["last_seen"] = datetime.utcnow().isoformat()
        await self.sm.store_hot(f"agent:heartbeat:{agent_id}", state, ttl=30)

    async def get(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return await self.sm.retrieve_hot(f"agent:heartbeat:{agent_id}")
