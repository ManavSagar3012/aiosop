import os

with open("src/ai_osop/memory/session_memory.py", "a") as f:
    f.write("\n\n    async def update_agent_heartbeat(self, agent_id: str, data: Dict[str, Any]) -> None:\n")
    f.write('        """Update agent heartbeat with ownership and state."""\n')
    f.write('        data["last_seen"] = datetime.utcnow().isoformat()\n')
    f.write('        await self.store_hot(f"agent:heartbeat:{agent_id}", data, ttl=30)\n')
    f.write("\n    async def get_agent_heartbeat(self, agent_id: str) -> Optional[Dict[str, Any]]:\n")
    f.write('        """Retrieve agent heartbeat."""\n')
    f.write('        return await self.retrieve_hot(f"agent:heartbeat:{agent_id}")\n')
