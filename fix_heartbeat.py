import os

filepath = "src/ai_osop/memory/session_memory.py"
with open(filepath, "r") as f:
    content = f.read()

# Replace the method with correct implementation
old_method = """    async def update_agent_heartbeat(self, agent_id: str, data: Dict[str, Any]) -> None:
        \"\"\"Update agent heartbeat with ownership and state.\"\"\"
        data["last_seen"] = datetime.utcnow().isoformat()
        await self.store_hot(f"agent:heartbeat:{agent_id}", data, ttl=60)"""

new_method = """    async def update_agent_heartbeat(self, agent_id: str, data: Dict[str, Any]) -> None:
        \"\"\"Update agent heartbeat with ownership and state.\"\"\"
        if "last_seen" not in data:
            data["last_seen"] = datetime.utcnow().isoformat()
        await self.store_hot(f"agent:heartbeat:{agent_id}", data, ttl=60)"""

# Handle potential duplication (looks like I might have duplicated it in previous failed attempts)
content = content.replace(old_method, new_method)
content = content.replace(old_method.replace("60", "30"), new_method) # handle duplicate

with open(filepath, "w") as f:
    f.write(content)
