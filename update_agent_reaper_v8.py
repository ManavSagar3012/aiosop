import re
filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

# Add debug prints for agents and heartbeats
old_reap = """    async def _reap(self) -> None:
        agents = await self.orch.session_memory.get_all_agents()
        for agent_id, agent_info in agents.items():
            heartbeat = await self.orch.session_memory.get_agent_heartbeat(agent_id)
            if not heartbeat:
                continue"""

new_reap = """    async def _reap(self) -> None:
        agents = await self.orch.session_memory.get_all_agents()
        print(f"DEBUG: Found {len(agents)} agents: {list(agents.keys())}")
        for agent_id, agent_info in agents.items():
            heartbeat = await self.orch.session_memory.get_agent_heartbeat(agent_id)
            print(f"DEBUG: Agent {agent_id} heartbeat: {heartbeat}")
            if not heartbeat:
                continue"""

content = content.replace(old_reap, new_reap)

with open(filepath, "w") as f:
    f.write(content)
