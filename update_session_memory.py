with open("src/ai_osop/memory/session_memory.py", "r") as f:
    content = f.read()

new_methods = """
    async def get_all_agents(self) -> Dict[str, Any]:
        r = await self._ensure_redis()
        keys = await r.keys("agent:*")
        agents = {}
        for key in keys:
            if not key.startswith("agent:heartbeat:"):
                data = await self.retrieve_hot(key)
                agents[key.replace("agent:", "")] = data
        return agents

    async def find_tasks_by_agent(self, agent_id: str) -> List[Any]:
        r = await self._ensure_redis()
        task_keys = await r.keys("task:*")
        tasks = []
        for key in task_keys:
            task = await self.retrieve_hot(key)
            if task.get("assigned_agent_id") == agent_id:
                tasks.append(task)
        return tasks

    async def acquire_lock(self, key: str, ttl: int = 30) -> bool:
        r = await self._ensure_redis()
        return await r.set(f"lock:{key}", "locked", nx=True, ex=ttl)

    async def release_lock(self, key: str) -> None:
        r = await self._ensure_redis()
        await r.delete(f"lock:{key}")
"""

# Append just before the end of class
content = content.rstrip() + "\n" + new_methods

with open("src/ai_osop/memory/session_memory.py", "w") as f:
    f.write(content)
