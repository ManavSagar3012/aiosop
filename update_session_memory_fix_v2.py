import os

filepath = "src/ai_osop/memory/session_memory.py"
with open(filepath, "r") as f:
    content = f.read()

new_method = """
    async def list_all_tasks(self) -> List[str]:
        r = await self._ensure_redis()
        return await r.keys("task:*")
"""

# Append just before the end of class, or look for close
if "async def list_all_tasks" not in content:
    content = content.replace("    async def close(self) -> None:", new_method + "\n    async def close(self) -> None:")

with open(filepath, "w") as f:
    f.write(content)
