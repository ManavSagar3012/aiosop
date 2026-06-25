filepath = "src/ai_osop/memory/session_memory.py"
with open(filepath, "r") as f:
    content = f.read()

new_methods = """
    async def update_agent_status(self, agent_id: str, status: str) -> None:
        \"\"\"Update agent status in Redis.\"\"\"
        key = f"agent:{agent_id}"
        data = await self.retrieve_hot(key)
        if data:
            data["status"] = status
            await self.store_hot(key, data)
        else:
            await self.store_hot(key, {"status": status})
"""

# Append before the last few methods or after class definition
if "async def update_agent_status" not in content:
    # Look for the last method
    last_method_start = content.rfind("    async def ")
    content = content[:last_method_start] + new_methods + "\n" + content[last_method_start:]

with open(filepath, "w") as f:
    f.write(content)
