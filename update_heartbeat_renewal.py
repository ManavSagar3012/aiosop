filepath = "src/ai_osop/agents/base.py"
with open(filepath, "r") as f:
    content = f.read()

# Extend the lease in the heartbeat loop
# Find the heartbeat loop block and add the lease extension
pattern = r'await self.ctx.session_memory.update_agent_heartbeat\('
# I'll inject the logic to extend the lease before the heartbeat update
extension = """
            if self.ctx.current_task:
                self.ctx.current_task.lease_expires = datetime.utcnow() + timedelta(seconds=90)
                await self.ctx.session_memory.store_task(self.ctx.current_task)
"""
# Insert extension before heartbeat update
content = re.sub(pattern, extension + '\n            await self.ctx.session_memory.update_agent_heartbeat(', content)

with open(filepath, "w") as f:
    f.write(content)
