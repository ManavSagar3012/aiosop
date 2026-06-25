import re
from datetime import datetime, timedelta

filepath = "src/ai_osop/agents/base.py"
with open(filepath, "r") as f:
    content = f.read()

pattern = r'await self.ctx.session_memory.update_agent_heartbeat\('
extension = """
            if self.ctx.current_task:
                self.ctx.current_task.lease_expires = datetime.utcnow() + timedelta(seconds=90)
                await self.ctx.session_memory.store_task(self.ctx.current_task)
"""
content = re.sub(pattern, extension + '\n            await self.ctx.session_memory.update_agent_heartbeat(', content)

with open(filepath, "w") as f:
    f.write(content)
