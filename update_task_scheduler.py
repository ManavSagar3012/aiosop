import re

with open("src/ai_osop/orchestrator/task_scheduler.py", "r") as f:
    content = f.read()

# Replace assignment logic
old_block = """                task.assigned_agent_id = agent.ctx.agent_id
                task.status = "running"
                task.started_at = datetime.utcnow()
                await self._orch.graph_memory.upsert_task(task)
                await self._orch.session_memory.store_task(task)"""

new_block = """                task.assigned_agent_id = agent.ctx.agent_id
                task.status = "running"
                task.started_at = datetime.utcnow()
                task.lease_expires = datetime.utcnow() + timedelta(seconds=90)
                await self._orch.graph_memory.upsert_task(task)
                await self._orch.session_memory.store_task(task)"""

content = content.replace(old_block, new_block)

# Add timedelta import
if "from datetime import datetime, timedelta" not in content:
    content = content.replace("from datetime import datetime", "from datetime import datetime, timedelta")

with open("src/ai_osop/orchestrator/task_scheduler.py", "w") as f:
    f.write(content)
