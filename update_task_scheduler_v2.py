import os

filepath = "src/ai_osop/orchestrator/task_scheduler.py"
with open(filepath, "r") as f:
    content = f.read()

# Make sure imports are correct
content = content.replace("from datetime import datetime", "from datetime import datetime, timedelta")

# Replace task assignment
old_pattern = r'task.assigned_agent_id = agent.ctx.agent_id\n                task.status = "running"\n                task.started_at = datetime.utcnow()'
new_pattern = r'task.assigned_agent_id = agent.ctx.agent_id\n                task.status = "running"\n                task.started_at = datetime.utcnow()\n                task.lease_expires = datetime.utcnow() + timedelta(seconds=90)'

import re
content = re.sub(old_pattern, new_pattern, content)

with open(filepath, "w") as f:
    f.write(content)
