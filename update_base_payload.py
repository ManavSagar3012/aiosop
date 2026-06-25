import re

with open("src/ai_osop/agents/base.py", "r") as f:
    content = f.read()

# Define the new dictionary content
new_dict = """                {
                    "agent_id": self.ctx.agent_id,
                    "agent_type": str(self.ctx.agent_type),
                    "status": self.ctx.status,
                    "task_id": self.ctx.current_task.id if self.ctx.current_task else None,
                    "engagement_id": self.ctx.session_id,
                    "version": "8.0",
                    "pid": os.getpid(),
                    "hostname": os.uname().nodename,
                },"""

# Replace the old dict
old_dict = """                {
                    "agent_id": self.ctx.agent_id,
                    "agent_type": str(self.ctx.agent_type),
                    "status": self.ctx.status,
                    "task_id": self.ctx.current_task.id if self.ctx.current_task else None,
                    "engagement_id": self.ctx.session_id,
                    "version": "8.0",
                },"""

# Need to import os in base.py if not already present
if "import os" not in content:
    content = "import os\n" + content

content = content.replace(old_dict, new_dict)

with open("src/ai_osop/agents/base.py", "w") as f:
    f.write(content)
