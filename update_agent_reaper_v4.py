import re

filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

# Fix the dot notation to dictionary access and object conversion
old_recover = """                for task in tasks:
                    # task is a dict because it comes from retrieve_hot (json)
                    if task.get("status") == "running":
                        task["status"] = "pending"
                        task["assigned_agent_id"] = None
                        task["lease_expires"] = None
                        task["retry_count"] = task.get("retry_count", 0) + 1
                        # Re-convert to Task object for graph/session memory storage if needed
                        # Or just store the updated dict directly if upsert_task accepts dict?
                        # Assuming Task object is required for upsert
                        from ai_osop.core.models import Task
                        task_obj = Task(**task)
                        await self.orch.graph_memory.upsert_task(task_obj)
                        await self.orch.session_memory.store_task(task_obj)
                        await self.orch.task_scheduler.schedule_task(task_obj)"""

# Need to handle potential import inside method if not imported at top level
new_recover = """                from ai_osop.core.models import Task
                for task in tasks:
                    if task.get("status") == "running":
                        task["status"] = "pending"
                        task["assigned_agent_id"] = None
                        task["lease_expires"] = None
                        task["retry_count"] = task.get("retry_count", 0) + 1
                        task_obj = Task(**task)
                        await self.orch.graph_memory.upsert_task(task_obj)
                        await self.orch.session_memory.store_task(task_obj)
                        await self.orch.task_scheduler.schedule_task(task_obj)"""

# Handle the case where the previous attempt failed and added partial/messy code
# I'll replace the block with the clean new_recover
content = re.sub(r'for task in tasks:.*?\n                        await self\.orch\.task_scheduler\.schedule_task\(task_obj\)', new_recover, content, flags=re.DOTALL)

with open(filepath, "w") as f:
    f.write(content)
