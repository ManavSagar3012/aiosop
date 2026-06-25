import re

filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

# Replace the loop
old_loop = """                for task in tasks:
                    if task.status == "running":
                        task.status = "pending"
                        task.assigned_agent_id = None
                        task.lease_expires = None
                        task.retry_count += 1
                        await self.orch.graph_memory.upsert_task(task)
                        await self.orch.session_memory.store_task(task)
                        await self.orch.task_scheduler.schedule_task(task)
                        TASK_REQUEUES_TOTAL.inc()
                        await self.orch.session_memory.write_audit_event(AuditEvent(event_type='task_recovered', severity='INFO', actor_type='system', actor_id='reaper', action={'task_id': task.id}, result={'status': 'requeued'}, engagement_id=task.engagement_id))"""

# I need the Task import for this
new_loop = """                from ai_osop.core.models import Task
                for task_dict in tasks:
                    if task_dict.get("status") == "running":
                        task_dict["status"] = "pending"
                        task_dict["assigned_agent_id"] = None
                        task_dict["lease_expires"] = None
                        task_dict["retry_count"] = task_dict.get("retry_count", 0) + 1
                        
                        task = Task(**task_dict)
                        await self.orch.graph_memory.upsert_task(task)
                        await self.orch.session_memory.store_task(task)
                        await self.orch.task_scheduler.schedule_task(task)
                        TASK_REQUEUES_TOTAL.inc()
                        await self.orch.session_memory.write_audit_event(AuditEvent(event_type='task_recovered', severity='INFO', actor_type='system', actor_id='reaper', action={'task_id': task.id}, result={'status': 'requeued'}, engagement_id=task.engagement_id))"""

content = content.replace(old_loop, new_loop)

with open(filepath, "w") as f:
    f.write(content)
