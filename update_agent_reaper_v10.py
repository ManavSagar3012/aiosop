import re
filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

# I'll replace the entire loop to be extremely verbose about what it finds and why it skips
old_recover = """                from ai_osop.core.models import Task
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

new_recover = """                from ai_osop.core.models import Task
                print(f"DEBUG: Found {len(tasks)} tasks: {tasks}")
                for task_dict in tasks:
                    status = task_dict.get("status")
                    print(f"DEBUG: Checking task {task_dict.get('id')}, status={status}")
                    if status == "running":
                        print(f"DEBUG: Recovering task {task_dict.get('id')}")
                        task_dict["status"] = "pending"
                        task_dict["assigned_agent_id"] = None
                        task_dict["lease_expires"] = None
                        task_dict["retry_count"] = task_dict.get("retry_count", 0) + 1
                        
                        task = Task(**task_dict)
                        await self.orch.graph_memory.upsert_task(task)
                        await self.orch.session_memory.store_task(task)
                        await self.orch.task_scheduler.schedule_task(task)
                        TASK_REQUEUES_TOTAL.inc()
                        # Need to import AuditEvent if not imported
                        from ai_osop.core.models import AuditEvent
                        await self.orch.session_memory.write_audit_event(AuditEvent(event_type='task_recovered', severity='INFO', actor_type='system', actor_id='reaper', action={'task_id': task.id}, result={'status': 'requeued'}, engagement_id=task.engagement_id))
                    else:
                        print(f"DEBUG: Task {task_dict.get('id')} not recovered (status={status})")"""

content = content.replace(old_recover, new_recover)

with open(filepath, "w") as f:
    f.write(content)
