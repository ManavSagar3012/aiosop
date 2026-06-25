filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

# Fill in _recover_agent
old_recover = """    async def _recover_agent(self, agent_id: str) -> None:
        lock_key = f"agent-recovery:{agent_id}"
        if await self.orch.session_memory.acquire_lock(lock_key, ttl=30):
            try:
                tasks = await self.orch.session_memory.find_tasks_by_agent(agent_id)
                for task in tasks:
                    if task.status == "running":
                        task.status = "pending"
                        task.assigned_agent_id = None
                        task.lease_expires = None
                        task.retry_count += 1
                        await self.orch.graph_memory.upsert_task(task)
                        await self.orch.session_memory.store_task(task)
                        await self.orch.task_scheduler.schedule_task(task)
                
                await self.orch.session_memory.update_agent_status(agent_id, AgentState.OFFLINE.value)
            finally:
                await self.orch.session_memory.release_lock(lock_key)"""

# Add audit log
new_recover = old_recover.replace("await self.orch.task_scheduler.schedule_task(task)", 
                                  "await self.orch.task_scheduler.schedule_task(task)\n                        await self.orch.session_memory.write_audit_event(AuditEvent(event_type='task_recovered', severity='INFO', actor_type='system', actor_id='reaper', action={'task_id': task.id}, result={'status': 'requeued'}, engagement_id=task.engagement_id))")

content = content.replace(old_recover, new_recover)

with open(filepath, "w") as f:
    f.write(content)
