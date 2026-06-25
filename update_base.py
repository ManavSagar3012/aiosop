import re

with open("src/ai_osop/agents/base.py", "r") as f:
    content = f.read()

# The target block to replace
target = """            await self.ctx.session_memory.store_agent_state(
                self.ctx.agent_id,
                {
                    "status": self.ctx.status,
                    "last_heartbeat": self.ctx.last_heartbeat.isoformat(),
                    "current_task": self.ctx.current_task.id if self.ctx.current_task else None,
                    "task_queue_depth": self._task_queue.qsize(),
                },
                ttl=60,
            )
            await asyncio.sleep(30)"""

replacement = """            await self.ctx.session_memory.update_agent_heartbeat(
                self.ctx.agent_id,
                {
                    "agent_id": self.ctx.agent_id,
                    "agent_type": str(self.ctx.agent_type),
                    "status": self.ctx.status,
                    "task_id": self.ctx.current_task.id if self.ctx.current_task else None,
                    "engagement_id": self.ctx.session_id,
                    "version": "8.0",
                },
            )
            await asyncio.sleep(5)"""

new_content = content.replace(target, replacement)

with open("src/ai_osop/agents/base.py", "w") as f:
    f.write(new_content)
