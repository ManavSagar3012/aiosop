import os

# 1. Update core/metrics.py
metrics_path = "src/ai_osop/core/metrics.py"
with open(metrics_path, "a") as f:
    f.write("\nfrom prometheus_client import Counter\n")
    f.write('AGENT_RECOVERIES_TOTAL = Counter("ai_osop_agent_recoveries_total", "Total agent recoveries")\n')
    f.write('AGENT_TIMEOUTS_TOTAL = Counter("ai_osop_agent_timeouts_total", "Total agent timeouts")\n')
    f.write('TASK_REQUEUES_TOTAL = Counter("ai_osop_task_requeues_total", "Total task requeues")\n')
    f.write('STALE_LEASES_TOTAL = Counter("ai_osop_stale_leases_total", "Total stale task leases detected")\n')

# 2. Update AgentReaper
reaper_path = "src/ai_osop/reliability/agent_reaper.py"
with open(reaper_path, "r") as f:
    content = f.read()

# Add imports
content = content.replace("from typing import Any", "from typing import Any\nfrom ai_osop.core.metrics import AGENT_RECOVERIES_TOTAL, AGENT_TIMEOUTS_TOTAL, TASK_REQUEUES_TOTAL, STALE_LEASES_TOTAL")

# Update _reap
old_reap_log = '                logger.warning("agent_dead", agent_id=agent_id)\n                await self._recover_agent(agent_id)'
new_reap_log = '                logger.warning("agent_dead", agent_id=agent_id)\n                AGENT_TIMEOUTS_TOTAL.inc()\n                await self._recover_agent(agent_id)\n                AGENT_RECOVERIES_TOTAL.inc()'
content = content.replace(old_reap_log, new_reap_log)

# Update _recover_agent (task requeue increment)
old_requeue = '                        await self.orch.task_scheduler.schedule_task(task)'
new_requeue = '                        await self.orch.task_scheduler.schedule_task(task)\n                        TASK_REQUEUES_TOTAL.inc()'
content = content.replace(old_requeue, new_requeue)

with open(reaper_path, "w") as f:
    f.write(content)
