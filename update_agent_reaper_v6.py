import re
filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

# Add a print statement in _reap
old_reap = '                logger.warning("agent_dead", agent_id=agent_id)\n                AGENT_TIMEOUTS_TOTAL.inc()'
new_reap = '                print(f"DEBUG: Reaper triggered for agent: {agent_id}")\n                logger.warning("agent_dead", agent_id=agent_id)\n                AGENT_TIMEOUTS_TOTAL.inc()'

content = content.replace(old_reap, new_reap)

with open(filepath, "w") as f:
    f.write(content)
