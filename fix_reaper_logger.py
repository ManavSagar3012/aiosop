import re

filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

# Fix logger.warning("agent_dead", agent_id=agent_id) -> logger.warning(f"agent_dead: {agent_id}")
# I will just replace the logger call entirely.
content = content.replace('logger.warning("agent_dead", agent_id=agent_id)', 'logger.warning(f"agent_dead: {agent_id}")')

# Also check other logger calls
content = content.replace('logger.error("reaper_error", error=str(e))', 'logger.error(f"reaper_error: {e}")')

with open(filepath, "w") as f:
    f.write(content)
