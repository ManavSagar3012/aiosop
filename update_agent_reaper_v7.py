import re
filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

# Add debug print for heartbeat age
old_reap = '            last_seen = datetime.fromisoformat(heartbeat["last_seen"])\n            if datetime.utcnow() - last_seen > timedelta(seconds=self.heartbeat_timeout):'
new_reap = '            last_seen = datetime.fromisoformat(heartbeat["last_seen"])\n            age = (datetime.utcnow() - last_seen).total_seconds()\n            print(f"DEBUG: Agent {agent_id} last_seen: {last_seen}, age: {age}")\n            if age > self.heartbeat_timeout:'

content = content.replace(old_reap, new_reap)

with open(filepath, "w") as f:
    f.write(content)
