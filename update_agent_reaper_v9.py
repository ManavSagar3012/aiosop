import re
filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

old_reap = """            last_seen = datetime.fromisoformat(heartbeat["last_seen"])
            age = (datetime.utcnow() - last_seen).total_seconds()
            print(f"DEBUG: Agent {agent_id} last_seen: {last_seen}, age: {age}")
            if age > self.heartbeat_timeout:"""

new_reap = """            last_seen = datetime.fromisoformat(heartbeat["last_seen"])
            now = datetime.utcnow()
            age = (now - last_seen).total_seconds()
            print(f"DEBUG: Agent {agent_id} last_seen: {last_seen}, now: {now}, age: {age}")
            if age > self.heartbeat_timeout:"""

content = content.replace(old_reap, new_reap)

with open(filepath, "w") as f:
    f.write(content)
