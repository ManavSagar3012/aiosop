import os

filepath = "src/ai_osop/core/config.py"
with open(filepath, "r") as f:
    content = f.read()

if "class AgentState" not in content:
    with open(filepath, "a") as f:
        f.write("""

class AgentState(str, Enum):
    IDLE = "idle"
    ASSIGNED = "assigned"
    RUNNING = "running"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    RECOVERING = "recovering"
""")
