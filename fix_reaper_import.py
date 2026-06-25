filepath = "src/ai_osop/reliability/agent_reaper.py"
with open(filepath, "r") as f:
    content = f.read()

if "from ai_osop.core.models import AuditEvent" not in content:
    content = content.replace("from ai_osop.core.config import AgentState",
                              "from ai_osop.core.config import AgentState\nfrom ai_osop.core.models import AuditEvent")

with open(filepath, "w") as f:
    f.write(content)
