filepath = "src/ai_osop/orchestrator/orchestrator.py"
with open(filepath, "r") as f:
    content = f.read()

# Add import if missing
if "from ai_osop.reliability.agent_reaper import AgentReaper" not in content:
    content = content.replace("from ai_osop.orchestrator.recovery_service import RecoveryService",
                              "from ai_osop.orchestrator.recovery_service import RecoveryService\nfrom ai_osop.reliability.agent_reaper import AgentReaper")

# Add initialization if missing
if "self.agent_reaper =" not in content:
    content = content.replace("        self.recovery_service = RecoveryService(self)",
                              "        self.recovery_service = RecoveryService(self)\n        self.agent_reaper = AgentReaper(self)")

# Add task start if missing
if "self._agent_reaper_task =" not in content:
    content = content.replace("        # Reliability sprint: background stuck-task reaper.",
                              "        # Reliability sprint: background stuck-task reaper.\n        self._agent_reaper_task = asyncio.create_task(self.agent_reaper.run())")

with open(filepath, "w") as f:
    f.write(content)
