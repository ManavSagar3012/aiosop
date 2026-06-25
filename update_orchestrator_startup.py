filepath = "src/ai_osop/orchestrator/orchestrator.py"
with open(filepath, "r") as f:
    content = f.read()

# Find the start of the scheduler loop or just after init
pattern = r'self._agent_reaper_task = asyncio.create_task\(self.agent_reaper.run\(\)\)'
# Inject reconciliation just after starting reaper
injection = """
        await self.agent_reaper.reconcile_all()
"""
content = re.sub(pattern, pattern + injection, content)

with open(filepath, "w") as f:
    f.write(content)
