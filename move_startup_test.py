filepath = "src/ai_osop/api/main.py"
with open(filepath, "r") as f:
    content = f.read()

# Remove from early position
old_injection = '    # Startup\n    startup_results = await run_startup_self_test()\n    if startup_results["status"] != "healthy":\n        logger.critical(f"Startup self-test failed: {startup_results}")\n        # Optional: raise RuntimeError("Startup self-test failed")\n    \n    health_status = {'
new_lifespan_start = '    # Startup\n    health_status = {'
content = content.replace(old_injection, new_lifespan_start)

# Add to later position, after orchestrator initialization
# I need to find where orchestrator is initialized (search for 'orch = Orchestrator')
# Actually, the orchestrator is built inside the with block.
new_injection = """
        # Reliability sprint: Run self-test after orchestrator initialization
        startup_results = await run_startup_self_test()
        if startup_results["status"] != "healthy":
            logger.critical(f"Startup self-test failed: {startup_results}")
            # raise RuntimeError("Startup self-test failed")
"""
# I will find a good insertion point (after 'orch = Orchestrator(...)')
content = content.replace("        orch = Orchestrator(", "        orch = Orchestrator(" + new_injection)

with open(filepath, "w") as f:
    f.write(content)
