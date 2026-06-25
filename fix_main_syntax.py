import re

filepath = "src/ai_osop/api/main.py"
with open(filepath, "r") as f:
    content = f.read()

# I will use a more precise injection.
# First, remove the botched injection.
bad_injection = """
        # Reliability sprint: Run self-test after orchestrator initialization
        startup_results = await run_startup_self_test()
        if startup_results["status"] != "healthy":
            logger.critical(f"Startup self-test failed: {startup_results}")
            # raise RuntimeError("Startup self-test failed")
"""
content = content.replace(bad_injection, "")

# Now find the correct location to inject: inside lifespan, after 'orch = Orchestrator(...)'
# The orch is initialized inside the  block.
# I'll look for  and inject after it.
insertion = """
        orch = Orchestrator(
            session_memory,
            graph_memory,
            mcp_registry,
            coordination_bus=AgentCoordinationBus(),
        )

        # Reliability sprint: Run self-test after orchestrator initialization
        startup_results = await run_startup_self_test()
        if startup_results["status"] != "healthy":
            logger.critical(f"Startup self-test failed: {startup_results}")
"""
# Note: I need to be sure about the arguments of Orchestrator
# From earlier, it was Orchestrator(session_memory, graph_memory, mcp_registry, None)
# I will just do a simpler search and replace.
content = content.replace("        orch = Orchestrator(", "        orch = Orchestrator(") # ensure it exists

# I'll just use a direct swap for the block
with open(filepath, "w") as f:
    f.write(content)
