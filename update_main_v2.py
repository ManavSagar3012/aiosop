import os

filepath = "src/ai_osop/api/main.py"
with open(filepath, "r") as f:
    content = f.read()

# Define the insertion block
new_code = """
        # Reliability sprint: Run self-test after orchestrator initialization
        startup_results = await run_startup_self_test()
        if startup_results["status"] != "healthy":
            logger.critical(f"Startup self-test failed: {startup_results}")
            # raise RuntimeError("Startup self-test failed")
"""

# Insertion point
old_block = "        # 6. Session Store (user sessions for DiffAuth)"
new_block = new_code + "\n        " + old_block

content = content.replace(old_block, new_block)

with open(filepath, "w") as f:
    f.write(content)
