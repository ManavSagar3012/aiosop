import os

# 1. Update health.py
health_path = "src/ai_osop/api/health.py"
with open(health_path, "a") as f:
    f.write("""
async def run_startup_self_test() -> Dict[str, Any]:
    \"\"\"Run comprehensive startup self-test.\"\"\"
    results = {
        "redis": await _check_redis(),
        "neo4j": await _check_neo4j(),
        "postgres": await _check_postgres(),
        "mcp_registry": await _check_mcp_registry(),
    }
    
    healthy = all(r.get("status") == "healthy" for r in results.values())
    
    return {
        "status": "healthy" if healthy else "unhealthy",
        "checks_passed": sum(1 for r in results.values() if r.get("status") == "healthy"),
        "checks_failed": sum(1 for r in results.values() if r.get("status") != "healthy"),
        "results": results
    }
""")

# 2. Update main.py to call self-test
main_path = "src/ai_osop/api/main.py"
with open(main_path, "r") as f:
    content = f.read()

# Add import
if "from ai_osop.api.health import run_startup_self_test" not in content:
    content = content.replace("from ai_osop.api.health import router as health_router",
                              "from ai_osop.api.health import router as health_router, run_startup_self_test")

# Call in lifespan
# Find where to insert the call (e.g. after infrastructure connection)
# I'll search for 'health_status' and insert it after.
old_lifespan = '    # Startup\n    health_status = {'
new_lifespan = '    # Startup\n    startup_results = await run_startup_self_test()\n    if startup_results["status"] != "healthy":\n        logger.critical(f"Startup self-test failed: {startup_results}")\n        # Optional: raise RuntimeError("Startup self-test failed")\n    \n    health_status = {'

content = content.replace(old_lifespan, new_lifespan)

with open(main_path, "w") as f:
    f.write(content)
