"""Test asyncpg connection with different event loop policies."""
import asyncio
import sys

# Force selector event loop (required for asyncpg on Windows)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import asyncpg

async def main():
    print(f"Event loop: {type(asyncio.get_running_loop()).__name__}", flush=True)
    
    # Try 1: Direct connection with timeout
    print("--- Test 1: Direct connect ---", flush=True)
    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(
                host="127.0.0.1", port=15432,
                user="ai_osop", password="ai_osop",
                database="ai_osop",
                timeout=5,
                command_timeout=10
            ),
            timeout=15
        )
        r = await conn.fetchval("SELECT 1")
        print(f"  Result: {r}", flush=True)
        await conn.close()
    except asyncio.TimeoutError:
        print("  TIMEOUT after 15s", flush=True)
    except Exception as e:
        print(f"  FAIL: {type(e).__name__}: {e}", flush=True)

    # Try 2: Pool
    print("--- Test 2: create_pool ---", flush=True)
    try:
        pool = await asyncio.wait_for(
            asyncpg.create_pool(
                host="127.0.0.1", port=15432,
                user="ai_osop", password="ai_osop",
                database="ai_osop",
                min_size=1, max_size=5,
                timeout=5,
                command_timeout=10
            ),
            timeout=20
        )
        async with pool.acquire() as conn:
            r = await conn.fetchval("SELECT 42")
            print(f"  Result: {r}", flush=True)
        await pool.close()
    except asyncio.TimeoutError:
        print("  TIMEOUT after 20s", flush=True)
    except Exception as e:
        print(f"  FAIL: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
