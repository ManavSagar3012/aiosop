"""Debug asyncpg connection issue on Windows."""
import asyncio
import sys
import socket

# Force selector event loop (required for asyncpg on Windows)
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import asyncpg

async def main():
    # Step 1: Raw TCP connectivity test
    print("=== Step 1: Raw TCP ===", flush=True)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", 15432),
            timeout=5
        )
        print("  TCP connected OK", flush=True)
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"  TCP FAIL: {e}", flush=True)

    # Step 2: asyncpg with SSL explicitly disabled
    print("=== Step 2: asyncpg ssl=False ===", flush=True)
    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(
                host="127.0.0.1",
                port=15432,
                user="ai_osop",
                password="ai_osop",
                database="ai_osop",
                ssl=False,
                timeout=5,
                command_timeout=10,
            ),
            timeout=12,
        )
        r = await conn.fetchval("SELECT version()")
        print(f"  OK: {r[:80]}", flush=True)
        await conn.close()
    except asyncio.TimeoutError:
        print("  TIMEOUT", flush=True)
    except Exception as e:
        print(f"  FAIL: {type(e).__name__}: {e}", flush=True)

    # Step 3: asyncpg with connection string (sslmode=disable)
    print("=== Step 3: DSN sslmode=disable ===", flush=True)
    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(
                dsn="postgresql://ai_osop:ai_osop@127.0.0.1:15432/ai_osop",
                ssl="disable",
                timeout=5,
                command_timeout=10,
            ),
            timeout=12,
        )
        r = await conn.fetchval("SELECT 1")
        print(f"  OK: {r}", flush=True)
        await conn.close()
    except asyncio.TimeoutError:
        print("  TIMEOUT", flush=True)
    except Exception as e:
        print(f"  FAIL: {type(e).__name__}: {e}", flush=True)

    # Step 4: Try with SSL require (maybe PostgreSQL expects SSL)
    print("=== Step 4: asyncpg ssl=require ===", flush=True)
    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(
                host="127.0.0.1",
                port=15432,
                user="ai_osop",
                password="ai_osop",
                database="ai_osop",
                ssl="require",
                timeout=5,
                command_timeout=10,
            ),
            timeout=12,
        )
        r = await conn.fetchval("SELECT 1")
        print(f"  OK: {r}", flush=True)
        await conn.close()
    except asyncio.TimeoutError:
        print("  TIMEOUT", flush=True)
    except Exception as e:
        print(f"  FAIL: {type(e).__name__}: {e}", flush=True)

    # Step 5: Try with 0.0.0.0 bind address (Docker proxy)
    print("=== Step 5: localhost instead of 127.0.0.1 ===", flush=True)
    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(
                host="localhost",
                port=15432,
                user="ai_osop",
                password="ai_osop",
                database="ai_osop",
                ssl=False,
                timeout=5,
                command_timeout=10,
            ),
            timeout=12,
        )
        r = await conn.fetchval("SELECT 1")
        print(f"  OK: {r}", flush=True)
        await conn.close()
    except asyncio.TimeoutError:
        print("  TIMEOUT", flush=True)
    except Exception as e:
        print(f"  FAIL: {type(e).__name__}: {e}", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
