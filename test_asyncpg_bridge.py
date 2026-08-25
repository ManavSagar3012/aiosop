"""Debug asyncpg connection via Docker network IP."""
import asyncio
import sys
import socket

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import asyncpg

async def main():
    # Check if the issue is Docker Desktop's userland proxy
    # Try connecting via Docker bridge IP (172.18.0.4:5432)
    targets = [
        ("Docker bridge", "172.18.0.4", 5432),
        ("localhost", "127.0.0.1", 15432),
    ]
    
    for label, host, port in targets:
        print(f"\n=== {label} ({host}:{port}) ===", flush=True)
        
        # Raw TCP check
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            print(f"  TCP: OK", flush=True)
            w.close()
            await w.wait_closed()
        except Exception as e:
            print(f"  TCP: FAIL ({e})", flush=True)
            continue
        
        # asyncpg
        try:
            conn = await asyncio.wait_for(
                asyncpg.connect(
                    host=host, port=port,
                    user="ai_osop", password="ai_osop",
                    database="ai_osop",
                    ssl=False,
                    timeout=5,
                    command_timeout=10,
                ),
                timeout=12,
            )
            r = await conn.fetchval("SELECT 1")
            print(f"  asyncpg: OK ({r})", flush=True)
            await conn.close()
        except asyncio.TimeoutError:
            print("  asyncpg: TIMEOUT", flush=True)
        except Exception as e:
            print(f"  asyncpg: FAIL ({type(e).__name__}: {e})", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
