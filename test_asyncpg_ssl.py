"""Debug asyncpg SSL negotiation issue on Windows."""
import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import asyncpg

async def main():
    # The HBA shows:
    # - trust for 127.0.0.1 (loopback only)
    # - scram-sha-256 for all other IPs
    # Docker gateway IP (172.18.0.1) hits scram-sha-256 rule
    # Password IS correct, but asyncpg might be doing SSL negotiation first
    
    # Test: sslmode=prefer (asyncpg default is to try SSL negotiation)
    configs = [
        ("prefer", "prefer"),
        ("allow", "allow"),
        ("disable", "disable"),
    ]
    
    for label, sslmode in configs:
        print(f"=== sslmode={sslmode} ===", flush=True)
        try:
            # Use the DSN with sslmode parameter
            conn = await asyncio.wait_for(
                asyncpg.connect(
                    dsn=f"postgresql://ai_osop:ai_osop@127.0.0.1:15432/ai_osop?sslmode={sslmode}",
                    timeout=5,
                    command_timeout=10,
                ),
                timeout=15,
            )
            r = await conn.fetchval("SELECT 1")
            print(f"  OK: {r}", flush=True)
            await conn.close()
            return  # Success!
        except asyncio.TimeoutError:
            print("  TIMEOUT", flush=True)
        except Exception as e:
            print(f"  FAIL: {type(e).__name__}: {e}", flush=True)

    # Extra: try with ssl=True (force SSL negotiation)
    print("=== ssl=True ===", flush=True)
    try:
        import ssl as ssl_mod
        ctx = ssl_mod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE
        conn = await asyncio.wait_for(
            asyncpg.connect(
                host="127.0.0.1", port=15432,
                user="ai_osop", password="ai_osop", database="ai_osop",
                ssl=ctx,
                timeout=5,
                command_timeout=10,
            ),
            timeout=15,
        )
        r = await conn.fetchval("SELECT 1")
        print(f"  OK: {r}", flush=True)
        await conn.close()
    except asyncio.TimeoutError:
        print("  TIMEOUT", flush=True)
    except Exception as e:
        print(f"  FAIL: {type(e).__name__}: {e}", flush=True)

    # Extra: try with ssl=allow (asyncpg 0.29+ supports this)
    print("=== ssl=allow ===", flush=True)
    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(
                host="127.0.0.1", port=15432,
                user="ai_osop", password="ai_osop", database="ai_osop",
                ssl="allow",
                timeout=5,
                command_timeout=10,
            ),
            timeout=15,
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
