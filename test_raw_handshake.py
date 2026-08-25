"""Debug asyncpg connection - focus on auth method and connection startup."""
import asyncio
import sys
import struct

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


async def raw_postgres_handshake():
    """Do a raw PostgreSQL handshake to see what happens."""
    print("=== Raw PostgreSQL handshake ===", flush=True)
    
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", 15432),
        timeout=5
    )
    print("  TCP connected", flush=True)
    
    # Send SSLRequest first (like asyncpg does)
    ssl_request = struct.pack("!II", 8, 80877103)  # SSLRequest code
    writer.write(ssl_request)
    await writer.drain()
    
    # Read response
    response = await asyncio.wait_for(reader.read(1), timeout=5)
    ssl_byte = response[0:1]
    print(f"  SSL response: {ssl_byte!r} ({'S' if ssl_byte == b'S' else 'N' if ssl_byte == b'N' else 'UNKNOWN'})", flush=True)
    
    if ssl_byte == b'N':
        # Server doesn't support SSL, send startup message
        user = b"ai_osop\x00"
        db = b"ai_osop\x00"
        params = b"user\x00" + user + b"database\x00" + db + b"\x00"
        startup = struct.pack("!II", 4 + 4 + len(params), 196608) + params  # protocol 3.0
        writer.write(startup)
        await writer.drain()
        
        # Read auth response
        resp = await asyncio.wait_for(reader.read(1024), timeout=5)
        print(f"  Auth response ({len(resp)} bytes): {resp[:50]!r}", flush=True)
        
        # Parse response type
        if resp and len(resp) >= 5:
            msg_type = chr(resp[0])
            msg_len = struct.unpack("!I", resp[1:5])[0]
            print(f"  Message type: {msg_type}, length: {msg_len}", flush=True)
            
            if msg_type == 'R':  # Authentication
                auth_type = struct.unpack("!I", resp[5:9])[0]
                auth_names = {
                    0: "OK", 2: "KerberosV5", 3: "CleartextPassword",
                    5: "MD5Password", 6: "SCMCredential", 7: "GSS",
                    8: "GSSContinue", 9: "SSPI", 10: "SASL",
                    11: "SASLContinue", 12: "SASLFinal"
                }
                print(f"  Auth type: {auth_type} ({auth_names.get(auth_type, 'UNKNOWN')})", flush=True)
                if auth_type == 0:
                    print("  Authentication OK (trust)", flush=True)
                elif auth_type == 10:
                    # SASL - extract mechanism list
                    mech_end = resp.find(b'\x00', 9)
                    if mech_end > 9:
                        mechanisms = resp[9:mech_end].decode()
                        print(f"  SASL mechanisms: {mechanisms}", flush=True)
            
            elif msg_type == 'E':  # Error
                print(f"  ERROR response: {resp[5:msg_len]!r}", flush=True)
    
    writer.close()
    await writer.wait_closed()


asyncio.run(raw_postgres_handshake())
