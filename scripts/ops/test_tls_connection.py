#!/usr/bin/env python3
"""Test TLS connection to Redis."""
import ssl
import socket
import json
import sys
from pathlib import Path

certs_dir = Path("certs")
result = {"status": "unknown"}

try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(
        certfile=str(certs_dir / "client.pem"),
        keyfile=str(certs_dir / "client-key.pem"),
    )
    ctx.load_verify_locations(cafile=str(certs_dir / "ca.pem"))
    ctx.verify_mode = ssl.CERT_REQUIRED

    s = ctx.wrap_socket(socket.socket(), server_hostname="localhost")
    s.connect(("localhost", 6380))

    peer_cert = s.getpeercert()
    cipher = s.cipher()

    result = {
        "status": "OK",
        "tls_version": s.version(),
        "cipher": cipher[0] if cipher else "unknown",
        "peer_subject": dict(x[0] for x in peer_cert.get("subject", ())) if peer_cert else {},
    }
    s.close()

except ssl.SSLCertVerificationError as e:
    result = {"status": "CERT_ERROR", "error": str(e)}
except ConnectionRefusedError:
    result = {"status": "CONNECTION_REFUSED", "error": "Redis TLS not listening on port 6380"}
except Exception as e:
    result = {"status": "ERROR", "error": str(e)}

with open("tls_result.json", "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
sys.exit(0 if result["status"] == "OK" else 1)
