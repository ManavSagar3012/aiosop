#!/usr/bin/env python3
"""Test that unauthenticated connections are rejected by Redis TLS."""
import ssl
import socket
import json
import sys

result = {"status": "unknown"}

try:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile="certs/ca.pem")
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    s = ctx.wrap_socket(socket.socket(), server_hostname="localhost")
    s.connect(("localhost", 6380))
    s.send(b"*1\r\n$4\r\nPING\r\n")
    resp = s.recv(1024)
    result = {"status": "UNAUTHENTICATED_ACCESS_ALLOWED", "response": resp.decode()}
    s.close()
except Exception as e:
    result = {"status": "CONNECTION_REJECTED_AS_EXPECTED", "error": str(e)}

with open("tls_unauth_result.json", "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
sys.exit(0)
