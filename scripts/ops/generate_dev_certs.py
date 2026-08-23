#!/usr/bin/env python3
"""
Development TLS Certificate Generator for AI-OSOP mTLS

Generates a self-signed CA + server/client certificates for testing
mutual TLS between Redis, Neo4j, and inter-service connections.

Usage:
    python scripts/ops/generate_dev_certs.py

Output:
    certs/ca.pem          — CA certificate
    certs/server.pem      — Server certificate
    certs/server-key.pem  — Server private key
    certs/client.pem      — Client certificate (for mTLS)
    certs/client-key.pem  — Client private key

IMPORTANT: These are DEVELOPMENT certificates only.
Never use self-signed certs in production.
"""

import os
import subprocess
import sys
from pathlib import Path

CERTS_DIR = Path(__file__).parent.parent.parent / "certs"


def generate_certs():
    """Generate CA, server, and client certificates."""
    CERTS_DIR.mkdir(exist_ok=True)

    print("=" * 60)
    print("AI-OSOP Development TLS Certificate Generator")
    print("=" * 60)

    # Step 1: Generate CA key and certificate
    print("\n[1/4] Generating CA certificate...")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(CERTS_DIR / "ca-key.pem"),
            "-out", str(CERTS_DIR / "ca.pem"),
            "-days", "365", "-nodes",
            "-subj", "/C=US/ST=Dev/L=Dev/O=AI-OSOP Dev CA/CN=AI-OSOP Dev CA",
        ],
        check=True,
        capture_output=True,
    )
    print("  [OK] CA certificate created")

    # Step 2: Generate server key and CSR
    print("\n[2/4] Generating server certificate...")
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048",
            "-keyout", str(CERTS_DIR / "server-key.pem"),
            "-out", str(CERTS_DIR / "server.csr"),
            "-nodes",
            "-subj", "/C=US/ST=Dev/L=Dev/O=AI-OSOP/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )

    # Create server ext file for SAN
    server_ext = CERTS_DIR / "server.ext"
    server_ext.write_text(
        "authorityKeyIdentifier=keyid,issuer\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "subjectAltName=@alt_names\n"
        "\n"
        "[alt_names]\n"
        "DNS.1 = localhost\n"
        "DNS.2 = redis-master\n"
        "DNS.3 = neo4j-core-1\n"
        "IP.1 = 127.0.0.1\n"
    )

    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", str(CERTS_DIR / "server.csr"),
            "-CA", str(CERTS_DIR / "ca.pem"),
            "-CAkey", str(CERTS_DIR / "ca-key.pem"),
            "-CAcreateserial",
            "-out", str(CERTS_DIR / "server.pem"),
            "-days", "365",
            "-extfile", str(server_ext),
        ],
        check=True,
        capture_output=True,
    )
    print("  [OK] Server certificate created")

    # Step 3: Generate client key and CSR
    print("\n[3/4] Generating client certificate...")
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048",
            "-keyout", str(CERTS_DIR / "client-key.pem"),
            "-out", str(CERTS_DIR / "client.csr"),
            "-nodes",
            "-subj", "/C=US/ST=Dev/L=Dev/O=AI-OSOP/CN=aiosop-agent",
        ],
        check=True,
        capture_output=True,
    )

    # Create client ext file
    client_ext = CERTS_DIR / "client.ext"
    client_ext.write_text(
        "authorityKeyIdentifier=keyid,issuer\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature\n"
    )

    subprocess.run(
        [
            "openssl", "x509", "-req",
            "-in", str(CERTS_DIR / "client.csr"),
            "-CA", str(CERTS_DIR / "ca.pem"),
            "-CAkey", str(CERTS_DIR / "ca-key.pem"),
            "-CAcreateserial",
            "-out", str(CERTS_DIR / "client.pem"),
            "-days", "365",
            "-extfile", str(client_ext),
        ],
        check=True,
        capture_output=True,
    )
    print("  [OK] Client certificate created")

    # Step 4: Verify certificates
    print("\n[4/4] Verifying certificates...")
    result = subprocess.run(
        [
            "openssl", "verify",
            "-CAfile", str(CERTS_DIR / "ca.pem"),
            str(CERTS_DIR / "server.pem"),
        ],
        capture_output=True,
        text=True,
    )
    if "OK" in result.stdout:
        print("  [OK] Server certificate verified against CA")
    else:
        print(f"  [FAIL] Server verification failed: {result.stdout}")

    result = subprocess.run(
        [
            "openssl", "verify",
            "-CAfile", str(CERTS_DIR / "ca.pem"),
            str(CERTS_DIR / "client.pem"),
        ],
        capture_output=True,
        text=True,
    )
    if "OK" in result.stdout:
        print("  [OK] Client certificate verified against CA")
    else:
        print(f"  [FAIL] Client verification failed: {result.stdout}")

    # Cleanup CSR and ext files
    for f in ["server.csr", "client.csr", "server.ext", "client.ext"]:
        p = CERTS_DIR / f
        if p.exists():
            p.unlink()

    print("\n" + "=" * 60)
    print("Certificates generated in:", CERTS_DIR)
    print()
    print("Files:")
    for cert_file in sorted(CERTS_DIR.glob("*.pem")):
        print(f"  {cert_file.name}")
    print()
    print("Environment variables for mTLS:")
    print(f"  OSOP_MTLS_CERT_PATH={CERTS_DIR / 'client.pem'}")
    print(f"  OSOP_MTLS_KEY_PATH={CERTS_DIR / 'client-key.pem'}")
    print(f"  OSOP_MTLS_CA_CERT_PATH={CERTS_DIR / 'ca.pem'}")
    print(f"  OSOP_MTLS_ENABLED=true")
    print(f"  OSOP_REDIS_TLS_ENABLED=true")
    print(f"  OSOP_NEO4J_TLS_ENABLED=true")
    print("=" * 60)


if __name__ == "__main__":
    generate_certs()
