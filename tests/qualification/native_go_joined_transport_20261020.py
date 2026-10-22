"""Real native Recon Go MCP + mounted FastAPI over pinned local HTTPS.

Reusable only by explicitly disposable qualification tests. It compiles the
real native cmd from source with GOPROXY=off, binds its Go MCP listener to a
unique loopback port, and starts the application's actual FastAPI router on a
separately pinned TLS endpoint. No target, provider or existing DB is started.
Source-side native handlers remain blocked except inert authority_status.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ai_osop.api.routers import native_mcp_redemption as redemption
from ai_osop.mcp.protocol import MCPRegistry


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        number = listener.getsockname()[1]
        assert 1024 <= number <= 65535
        return number


def _write_tls_identity(directory: Path) -> tuple[Path, Path, str]:
    # Sole local trust anchor; the Go process receives this cert in its own
    # owner-managed config, not from the outbound grant or HTTP request.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(minutes=20))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_file = directory / "native-validator-local.pem"
    key_file = directory / "native-validator-local-key.pem"
    cert_file.write_bytes(cert_pem)
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file, cert_pem.decode("ascii")


@asynccontextmanager
async def native_go_mounted_fastapi(
    *,
    memory: Any,
    registry: MCPRegistry,
    issuer_kid: str,
    issuer_public_raw: bytes,
    service_secret: str,
    initialization_engagement_id: str,
) -> AsyncIterator[SimpleNamespace]:
    """Start/stop the actual Go Recon binary + actual FastAPI mounted router.

    Caller must install a real signed PostgreSQL authority in `memory`, set
    issuer-private-key env in the current Python process, and use a genuine
    approved 0027 Action before calling registry.execute_tool. NO fake durable
    validator or synthetic source authority is installed here.
    """
    if not isinstance(registry, MCPRegistry):
        raise TypeError("Real production MCP registry required")
    if len(issuer_public_raw) != 32 or not 20 <= len(service_secret) <= 512:
        raise ValueError("Independent bounded native trust inputs required")

    repository = Path(__file__).resolve().parents[2]
    go_root = repository / "mcp-servers" / "go"
    original_orchestrator = redemption.state.get("orchestrator")
    with tempfile.TemporaryDirectory(prefix="osop-real-native-join-") as temporary:
        directory = Path(temporary)
        cert_file, key_file, root_pem = _write_tls_identity(directory)
        go_port = _free_loopback_port()
        https_port = _free_loopback_port()
        assert go_port != https_port
        native_env = os.environ.copy()
        native_env.update(
            {
                "OSOP_RECON_MCP_LOCAL_PORT": str(go_port),
                "OSOP_NATIVE_MCP_LOCAL_TEST_TRACE": "1",
                "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON": json.dumps(
                    {
                        issuer_kid: base64.urlsafe_b64encode(issuer_public_raw)
                        .decode("ascii")
                        .rstrip("=")
                    }
                ),
                "OSOP_NATIVE_MCP_REDEEM_URL": (
                    f"https://127.0.0.1:{https_port}/native-grants/redeem"
                ),
                "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM": root_pem,
                # Each native process gets ONLY its own service identity.
                "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON": json.dumps(
                    {"recon-mcp": service_secret}
                ),
            }
        )
        binary = directory / ("recon-mcp.exe" if os.name == "nt" else "recon-mcp")

        def build() -> None:
            command = ["go", "build", "-o", str(binary), "./cmd/recon-mcp"]
            subprocess.run(
                command,
                cwd=go_root,
                env={**native_env, "GOPROXY": "off", "GOSUMDB": "off"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=90,
                check=True,
            )

        await asyncio.to_thread(build)
        process = None
        server = None
        server_task = None
        try:
            from ai_osop.api.main import app

            # Actual mounted FastAPI route. Lifespan is disabled ONLY to avoid
            # opening unrelated app Redis/PG/Neo4j/Temporal/provider runtimes.
            # Its state points to the test's own real PostgreSQL session maker.
            redemption.state["orchestrator"] = SimpleNamespace(
                session_memory=memory, mcp_registry=registry
            )
            server = uvicorn.Server(
                uvicorn.Config(
                    app,
                    host="127.0.0.1",
                    port=https_port,
                    ssl_certfile=str(cert_file),
                    ssl_keyfile=str(key_file),
                    lifespan="off",
                    access_log=False,
                    log_level="error",
                )
            )
            server_task = asyncio.create_task(server.serve())
            for _ in range(100):
                if server.started:
                    break
                if server_task.done():
                    raise RuntimeError("Isolated actual FastAPI TLS listener exited")
                await asyncio.sleep(0.05)
            assert server.started, "Isolated FastAPI TLS listener never initialized"

            process = await asyncio.create_subprocess_exec(
                str(binary),
                cwd=str(go_root),
                env=native_env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            registered = False
            for _ in range(70):
                if process.returncode is not None:
                    raise RuntimeError("Real native Go Recon server exited before negotiation")
                try:
                    await registry.register_server("recon-mcp", "127.0.0.1", go_port)
                    registered = True
                    break
                except Exception:
                    await asyncio.sleep(0.1)
            if not registered:
                raise RuntimeError("Real native Go Recon server never became reachable")
            initialized = await registry.initialize_server(
                "recon-mcp", {}, {}, initialization_engagement_id
            )
            assert initialized.server_id == "recon-mcp"
            assert initialized.status == "ready"
            assert [tool.name for tool in initialized.tools] == ["authority_status"]
            assert initialized.capabilities == ["native_grant_probe_v1"]
            yield SimpleNamespace(
                port=go_port,
                validator_port=https_port,
                registry=registry,
                native_process=process,
                # For the exclusively owned two-PROCESS qualification only.
                # Never exposed by the operator API or written as a log.
                native_binary=str(binary),
                native_env=native_env.copy(),
            )
        finally:
            await registry.close_all()
            if process is not None and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=3)
                except asyncio.TimeoutError:
                    process.kill()
                    await asyncio.wait_for(process.wait(), timeout=3)
            if server is not None:
                server.should_exit = True
            if server_task is not None:
                try:
                    await asyncio.wait_for(server_task, timeout=5)
                except asyncio.TimeoutError:
                    server_task.cancel()
                    await asyncio.gather(server_task, return_exceptions=True)
            if original_orchestrator is None:
                redemption.state.pop("orchestrator", None)
            else:
                redemption.state["orchestrator"] = original_orchestrator
