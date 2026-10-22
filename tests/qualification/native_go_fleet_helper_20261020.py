"""Five real Go command listeners and genuine pinned FastAPI redemption.

Only the caller-owned disposable PostgreSQL qualification may use this helper.
Each context owns one newly compiled Go binary, one new native loopback port,
one new pinned HTTPS loopback origin, its own ephemeral certificate trust root,
and their lifetimes. Native scanner/provider handlers are NEVER invoked.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import subprocess
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator

import aiohttp
import uvicorn
from cryptography.hazmat.primitives.serialization import Encoding

from ai_osop.api.routers import native_mcp_redemption as redemption
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_execution_grants import _native_manifest_sha256
from tests.qualification.native_go_joined_transport_20261020 import (
    _free_loopback_port,
    _write_tls_identity,
)


_SERVERS = frozenset(
    {"payload-mcp", "nuclei-mcp", "shodan-mcp", "threat-intel-mcp", "security-bridge"}
)


def _child_environment() -> dict[str, str]:
    """No inherited paid-provider credentials, target URLs or proxy settings."""
    system_keys = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "SystemRoot",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "OS",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
        "USER",
        "USERNAME",
        "USERDOMAIN",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "APPDATA",
        "PROGRAMDATA",
        "ALLUSERSPROFILE",
        "COMMONPROGRAMFILES",
        "COMPUTERNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    }
    return {k: v for k, v in os.environ.items() if k in system_keys}


@asynccontextmanager
async def native_go_fleet_mounted_fastapi(
    *,
    server_id: str,
    registry: MCPRegistry,
    issuer_kid: str,
    issuer_public_raw: bytes,
    service_secret: str,
    initialization_engagement_id: str,
) -> AsyncIterator[SimpleNamespace]:
    """Only real native process and mounted real FastAPI, no authority mocks.

    Caller installs its own genuine SessionMemory/PG in redemption.state after
    this context initializes. No source methods are patched or replaced.
    """
    if server_id not in _SERVERS or not isinstance(registry, MCPRegistry):
        raise ValueError("Known native Go server and production registry required")
    if len(issuer_public_raw) != 32 or not 20 <= len(service_secret) <= 512:
        raise ValueError("Real independent native trust inputs required")

    package = server_id
    root = Path(__file__).resolve().parents[2]
    go_root = root / "mcp-servers" / "go"
    previous_orchestrator = redemption.state.get("orchestrator")
    with tempfile.TemporaryDirectory(prefix=f"osop-native-{package}-") as raw:
        directory = Path(raw)
        cert_file, key_file, pem = _write_tls_identity(directory)
        native_port = _free_loopback_port()
        https_port = _free_loopback_port()
        assert native_port != https_port
        public = base64.urlsafe_b64encode(issuer_public_raw).decode("ascii").rstrip("=")

        # Server receives ONLY its own independently provisioned credential.
        child = _child_environment()
        child.update(
            {
                "OSOP_NATIVE_MCP_LOCAL_PORT": str(native_port),
                "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON": json.dumps({issuer_kid: public}),
                "OSOP_NATIVE_MCP_REDEEM_URL": (
                    f"https://127.0.0.1:{https_port}/native-grants/redeem"
                ),
                "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM": pem,
                "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON": json.dumps({server_id: service_secret}),
            }
        )
        binary = directory / (package + (".exe" if os.name == "nt" else ""))

        def build() -> None:
            env = os.environ.copy()
            env.update(
                {"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off"}
            )
            subprocess.run(
                ["go", "build", "-o", str(binary), f"./cmd/{package}"],
                cwd=go_root,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=90,
            )

        await asyncio.to_thread(build)
        process = None
        server = None
        server_task = None
        try:
            # Disable ONLY the FastAPI lifespan, preventing connections to
            # existing application Redis/Neo4j/PostgreSQL or remote providers.
            from ai_osop.api.main import app

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
                    raise RuntimeError("Owned pinned FastAPI TLS startup failed")
                await asyncio.sleep(0.05)
            assert server.started

            process = await asyncio.create_subprocess_exec(
                str(binary),
                cwd=str(go_root),
                env=child,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            healthy = False
            async with aiohttp.ClientSession() as client:
                for _ in range(100):
                    if process.returncode is not None:
                        # Source-specific Go startup errors are safe bounded
                        # diagnostics; never include env/private key values.
                        detail = await process.stderr.read(2048)
                        raise RuntimeError(
                            "Owned native Go server exited before readiness: "
                            + detail.decode("utf-8", errors="replace")[:400]
                        )
                    try:
                        async with client.get(
                            f"http://127.0.0.1:{native_port}/health",
                            timeout=aiohttp.ClientTimeout(total=0.5),
                            allow_redirects=False,
                        ) as response:
                            if response.status == 200:
                                health = await response.json()
                                assert health["server_id"] == server_id
                                assert health["status"] == "configured_unverified"
                                assert health["native_scanners_enabled"] is False
                                assert health["authority_verified"] is False
                                healthy = True
                                break
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        await asyncio.sleep(0.1)
            if not healthy:
                raise RuntimeError("Actual configured Go command not ready on owned loopback")
            await registry.register_server(server_id, "127.0.0.1", native_port)
            initialized = await registry.initialize_server(
                server_id, {}, {}, initialization_engagement_id
            )
            assert initialized.server_id == server_id
            assert initialized.status == "ready"
            assert initialized.capabilities == ["native_grant_probe_v1"]
            assert len(initialized.tools) == 1
            definition = initialized.tools[0]
            assert definition.name == "authority_status"
            assert definition.side_effect_class.value == "READ_ONLY"
            assert definition.requires_approval is True
            assert definition.scope_check is True
            assert definition.parameters == []
            assert FlowMCPActionStore.declaration_sha256(
                definition, server_id
            ) == _native_manifest_sha256(server_id)
            assert registry._servers[server_id]._initialized is True
            yield SimpleNamespace(
                native_port=native_port,
                https_port=https_port,
                service_id=server_id,
                registry=registry,
                process=process,
                binary=binary,
                service_root_pem=pem,
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
            if previous_orchestrator is None:
                redemption.state.pop("orchestrator", None)
            else:
                redemption.state["orchestrator"] = previous_orchestrator
