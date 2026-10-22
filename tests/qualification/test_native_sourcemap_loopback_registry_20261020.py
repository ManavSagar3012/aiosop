"""Real loopback SourceMap FastAPI HTTP/typed registry transport, no target.

This test does NOT claim a live PostgreSQL 0035 redemption. The original
artifact remains unavailable without its independently signed source receipt.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
import socket
import stat
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import aiohttp
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.mcp.protocol import MCPRegistry


def _native_module():
    source = Path(__file__).resolve().parents[2] / "mcp-servers/python/source_map_mcp.py"
    name = "_sourcemap_owned_loopback_20261020"
    spec = importlib.util.spec_from_file_location(name, source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@asynccontextmanager
async def _owned_native_server(app):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    listener.setblocking(False)
    port = listener.getsockname()[1]
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        access_log=False,
        log_level="error",
        lifespan="off",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        for _ in range(100):
            if server.started:
                break
            if task.done():
                raise AssertionError("Owned SourceMap native listener exited")
            await asyncio.sleep(0.02)
        assert server.started
        yield port
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=5)
        except asyncio.TimeoutError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        listener.close()


@pytest.mark.asyncio
async def test_configured_native_registry_real_tcp_only_admits_original_reviewed_tool(
    monkeypatch, tmp_path: Path
):
    native = _native_module()
    readonly = tmp_path / "originals"
    readonly.mkdir(mode=0o700)
    journal = tmp_path / "journal"
    journal.mkdir(mode=0o700)
    ca = tmp_path / "separate-central-ca.pem"
    ca.write_text(
        "-----BEGIN CERTIFICATE-----\n" + "A" * 128 + "\n-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    pub = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_URL",
        "https://authority.example.org/native-sourcemap/source-preflight",
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_CA_BUNDLE", str(ca))
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"independent-source-issuer": base64.b64encode(pub).decode("ascii")}),
    )
    central = "independent-central-sourcemap-service-token-for-test"
    client = "different-native-sourcemap-bearer-token-for-test"
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", central)
    monkeypatch.setenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", client)
    monkeypatch.setenv("OSOP_SOURCEMAP_ORIGINAL_READONLY_ROOT", str(readonly))
    monkeypatch.setenv("OSOP_SOURCEMAP_ONE_SHOT_ROOT", str(journal))
    native_signer = Ed25519PrivateKey.generate()
    native_key = tmp_path / "native-receipt.key"
    native_key.write_bytes(
        native_signer.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    native_key.chmod(0o400 if os.name == "posix" else stat.S_IREAD)
    monkeypatch.setenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KID", "native-loopback-signing")
    monkeypatch.setenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KEY_FILE", str(native_key))
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps(
            {
                "source-map-mcp": {
                    "native-loopback-signing": base64.b64encode(
                        native_signer.public_key().public_bytes(
                            serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw,
                        )
                    ).decode("ascii")
                }
            }
        ),
    )

    async with _owned_native_server(native.app) as port:
        registry = MCPRegistry()
        try:
            await registry.register_server("source-map-mcp", "127.0.0.1", port, client)
            declared = await registry.initialize_server(
                "source-map-mcp",
                scope={},
                credentials={},
                session_id="eng-local",
            )
            assert declared.status == "ready"
            assert declared.capabilities == [
                "mcp_bound_receipts_v1",
                "original_sourcemap_signed_preflight_v1",
            ]
            assert [t.name for t in declared.tools] == [
                "inspect_local_original_sourcemap",
            ]
            assert declared.tools[0].requires_approval is True
            assert registry._servers["source-map-mcp"]._initialized is True
            # Direct caller assertion with even a valid bearer cannot supply
            # independently signed original 0027/0035 Task authority.
            async with aiohttp.ClientSession(
                headers={"Authorization": "Bearer " + client},
            ) as caller:
                async with caller.post(
                    f"http://127.0.0.1:{port}/mcp/execute",
                    json={
                        "request_id": "req-" + "a" * 48,
                        "tool_name": "inspect_local_original_sourcemap",
                        "parameters": {"artifact_sha256": "a" * 64},
                    },
                    allow_redirects=False,
                ) as response:
                    assert response.status == 503
                    assert (await response.json())["status"] == "error"
            assert not list(journal.iterdir())
            assert not list(readonly.iterdir())
        finally:
            await registry.close_all()
