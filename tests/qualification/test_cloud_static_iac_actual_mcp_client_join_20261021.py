"""REAL 127.0.0.1 Cloud MCP HTTP + MCPRegistry interoperability.

Registry execution must remain DENIED without actual Task/Flow signed ROE,
approval and tool budget. Only a separate direct host-pinned API request to an
owned, inert tmp Terraform tree may run an existing local Checkov interpreter.
This is NOT production Task authorization, cloud IAM or target verification.
"""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import sys
from pathlib import Path

import httpx
import pytest
import uvicorn

from ai_osop.mcp.protocol import MCPRegistry


CLOUD_FILE = Path(__file__).resolve().parents[2] / "mcp-servers/python/cloud_mcp.py"
REPO = Path(__file__).resolve().parents[2]
CHECKOV = REPO / ".runtime/checkov-venv/Scripts/python.exe"
TOKEN = "locally-owned-iac-only-mcp-token-" + "f" * 40
REQUEST = {
    "tool_name": "scan_local_iac",
    "parameters": {},
    "request_id": "req-loopback-checkov-owned",
}


def load_cloud():
    spec = importlib.util.spec_from_file_location("_owned_cloud_static_http_join", CLOUD_FILE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def pin_host(monkeypatch, tmp_path: Path, *, checkov: bool) -> Path:
    root = tmp_path / "inert-host-controlled-terraform"
    root.mkdir(mode=0o700)
    (root / "main.tf").write_text(
        'resource "aws_s3_bucket" "inert_example" {\n'
        '  bucket = "inert-example-not-deployed"\n'
        "}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED", "1")
    monkeypatch.setenv("OSOP_CLOUD_MCP_IAC_ROOT", str(root))
    monkeypatch.setenv(
        "OSOP_CLOUD_MCP_CHECKOV_PYTHON", str(CHECKOV if checkov else Path(sys.executable))
    )
    monkeypatch.setenv("OSOP_CLOUD_MCP_BEARER_TOKEN", TOKEN)
    return root


class OwnedHttpServer:
    def __init__(self, app):
        self.app = app
        self.requests: list[str] = []
        self.sock: socket.socket | None = None
        self.server: uvicorn.Server | None = None
        self.task: asyncio.Task | None = None
        self.port = 0

        @app.middleware("http")
        async def track(request, call_next):
            self.requests.append(request.url.path)
            return await call_next(request)

    async def __aenter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(16)
        self.sock.setblocking(False)
        self.server = uvicorn.Server(
            uvicorn.Config(
                self.app,
                host="127.0.0.1",
                port=self.port,
                log_level="critical",
                access_log=False,
                lifespan="off",
            )
        )
        self.task = asyncio.create_task(self.server.serve(sockets=[self.sock]))
        for _ in range(80):
            if self.server.started:
                return self
            if self.task.done():
                raise AssertionError("Owned ASGI Cloud server terminated before startup")
            await asyncio.sleep(0.05)
        raise AssertionError("Owned ASGI Cloud server did not start")

    async def __aexit__(self, exc_type, exc, tb):
        if self.server:
            self.server.should_exit = True
        if self.task:
            await asyncio.wait_for(self.task, timeout=10)
        if self.sock:
            self.sock.close()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}"


@pytest.mark.asyncio
async def test_actual_registry_initializes_host_cloud_but_never_executes_without_signed_task(
    monkeypatch, tmp_path
):
    pin_host(monkeypatch, tmp_path, checkov=CHECKOV.is_file())
    cloud = load_cloud()
    async with OwnedHttpServer(cloud.app) as host:
        registry = MCPRegistry()
        try:
            connection = await registry.register_server(
                "cloud-mcp",
                "127.0.0.1",
                host.port,
                auth_token=TOKEN,
            )
            response = await registry.initialize_server(
                "cloud-mcp",
                scope={},
                credentials={},
                session_id="inert-discovery-only",
            )
            assert response.server_id == "cloud-mcp"
            assert response.status == "ready"
            assert [tool.name for tool in response.tools] == ["scan_local_iac"]
            assert response.tools[0].requires_approval is True
            assert response.tools[0].scope_check is True
            assert "local_iac_static_unverified" in response.capabilities
            assert connection._initialized is True
            assert host.requests.count("/mcp/execute") == 0
            denied = await registry.execute_tool(
                "cloud-mcp",
                "scan_local_iac",
                {},
                request_id="req-denied-no-signed-task",
            )
            assert denied.status != "success", denied
            assert (
                host.requests.count("/mcp/execute") == 0
            ), "Missing signed ROE/Task must never reach the Cloud HTTP execute endpoint"
        finally:
            await registry.close_all()


@pytest.mark.asyncio
async def test_real_operator_pinned_loopback_api_runs_only_local_inert_checkov(
    monkeypatch, tmp_path
):
    if not CHECKOV.is_file():
        pytest.skip("Existing locally installed Checkov interpreter unavailable; no installs")
    root = pin_host(monkeypatch, tmp_path, checkov=True)
    cloud = load_cloud()
    async with OwnedHttpServer(cloud.app) as host:
        async with httpx.AsyncClient(base_url=host.base, timeout=90, trust_env=False) as client:
            assert (await client.get("/health")).status_code == 200
            unsigned = await client.post("/mcp/execute", json=REQUEST)
            assert unsigned.status_code == 401
            arbitrary = await client.post(
                "/mcp/execute",
                json={
                    **REQUEST,
                    "parameters": {"path": str(tmp_path), "cloud_account": "fake"},
                },
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            assert arbitrary.status_code == 422
            result = await client.post(
                "/mcp/execute",
                json={
                    **REQUEST,
                    "timeout_override": None,
                },
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
        assert result.status_code == 200, result.text[:500]
        body = result.json()
        assert body["status"] == "success"
        assert body["request_id"] == REQUEST["request_id"]
        assert body["result"]["input_manifest_sha256"] == cloud._configuration()[3]
        assert body["result"]["source"] == "CHECKOV_LOCAL_IAC_UNVERIFIED"
        assert body["result"]["live_cloud_account_verified"] is False
        assert body["result"]["target_effect_verified"] is False
        assert body["result"]["findings_count"] > 0
        assert all(
            row["validation_state"] == "STATIC_IAC_ONLY" for row in body["result"]["findings"]
        )
        assert all(row["file"] == "main.tf" for row in body["result"]["findings"])
        assert (root / "main.tf").read_text(encoding="utf-8").startswith("resource")
        assert host.requests.count("/mcp/execute") == 3


@pytest.mark.asyncio
async def test_unconfigured_real_http_server_remains_unavailable_and_no_tools(monkeypatch):
    for key in (
        "OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED",
        "OSOP_CLOUD_MCP_IAC_ROOT",
        "OSOP_CLOUD_MCP_CHECKOV_PYTHON",
        "OSOP_CLOUD_MCP_BEARER_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)
    cloud = load_cloud()
    async with OwnedHttpServer(cloud.app) as host:
        async with httpx.AsyncClient(base_url=host.base, timeout=5, trust_env=False) as client:
            assert (await client.get("/health")).status_code == 503
            declaration = (await client.post("/mcp/initialize", json={})).json()
            assert declaration["status"] == "unavailable" and declaration["tools"] == []
            denied = await client.post(
                "/mcp/execute", json=REQUEST, headers={"Authorization": f"Bearer {TOKEN}"}
            )
            assert denied.status_code == 503
