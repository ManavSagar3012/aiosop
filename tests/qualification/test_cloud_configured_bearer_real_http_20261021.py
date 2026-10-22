"""Actual Cloud native HTTP/registry transport credential joins on localhost.

No scanner/provider is invoked: positive Checkov static-IaC execution is a
separate operator-gated, isolated fixture. This test proves the client can
authenticate its configured native transport, but cannot bypass signed
Task/Flow/ROE and source approval merely because a bearer exists.
"""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import uvicorn

from ai_osop.api import main
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPRegistry


def _module():
    path = Path(__file__).resolve().parents[2] / "mcp-servers/python/cloud_mcp.py"
    spec = importlib.util.spec_from_file_location("_owned_cloud_actual_http", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@asynccontextmanager
async def local_cloud(app):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="critical",
        access_log=False,
        lifespan="off",
        timeout_keep_alive=1,
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(70):
            if server.started:
                break
            if task.done():
                raise AssertionError("Owned Cloud HTTP service did not start")
            await asyncio.sleep(0.05)
        assert server.started
        yield port
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=5)


@pytest.mark.asyncio
async def test_cloud_current_config_bearer_is_forwarded_but_not_action_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terraform = tmp_path / "terraform"
    terraform.mkdir()
    (terraform / "main.tf").write_text(
        'resource "aws_s3_bucket" "inert" { bucket = "offline-fixture-only" }\n',
        encoding="utf-8",
    )
    python_executable = Path(sys.executable).resolve()
    token = "local-cloud-transport-bearer-20261021-only"
    monkeypatch.setenv("OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED", "1")
    monkeypatch.setenv("OSOP_CLOUD_MCP_IAC_ROOT", str(terraform))
    monkeypatch.setenv("OSOP_CLOUD_MCP_CHECKOV_PYTHON", str(python_executable))
    monkeypatch.setenv("OSOP_CLOUD_MCP_BEARER_TOKEN", token)
    module = _module()

    async def forbidden_scanner(*_args, **_kwargs):
        raise AssertionError("Unsigned registry call must NEVER enter Checkov")

    monkeypatch.setattr(module, "_scan", forbidden_scanner)
    async with local_cloud(module.app) as port:
        monkeypatch.setattr(main.settings, "cloud_mcp_host", "127.0.0.1")
        monkeypatch.setattr(main.settings, "cloud_mcp_port", port)
        monkeypatch.setattr(main.settings, "cloud_mcp_auth_token", token)
        exact = next(item for item in main.configured_mcp_server_specs() if item[0] == "cloud-mcp")
        assert exact == ("cloud-mcp", "127.0.0.1", port, token)
        registry = MCPRegistry()
        try:
            connection = await registry.register_server(*exact)
            assert connection.auth_token == token
            manifest = await registry.initialize_server("cloud-mcp", {}, {}, "offline-inert-test")
            assert manifest.status == "ready"
            assert [t.name for t in manifest.tools] == ["scan_local_iac"]
            assert manifest.tools[0].requires_approval is True
            RequestContext.bind(engagement_id="eng-no-signed-roe", task_id="task-not-approved")
            try:
                # A valid local bearer + read-only tool declaration cannot
                # authorize a consequential workflow without durable approval.
                denied = await registry.execute_tool(
                    "cloud-mcp", "scan_local_iac", {}, request_id="req-static-iac-no-roe"
                )
            finally:
                RequestContext.clear()
            assert denied.status != "success"
            assert not connection._executions
        finally:
            await registry.close_all()
