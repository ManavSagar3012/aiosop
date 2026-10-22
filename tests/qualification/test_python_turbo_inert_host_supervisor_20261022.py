"""Original owned ephemeral disabled Python MCP, no Action/target/provider."""

import asyncio
import hashlib
import json
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest

from ai_osop.mcp.python_inert_host_supervisor import (
    PythonInertHostDenied,
    PythonInertHostSupervisor,
    _SOURCE,
    _safe_environment,
)
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.core.exceptions import MCPConnectionError


def pinned() -> str:
    return hashlib.sha256(Path(_SOURCE).read_bytes()).hexdigest()


def host(**overrides) -> PythonInertHostSupervisor:
    arguments = {
        "reviewed_source_sha256": pinned(),
        "reviewed_interpreter_sha256": hashlib.sha256(
            Path(sys.executable).read_bytes()
        ).hexdigest(),
        "reviewed_runtime_sha256": hashlib.sha256(
            Path(getattr(sys, "_base_executable", sys.executable)).read_bytes()
        ).hexdigest(),
        "explicitly_opted_in": True,
    }
    arguments.update(overrides)
    return PythonInertHostSupervisor(**arguments)


@pytest.mark.asyncio
async def test_disabled_python_supervisor_denies_without_host_opt_in_and_sha() -> None:
    for digest, opt in (("0" * 64, False), ("0" * 64, True), ("not_sha", True)):
        fleet = host(reviewed_source_sha256=digest, explicitly_opted_in=opt)
        with pytest.raises(PythonInertHostDenied):
            await fleet.start()
        with pytest.raises(PythonInertHostDenied):
            await fleet.status()


def test_child_env_does_not_inherit_api_provider_or_signer_authority(monkeypatch) -> None:
    monkeypatch.setenv("OSOP_SECRET_SIGNER_PRIVATE_KEY", "synthetic-fixture-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-fixture-paid-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-cloud-key")
    environment = _safe_environment()
    assert not any(
        "OSOP" in name or "AWS" in name or "PROXY" in name or "API_KEY" in name
        for name in environment
    )
    assert "synthetic-fixture-secret" not in str(environment)
    assert "synthetic-fixture-paid-key" not in str(environment)


@pytest.mark.asyncio
async def test_actual_inert_turbo_process_owned_health_and_rejects_execute() -> None:
    fleet = host()
    try:
        observation = await fleet.start()
        assert observation.service_id == "turbo-intruder-mcp"
        assert observation.process_owned and observation.listener_owned
        assert observation.health_unavailable
        assert observation.signed_action_verified is False
        assert observation.native_execution_enabled is False
        assert observation.independent_target_effect_verified is False
        assert observation.production_certified is False
        current = await fleet.status()
        assert current == observation
        assert fleet._port not in (
            8081,
            8082,
            8083,
            8084,
            8085,
            8086,
            8087,
            8091,
            8096,
            8097,
            8098,
            8200,
        )
        port = fleet._port
        assert port is not None
        url = f"http://127.0.0.1:{port}/mcp/execute"
        body = json.dumps(
            {
                "server_id": "turbo-intruder-mcp",
                "tool_name": "execute_single_packet_attack",
                "parameters": {
                    "target_url": "https://never-used.example.invalid",
                    "concurrent_requests": 2,
                },
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url, body, {"Content-Type": "application/json"}, method="POST"
        )
        # The real host-side service rejects even a direct attempted call
        # without contacting the embedded synthetic fixture target.
        with pytest.raises(urllib.error.HTTPError) as denied:
            await asyncio.to_thread(urllib.request.urlopen, request, None, 1)
        assert denied.value.code == 503
        result = json.loads(denied.value.read())
        assert result["execution_enabled"] is False
        assert result["status"] == "error"
        with pytest.raises(PythonInertHostDenied):
            await fleet.start()
    finally:
        port = fleet._port
        await fleet.stop()
        assert fleet._port is None and fleet._child is None
    if port is not None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            assert probe.connect_ex(("127.0.0.1", port)) != 0


@pytest.mark.asyncio
async def test_host_pin_does_not_allow_source_modification_or_synthetic_execution() -> None:
    fleet = host()
    with patch("ai_osop.mcp.python_inert_host_supervisor._hash_file", return_value="0" * 64):
        with pytest.raises(PythonInertHostDenied):
            await fleet.start()
    assert fleet._child is None


@pytest.mark.asyncio
async def test_incorrect_python_or_base_runtime_hash_cannot_launch() -> None:
    for override in (
        {"reviewed_interpreter_sha256": "0" * 64},
        {"reviewed_runtime_sha256": "0" * 64},
    ):
        supervisor = host(**override)
        with pytest.raises(PythonInertHostDenied):
            await supervisor.start()
        assert supervisor._child is None


@pytest.mark.asyncio
async def test_lost_startup_task_cancels_owned_process_tree_without_retry() -> None:
    fleet = host()
    observing = asyncio.Event()

    async def lost_observation():
        observing.set()
        await asyncio.sleep(100)

    with patch.object(fleet, "_observe", side_effect=lost_observation):
        attempted = asyncio.create_task(fleet.start())
        await asyncio.wait_for(observing.wait(), timeout=8)
        assert fleet._child is not None
        attempted.cancel()
        with pytest.raises(asyncio.CancelledError):
            await attempted
    assert fleet._child is None
    assert fleet._port is None


@pytest.mark.asyncio
async def test_actual_disabled_turbo_cannot_initialize_or_register_ready_mcp() -> None:
    fleet = host()
    registry = MCPRegistry()
    try:
        await fleet.start()
        # Real loopback transport, real child process and real /health=503.
        # Registration must refuse before an MCP tool can become usable.
        with pytest.raises(MCPConnectionError):
            await registry.register_server("turbo-intruder-mcp", "127.0.0.1", fleet._port)
        assert registry._servers == {}
        await registry.close_all()
    finally:
        await fleet.stop()
