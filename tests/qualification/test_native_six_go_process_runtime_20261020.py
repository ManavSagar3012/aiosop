"""Six ACTUAL Windows Go MCP command listeners, local inert transport only.

Opt in with OSOP_NATIVE_SIX_GO_PROCESS_RUNTIME_20261020=1. Does not use Docker,
an app DB, a source validator, a provider, a target, or any scanner/exploit
handler. Status "ready" means ONLY local inert catalog initialized, never
signed Flow/Task authorization or actual 0029/0033 remote effect evidence.
"""

from __future__ import annotations

import json
import os
import platform
import time
import warnings
from pathlib import Path
from urllib.error import URLError

import pytest

from ai_osop.core.exceptions import MCPConnectionError
from ai_osop.mcp.protocol import MCPInitializeResponse, MCPRegistry, SideEffectClass
from tests.qualification import native_six_go_process_helper_20261020 as six


_RUN = platform.system() == "Windows" and os.getenv(six.RUNTIME_OPT_IN) == "1"
_WINDOWS_ONLY = pytest.mark.skipif(
    not _RUN, reason=f"Opt in to isolated Windows native process checks with {six.RUNTIME_OPT_IN}=1"
)
_INIT = {
    "scope": {},
    "auth_credentials": {},
    "session_id": "six-native-inert-process-qualification",
    "metadata": {},
}
_EXECUTE_INERT = {
    "tool_name": "authority_status",
    "parameters": {},
    "request_id": "req-process-inert-without-grant",
}


def _explicit_negative_denial(process: six.OwnedGoProcess, payload: dict) -> tuple[int, dict]:
    """At most one additional *no-grant* negative request on Windows reset.

    No signed token or target is ever present. The test only passes after it
    independently observes a real HTTP 503 from the owned Go PID. A failed or
    missing ACK can never be counted as successful execution or delivery.
    """
    for attempt in range(2):
        try:
            return six.local_request(process.port, "/mcp/execute", payload)
        except (ConnectionResetError, ConnectionAbortedError) as exc:
            if process.process.poll() is not None or not six._owner_listens(
                process.pid, process.port
            ):
                raise AssertionError(
                    f"{process.service} exited/lost listener on unsigned denial"
                ) from exc
            if attempt:
                raise
            warnings.warn(
                f"{process.service} local no-grant HTTP reset; independently verifying a fresh 503",
                RuntimeWarning,
                stacklevel=2,
            )
    raise AssertionError("Unobserved native denial")


def test_go_six_service_sources_and_port_override_are_explicit_and_inert() -> None:
    assert set(six.SIX_NATIVE) == {
        "recon-mcp",
        "payload-mcp",
        "nuclei-mcp",
        "shodan-mcp",
        "threat-intel-mcp",
        "security-bridge",
    }
    assert sorted(port for port, _ in six.SIX_NATIVE.values()) == list(range(8082, 8088))
    for service, (default_port, legacy_handler) in six.SIX_NATIVE.items():
        directory = six.GO_ROOT / "cmd" / service
        main = (directory / "main.go").read_text(encoding="utf-8")
        assert f'sdk.NewServer("{service}")' in main
        assert f"Name: " in main and f'"{legacy_handler}"' in main
        if service != "recon-mcp":
            assert f"sdk.LocalPortAddress({default_port})" in main
        else:
            assert "reconListenAddress()" in main
            recon = (directory / "web_search.go").read_text(encoding="utf-8")
            assert "OSOP_RECON_MCP_LOCAL_PORT" in recon
            assert f'return "127.0.0.1:{default_port}"' in recon
    sdk = (six.GO_ROOT / "sdk/server.go").read_text(encoding="utf-8")
    assert "item.Handler = nil" in sdk
    assert "native_execution_not_authorized" in sdk
    assert 'mux.HandleFunc("/mcp/execute"' in sdk
    assert 'return net.JoinHostPort("127.0.0.1", port), nil' in sdk


def test_environment_does_not_inherit_application_or_paid_provider_secrets(monkeypatch) -> None:
    monkeypatch.setenv("OSOP_SHODAN_API_KEY", "private-test-only-no-provider")
    monkeypatch.setenv("OSOP_POSTGRES_URI", "postgresql://private-test-only")
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.invalid:80")
    child = six.clean_child_environment()
    assert not any("PRIVATE" in v.upper() for v in child.values())
    assert "OSOP_SHODAN_API_KEY" not in child
    assert "OSOP_POSTGRES_URI" not in child
    assert "HTTPS_PROXY" not in child
    for service in six.SIX_NATIVE:
        environment = six.native_environment(service, 55200, "unconfigured")
        assert not any(name.startswith("OSOP_NATIVE_MCP_REDEEM") for name in environment)
        override = (
            "OSOP_RECON_MCP_LOCAL_PORT" if service == "recon-mcp" else "OSOP_NATIVE_MCP_LOCAL_PORT"
        )
        assert environment[override] == "55200"
        assert (
            environment.get(
                "OSOP_RECON_MCP_LOCAL_PORT"
                if service != "recon-mcp"
                else "OSOP_NATIVE_MCP_LOCAL_PORT"
            )
            is None
        )


@pytest.fixture(scope="module")
def binaries(tmp_path_factory):
    if not _RUN:
        pytest.skip("Explicit Windows process opt-in not enabled")
    return six.build_all_six(tmp_path_factory.mktemp("owned-six-windows-go"))


@pytest.fixture(scope="module")
def public_trust():
    if not _RUN:
        pytest.skip("Explicit Windows process opt-in not enabled")
    return six.pinned_public_metadata()


@_WINDOWS_ONLY
@pytest.mark.parametrize("service", tuple(six.SIX_NATIVE))
@pytest.mark.asyncio
async def test_real_configured_go_process_typed_inert_registry_and_handler_503(
    service, binaries, public_trust
):
    with six.isolated_go_process(
        service, binaries[service], "configured", trust=public_trust
    ) as running:
        status, health = running.wait_for_health()
        assert status == 200 and health == {
            "status": "configured_unverified",
            "server_id": service,
            "execution_enabled": False,
            "authority_verified": False,
            "native_scanners_enabled": False,
        }
        assert running.process.poll() is None

        # Genuine production Python MCP registry negotiates the Go cmd server.
        registry = MCPRegistry()
        try:
            connection = await registry.register_server(service, "127.0.0.1", running.port)
            initialized = await registry.initialize_server(
                service, scope={}, credentials={}, session_id=_INIT["session_id"]
            )
            assert isinstance(initialized, MCPInitializeResponse)
            assert initialized.server_id == service
            assert initialized.status == "ready"
            assert initialized.capabilities == ["native_grant_probe_v1"]
            assert len(initialized.tools) == 1
            tool = initialized.tools[0]
            assert tool.name == "authority_status"
            assert tool.side_effect_class == SideEffectClass.READ_ONLY
            assert tool.requires_approval is True and tool.scope_check is True
            assert tool.parameters == []
            assert connection._initialized is True
            assert set(connection._tools) == {"authority_status"}
        finally:
            await registry.close_all()

        invalid, invalid_body = six.local_request(running.port, "/mcp/initialize", {})
        assert invalid == 400 and invalid_body["error"] == "invalid_initialize_metadata"
        # No original grant/supervisor proof, so not even the inert built-in
        # can reach the independently pinned (unstarted) source validator.
        try:
            builtin_status, builtin = _explicit_negative_denial(running, _EXECUTE_INERT)
        except OSError as exc:
            pytest.fail(
                f"{service} process denied-response connection failed: "
                f"error={type(exc).__name__}, exit={running.process.poll()}, "
                f"owned_listener={six._owner_listens(running.pid, running.port)}, "
                f"stderr_class={running.safe_stderr_kind()}"
            )
        assert builtin_status == 503
        assert builtin == {
            "status": "error",
            "error": "native_execution_not_authorized",
            "execution_enabled": False,
        }
        # The registered legacy tool is invoked with NO TARGET PARAMETERS;
        # the shared Go HTTP handler must block before calling Tool.Handler.
        legacy_status, legacy = _explicit_negative_denial(
            running,
            {
                "tool_name": six.SIX_NATIVE[service][1],
                "parameters": {},
                "request_id": "req-no-exec",
            },
        )
        assert legacy_status == 503 and legacy == builtin
        # "configured_unverified" stays truthful even after nominal init.
        again, after = six.local_request(running.port, "/health")
        assert again == 200 and after["authority_verified"] is False
        assert after["native_scanners_enabled"] is False
        assert running.pid > 0


@_WINDOWS_ONLY
@pytest.mark.parametrize("service", tuple(six.SIX_NATIVE))
@pytest.mark.asyncio
async def test_real_unconfigured_go_process_health_unavailable_registry_denied(service, binaries):
    with six.isolated_go_process(service, binaries[service], "unconfigured") as running:
        status, health = running.wait_for_health()
        assert status == 503
        assert health["server_id"] == service
        assert health["status"] == "unavailable"
        assert health["execution_enabled"] is False
        assert health["authority_verified"] is False

        # HTTP200 catalog with status "unavailable" cannot establish readiness.
        # Actual MCPRegistry.connect first probes /health and rejects its 503.
        response_status, declaration = six.local_request(running.port, "/mcp/initialize", _INIT)
        assert response_status == 200
        assert declaration["server_id"] == service
        assert declaration["status"] == "unavailable"
        assert declaration["execution_enabled"] is False
        assert declaration["capabilities"] == []
        registry = MCPRegistry()
        try:
            with pytest.raises(MCPConnectionError):
                await registry.register_server(service, "127.0.0.1", running.port)
            assert service not in registry._servers
        finally:
            await registry.close_all()

        for tool_name in ("authority_status", six.SIX_NATIVE[service][1]):
            denied, body = _explicit_negative_denial(
                running,
                {"tool_name": tool_name, "parameters": {}, "request_id": "req-unconfigured"},
            )
            assert denied == 503
            assert body["status"] == "error"
            assert body["execution_enabled"] is False
            assert body["error"] == "native_execution_not_authorized"


@_WINDOWS_ONLY
@pytest.mark.parametrize("service", tuple(six.SIX_NATIVE))
def test_real_incomplete_trust_process_aborts_without_binding(service, binaries, public_trust):
    with six.isolated_go_process(
        service, binaries[service], "incomplete", trust=public_trust
    ) as running:
        # No child should be listening: SDK Run rejects partial issuer/root/
        # redemption/service credential BEFORE HTTP listener startup.
        try:
            exit_code = running.process.wait(timeout=4)
        except Exception as exc:
            pytest.fail(
                f"{service} did not fail closed for incomplete authority: {type(exc).__name__}"
            )
        assert exit_code != 0, f"{service} started without complete native trust"
        with pytest.raises((URLError, OSError)):
            six.local_request(running.port, "/health")
