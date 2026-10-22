"""Eleven configured MCP identity qualification; safe by default.

Normal pytest runs use httpx.MockTransport and never bind or contact a live
listener. The final opt-in test is the ONLY path that contacts a configured
endpoint: one pinned localhost host-owned service, no bearer, no tool calls.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

import httpx
import pytest

from ai_osop.api.main import configured_mcp_server_specs
from ai_osop.api.mcp_fleet_readiness import _FLEET
from ai_osop.mcp.native_inert_process_fleet import SIX_SERVICES, _UNSAFE_PORTS
from ai_osop.mcp.protocol import MCPInitializeResponse


_EXACT_ELEVEN = frozenset(name for name, _ in _FLEET)
_NO_PAID_OR_AUTH = frozenset(
    {"recon-mcp", "payload-mcp", "nuclei-mcp", "threat-intel-mcp", "security-bridge"}
)
_OPT_IN = "OSOP_MCP_ELEVEN_CONFIGURED_IDENTITY_OBSERVE_20261022"
_NAME = "OSOP_MCP_ELEVEN_CONFIGURED_IDENTITY_SERVICE_20261022"
_PIN = "OSOP_MCP_ELEVEN_CONFIGURED_IDENTITY_SHA256_20261022"
_ALLOW_INITIALIZE = "OSOP_MCP_ELEVEN_CONFIGURED_IDENTITY_INITIALIZE_20261022"
_PROXY_HINTS = ("docker", "proxy", "wsl", "vpn", "tunnel", "portproxy")
_HEALTH_LIMIT = 4096
_INIT_LIMIT = 32768
_TIMEOUT = httpx.Timeout(1.5, connect=0.5, read=1.0, write=0.5, pool=0.5)


class IdentityRejected(ValueError):
    """Sanitized refusal, never includes private executable/config paths."""


@dataclass(frozen=True)
class OwnedListener:
    """OS observation and operator-pinned bytes, not signed process identity."""

    pid: int
    created_at: float
    sha256: str
    service_id: str
    port: int


def _specs(
    supplied: Sequence[tuple[str, str, int, Optional[str]]],
) -> dict[str, tuple[str, int, Optional[str]]]:
    if type(supplied) not in (list, tuple) or len(supplied) != 11:
        raise IdentityRejected("Expected exactly eleven configured services")
    rows: dict[str, tuple[str, int, Optional[str]]] = {}
    for record in supplied:
        if (
            type(record) is not tuple
            or len(record) != 4
            or type(record[0]) is not str
            or record[0] not in _EXACT_ELEVEN
            or record[0] in rows
            or type(record[1]) is not str
            or type(record[2]) is not int
            or not 1 <= record[2] <= 65535
            or (record[3] is not None and type(record[3]) is not str)
        ):
            raise IdentityRejected("Configured identity roster invalid")
        rows[record[0]] = (record[1], record[2], record[3])
    if set(rows) != _EXACT_ELEVEN:
        raise IdentityRejected("Configured identity roster incomplete")
    return rows


def _selected(
    supplied: Sequence[tuple[str, str, int, Optional[str]]],
    service_id: str,
) -> tuple[str, int]:
    rows = _specs(supplied)
    if type(service_id) is not str or service_id not in _NO_PAID_OR_AUTH:
        raise IdentityRejected("Service not admitted for read-only observation")
    host, port, bearer = rows[service_id]
    if host != "127.0.0.1" or bearer is not None:
        raise IdentityRejected("Exact numeric-loopback credential-free transport required")
    return host, port


def _unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate JSON member")
        output[key] = value
    return output


async def _bounded_json(response: httpx.Response, limit: int) -> dict[str, Any]:
    if not response.headers.get("content-type", "").lower().startswith("application/json"):
        raise IdentityRejected("Unrecognized local MCP response type")
    data = bytearray()
    async for chunk in response.aiter_bytes():
        if len(data) + len(chunk) > limit:
            raise IdentityRejected("Oversized local MCP response")
        data.extend(chunk)
    try:
        decoded = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_json,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
        )
    except (UnicodeError, ValueError) as exc:
        raise IdentityRejected("Invalid local MCP response JSON") from exc
    if type(decoded) is not dict:
        raise IdentityRejected("MCP response object required")
    return decoded


def _validate_initialize(data: dict[str, Any], expected: str) -> bool:
    if (
        data.get("server_id") != expected
        or data.get("status") != "ready"
        or type(data.get("tools")) is not list
        or not 1 <= len(data["tools"]) <= 128
        or type(data.get("capabilities")) is not list
        or any(
            type(tool) is not dict
            or tool.get("side_effect_class")
            not in {"READ_ONLY", "RECON_ACTIVE", "INVASIVE_EXPLOIT"}
            or type(tool.get("requires_approval")) is not bool
            or tool.get("scope_check") is not True
            or (
                tool.get("side_effect_class") != "READ_ONLY"
                and tool.get("requires_approval") is not True
            )
            or type(tool.get("parameters")) is not list
            or len(tool["parameters"]) > 32
            for tool in data["tools"]
        )
    ):
        return False
    try:
        parsed = MCPInitializeResponse(**data)
    except Exception:
        return False
    return (
        parsed.server_id == expected
        and parsed.status == "ready"
        and len({tool.name for tool in parsed.tools}) == len(parsed.tools)
    )


async def _observe_configured(
    supplied: Sequence[tuple[str, str, int, Optional[str]]],
    service_id: str,
    owner: OwnedListener,
    *,
    verify_owner: Callable[[], OwnedListener],
    allow_initialize: bool,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> dict[str, Any]:
    """Fixed GET /health; optional manually authorized inert initialize.

    The caller MUST supply independently reviewed executable SHA and a real
    matching local listener witness. No credentials, execute, ping, reconnect,
    cancellation, scan, provider API, target input, or redirects are sent.
    """
    host, port = _selected(supplied, service_id)
    if (
        type(owner) is not OwnedListener
        or type(owner.pid) is not int
        or owner.pid <= 0
        or type(owner.created_at) is not float
        or owner.created_at <= 0
        or type(owner.sha256) is not str
        or re.fullmatch("[0-9a-f]{64}", owner.sha256) is None
        or owner.service_id != service_id
        or owner.port != port
        or verify_owner() != owner
        or type(allow_initialize) is not bool
    ):
        raise IdentityRejected("Current pinned local process identity unavailable")

    result: dict[str, Any] = {
        "server_id": service_id,
        "configured_transport": "numeric_loopback_plain_http",
        "health_identity": "unavailable",
        "initialize": "not_attempted",
        "registered_in_app": None,
        "owned_inert_go_supervisor_pid_verified": False,
        "independent_process_witness_verified": False,
        "signed_0033_witness_verified": False,
        "signed_action_verified": False,
        "independent_target_effect_verified": False,
        "production_certified": False,
    }
    try:
        async with httpx.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=_TIMEOUT,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        ) as client:
            async with client.stream("GET", f"http://{host}:{port}/health") as response:
                if response.status_code not in (200, 503):
                    result["health_identity"] = "unavailable_http_status"
                    return result
                health = await _bounded_json(response, _HEALTH_LIMIT)
                if verify_owner() != owner:
                    raise IdentityRejected("Current owned listener changed during readback")
                if health.get("server_id") != service_id:
                    result["health_identity"] = (
                        "claimed_name_mismatch"
                        if "server_id" in health
                        else "service_identity_unattributed"
                    )
                    return result
                if response.status_code == 503:
                    result["health_identity"] = "matching_inert_or_unavailable_503"
                    return result
                if health.get("status") not in ("healthy", "ready"):
                    result["health_identity"] = "unrecognized_service_health"
                    return result
                result["health_identity"] = "matching_provider_claim_only"
            if not allow_initialize:
                return result
            if verify_owner() != owner:
                raise IdentityRejected("Current owned listener changed before initialize")
            # Only inert initialization metadata; never service auth/ROE/Task.
            async with client.stream(
                "POST",
                f"http://{host}:{port}/mcp/initialize",
                json={
                    "scope": {},
                    "auth_credentials": {},
                    "session_id": "qualification-inert-local-20261022",
                    "metadata": {},
                },
            ) as response:
                if response.status_code != 200:
                    result["initialize"] = "unavailable_http_status"
                    return result
                data = await _bounded_json(response, _INIT_LIMIT)
                if verify_owner() != owner:
                    raise IdentityRejected("Current owned listener changed after initialize")
                result["initialize"] = (
                    "matching_declared_schema_only"
                    if _validate_initialize(data, service_id)
                    else "identity_or_schema_mismatch"
                )
                return result
    except (httpx.RequestError, TimeoutError):
        result["health_identity"] = "unreachable_or_transport_unknown"
        result["initialize"] = "not_attempted"
        return result


def _real_listener_owner(service_id: str, port: int, expected_sha256: str) -> OwnedListener:
    """Read-only OS listener/executable identity; never starts or kills PIDs."""
    if (
        service_id not in _NO_PAID_OR_AUTH
        or type(port) is not int
        or not 1 <= port <= 65535
        or type(expected_sha256) is not str
        or re.fullmatch("[0-9a-f]{64}", expected_sha256) is None
    ):
        raise IdentityRejected("Operator-reviewed executable pin required")
    try:
        import psutil

        listening = [
            item
            for item in psutil.net_connections(kind="tcp")
            if item.status == psutil.CONN_LISTEN and item.laddr and item.laddr.port == port
        ]
        if (
            len(listening) != 1
            or listening[0].laddr.ip != "127.0.0.1"
            or type(listening[0].pid) is not int
            or listening[0].pid <= 0
        ):
            raise IdentityRejected("Local listener absent, shared or proxy-ambiguous")
        process = psutil.Process(listening[0].pid)
        name = process.name().lower()
        if any(hint in name for hint in _PROXY_HINTS):
            raise IdentityRejected("Local port is controlled by a proxy or broker")
        executable = Path(process.exe())
        if executable.is_symlink() or not executable.is_file():
            raise IdentityRejected("Pinned local executable unavailable")
        before_stat = executable.lstat()
        if (
            not stat.S_ISREG(before_stat.st_mode)
            or getattr(before_stat, "st_file_attributes", 0) & 0x400
            or not 1 <= before_stat.st_size <= 100_000_000
        ):
            raise IdentityRejected("Unsafe or oversized local executable")
        digest = hashlib.sha256()
        with executable.open("rb") as file:
            for part in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(part)
        if digest.hexdigest() != expected_sha256:
            raise IdentityRejected("Local executable differs from operator pin")
        after_stat = executable.lstat()
        if (
            before_stat.st_dev,
            before_stat.st_ino,
            before_stat.st_size,
            before_stat.st_mtime_ns,
        ) != (after_stat.st_dev, after_stat.st_ino, after_stat.st_size, after_stat.st_mtime_ns):
            raise IdentityRejected("Local executable changed during identity readback")
        created_at = float(process.create_time())
        return OwnedListener(
            pid=process.pid,
            created_at=created_at,
            sha256=digest.hexdigest(),
            service_id=service_id,
            port=port,
        )
    except IdentityRejected:
        raise
    except Exception as exc:
        raise IdentityRejected("Local listener ownership observation unavailable") from exc


def _synthetic_specs(
    service_id: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8086,
    token: Optional[str] = None,
) -> list[tuple[str, str, int, Optional[str]]]:
    return [
        (
            name,
            host if name == service_id else "127.0.0.1",
            port if name == service_id else 65000 + idx,
            token if name == service_id else None,
        )
        for idx, (name, _) in enumerate(_FLEET)
    ]


def _owned(service_id: str, port: int) -> OwnedListener:
    return OwnedListener(
        pid=49111,
        created_at=100.0,
        sha256="a" * 64,
        service_id=service_id,
        port=port,
    )


def _declaration(name: str) -> dict[str, Any]:
    return {
        "server_id": name,
        "status": "ready",
        "version": "fixture-inert",
        "capabilities": ["mcp_bound_receipts_v1"],
        "tools": [
            {
                "name": "authority_status",
                "description": "Inert only",
                "parameters": [],
                "returns": {"type": "object"},
                "side_effect_class": "READ_ONLY",
                "requires_approval": False,
                "scope_check": True,
            }
        ],
    }


def test_original_configured_eleven_and_go_distinct_process_ports() -> None:
    actual = _specs(configured_mcp_server_specs())
    assert set(actual) == _EXACT_ELEVEN
    assert len(_EXACT_ELEVEN) == 11
    assert len(SIX_SERVICES) == 6
    assert set(SIX_SERVICES) <= _EXACT_ELEVEN
    assert {name for name, role in _FLEET if role == "critical"} == {
        "browser-mcp",
        "source-map-mcp",
        "cloud-mcp",
        "turbo-intruder-mcp",
        "nuclei-mcp",
    }
    assert set(_UNSAFE_PORTS) >= {8081, 8082, 8083, 8084, 8085, 8086, 8087, 8091, 8096, 8097, 8098}
    assert not (_NO_PAID_OR_AUTH - set(SIX_SERVICES))
    assert actual["threat-intel-mcp"][1] >= 1


@pytest.mark.parametrize(
    "bad",
    [
        [],
        _synthetic_specs("threat-intel-mcp")[:-1],
        _synthetic_specs("threat-intel-mcp")[:-1] + [_synthetic_specs("threat-intel-mcp")[0]],
    ],
)
def test_invalid_roster_never_authorizes_http(bad: Any) -> None:
    with pytest.raises(IdentityRejected):
        _selected(bad, "threat-intel-mcp")


@pytest.mark.parametrize(
    "host,token,name",
    [
        ("localhost", None, "threat-intel-mcp"),
        ("127.0.0.2", None, "threat-intel-mcp"),
        ("::1", None, "threat-intel-mcp"),
        ("remote.invalid", None, "threat-intel-mcp"),
        ("127.0.0.1", "secret-never-sent", "threat-intel-mcp"),
        ("127.0.0.1", None, "shodan-mcp"),
        ("127.0.0.1", None, "browser-mcp"),
    ],
)
def test_refuse_unpinned_or_paid_or_credentialed_network(
    host: str, token: Optional[str], name: str
) -> None:
    with pytest.raises(IdentityRejected):
        _selected(_synthetic_specs(name, host=host, token=token), name)


@pytest.mark.asyncio
async def test_mocked_local_http_matching_health_and_inert_initialize_only() -> None:
    name = "threat-intel-mcp"
    witnessed = _owned(name, 8086)
    seen: list[tuple[str, str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, dict(request.headers)))
        assert request.url.host == "127.0.0.1" and request.url.port == 8086
        assert "authorization" not in request.headers
        assert "proxy-authorization" not in request.headers
        if request.method == "GET":
            return httpx.Response(200, json={"server_id": name, "status": "healthy"})
        assert request.method == "POST"
        assert json.loads(request.content) == {
            "scope": {},
            "auth_credentials": {},
            "session_id": "qualification-inert-local-20261022",
            "metadata": {},
        }
        return httpx.Response(200, json=_declaration(name))

    response = await _observe_configured(
        _synthetic_specs(name),
        name,
        witnessed,
        verify_owner=lambda: witnessed,
        allow_initialize=True,
        transport=httpx.MockTransport(handler),
    )
    assert [(method, path) for method, path, _ in seen] == [
        ("GET", "/health"),
        ("POST", "/mcp/initialize"),
    ]
    assert response["health_identity"] == "matching_provider_claim_only"
    assert response["initialize"] == "matching_declared_schema_only"
    assert response["independent_process_witness_verified"] is False
    assert response["signed_0033_witness_verified"] is False
    assert response["independent_target_effect_verified"] is False
    assert response["production_certified"] is False
    assert "49111" not in repr(response)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,health,expected",
    [
        (200, {"server_id": "wrong-mcp", "status": "healthy"}, "claimed_name_mismatch"),
        (200, {"status": "healthy"}, "service_identity_unattributed"),
        (
            503,
            {"server_id": "threat-intel-mcp", "status": "unavailable"},
            "matching_inert_or_unavailable_503",
        ),
        (302, {"server_id": "threat-intel-mcp", "status": "healthy"}, "unavailable_http_status"),
    ],
)
async def test_health_identity_and_docker_proxy_ambiguity_cannot_initialize(
    status: int,
    health: dict[str, Any],
    expected: str,
) -> None:
    name = "threat-intel-mcp"
    witness = _owned(name, 8086)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(status, json=health)

    response = await _observe_configured(
        _synthetic_specs(name),
        name,
        witness,
        verify_owner=lambda: witness,
        allow_initialize=True,
        transport=httpx.MockTransport(handler),
    )
    assert calls == ["/health"]
    assert response["health_identity"] == expected
    assert response["initialize"] == "not_attempted"


@pytest.mark.asyncio
async def test_unreachable_or_oversized_or_duplicate_http_are_never_trusted() -> None:
    name = "threat-intel-mcp"
    witness = _owned(name, 8086)

    def unreachable(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("a fake closed localhost port")

    outcome = await _observe_configured(
        _synthetic_specs(name),
        name,
        witness,
        verify_owner=lambda: witness,
        allow_initialize=True,
        transport=httpx.MockTransport(unreachable),
    )
    assert outcome["health_identity"] == "unreachable_or_transport_unknown"
    assert outcome["initialize"] == "not_attempted"

    for body in (
        b'{"status":"ready","server_id":"threat-intel-mcp","server_id":"different"}',
        b"X" * (_HEALTH_LIMIT + 1),
    ):
        calls: list[str] = []

        def bad_response(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            return httpx.Response(200, content=body, headers={"content-type": "application/json"})

        with pytest.raises(IdentityRejected):
            await _observe_configured(
                _synthetic_specs(name),
                name,
                witness,
                verify_owner=lambda: witness,
                allow_initialize=True,
                transport=httpx.MockTransport(bad_response),
            )
        assert calls == ["/health"]


@pytest.mark.asyncio
async def test_initialize_wrong_name_bad_risk_flags_and_owner_change_deny_verification() -> None:
    name = "threat-intel-mcp"
    witness = _owned(name, 8086)
    for invalid in (
        {**_declaration(name), "server_id": "recon-mcp"},
        {**_declaration(name), "tools": [{**_declaration(name)["tools"][0], "scope_check": False}]},
        {
            **_declaration(name),
            "tools": [
                {
                    **_declaration(name)["tools"][0],
                    "requires_approval": False,
                    "side_effect_class": "INVASIVE_EXPLOIT",
                }
            ],
        },
    ):

        def handler(request: httpx.Request) -> httpx.Response:
            return (
                httpx.Response(200, json={"server_id": name, "status": "healthy"})
                if request.method == "GET"
                else httpx.Response(200, json=invalid)
            )

        result = await _observe_configured(
            _synthetic_specs(name),
            name,
            witness,
            verify_owner=lambda: witness,
            allow_initialize=True,
            transport=httpx.MockTransport(handler),
        )
        assert result["initialize"] == "identity_or_schema_mismatch"

    counter = 0

    def changing_owner() -> OwnedListener:
        nonlocal counter
        counter += 1
        return witness if counter <= 2 else _owned(name, 8085)

    with pytest.raises(IdentityRejected):
        await _observe_configured(
            _synthetic_specs(name),
            name,
            witness,
            verify_owner=changing_owner,
            allow_initialize=True,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, json={"server_id": name, "status": "healthy"})
            ),
        )


def test_forged_local_owner_and_known_docker_proxy_refused_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Synthetic psutil metadata only; never query real ports in unit tests."""
    import sys
    from types import SimpleNamespace

    fake_module = SimpleNamespace(
        CONN_LISTEN="LISTEN",
        net_connections=lambda kind: [
            SimpleNamespace(
                status="LISTEN", laddr=SimpleNamespace(ip="127.0.0.1", port=8086), pid=35352
            )
        ],
        Process=lambda _pid: SimpleNamespace(name=lambda: "com.docker.backend.exe"),
    )
    monkeypatch.setitem(sys.modules, "psutil", fake_module)
    with pytest.raises(IdentityRejected, match="proxy or broker"):
        _real_listener_owner("threat-intel-mcp", 8086, "a" * 64)


def test_os_listener_requires_unique_exact_loopback_and_reviewed_binary_pin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sys
    from types import SimpleNamespace

    executable = tmp_path / "benign-test-native.exe"
    executable.write_bytes(b"NON-EXECUTED LOCAL TEST BYTES")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    listener = SimpleNamespace(
        status="LISTEN", laddr=SimpleNamespace(ip="127.0.0.1", port=8086), pid=55555
    )
    connection_rows = [listener]
    process = SimpleNamespace(
        name=lambda: "benign-test-native.exe",
        exe=lambda: str(executable),
        pid=55555,
        create_time=lambda: 234.0,
    )
    fake_psutil = SimpleNamespace(
        CONN_LISTEN="LISTEN",
        net_connections=lambda kind: connection_rows,
        Process=lambda pid: process,
    )
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)
    proof = _real_listener_owner("threat-intel-mcp", 8086, digest)
    assert proof == OwnedListener(
        pid=55555,
        created_at=234.0,
        sha256=digest,
        service_id="threat-intel-mcp",
        port=8086,
    )
    with pytest.raises(IdentityRejected, match="executable differs"):
        _real_listener_owner("threat-intel-mcp", 8086, "b" * 64)
    connection_rows.append(
        SimpleNamespace(status="LISTEN", laddr=SimpleNamespace(ip="0.0.0.0", port=8086), pid=55555)
    )
    with pytest.raises(IdentityRejected, match="listener absent, shared or proxy"):
        _real_listener_owner("threat-intel-mcp", 8086, digest)
    connection_rows[:] = [
        SimpleNamespace(status="LISTEN", laddr=SimpleNamespace(ip="0.0.0.0", port=8086), pid=55555)
    ]
    with pytest.raises(IdentityRejected, match="listener absent, shared or proxy"):
        _real_listener_owner("threat-intel-mcp", 8086, digest)


@pytest.mark.asyncio
async def test_opt_in_real_configured_loopback_observation_only() -> None:
    """Never open ANY real socket without explicit independent operator pins."""
    if os.getenv(_OPT_IN) != "1":
        pytest.skip("Live configured listener observation requires explicit opt-in")
    name = os.getenv(_NAME, "")
    pin = os.getenv(_PIN, "")
    if name not in _NO_PAID_OR_AUTH or re.fullmatch("[0-9a-f]{64}", pin) is None:
        pytest.skip("No independently reviewed selected local executable identity pin")
    specs = configured_mcp_server_specs()
    _, port = _selected(specs, name)
    first = _real_listener_owner(name, port, pin)
    observed = await _observe_configured(
        specs,
        name,
        first,
        verify_owner=lambda: _real_listener_owner(name, port, pin),
        allow_initialize=(os.getenv(_ALLOW_INITIALIZE) == "1"),
    )
    # GET /health is descriptive only. A proxy, unavailable service or
    # mismatch remains a visible failed qualification, not success.
    assert observed["health_identity"] in {
        "matching_provider_claim_only",
        "matching_inert_or_unavailable_503",
    }, observed["health_identity"]
    assert observed["signed_0033_witness_verified"] is False
    assert observed["independent_target_effect_verified"] is False
    assert observed["production_certified"] is False
