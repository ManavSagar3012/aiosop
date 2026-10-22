"""Opt-in actual six native Go CMD processes: inert, local and short-lived.

No native signer, original Action, credential, target or scanner is provisioned.
Only the test's own rebuilt binaries and OS-selected 127.0.0.1 ports are used.

Invoke with OSOP_NATIVE_GO_SIX_REAL_PROCESS_20261021=1 and offline Go installed.
Absent opt-in, this file proves source contracts only and SKIPS process claims.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterator

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "mcp-servers" / "go"
OPT_IN = "OSOP_NATIVE_GO_SIX_REAL_PROCESS_20261021"
SIX = (
    ("recon-mcp", 8082, "OSOP_RECON_MCP_LOCAL_PORT"),
    ("payload-mcp", 8083, "OSOP_NATIVE_MCP_LOCAL_PORT"),
    ("nuclei-mcp", 8084, "OSOP_NATIVE_MCP_LOCAL_PORT"),
    ("shodan-mcp", 8085, "OSOP_NATIVE_MCP_LOCAL_PORT"),
    ("threat-intel-mcp", 8086, "OSOP_NATIVE_MCP_LOCAL_PORT"),
    ("security-bridge", 8087, "OSOP_NATIVE_MCP_LOCAL_PORT"),
)
SIX_IDS = tuple(x[0] for x in SIX)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _isolated_environment(*, server_id: str = "", port: int | None = None) -> dict[str, str]:
    """No project provider, token, trust root, URL or proxy reaches a child."""
    # A minimal Windows process environment still needs SystemRoot/COMSPEC;
    # Go build may need the current nonsecret GOPATH/GOCACHE.
    whitelist = {
        "SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "COMSPEC", "TEMP", "TMP",
        "TMPDIR", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "GOPATH",
        "GOCACHE", "GOENV", "HOMEDRIVE", "HOMEPATH", "USER", "USERNAME",
    }
    cleaned = {k: v for k, v in os.environ.items() if k.upper() in whitelist}
    cleaned.update({
        "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local",
        "GOWORK": "off", "GOFLAGS": "-buildvcs=false",
    })
    assert not any(k.startswith("OSOP_") for k in cleaned)
    assert not any("PROXY" in k.upper() and k.upper() != "GOPROXY" for k in cleaned)
    if port is not None:
        assert server_id in SIX_IDS and 1024 <= port <= 65535
        name = next(var for name, _, var in SIX if name == server_id)
        cleaned[name] = str(port)
    return cleaned


def _check_go_prerequisites() -> str:
    go = shutil.which("go")
    if not go:
        pytest.skip("SOURCE ONLY / BLOCKED: local Go compiler unavailable")
    result = subprocess.run(
        [go, "version"], cwd=MODULE, env=_isolated_environment(),
        text=True, capture_output=True, timeout=15, check=False,
    )
    if result.returncode != 0 or not re.search(r"go1\.(?:2[2-9]|[3-9]\d)", result.stdout):
        pytest.skip("SOURCE ONLY / BLOCKED: compatible offline local Go 1.22+ unavailable")
    return go


def _host_psutil():
    try:
        import psutil
    except ImportError:
        pytest.skip("SOURCE ONLY / BLOCKED: psutil unavailable for PID ownership proof")
    return psutil


@pytest.fixture(scope="session")
def rebuilt_binaries() -> Iterator[dict[str, Path]]:
    if os.getenv(OPT_IN) != "1":
        pytest.skip(f"SOURCE ONLY: set {OPT_IN}=1 to compile and run real six Go processes")
    go = _check_go_prerequisites()
    _host_psutil()
    # Tempdir outside the dirty project and clean at the end of the session;
    # ignore pre-existing repository .exe files (which may be stale).
    with tempfile.TemporaryDirectory(prefix="aiosop-real-six-inert-go-") as folder:
        output = Path(folder).resolve(strict=True)
        assert not output.is_relative_to(ROOT.resolve())
        binaries: dict[str, Path] = {}
        for server_id in SIX_IDS:
            binary = output / (server_id + (".exe" if sys.platform == "win32" else ""))
            command = [go, "build", "-buildvcs=false", "-trimpath", "-o",
                       str(binary), "./cmd/" + server_id]
            try:
                result = subprocess.run(
                    command, cwd=MODULE, env=_isolated_environment(),
                    text=True, capture_output=True, timeout=110, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                pytest.fail(f"OFFLINE BUILD BLOCKED for {server_id}: {type(exc).__name__}")
            if result.returncode != 0:
                pytest.fail(
                    f"OFFLINE BUILD BLOCKED for {server_id}: "
                    f"exit {result.returncode} / {result.stderr[-850:]}"
                )
            assert binary.is_file() and binary.stat().st_size > 0
            binaries[server_id] = binary
        yield binaries


def _owned_port() -> int:
    # Reserve a genuinely ephemeral, test-owned *IPv4 loopback* port, then
    # release it for the Go child. Never use any production fixed port.
    for _ in range(8):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            if 1024 <= port <= 65535 and port not in {item[1] for item in SIX}:
                return port
    pytest.fail("Cannot reserve an owned nondefault IPv4 loopback test port")


def _spawn(binary: Path, name: str, port: int) -> subprocess.Popen[str]:
    assert binary.is_file() and binary.parent.name.startswith("aiosop-real-six-inert-go-")
    return subprocess.Popen(
        [str(binary)], cwd=binary.parent,
        env=_isolated_environment(server_id=name, port=port),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
    )


def _stop_owned(proc: subprocess.Popen[str], port: int) -> str:
    assert proc.pid > 0
    if proc.poll() is None:
        proc.terminate()
    try:
        _, log = proc.communicate(timeout=6)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, log = proc.communicate(timeout=6)
        pytest.fail(f"Owned Go PID {proc.pid} failed graceful bounded termination")
    assert proc.poll() is not None
    psutil = _host_psutil()
    assert not psutil.pid_exists(proc.pid), f"Owned Go process survived: {proc.pid}"
    # A released ephemeral port is not the same as a global no-listener proof,
    # but if another process binds this port we must not mistake it for ours.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.25)
        assert connection.connect_ex(("127.0.0.1", port)) != 0
    return log


@contextlib.contextmanager
def _owned_process(binary: Path, name: str, port: int) -> Iterator[subprocess.Popen[str]]:
    proc = _spawn(binary, name, port)
    try:
        yield proc
    finally:
        log = _stop_owned(proc, port)
        # A genuine listener should describe itself as metadata-only. Log
        # inspection alone is never treated as a service readiness proof.
        if "metadata-only MCP listener" in log:
            assert f"{name} metadata-only MCP listener on 127.0.0.1:{port}" in log


def _assert_owned_running_pid(proc: subprocess.Popen[str], binary: Path):
    psutil = _host_psutil()
    observed = psutil.Process(proc.pid)
    assert observed.ppid() == os.getpid()
    assert observed.is_running() and proc.poll() is None
    assert Path(observed.exe()).resolve().samefile(binary.resolve())
    assert observed.username().casefold() == psutil.Process(os.getpid()).username().casefold()
    # Windows can attach a system-owned conhost.exe console helper even with
    # CREATE_NO_WINDOW. Reject *other* subprocesses (including a scanner),
    # but do not mislabel a console host as child target execution.
    children = observed.children(recursive=True)
    assert all(sys.platform == "win32" and child.name().casefold() == "conhost.exe"
               for child in children), "Native subprocess unexpectedly launched non-console child"
    return observed.create_time()


def _assert_loopback_listener_owned_by_pid(proc: subprocess.Popen[str], port: int) -> None:
    """Attribute the actual LISTEN socket to this binary, not a lookalike."""
    psutil = _host_psutil()
    owner = psutil.Process(proc.pid)
    sockets = owner.connections(kind="tcp")
    matching = [conn for conn in sockets
                if conn.status == psutil.CONN_LISTEN
                and conn.laddr.ip == "127.0.0.1" and conn.laddr.port == port]
    assert len(matching) == 1, (
        f"PID {proc.pid} is not the owner of its claimed 127.0.0.1:{port} socket"
    )


def _http(port: int, path: str, *, payload: object | None = None,
          method: str = "GET", raw: bytes | None = None,
          content_type: str = "application/json") -> tuple[int, dict]:
    assert path.startswith("/") and "?" not in path
    url = f"http://127.0.0.1:{port}{path}"
    body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
    request = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        request.add_header("Content-Type", content_type)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=1.5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        assert response.headers.get("Content-Type", "").startswith("application/json") or response.status == 404
        data = response.read(64 * 1024)
        assert len(data) < 64 * 1024
        # The Go net/http 404 for non-existent cancel/status endpoints is
        # deliberately plain text, NOT an MCP confirmation envelope.
        decoded = json.loads(data) if data and response.status != 404 else {}
        assert type(decoded) is dict
        return response.status, decoded


def _await_listener(proc: subprocess.Popen[str], port: int) -> None:
    end = time.monotonic() + 5.0
    while time.monotonic() < end:
        if proc.poll() is not None:
            pytest.fail(f"Go child exited before binding owned loopback port: PID={proc.pid}")
        try:
            status, data = _http(port, "/health")
        except (OSError, ValueError, TimeoutError):
            time.sleep(0.05)
            continue
        assert status == 503
        assert data.get("status") == "unavailable"
        return
    pytest.fail(f"Go child failed bounded startup on owned loopback port: PID={proc.pid}")


def test_six_entrypoints_and_sdk_have_only_inert_unenrolled_bootstrap() -> None:
    server = _text(MODULE / "sdk/server.go")
    ports = _text(MODULE / "sdk/local_port.go")
    recon_port = _text(MODULE / "cmd/recon-mcp/web_search.go")
    assert 'mux.HandleFunc("/health"' in server
    assert 'mux.HandleFunc("/mcp/initialize"' in server
    assert 'mux.HandleFunc("/mcp/execute"' in server
    assert 'mux.HandleFunc("/mcp/cancel"' not in server
    assert 'mux.HandleFunc("/mcp/request/status"' not in server
    assert "item.Handler = nil" in server
    assert "s.verifyAndRedeemAuthorityStatus(" in server
    assert "return []Tool{authorityStatusTool()}" in server
    assert '"execution_enabled": false' in server
    assert '"native_execution_not_authorized"' in server
    assert 'NativeMCPLocalPortEnv = "OSOP_NATIVE_MCP_LOCAL_PORT"' in ports
    assert 'os.Getenv("OSOP_RECON_MCP_LOCAL_PORT")' in recon_port
    assert 'return "127.0.0.1:0"' in recon_port  # invalid port => SDK fails
    for name, default_port, env in SIX:
        main = _text(MODULE / "cmd" / name / "main.go")
        assert f'sdk.NewServer("{name}")' in main
        assert "server.Run(" in main
        assert "/mcp/execute" not in main
        if name == "recon-mcp":
            assert "reconListenAddress()" in main
        else:
            assert f"sdk.LocalPortAddress({default_port})" in main
            assert env == "OSOP_NATIVE_MCP_LOCAL_PORT"


@pytest.mark.parametrize("name,default,port_env", SIX, ids=SIX_IDS)
def test_real_owned_go_process_http_denied_without_grant(
    rebuilt_binaries: dict[str, Path], name: str, default: int, port_env: str,
) -> None:
    port = _owned_port()
    assert port != default
    binary = rebuilt_binaries[name]
    with _owned_process(binary, name, port) as proc:
        _await_listener(proc, port)
        initial_start = _assert_owned_running_pid(proc, binary)
        _assert_loopback_listener_owned_by_pid(proc, port)

        status, body = _http(port, "/health")
        assert status == 503
        assert body == {
            "status": "unavailable", "server_id": name,
            "execution_enabled": False, "authority_verified": False,
            "reason": "source_side_signed_authority_unavailable",
        }

        # Real Go parser accepts *typed* initialize, but unavailable is not
        # READY, and catalog metadata never establishes signed authority.
        init = {"scope": {}, "auth_credentials": {}, "session_id": "local-inert-test",
                "metadata": {"fixture": "no_authority"}}
        status, body = _http(port, "/mcp/initialize", method="POST", payload=init)
        assert status == 200 and body["server_id"] == name
        assert body["status"] == "unavailable" and body["execution_enabled"] is False
        assert body["authority_verified"] is False and body["capabilities"] == []
        assert all(t["scope_check"] is True and t["requires_approval"] is True
                   for t in body["tools"])
        assert all(t["side_effect_class"] in {
            "READ_ONLY", "RECON_ACTIVE", "INVASIVE_EXPLOIT"
        } for t in body["tools"])
        assert not any(t.get("name") == "authority_status" for t in body["tools"])

        # Duplicate JSON, oversized init, wrong method and invalid shape
        # fail before any tool, source or worker invocation.
        for raw in (
            b'{"scope":{},"scope":{},"auth_credentials":{},"session_id":"test"}',
            b'{"scope":{},"auth_credentials":{},"session_id":[]}',
            b"{" + b" " * 8300 + b"}",
        ):
            status, denied = _http(port, "/mcp/initialize", method="POST", raw=raw)
            assert status == 400 and denied.get("error") == "invalid_initialize_metadata"
        status, denied = _http(port, "/mcp/initialize", method="GET")
        assert status == 405 and denied.get("error") == "method_not_allowed"

        # No signed original native grant, independently enrolled roots or
        # redeem service: even SDK's BUILTIN inert authority_status is denied.
        for request_id in ("req-inert-test-only", "req-inert-test-only"):
            try:
                status, denied = _http(port, "/mcp/execute", method="POST", payload={
                    "tool_name": "authority_status", "parameters": {},
                    "request_id": request_id,
                })
            except ConnectionResetError:
                # Unenrolled SDK refuses before parsing/exhausting the POST
                # entity. Go net/http can RST an unread entity on Windows.
                # This is an UNKNOWN transport observation, never an ACK;
                # do NOT retry the original one-use request with a grant.
                assert proc.poll() is None
                continue
            assert status == 503
            assert denied["error"] == "native_execution_not_authorized"
            assert denied["execution_enabled"] is False
            assert "result" not in denied and "request_id" not in denied
        # Empty POST has no unread entity. This proves actual denial on the
        # same process without retrying the original request ID or presenting
        # a credential, root, native Action or target argument.
        status, denied = _http(port, "/mcp/execute", method="POST", raw=b"")
        assert status == 503
        assert denied["error"] == "native_execution_not_authorized"
        assert denied["execution_enabled"] is False
        assert "result" not in denied
        # No cancel/readback route on actual six native Go SDK processes; a
        # 404 is NOT physical cancellation or an independently signed STATUS.
        # Avoid a request body: on Windows Go net/http can reset an unmatched
        # POST whose request body was never drained by ServeMux.
        for endpoint in ("/mcp/cancel", "/mcp/request/status"):
            status, denied = _http(port, endpoint, method="POST")
            assert status == 404 and not denied
        assert _assert_owned_running_pid(proc, binary) == initial_start


@pytest.mark.parametrize("name,default,port_env", SIX, ids=SIX_IDS)
def test_real_go_rejects_invalid_port_without_default_fallback(
    rebuilt_binaries: dict[str, Path], name: str, default: int, port_env: str,
) -> None:
    # This launch has no valid TCP port at all. The process must fail CLOSED,
    # rather than fall back to any of 8082..8087 or listen on port zero.
    binary = rebuilt_binaries[name]
    environment = _isolated_environment(server_id=name, port=54321)
    environment[port_env] = "0"
    try:
        result = subprocess.run(
            [str(binary)], cwd=binary.parent, env=environment,
            stdin=subprocess.DEVNULL, text=True, capture_output=True,
            timeout=4, check=False,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{name}: invalid port was accepted; Go listener failed to exit")
    assert result.returncode != 0
    assert "port" in result.stderr.lower() or "loopback" in result.stderr.lower()
    assert "metadata-only MCP listener" not in result.stderr


@pytest.mark.parametrize("name,default,port_env", SIX, ids=SIX_IDS)
def test_real_go_early_cancel_terminates_owned_child_before_readiness_claim(
    rebuilt_binaries: dict[str, Path], name: str, default: int, port_env: str,
) -> None:
    port = _owned_port()
    proc = _spawn(rebuilt_binaries[name], name, port)
    # Stop immediately. A process that might not yet have bound is NOT
    # considered READY or an executed Action. No HTTP attempts occur here.
    _stop_owned(proc, port)

