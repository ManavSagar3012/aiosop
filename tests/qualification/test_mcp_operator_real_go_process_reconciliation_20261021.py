"""Operator eleven-roster ↔ six REAL Go PID reconciliation; opt-in only.

No app DB, external provider, target, scanner, Docker, network except test-owned
numeric-loopback Go processes. Existing executable blobs are NOT assumed to
match current dirty source: opt-in uses a fresh offline cached-module build.
The original MCPRegistry + operator diagnostic, not a fake registry, are used.

Set OSOP_MCP_OPERATOR_REAL_GO_JOIN_20261021=1 to permit exactly six
short-lived process launches (and one extra inert signer-negative process).
Without that explicit opt-in, every process assertion SKIPS honestly.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import platform
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterator

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.qualification import mcp_eleven_inert_diagnostic_20261021 as diagnostic
from tests.qualification import native_six_go_process_helper_20261020 as native


ROOT = Path(__file__).resolve().parents[2]
GO_ROOT = ROOT / "mcp-servers" / "go"
OPT_IN = "OSOP_MCP_OPERATOR_REAL_GO_JOIN_20261021"
SIX = tuple(native.SIX_NATIVE)
FIVE = tuple(name for name in diagnostic.SERVICE_IDS if name not in SIX)
_BOOTSTRAP = {
    "scope": {}, "auth_credentials": {},
    "session_id": "six-real-operator-reconcile",
    "metadata": {},
}


def _go_build_environment() -> dict[str, str]:
    """Local Go cache only; no package download, VCS or inherited credentials."""
    env = native.clean_child_environment()
    env.update({
        "GOENV": "off", "GOPROXY": "off", "GOSUMDB": "off",
        "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-buildvcs=false",
        "GOOS": "windows", "GOARCH": "amd64", "CGO_ENABLED": "0",
    })
    assert not any(k.upper().startswith("OSOP_") for k in env)
    assert not any("PROXY" in k.upper() and k.upper() != "GOPROXY" for k in env)
    return env


@pytest.fixture(scope="module")
def binaries() -> Iterator[dict[str, Path]]:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"NO GO PROCESSES: explicit operator opt-in {OPT_IN}=1 absent")
    if platform.system() != "Windows" or os.name != "nt":
        pytest.skip("NO GO PROCESSES: current source runtime uses Windows Go children")
    go = shutil.which("go")
    if not go:
        pytest.skip("NO GO PROCESSES: offline Go toolchain missing")
    try:
        import psutil  # noqa: F401 - strict OS-owned PID/socket proof
    except ImportError:
        pytest.skip("NO GO PROCESSES: psutil missing for PID and socket ownership")
    env = _go_build_environment()
    try:
        version = subprocess.run([go, "version"], cwd=GO_ROOT, env=env,
                                 capture_output=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("NO GO PROCESSES: offline local Go toolchain unavailable")
    if version.returncode != 0 or b"windows/amd64" not in version.stdout:
        pytest.skip("NO GO PROCESSES: compatible local Windows Go toolchain missing")

    with tempfile.TemporaryDirectory(prefix="aiosop-operator-six-go-owned-") as raw:
        out = Path(raw).resolve()
        assert not out.is_relative_to(ROOT.resolve())
        built: dict[str, Path] = {}
        for name in SIX:
            exe = out / (name + ".exe")
            try:
                result = subprocess.run(
                    [go, "build", "-buildvcs=false", "-trimpath", "-o",
                     str(exe), "./cmd/" + name],
                    cwd=GO_ROOT, env=env, stdin=subprocess.DEVNULL,
                    capture_output=True, timeout=105, check=False,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                pytest.skip(f"NO GO PROCESSES: offline build unavailable ({type(exc).__name__})")
            if result.returncode != 0:
                log = result.stderr.lower()
                if any(word in log for word in (
                    b"module lookup disabled", b"goproxy=off", b"toolchain not available",
                    b"cannot find module", b"not in goroot",
                )):
                    pytest.skip("NO GO PROCESSES: needed Go module not offline-cached")
                pytest.fail(f"Current {name} Go source did not build offline (exit {result.returncode})")
            assert exe.is_file() and exe.stat().st_size > 100_000
            with exe.open("rb") as fd:
                assert fd.read(2) == b"MZ"
            built[name] = exe
        yield built


def _owned_port(occupied: set[int]) -> int:
    for _ in range(32):
        port = native.choose_owned_port()
        if (port not in occupied and port not in diagnostic._FORBIDDEN_PORTS
                and port not in {entry[0] for entry in native.SIX_NATIVE.values()}):
            occupied.add(port)
            return port
    raise AssertionError("No distinct test-only ephemeral loopback port")


@contextlib.contextmanager
def _child(name: str, exe: Path, port: int, *, trust: tuple[str, str] | None = None
           ) -> Iterator[subprocess.Popen[bytes]]:
    if name not in SIX or not exe.is_file() or exe.name != name + ".exe":
        raise AssertionError("Unowned Go binary was selected")
    env = native.native_environment(name, port, "configured" if trust else "unconfigured",
                                    trust=trust)
    assert set(k for k in env if k.startswith("OSOP_")) <= {
        "OSOP_RECON_MCP_LOCAL_PORT", "OSOP_NATIVE_MCP_LOCAL_PORT",
        "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON", "OSOP_NATIVE_MCP_REDEEM_URL",
        "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM", "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
    }
    with tempfile.TemporaryFile("w+b") as stderr:
        proc = subprocess.Popen([str(exe)], cwd=GO_ROOT, env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=4)
                pytest.fail("Owned Go child failed bounded graceful shutdown")
            assert proc.poll() is not None
            import psutil
            assert not psutil.pid_exists(proc.pid), "Owned child survived cleanup"
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.2)
                assert probe.connect_ex(("127.0.0.1", port)) != 0


def _ready_pid(name: str, exe: Path, port: int, proc: subprocess.Popen[bytes],
               *, status: int) -> float:
    """A process-owned listener is evidence only of a process, not MCP READY."""
    import psutil

    stop = time.monotonic() + 4
    while time.monotonic() < stop:
        assert proc.poll() is None, "Owned Go process exited before bounded startup"
        try:
            owner = psutil.Process(proc.pid)
            linked = [s for s in owner.net_connections(kind="tcp")
                      if s.status == psutil.CONN_LISTEN and s.laddr.ip == "127.0.0.1"
                      and s.laddr.port == port]
            if linked:
                code, response = native.local_request(port, "/health")
                assert code == status and response["server_id"] == name
                assert response["authority_verified"] is False
                assert response["execution_enabled"] is False
                assert owner.ppid() == os.getpid()
                assert Path(owner.exe()).resolve().samefile(exe.resolve())
                assert owner.username().casefold() == psutil.Process(os.getpid()).username().casefold()
                assert all(child.name().casefold() == "conhost.exe"
                           for child in owner.children(recursive=True))
                return owner.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
            pass
        time.sleep(0.05)
    pytest.fail("No test-owned Go PID/listener/health evidence before deadline")


def _local_forged_grant(port: int, request_id: str, token: str) -> str:
    """One self-contained negative POST. RST is UNKNOWN; never retried."""
    assert request_id.startswith("req-") and len(token) < 4000
    data = json.dumps({"tool_name": "authority_status", "parameters": {},
                       "request_id": request_id}, separators=(",", ":")).encode("ascii")
    url = f"http://127.0.0.1:{port}/mcp/execute"
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "X-OSOP-Native-Grant": token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        try:
            response = opener.open(req, timeout=1.5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read(2049)
            assert len(data) <= 2048
            assert response.status == 503
            body = json.loads(data)
            assert body == {"status": "error", "error": "native_execution_not_authorized",
                            "execution_enabled": False}
            return "denied_503"
    except (ConnectionResetError, ConnectionAbortedError, TimeoutError,
            urllib.error.URLError, BrokenPipeError):
        # Windows Go may reject an unread body by resetting its connection.
        # Never count this as an ACK, grant redemption, success, or cancellation.
        return "unknown_transport"


def _wrong_signer_grant(name: str, *, request_id: str, expired: bool = False) -> str:
    now = int(time.time())
    issued = now - 80 if expired else now
    claims: dict[str, Any] = {
        "version": 1, "grant_id": "ngr-" + "a" * 32,
        "request_id": request_id, "engagement_id": "eng-test",
        "flow_id": "flow-test", "task_id": "task-test", "subtask_id": "subtask-test",
        "action_id": "action-test", "server_id": name, "tool_name": "authority_status",
        "parameters_sha256": "a" * 64, "manifest_sha256": "b" * 64,
        "authorization_version": 1, "authorization_sha256": "c" * 64,
        "lease_id": "lease-test", "resource_sha256": None,
        "issued_at": issued, "expires_at": issued + 5,
        "side_effect_class": "READ_ONLY",
    }
    forged_signer = Ed25519PrivateKey.generate()  # never the enrolled public root
    signed = b"ai-osop/native-grant/v1\x00" + json.dumps(
        claims, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).encode("ascii")
    signature = base64.urlsafe_b64encode(forged_signer.sign(signed)).decode("ascii").rstrip("=")
    envelope = {"claims": claims, "kid": "process-test-key", "signature": signature}
    return base64.urlsafe_b64encode(json.dumps(
        envelope, sort_keys=True, separators=(",", ":")
    ).encode("ascii")).decode("ascii").rstrip("=")


def _lose_ack_without_grant(port: int) -> str:
    """Exactly one inert no-grant POST, socket closed before reading reply."""
    request_id = "req-lost-ack-inert-" + "b" * 16
    body = json.dumps({"tool_name": "authority_status", "parameters": {},
                       "request_id": request_id}).encode("ascii")
    header = (f"POST /mcp/execute HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
              f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
              "Connection: close\r\n\r\n").encode("ascii")
    with socket.create_connection(("127.0.0.1", port), timeout=1.5) as sock:
        sock.settimeout(1.5)
        sock.sendall(header + body)
        # Intentionally no read/ACK. This does not imply server received,
        # accepted, completed, stopped or durably recorded this no-grant POST.
    return "unknown_no_ack_no_retry"


def test_source_and_diagnostic_eleven_truth_boundary() -> None:
    assert set(SIX) == {
        "recon-mcp", "payload-mcp", "nuclei-mcp", "shodan-mcp",
        "threat-intel-mcp", "security-bridge",
    }
    assert len(FIVE) == 5 and len(diagnostic.SERVICE_IDS) == 11
    assert set(SIX).isdisjoint(FIVE) and set(SIX + FIVE) == set(diagnostic.SERVICE_IDS)
    sdk = (GO_ROOT / "sdk/server.go").read_text(encoding="utf-8")
    assert '"status": "unavailable"' in sdk
    assert '"execution_enabled": false' in sdk
    assert "item.Handler = nil" in sdk
    assert 'mux.HandleFunc("/mcp/execute"' in sdk
    assert 'mux.HandleFunc("/mcp/request/status"' not in sdk
    for name in SIX:
        main = (GO_ROOT / "cmd" / name / "main.go").read_text(encoding="utf-8")
        assert f'sdk.NewServer("{name}")' in main
    assert diagnostic._TOOL == "list_tools"
    assert all(diagnostic._empty_result(name)["state"] == "not_allowed" for name in FIVE)
    assert "native_grant=" not in (ROOT / "scripts/qualification/mcp_eleven_inert_diagnostic_20261021.py").read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_six_live_pid_and_unavailable_in_one_actual_operator_eleven_roster(
    binaries: dict[str, Path],
) -> None:
    import psutil

    occupied: set[int] = set()
    started: dict[str, tuple[int, subprocess.Popen[bytes], float, Path]] = {}
    with contextlib.ExitStack() as owned:
        for name in SIX:
            port = _owned_port(occupied)
            proc = owned.enter_context(_child(name, binaries[name], port))
            created = _ready_pid(name, binaries[name], port, proc, status=503)
            started[name] = (port, proc, created, binaries[name])

        # Uses the EXACT operator diagnostic with actual MCPRegistry; none of
        # the five other configured services has a permitted network endpoint.
        rows = await diagnostic.diagnose({n: value[0] for n, value in started.items()})
        assert len(rows) == 11
        assert [row["server_id"] for row in rows] == list(diagnostic.SERVICE_IDS)
        assert len([row for row in rows if row["state"] == "not_allowed"]) == 5
        for row in rows:
            name = row["server_id"]
            assert row["target_effect_verified"] is False
            assert row["production_certified"] is False
            if name in SIX:
                assert row["state"] == "unknown"
                assert row["registered"] is False
                assert row["initialized"] is False
                assert row["inert_outcome"] == "unknown"
                port, proc, created, exe = started[name]
                assert proc.poll() is None
                assert psutil.Process(proc.pid).create_time() == created
                code, body = native.local_request(port, "/health")
                assert code == 503
                assert body["status"] == "unavailable"
                assert body["execution_enabled"] is False
                assert body["authority_verified"] is False
                # Even a typed successful HTTP initialize is explicitly
                # unavailable, never evidence of native tool readiness.
                code, init = native.local_request(port, "/mcp/initialize", _BOOTSTRAP)
                assert code == 200 and init["status"] == "unavailable"
                assert init["server_id"] == name
                assert init["execution_enabled"] is False
                assert init["authority_verified"] is False
            else:
                assert name in FIVE
                assert row["state"] == "not_allowed"
                assert row["inert_outcome"] == "not_checked"
                assert row["registered"] is False and row["initialized"] is False


def test_real_inert_configured_wrong_signer_expired_and_lost_ack_are_not_grants(
    binaries: dict[str, Path],
) -> None:
    # This separate one-process negative case installs PUBLIC ephemeral test
    # trust only, with a deliberately unreachable HTTPS redemption port. It
    # never has private issuer material, a valid grant or a running validator.
    name = "recon-mcp"
    port = _owned_port(set())
    trust = native.pinned_public_metadata()
    with _child(name, binaries[name], port, trust=trust) as proc:
        _ready_pid(name, binaries[name], port, proc, status=200)
        code, health = native.local_request(port, "/health")
        assert code == 200 and health["status"] == "configured_unverified"
        assert health["execution_enabled"] is False
        assert health["authority_verified"] is False
        code, init = native.local_request(port, "/mcp/initialize", _BOOTSTRAP)
        assert code == 200 and init["status"] == "ready"
        assert [tool["name"] for tool in init["tools"]] == ["authority_status"]
        assert init["tools"][0]["requires_approval"] is True

        attempted: set[str] = set()
        for suffix, expired in (("foreign-signer", False), ("expired-wrong-signer", True)):
            request_id = "req-operator-" + suffix
            assert request_id not in attempted
            attempted.add(request_id)
            token = _wrong_signer_grant(name, request_id=request_id, expired=expired)
            assert _local_forged_grant(port, request_id, token) in {
                "denied_503", "unknown_transport",
            }
        assert len(attempted) == 2  # neither original request ID was replayed

        # Intentionally lose one no-grant HTTP ACK; report UNKNOWN, do NOT
        # resend, claim stopped, infer target effect or issue another grant.
        assert _lose_ack_without_grant(port) == "unknown_no_ack_no_retry"
        code, post = native.local_request(port, "/health")
        assert code == 200 and post["authority_verified"] is False
        assert post["execution_enabled"] is False
        # Deliberately non-credentialed connection / no grant for the PID.
        assert proc.poll() is None
