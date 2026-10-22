"""Fail-closed six-Go inert process owner, no production targets or App DB.

Default tests mock ONLY the test-owned subprocess and health observation and
verify policy/cleanup. Real native process qualification requires TWO explicit
test opt-ins plus worker40's offline cached build fixture; otherwise SKIP.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

import pytest

from ai_osop.mcp import native_inert_process_fleet as fleet


@pytest.fixture
def fake_binaries(tmp_path: Path) -> tuple[Path, dict[str, fleet.VerifiedGoBinary]]:
    root = tmp_path.resolve()
    assert root.is_absolute()
    supplied = {}
    for name in fleet.SIX_SERVICES:
        path = root / f"{name}.exe"
        path.write_bytes(b"MZ" + b"go-build-info-only-placeholder" + b"x" * 110_000)
        supplied[name] = fleet.VerifiedGoBinary(
            path=path, sha256=hashlib.sha256(path.read_bytes()).hexdigest()
        )
    return root, supplied


def _ready_object(
    root: Path, pins: dict[str, fleet.VerifiedGoBinary], *, enabled: bool = True
) -> fleet.NativeInertProcessFleet:
    return fleet.NativeInertProcessFleet(
        trusted_build_root=root, binaries=pins, operator_opt_in=enabled
    )


def test_sha_verified_stable_executable_identity_ignores_only_access_time(
    tmp_path: Path,
) -> None:
    path = tmp_path / "owned.exe"
    path.write_bytes(b"MZ" + b"inert" * 8192)
    original = path.lstat()
    import os as _os

    changed_access = original.st_atime_ns - 2_000_000_000
    _os.utime(path, ns=(changed_access, original.st_mtime_ns))
    after_read_time = path.lstat()
    assert fleet._stable_file_identity(original) == fleet._stable_file_identity(after_read_time)
    path.write_bytes(path.read_bytes() + b"tampered")
    assert fleet._stable_file_identity(original) != fleet._stable_file_identity(path.lstat())


@pytest.mark.parametrize(
    "env_value,enable",
    [
        (None, False),
        (None, True),
        ("0", True),
        ("true", True),
        ("1", False),
    ],
)
def test_no_implicit_enrollment_or_process_spawn(
    monkeypatch: pytest.MonkeyPatch,
    fake_binaries: tuple[Path, dict[str, fleet.VerifiedGoBinary]],
    env_value: str | None,
    enable: bool,
) -> None:
    root, pins = fake_binaries
    monkeypatch.delenv(fleet.OPT_IN_ENV, raising=False)
    if env_value is not None:
        monkeypatch.setenv(fleet.OPT_IN_ENV, env_value)
    launches: list[Any] = []
    monkeypatch.setattr(fleet.subprocess, "Popen", lambda *a, **k: launches.append((a, k)))
    supervisor = _ready_object(root, pins, enabled=enable)
    assert supervisor.state == "new"
    with pytest.raises(fleet.InertFleetDenied):
        supervisor.start()
    assert launches == []
    assert supervisor.state == "closed"
    supervisor.stop()
    with pytest.raises(fleet.InertFleetDenied, match="may not restart"):
        supervisor.start()


@pytest.mark.parametrize(
    "corrupted",
    [
        "missing",
        "relative",
        "wrong_name",
        "other_root",
        "digest",
        "uppercase_digest",
        "non_exe",
        "symlink",
    ],
)
def test_untrusted_paths_are_denied_before_launch(
    monkeypatch: pytest.MonkeyPatch,
    fake_binaries: tuple[Path, dict[str, fleet.VerifiedGoBinary]],
    corrupted: str,
    tmp_path: Path,
) -> None:
    root, original = fake_binaries
    pins = dict(original)
    name = "nuclei-mcp"
    candidate = pins[name]
    if corrupted == "missing":
        del pins[name]
    elif corrupted == "relative":
        pins[name] = fleet.VerifiedGoBinary(Path("nuclei-mcp.exe"), candidate.sha256)
    elif corrupted == "wrong_name":
        path = root / "fake-nuclei.exe"
        path.write_bytes(candidate.path.read_bytes())
        pins[name] = fleet.VerifiedGoBinary(path, candidate.sha256)
    elif corrupted == "other_root":
        target = tmp_path / "other"
        target.mkdir()
        path = target / "nuclei-mcp.exe"
        path.write_bytes(candidate.path.read_bytes())
        pins[name] = fleet.VerifiedGoBinary(path, candidate.sha256)
    elif corrupted == "digest":
        pins[name] = fleet.VerifiedGoBinary(candidate.path, "0" * 64)
    elif corrupted == "uppercase_digest":
        pins[name] = fleet.VerifiedGoBinary(candidate.path, "A" * 64)
    elif corrupted == "non_exe":
        candidate.path.write_bytes(b"#! python\n" + b"x" * 110_000)
        pins[name] = fleet.VerifiedGoBinary(
            candidate.path, hashlib.sha256(candidate.path.read_bytes()).hexdigest()
        )
    else:
        target = root / "real-nuclei.exe"
        candidate.path.rename(target)
        try:
            candidate.path.symlink_to(target)
        except (OSError, NotImplementedError):
            # Simulate the OS reparse/symlink bit on machines lacking Windows
            # developer privileges; fail-closed policy still gets exercised.
            candidate.path.write_bytes(target.read_bytes())
            old = Path.is_symlink
            monkeypatch.setattr(
                Path,
                "is_symlink",
                lambda path: path == candidate.path or old(path),
            )

    monkeypatch.setenv(fleet.OPT_IN_ENV, "1")
    monkeypatch.setattr(fleet, "_get_go_inspector", lambda: Path("C:/go/bin/go.exe"))
    inspections: list[str] = []

    def inspected(argv: list[str], **kwargs: Any) -> Any:
        examined = Path(argv[-1]).stem
        inspections.append(examined)
        stdout = (
            f"go1.26.3\n\tpath\tgithub.com/ai-osop/mcp-servers/cmd/{examined}"
            "\n\tbuild\tGOOS=windows\n\tbuild\tGOARCH=amd64\n"
        ).encode("ascii")
        return SimpleNamespace(returncode=0, stdout=stdout)

    monkeypatch.setattr(fleet.subprocess, "run", inspected)
    with pytest.raises(fleet.InertFleetDenied):
        fleet._validated_binaries(pins, root)
    assert "nuclei-mcp" not in inspections or corrupted in {"digest"}


def test_repository_exe_and_non_go_pe_rejected_by_real_go_buildinfo(
    monkeypatch: pytest.MonkeyPatch,
    fake_binaries: tuple[Path, dict[str, fleet.VerifiedGoBinary]],
) -> None:
    root, pins = fake_binaries
    monkeypatch.setenv(fleet.OPT_IN_ENV, "1")
    tool = fleet.shutil.which("go")
    if not tool:
        pytest.skip("Local Go build-info inspector missing")
    with pytest.raises(fleet.InertFleetDenied, match="build identity"):
        fleet._validated_binaries(pins, root)
    repository = Path(__file__).resolve().parents[1]
    with pytest.raises(fleet.InertFleetDenied, match="overlap"):
        fleet._validated_binaries(pins, repository)


def test_clean_child_environment_no_native_enrollment_or_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON", "PRIVATE_SOURCE_ROOT")
    monkeypatch.setenv("OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON", "PRIVATE_TOKEN")
    monkeypatch.setenv("OSOP_POSTGRES_URI", "postgres://PRIVATE")
    monkeypatch.setenv("HTTPS_PROXY", "https://PRIVATE_PROXY")
    monkeypatch.setenv("GOFLAGS", "PRIVATE_GO_FLAGS")
    monkeypatch.setenv("NATIVE_TARGET", "PRIVATE_TARGET")
    for name in fleet.SIX_SERVICES:
        environment = fleet._clean_environment(name, 49152)
        assert not any("PRIVATE" in value for value in environment.values())
        assert set(key for key in environment if key.startswith("OSOP_")) == {
            fleet._PORT_OVERRIDES[name]
        }
        assert not any("PROXY" in key.upper() for key in environment)
        assert environment[fleet._PORT_OVERRIDES[name]] == "49152"


def test_ephemeral_ports_unique_with_default_and_database_ports_denied() -> None:
    used: set[int] = set()
    ports = [fleet._unique_ephemeral_port(used) for _ in fleet.SIX_SERVICES]
    assert len(ports) == len(set(ports)) == 6
    assert not fleet._UNSAFE_PORTS.intersection(ports)
    assert all(1024 <= port <= 65535 for port in ports)


@dataclass
class _FakeResponse:
    status: int
    body: bytes
    content_type: str = "application/json"

    def __post_init__(self) -> None:
        self.headers = {"Content-Type": self.content_type}

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


@pytest.mark.parametrize(
    "status,changes,bad_raw,ctype",
    [
        (200, {}, None, "application/json"),
        (503, {"status": "healthy"}, None, "application/json"),
        (503, {"execution_enabled": True}, None, "application/json"),
        (503, {"authority_verified": True}, None, "application/json"),
        (503, {"server_id": "payload-mcp"}, None, "application/json"),
        (503, {"target_effect_verified": True}, None, "application/json"),
        (503, {}, b'{"status":"unavailable","status":"ready"}', "application/json"),
        (503, {}, b'{"value":NaN}', "application/json"),
        (503, {}, b"x" * 2050, "application/json"),
        (503, {}, None, "text/html"),
    ],
)
def test_bounded_untrusted_health_only_accepts_explicit_inert_503(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    changes: dict[str, Any],
    bad_raw: bytes | None,
    ctype: str,
) -> None:
    payload = {
        "server_id": "recon-mcp",
        "status": "unavailable",
        "execution_enabled": False,
        "authority_verified": False,
        "reason": "source_side_signed_authority_unavailable",
    }
    payload.update(changes)
    raw = bad_raw if bad_raw is not None else json.dumps(payload).encode()
    observed: list[Any] = []

    class _Opener:
        def open(self, request: Any, *, timeout: float) -> _FakeResponse:
            observed.append((request, timeout))
            return _FakeResponse(status, raw, ctype)

    monkeypatch.setattr(fleet.urllib.request, "build_opener", lambda *a, **kw: _Opener())
    with pytest.raises(fleet.InertFleetDenied):
        fleet._health_503(49152, "recon-mcp")
    assert len(observed) == 1
    assert observed[0][0].get_method() == "GET"
    assert observed[0][0].full_url == "http://127.0.0.1:49152/health"


def test_positive_strict_unenrolled_503_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps(
        {
            "server_id": "recon-mcp",
            "status": "unavailable",
            "execution_enabled": False,
            "authority_verified": False,
            "reason": "source_side_signed_authority_unavailable",
        }
    ).encode()

    class _Opener:
        def open(self, request: Any, *, timeout: float) -> _FakeResponse:
            assert request.get_method() == "GET"
            return _FakeResponse(503, body)

    monkeypatch.setattr(fleet.urllib.request, "build_opener", lambda *a, **kw: _Opener())
    fleet._health_503(49152, "recon-mcp")


def test_redirect_never_permitted_by_native_health_transport() -> None:
    with pytest.raises(fleet.InertFleetDenied, match="redirect denied"):
        fleet._NoRedirect().redirect_request(
            None, None, 302, "redirect", {}, "http://127.0.0.1:49153/mcp/execute"
        )


def test_missing_os_pid_inspector_fails_before_process_spawn(
    fake_binaries: tuple[Path, dict[str, fleet.VerifiedGoBinary]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, pins = fake_binaries
    monkeypatch.setenv(fleet.OPT_IN_ENV, "1")
    monkeypatch.setattr(fleet, "psutil", None)
    with pytest.raises(fleet.InertFleetDenied, match="OS attestation"):
        _ready_object(root, pins).start()


def test_unowned_pid_cannot_be_attested_as_current_native_process(
    fake_binaries: tuple[Path, dict[str, fleet.VerifiedGoBinary]],
) -> None:
    _, pins = fake_binaries
    process = _FakePopen()
    process.pid = os.getpid()  # real Python pytest process, not a Go child
    child = fleet._Owned(
        name="recon-mcp",
        binary=pins["recon-mcp"].path,
        digest=pins["recon-mcp"].sha256,
        process=process,
        port=49152,
    )
    with pytest.raises(fleet.InertFleetDenied, match="PID executable or parent mismatch"):
        fleet.NativeInertProcessFleet._owned_attestation(child)


class _FakePopen:
    next_pid = 12340

    def __init__(self) -> None:
        type(self).next_pid += 1
        self.pid = type(self).next_pid
        self.return_code: int | None = None
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.return_code

    def terminate(self) -> None:
        self.terminated = True
        self.return_code = 0

    def kill(self) -> None:
        self.killed = True
        self.return_code = -9

    def wait(self, timeout: float) -> int:
        assert timeout <= 3
        assert self.return_code is not None
        return self.return_code


@pytest.fixture
def fake_running(
    monkeypatch: pytest.MonkeyPatch,
    fake_binaries: tuple[Path, dict[str, fleet.VerifiedGoBinary]],
) -> tuple[fleet.NativeInertProcessFleet, list[_FakePopen], dict[str, Any]]:
    root, pins = fake_binaries
    monkeypatch.setenv(fleet.OPT_IN_ENV, "1")
    created: list[_FakePopen] = []
    seen: list[tuple[str, dict[str, Any]]] = []
    old_popen = fleet.subprocess.Popen

    def spawn(command: list[str], **kwargs: Any) -> _FakePopen:
        assert len(command) == 1 and command[0].endswith(".exe")
        assert "shell" not in kwargs
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert all("TOKEN" not in k.upper() for k in kwargs["env"])
        process = _FakePopen()
        created.append(process)
        seen.append((command[0], kwargs))
        return process

    def validated(actual: Any, directory: Path) -> dict[str, tuple[Path, str]]:
        assert directory == root and set(actual) == set(fleet.SIX_SERVICES)
        return {name: (pins[name].path, pins[name].sha256) for name in pins}

    monkeypatch.setattr(fleet, "_validated_binaries", validated)
    monkeypatch.setattr(fleet.subprocess, "Popen", spawn)
    monkeypatch.setattr(
        fleet.NativeInertProcessFleet, "_owned_attestation", staticmethod(lambda entry: 123.0)
    )
    monkeypatch.setattr(fleet, "_health_503", lambda port, name: None)
    actual = _ready_object(root, pins)
    return actual, created, {"calls": seen, "original_popen": old_popen}


def test_explicit_start_health_stop_no_restart_and_no_tool_dispatch(
    fake_running: tuple[fleet.NativeInertProcessFleet, list[_FakePopen], dict[str, Any]],
) -> None:
    running, processes, record = fake_running
    assert running.state == "new" and processes == []
    rows = running.start()
    assert running.state == "running"
    assert len(rows) == len(processes) == 6
    assert len({row.port for row in rows}) == 6
    assert len({row.pid for row in rows}) == 6
    for row in rows:
        assert row.pid_owned and row.listener_owned
        assert row.status == "unavailable"
        assert not row.native_authority_verified
        assert not row.execution_enabled
        assert not row.target_effect_verified
        assert not row.production_certified
    assert all(
        "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON" not in args[1]["env"] for args in record["calls"]
    )
    assert running.health() == rows
    assert not hasattr(running, "execute_tool")
    assert not hasattr(running, "restart")
    assert not hasattr(running, "grant")
    running.stop()
    running.stop()
    assert running.state == "closed" and all(p.terminated for p in processes)
    with pytest.raises(fleet.InertFleetDenied, match="may not restart"):
        running.start()
    with pytest.raises(fleet.InertFleetDenied, match="not running"):
        running.health()


def test_partial_child_spawn_failure_closes_only_owned_children(
    fake_running: tuple[fleet.NativeInertProcessFleet, list[_FakePopen], dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running, children, _ = fake_running

    def broken_spawn(*args: Any, **kwargs: Any) -> _FakePopen:
        if len(children) == 2:
            raise OSError("PRIVATE_CHILD_SPAWN_SECRET")
        process = _FakePopen()
        children.append(process)
        return process

    monkeypatch.setattr(fleet.subprocess, "Popen", broken_spawn)
    with pytest.raises(OSError):
        running.start()
    assert running.state == "closed" and len(children) == 2
    assert all(child.terminated for child in children)
    assert running._owned == {}


def test_current_health_revocation_kills_all_own_children_no_action_retry(
    fake_running: tuple[fleet.NativeInertProcessFleet, list[_FakePopen], dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running, children, _ = fake_running
    running.start()

    def withdrawn(entry: Any) -> float:
        if entry.name == "shodan-mcp":
            raise fleet.InertFleetDenied("test ownership changed")
        return 123.0

    monkeypatch.setattr(
        fleet.NativeInertProcessFleet, "_owned_attestation", staticmethod(withdrawn)
    )
    with pytest.raises(fleet.InertFleetDenied, match="health unavailable"):
        running.health()
    assert all(child.terminated for child in children)
    assert running._owned == {} and running.state == "closed"


def test_context_manager_always_closes(
    fake_running: tuple[fleet.NativeInertProcessFleet, list[_FakePopen], dict[str, Any]],
) -> None:
    running, children, _ = fake_running
    with pytest.raises(RuntimeError, match="operator exit"):
        with running as owner:
            assert owner.state == "running"
            raise RuntimeError("operator exit")
    assert running.state == "closed" and all(child.terminated for child in children)


def test_listener_unavailable_never_restarts_and_cleans_first_owned_child(
    fake_running: tuple[fleet.NativeInertProcessFleet, list[_FakePopen], dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running, children, record = fake_running
    monkeypatch.setattr(fleet, "_STARTUP_SECONDS", 0.01)
    monkeypatch.setattr(fleet.time, "sleep", lambda _: None)

    def never_listens(entry: Any) -> float:
        raise fleet._ListenerNotBound("ephemeral listener not yet bound")

    monkeypatch.setattr(
        fleet.NativeInertProcessFleet, "_owned_attestation", staticmethod(never_listens)
    )
    with pytest.raises(fleet.InertFleetDenied, match="startup timed out"):
        running.start()
    assert len(record["calls"]) == len(children) == 1
    assert children[0].terminated
    assert running._owned == {} and running.state == "closed"


def test_cleanup_failure_retains_only_unresolved_owned_handle(
    fake_running: tuple[fleet.NativeInertProcessFleet, list[_FakePopen], dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running, children, _ = fake_running
    running.start()
    original = fleet.NativeInertProcessFleet._stop_owned
    failed_name = "nuclei-mcp"

    def interrupted(entry: Any) -> None:
        if entry.name == failed_name:
            raise OSError("owned Windows handle denied stop")
        original(entry)

    monkeypatch.setattr(fleet.NativeInertProcessFleet, "_stop_owned", staticmethod(interrupted))
    with pytest.raises(fleet.InertFleetDenied, match="cleanup could not"):
        running.stop()
    assert running.state == "closed"
    assert set(running._owned) == {failed_name}
    assert sum(not child.terminated for child in children) == 1
    monkeypatch.setattr(fleet.NativeInertProcessFleet, "_stop_owned", staticmethod(original))
    running.stop()
    assert running._owned == {} and all(child.terminated for child in children)


def test_lifecycle_source_is_not_mounted_and_has_no_action_call() -> None:
    source = Path(fleet.__file__).read_text(encoding="utf-8")
    assert '"/health"' in source and "GET" in source
    assert "mcp/execute" not in source
    assert "execute_tool(" not in source
    assert "native_grant=" not in source
    assert "go build" not in source
    assert fleet.NativeInertProcessFleet.__module__ == "ai_osop.mcp.native_inert_process_fleet"


@pytest.mark.skipif(
    os.getenv("OSOP_NATIVE_INERT_PROCESS_FLEET_REAL_TEST_20261021") != "1",
    reason="NO REAL CHILDREN without separate OSOP_NATIVE_INERT_PROCESS_FLEET_REAL_TEST_20261021=1",
)
def test_real_offline_worker40_six_process_inert_lifecycle(
    monkeypatch: pytest.MonkeyPatch, rebuilt_binaries: dict[str, Path]
) -> None:
    """Genuine PIDs only if BOTH independent test opt-ins are operator enabled.

    The imported worker40 fixture builds in temp, offline, and itself requires
    OSOP_NATIVE_GO_SIX_REAL_PROCESS_20261021=1. No additional compile here.
    """
    build_root = next(iter(rebuilt_binaries.values())).parent
    assert all(path.parent == build_root for path in rebuilt_binaries.values())
    pins = {
        name: fleet.VerifiedGoBinary(
            path=path, sha256=hashlib.sha256(path.read_bytes()).hexdigest()
        )
        for name, path in rebuilt_binaries.items()
    }
    monkeypatch.setenv(fleet.OPT_IN_ENV, "1")
    owner = fleet.NativeInertProcessFleet(
        binaries=pins, trusted_build_root=build_root, operator_opt_in=True
    )
    with owner:
        rows = owner.health()
        assert len(rows) == 6
        assert len({row.port for row in rows}) == 6
        assert all(row.status == "unavailable" and not row.execution_enabled for row in rows)
    assert owner.state == "closed"


from tests.qualification.test_native_go_six_supervised_inert_runtime_20261021 import (
    rebuilt_binaries,
)
