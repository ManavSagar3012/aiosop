"""Opt-in owner-local lifecycle for six **unenrolled, inert** Go MCP processes.

This module is intentionally NOT registered in API startup. It creates no
native grants, SourceMap/0033 identity, Action, scanner, or target effect. Its
only HTTP operation is GET /health to an OS-attested owned loopback listener.

An operator must explicitly supply a trusted offline build directory and six
absolute executables with SHA-256 pins. The locally installed Go tool is used
ONLY for ``go version -m <file>`` build-info inspection: no build/download.
All-or-nothing start and explicit stop make unknown outcomes fail closed;
there are no automatic restarts, tools/execute or retries of any Action.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

try:
    import psutil
except ImportError:  # pragma: no cover - explicit fail-closed prerequisite
    psutil = None


OPT_IN_ENV = "OSOP_NATIVE_INERT_PROCESS_FLEET_OPT_IN"
SIX_SERVICES = (
    "recon-mcp",
    "payload-mcp",
    "nuclei-mcp",
    "shodan-mcp",
    "threat-intel-mcp",
    "security-bridge",
)
_PORT_OVERRIDES = {
    name: "OSOP_RECON_MCP_LOCAL_PORT" if name == "recon-mcp" else "OSOP_NATIVE_MCP_LOCAL_PORT"
    for name in SIX_SERVICES
}
_UNSAFE_PORTS = frozenset(
    {
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
        5432,
        5433,
        6379,
        6380,
        7687,
        7474,
        8200,
        5173,
    }
)
_GO_MODULE = "github.com/ai-osop/mcp-servers"
_SAFE_ENV = frozenset(
    {
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "OS",
        "PROCESSOR_ARCHITECTURE",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "HOMEDRIVE",
        "HOMEPATH",
    }
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BINARY_BYTES = 100_000_000
_STARTUP_SECONDS = 4.0
_TERMINATE_SECONDS = 3.0
_HEALTH_BODY_BYTES = 2048
_HEALTH_PATH = "/health"


class InertFleetDenied(RuntimeError):
    """Generic failure: do not echo private input, child stderr or grants."""


class _ListenerNotBound(InertFleetDenied):
    """Only transient startup state allowed to be polled before deadline."""


@dataclass(frozen=True)
class VerifiedGoBinary:
    """Operator-supplied absolute binary path and independently verified pin.

    The operator owns verification of build provenance and the SHA pin. Go
    build-info inspection plus OS ownership constrains accidental substitution
    but is NOT a cryptographic supply-chain signer or a 0033 witness.
    """

    path: Path
    sha256: str


@dataclass(frozen=True)
class InertProcessHealth:
    """Host-local testable observation; NOT source/target authorization."""

    server_id: str
    pid: int
    port: int
    pid_owned: bool
    listener_owned: bool
    native_authority_verified: bool = False
    execution_enabled: bool = False
    target_effect_verified: bool = False
    production_certified: bool = False
    status: str = "unavailable"


@dataclass
class _Owned:
    name: str
    binary: Path
    digest: str
    process: subprocess.Popen[bytes]
    port: int
    created_at: float = 0.0


def _sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(part)
    return result.hexdigest()


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Compare executable identity, ignoring read-induced access-time changes.

    Windows may update st_atime between SHA checks or `go version -m`; full
    `os.stat_result` equality therefore falsely rejects unchanged binaries.
    Retain object type, device/inode, length, last-write time and reparse flags
    and still verify the original SHA-256 before AND after external inspection.
    """
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        getattr(metadata, "st_file_attributes", 0),
    )


def _within(candidate: Path, root: Path) -> bool:
    try:
        return candidate.is_relative_to(root)
    except ValueError:
        return False


def _clean_environment(name: str, port: int) -> dict[str, str]:
    if name not in SIX_SERVICES or type(port) is not int or not 1024 <= port <= 65535:
        raise InertFleetDenied("Unapproved inert process environment")
    environment = {key: value for key, value in os.environ.items() if key.upper() in _SAFE_ENV}
    environment[_PORT_OVERRIDES[name]] = str(port)
    if any(key.upper().startswith("OSOP_") and key != _PORT_OVERRIDES[name] for key in environment):
        raise InertFleetDenied("Inherited native process authority denied")
    if any(
        "PROXY" in key.upper() or "TOKEN" in key.upper() or "SECRET" in key.upper()
        for key in environment
    ):
        raise InertFleetDenied("Inherited external provider authority denied")
    return environment


def _get_go_inspector() -> Path:
    tool = shutil.which("go")
    if not tool:
        raise InertFleetDenied("Offline Go build-info inspector unavailable")
    path = Path(tool).resolve(strict=True)
    if not path.is_absolute() or not path.is_file() or path.suffix.lower() != ".exe":
        raise InertFleetDenied("Local Windows Go inspection tool unavailable")
    return path


def _validated_binaries(
    binaries: Mapping[str, VerifiedGoBinary], build_root: Path
) -> dict[str, tuple[Path, str]]:
    if type(binaries) is not dict or set(binaries) != set(SIX_SERVICES):
        raise InertFleetDenied("Exact six independently supplied Go binary pins required")
    if not isinstance(build_root, Path) or not build_root.is_absolute():
        raise InertFleetDenied("Absolute verified offline build root required")
    if (
        build_root.is_symlink()
        or not build_root.is_dir()
        or getattr(build_root.lstat(), "st_file_attributes", 0) & 0x400
    ):
        raise InertFleetDenied("Untrusted offline build root denied")
    root = build_root.resolve(strict=True)
    if root != build_root:
        raise InertFleetDenied("Unresolved offline build root denied")
    # Prebuilt repo executable blobs may be stale; the build must be owned
    # separately by the operator, not scraped from a dirty Git checkout.
    repository = Path(__file__).resolve().parents[3]
    if _within(root, repository) or _within(repository, root):
        raise InertFleetDenied("Build root cannot overlap application sources")
    inspector = _get_go_inspector()
    completed: dict[str, tuple[Path, str]] = {}
    for name in SIX_SERVICES:
        record = binaries[name]
        if type(record) is not VerifiedGoBinary or not isinstance(record.path, Path):
            raise InertFleetDenied("Verified binary path and digest required")
        path = record.path
        if (
            not path.is_absolute()
            or path.parent != root
            or path.name != f"{name}.exe"
            or path.is_symlink()
        ):
            raise InertFleetDenied("Go executable must be an exact direct offline build child")
        try:
            meta = path.lstat()
        except OSError:
            raise InertFleetDenied("Go executable unavailable") from None
        # FILE_ATTRIBUTE_REPARSE_POINT is present on Windows junctions and
        # reparse variants even when Path.is_symlink() does not catch them.
        if (
            not stat.S_ISREG(meta.st_mode)
            or getattr(meta, "st_file_attributes", 0) & 0x400
            or not 100_000 <= meta.st_size <= _MAX_BINARY_BYTES
            or type(record.sha256) is not str
            or not _HEX64.fullmatch(record.sha256)
        ):
            raise InertFleetDenied("Unsafe or unpinned Go executable denied")
        actual = path.resolve(strict=True)
        if actual != path or not _within(actual, root):
            raise InertFleetDenied("Go executable path escaped trusted build directory")
        with path.open("rb") as handle:
            if handle.read(2) != b"MZ":
                raise InertFleetDenied("Non-Windows Go executable denied")
        if _sha256_file(path) != record.sha256:
            raise InertFleetDenied("Go executable differs from independent digest")
        try:
            inspected = subprocess.run(
                [str(inspector), "version", "-m", str(path)],
                env={
                    **_clean_environment(name, 49152),
                    "GOTOOLCHAIN": "local",
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GOENV": "off",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=4,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise InertFleetDenied("Go build-info attestation unavailable") from None
        marker = ("\tpath\t" + _GO_MODULE + "/cmd/" + name).encode("ascii")
        if (
            inspected.returncode != 0
            or len(inspected.stdout) > 8192
            or marker not in inspected.stdout.splitlines()
            or b"\tbuild\tGOOS=windows" not in inspected.stdout
            or b"\tbuild\tGOARCH=amd64" not in inspected.stdout
        ):
            raise InertFleetDenied("Go binary build identity mismatch")
        # Inspector must not change the object being pinned; this also narrows
        # a symlink/file-swap race, without claiming atomic signed binaries.
        if (
            _stable_file_identity(path.lstat()) != _stable_file_identity(meta)
            or _sha256_file(path) != record.sha256
        ):
            raise InertFleetDenied("Go executable changed during offline verification")
        completed[name] = (path, record.sha256)
    return completed


def _unique_ephemeral_port(used: set[int]) -> int:
    for _ in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        if 1024 <= port <= 65535 and port not in used and port not in _UNSAFE_PORTS:
            used.add(port)
            return port
    raise InertFleetDenied("Test-owned ephemeral loopback port unavailable")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise InertFleetDenied("Local native health redirect denied")


def _health_503(port: int, name: str) -> None:
    # Only /health. Never initialize, execute, status/cancel or scan. Disable
    # proxies explicitly, prevent redirects and cap response bytes.
    url = f"http://127.0.0.1:{port}{_HEALTH_PATH}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, method="GET")
    try:
        try:
            response = opener.open(request, timeout=0.7)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.status != 503 or not response.headers.get("Content-Type", "").startswith(
                "application/json"
            ):
                raise InertFleetDenied("Go inert-only health declaration unavailable")
            body = response.read(_HEALTH_BODY_BYTES + 1)
    except (OSError, TimeoutError, ValueError):
        raise InertFleetDenied("Go inert-only health unavailable") from None
    if len(body) > _HEALTH_BODY_BYTES:
        raise InertFleetDenied("Go native health oversized")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ambiguous provider JSON")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            body,
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
    except (UnicodeDecodeError, ValueError):
        raise InertFleetDenied("Untrusted native health response denied") from None
    if (
        type(parsed) is not dict
        or set(parsed)
        != {"status", "server_id", "execution_enabled", "authority_verified", "reason"}
        or parsed["status"] != "unavailable"
        or parsed["server_id"] != name
        or parsed["execution_enabled"] is not False
        or parsed["authority_verified"] is not False
        or parsed["reason"] != "source_side_signed_authority_unavailable"
    ):
        raise InertFleetDenied("Go native process claimed unexpected authority")


class NativeInertProcessFleet:
    """Explicit six-process lifecycle with fail-closed OS process attestation.

    Instantiate without side effects; call ``start()`` only under *two* gates:
    constructor ``operator_opt_in=True`` and OS environment OPT_IN_ENV == '1'.
    ``health()`` revalidates live PID/path/socket and inert HTTP 503; any
    uncertainty closes every owned process and forbids restart on this object.
    ``stop()`` is idempotent. Use as a context manager for closed-state cleanup.
    """

    def __init__(
        self,
        *,
        binaries: dict[str, VerifiedGoBinary],
        trusted_build_root: Path,
        operator_opt_in: bool = False,
    ) -> None:
        self._pins = dict(binaries) if type(binaries) is dict else binaries
        self._root = trusted_build_root
        self._operator_opt_in = operator_opt_in
        self._lock = threading.RLock()
        self._state = "new"
        self._owned: dict[str, _Owned] = {}

    @property
    def state(self) -> str:
        return self._state

    def _gates(self) -> None:
        if (
            self._operator_opt_in is not True
            or os.getenv(OPT_IN_ENV) != "1"
            or sys.platform != "win32"
            or os.name != "nt"
            or psutil is None
        ):
            raise InertFleetDenied("Inert process opt-in or OS attestation unavailable")

    @staticmethod
    def _owned_attestation(entry: _Owned) -> float:
        if psutil is None or entry.process.poll() is not None:
            raise InertFleetDenied("Owned Go process is unavailable")
        try:
            process = psutil.Process(entry.process.pid)
            if (
                process.ppid() != os.getpid()
                or Path(process.exe()).resolve(strict=True) != entry.binary
                or process.username().casefold()
                != psutil.Process(os.getpid()).username().casefold()
            ):
                raise InertFleetDenied("Go PID executable or parent mismatch")
            created = process.create_time()
            if entry.created_at and created != entry.created_at:
                raise InertFleetDenied("Go PID creation epoch changed")
            sockets = process.net_connections(kind="tcp")
            listeners = [
                connection
                for connection in sockets
                if connection.status == psutil.CONN_LISTEN
                and connection.laddr.ip == "127.0.0.1"
                and connection.laddr.port == entry.port
            ]
            if len(listeners) != 1:
                raise _ListenerNotBound("Go listener has not bound expected loopback port")
            descendants = process.children(recursive=True)
            if any(child.name().casefold() != "conhost.exe" for child in descendants):
                raise InertFleetDenied("Unexpected native scanner subprocess")
            if _sha256_file(entry.binary) != entry.digest:
                raise InertFleetDenied("Go executable digest changed after launch")
            return created
        except (psutil.Error, OSError, ValueError):
            raise InertFleetDenied("Current Go PID or socket attestation unavailable") from None

    @staticmethod
    def _stop_owned(entry: _Owned) -> None:
        # Never kill by port, psutil discovery, image name or a stale PID; only
        # the Popen object this supervisor itself created is an owned child.
        process = entry.process
        if process.poll() is None:
            try:
                process.terminate()
            except OSError:
                process.kill()  # still the same Popen-owned Windows process handle
        try:
            process.wait(timeout=_TERMINATE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=_TERMINATE_SECONDS)
        if process.poll() is None:
            raise InertFleetDenied("Owned Go child could not be terminated")
        # Do not confuse a stale PID or a different local server with the
        # process we started. Verification failure does not authorize killing
        # a foreign owner, only flags unresolved cleanup to the operator.
        if psutil is None:
            raise InertFleetDenied("Owned Go process exit verification unavailable")
        try:
            if psutil.pid_exists(process.pid):
                owner = psutil.Process(process.pid)
                if entry.created_at == 0 or owner.create_time() == entry.created_at:
                    raise InertFleetDenied("Owned Go PID remains after stop")
        except psutil.NoSuchProcess:
            pass
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", entry.port)) == 0:
                raise InertFleetDenied("Owned Go loopback port remains occupied after stop")

    def stop(self) -> None:
        with self._lock:
            self._state = "closed"
            errors = False
            for name, child in tuple(self._owned.items()):
                try:
                    self._stop_owned(child)
                except (OSError, subprocess.SubprocessError, InertFleetDenied):
                    errors = True
                else:
                    self._owned.pop(name, None)
            if errors:
                raise InertFleetDenied("Inert fleet cleanup could not be fully verified")

    close = stop

    def start(self) -> tuple[InertProcessHealth, ...]:
        with self._lock:
            if self._state != "new":
                raise InertFleetDenied("Inert fleet may not restart after a previous attempt")
            try:
                self._gates()
                identities = _validated_binaries(self._pins, self._root)
                self._state = "starting"
                used: set[int] = set()
                for name in SIX_SERVICES:
                    path, digest = identities[name]
                    if _sha256_file(path) != digest:
                        raise InertFleetDenied("Go executable changed before spawn")
                    port = _unique_ephemeral_port(used)
                    env = _clean_environment(name, port)
                    process = subprocess.Popen(
                        [str(path)],
                        cwd=str(path.parent),
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    entry = _Owned(
                        name=name, binary=path, digest=digest, process=process, port=port
                    )
                    self._owned[name] = entry  # own BEFORE checking the PID
                    deadline = time.monotonic() + _STARTUP_SECONDS
                    while True:
                        if time.monotonic() >= deadline:
                            raise InertFleetDenied("Owned Go process startup timed out")
                        try:
                            entry.created_at = self._owned_attestation(entry)
                            _health_503(port, name)
                            break
                        except _ListenerNotBound:
                            # Only a not-yet-bound owned socket can be polled.
                            # Wrong owner/signature, bad 503, missing psutil
                            # or changed executable is an immediate denial.
                            if process.poll() is not None:
                                raise
                            time.sleep(0.05)
                self._state = "running"
                return self.health()
            except BaseException:
                # Includes cancellation/KeyboardInterrupt after a child spawned.
                # Always terminate test-owned PIDs; never affect unrelated PIDs.
                self.stop()
                raise

    def health(self) -> tuple[InertProcessHealth, ...]:
        with self._lock:
            if self._state != "running" or set(self._owned) != set(SIX_SERVICES):
                raise InertFleetDenied("Inert process fleet is not running")
            try:
                rows = []
                for name in SIX_SERVICES:
                    child = self._owned[name]
                    self._owned_attestation(child)
                    _health_503(child.port, name)
                    rows.append(
                        InertProcessHealth(
                            server_id=name,
                            pid=child.process.pid,
                            port=child.port,
                            pid_owned=True,
                            listener_owned=True,
                        )
                    )
                return tuple(rows)
            except BaseException:
                self.stop()
                raise InertFleetDenied("Inert fleet current process health unavailable") from None

    def __enter__(self) -> "NativeInertProcessFleet":
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop()
