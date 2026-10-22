"""Explicit host-owned process witness for the DISABLED Python Turbo MCP.

This is deliberately narrower than a generic Python subprocess controller.
Only the repository's fixed, inert Turbo module can start, on an owned
ephemeral local port, after a separately reviewed host SHA pin is installed.
This does not authorize tool dispatch, scanning, signed Task/0033 or release.
Never instantiate/start this service from ordinary API startup.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import stat
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:  # pragma: no cover - deterministic fail closed
    psutil = None


_REPO = Path(__file__).resolve().parents[3]
_SOURCE = _REPO / "mcp-servers" / "python" / "turbo_intruder_mcp.py"
_ALLOWED = {
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "TEMP",
    "TMP",
    "TMPDIR",
}
_RESERVED = frozenset(
    {8081, 8082, 8083, 8084, 8085, 8086, 8087, 8091, 8096, 8097, 8098, 8200, 5173, 5432, 6379, 7687}
)


class PythonInertHostDenied(RuntimeError):
    """Fixed outcome: never serialize source path, arguments or environment."""

    def __init__(self) -> None:
        super().__init__("Host-pinned inert Python process unavailable")


@dataclass(frozen=True)
class PythonInertProcessObservation:
    service_id: str
    process_owned: bool
    listener_owned: bool
    health_unavailable: bool
    signed_action_verified: bool = False
    native_execution_enabled: bool = False
    independent_target_effect_verified: bool = False
    production_certified: bool = False


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(path: Path) -> tuple[int, int, int, int, int]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or getattr(metadata, "st_nlink", 1) != 1
            or metadata.st_size > 250000
            or metadata.st_size < 200
            or getattr(metadata, "st_file_attributes", 0) & 0x400
        ):
            raise PythonInertHostDenied()
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_mode,
        )
    except (OSError, ValueError):
        raise PythonInertHostDenied() from None


def _safe_environment() -> dict[str, str]:
    # Do not transmit credentials, signed ROE, config, proxies or cloud keys
    # into a diagnostic subprocess, even if they exist in the API host env.
    return {key: value for key, value in os.environ.items() if key.upper() in _ALLOWED}


def _health(port: int) -> bool:
    class DenyRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args: object, **_kwargs: object) -> None:
            raise PythonInertHostDenied()

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), DenyRedirect())
    try:
        opener.open(f"http://127.0.0.1:{port}/health", timeout=0.5)
        return False  # Unexpected 200 is not the disabled Turbo server.
    except urllib.error.HTTPError as error:
        if error.code != 503:
            return False
        try:
            wire = error.read(2049)
            value = json.loads(wire)
        except (ValueError, TypeError, UnicodeError, OSError):
            return False
        return (
            len(wire) <= 2048
            and type(value) is dict
            and value.get("server_id") == "turbo-intruder-mcp"
            and value.get("status") == "unavailable"
            and value.get("execution_enabled") is False
            and value.get("source_side_signed_authorization_verified") is False
        )
    except (urllib.error.URLError, TimeoutError, OSError, PythonInertHostDenied):
        return False


class PythonInertHostSupervisor:
    """Host-only opt-in: one disabled Turbo process, never tool dispatch."""

    def __init__(
        self,
        *,
        reviewed_source_sha256: str,
        reviewed_interpreter_sha256: str,
        reviewed_runtime_sha256: str,
        explicitly_opted_in: bool = False,
    ) -> None:
        self._pin = reviewed_source_sha256
        self._python_pin = reviewed_interpreter_sha256
        self._runtime_pin = reviewed_runtime_sha256
        self._opt_in = explicitly_opted_in is True
        self._child: Optional[asyncio.subprocess.Process] = None
        self._port: Optional[int] = None
        self._original_identity: Optional[tuple[int, int, int, int, int]] = None
        # Windows venv python.exe is a launcher and may run uvicorn in its
        # direct child. Record exact child PID+creation timestamp for teardown.
        self._observed_workers: dict[int, float] = {}
        self._lock = asyncio.Lock()

    def _reviewed_source(self) -> tuple[int, int, int, int, int]:
        if not self._opt_in or type(self._pin) is not str or len(self._pin) != 64:
            raise PythonInertHostDenied()
        if any(c not in "0123456789abcdef" for c in self._pin) or psutil is None:
            raise PythonInertHostDenied()
        current = _identity(_SOURCE)
        try:
            if _hash_file(_SOURCE) != self._pin or _identity(_SOURCE) != current:
                raise PythonInertHostDenied()
            # A reviewed script digest alone does not pin the executable
            # interpreter. Windows virtualenv stubs can launch a DIFFERENT
            # base python.exe; both host-owned bytes need independent pins.
            for executable, expected in (
                (Path(sys.executable).resolve(strict=True), self._python_pin),
                (
                    Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True),
                    self._runtime_pin,
                ),
            ):
                if (
                    type(expected) is not str
                    or len(expected) != 64
                    or any(ch not in "0123456789abcdef" for ch in expected)
                    or not executable.is_file()
                    or executable.stat().st_size > 100_000_000
                    or _hash_file(executable) != expected
                ):
                    raise PythonInertHostDenied()
        except OSError:
            raise PythonInertHostDenied() from None
        return current

    async def start(self) -> PythonInertProcessObservation:
        async with self._lock:
            if self._child is not None:
                raise PythonInertHostDenied()
            identity = self._reviewed_source()
            # Privately reserve an unused ephemeral local socket, then release
            # immediately before launching. Competing bind causes safe denial.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as binding:
                binding.bind(("127.0.0.1", 0))
                port = binding.getsockname()[1]
            if port in _RESERVED or port < 1024:
                raise PythonInertHostDenied()
            try:
                child = await asyncio.create_subprocess_exec(
                    sys.executable,
                    str(_SOURCE),
                    "--port",
                    str(port),
                    cwd=str(_REPO),
                    env=_safe_environment(),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                self._child = child
                self._port = port
                self._original_identity = identity
                for _ in range(50):
                    if child.returncode is not None:
                        raise PythonInertHostDenied()
                    await asyncio.sleep(0.08)
                    try:
                        observed = await self._observe()
                    except PythonInertHostDenied:
                        continue
                    if observed.health_unavailable:
                        return observed
                raise PythonInertHostDenied()
            except BaseException:
                await self._stop_owned()
                raise

    async def _observe(self) -> PythonInertProcessObservation:
        child = self._child
        port = self._port
        if child is None or port is None or child.returncode is not None:
            raise PythonInertHostDenied()
        if self._reviewed_source() != self._original_identity:
            raise PythonInertHostDenied()
        try:
            parent = psutil.Process(child.pid)
            owned = [parent] + parent.children(recursive=True)
            expected = {
                str(Path(sys.executable).resolve()).casefold(),
                str(Path(getattr(sys, "_base_executable", sys.executable)).resolve()).casefold(),
            }
            if any(item.exe().casefold() not in expected for item in owned):
                raise PythonInertHostDenied()
            matching = [
                item
                for item in owned
                if any(
                    conn.status == psutil.CONN_LISTEN
                    and conn.laddr.port == port
                    and conn.laddr.ip == "127.0.0.1"
                    for conn in item.net_connections(kind="tcp")
                )
            ]
            if len(matching) != 1:
                raise PythonInertHostDenied()
            self._observed_workers[matching[0].pid] = matching[0].create_time()
        except (psutil.Error, AttributeError, OSError):
            raise PythonInertHostDenied() from None
        # urllib is blocking: keep server polling off the event loop.
        available = await asyncio.to_thread(_health, port)
        if not available:
            raise PythonInertHostDenied()
        return PythonInertProcessObservation(
            service_id="turbo-intruder-mcp",
            process_owned=True,
            listener_owned=True,
            health_unavailable=True,
        )

    async def status(self) -> PythonInertProcessObservation:
        async with self._lock:
            try:
                return await self._observe()
            except PythonInertHostDenied:
                await self._stop_owned()
                raise

    async def _stop_owned(self) -> None:
        child = self._child
        known = dict(self._observed_workers)
        self._observed_workers.clear()
        self._child = None
        self._port = None
        self._original_identity = None
        if child is None:
            return
        descendants: dict[int, float] = {}
        try:
            parent = psutil.Process(child.pid)
            # Never kill an unrelated process merely because it reused an
            # integer PID. Children are collected through our own live parent.
            descendants = {p.pid: p.create_time() for p in parent.children(recursive=True)}
        except psutil.Error:
            pass
        # A Windows launcher might have exited and reparented the service.
        # An observed worker may only be stopped with its pinned creation
        # identity; otherwise leave UNKNOWN rather than kill an unknown PID.
        for pid, started in {**descendants, **known}.items():
            try:
                process = psutil.Process(pid)
                if abs(process.create_time() - started) < 0.001:
                    process.terminate()
                    try:
                        await asyncio.to_thread(process.wait, 2.0)
                    except psutil.TimeoutExpired:
                        if abs(process.create_time() - started) < 0.001:
                            process.kill()
                            await asyncio.to_thread(process.wait, 2.0)
            except (psutil.Error, OSError):
                continue
        if child.returncode is None:
            child.terminate()
            try:
                await asyncio.wait_for(child.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                child.kill()
                await asyncio.wait_for(child.wait(), timeout=2.0)
        else:
            await child.wait()

    async def stop(self) -> None:
        async with self._lock:
            await self._stop_owned()
