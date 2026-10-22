"""Owned, bounded Windows Go MCP listener qualification (NO native execution).

Six genuine cmd binaries are built offline and launched one at a time with
strictly local, disposable metadata-only trust. No app services, databases,
targets, providers, Docker, scanner handlers or arbitrary network origins.

The "configured" mode allows only *declaration* of SDK inert authority_status.
The source HTTPS endpoint is an unused loopback port: no grant is created,
redeemed, signed, or submitted, so this is NOT 0029/0033 qualification.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import platform
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterator
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import psutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

GO_ROOT = Path(__file__).resolve().parents[2] / "mcp-servers" / "go"
SIX_NATIVE = {
    "recon-mcp": (8082, "subfinder_enum"),
    "payload-mcp": (8083, "generate_payload"),
    "nuclei-mcp": (8084, "scan"),
    "shodan-mcp": (8085, "shodan_lookup"),
    "threat-intel-mcp": (8086, "cve_lookup"),
    "security-bridge": (8087, "sqlmap"),
}
RUNTIME_OPT_IN = "OSOP_NATIVE_SIX_GO_PROCESS_RUNTIME_20261020"
_APP_TRUST_KEYS = {
    "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
    "OSOP_NATIVE_MCP_REDEEM_URL",
    "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM",
    "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
    "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON",
}
_SAFE_WINDOWS_KEYS = {
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
    "HOMEDRIVE",
    "HOMEPATH",
}
_SAFE_PATHS = frozenset({"/health", "/mcp/initialize", "/mcp/execute"})


def ensure_windows_opt_in() -> None:
    if platform.system() != "Windows" or os.name != "nt":
        raise RuntimeError("This qualification requires actual Windows Go processes")
    if os.getenv(RUNTIME_OPT_IN) != "1":
        raise RuntimeError("Explicit process runtime qualification opt-in required")


def clean_child_environment() -> dict[str, str]:
    """Do not inherit API tokens, proxies, provider keys or app DB credentials."""
    return {key: value for key, value in os.environ.items() if key.upper() in _SAFE_WINDOWS_KEYS}


def choose_owned_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        number = int(sock.getsockname()[1])
    if not 1024 <= number <= 65535:
        raise RuntimeError("Native test loopback port unavailable")
    return number


def build_all_six(directory: Path) -> dict[str, Path]:
    """Build actual cmd entrypoints, offline, into one test-owned temporary dir."""
    ensure_windows_opt_in()
    if not GO_ROOT.is_dir() or not directory.is_dir():
        raise RuntimeError("Go module or owned build output missing")
    env = clean_child_environment()
    env.update(
        {
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOOS": "windows",
            "GOARCH": "amd64",
            "CGO_ENABLED": "0",
        }
    )
    binaries = {}
    for service in SIX_NATIVE:
        destination = directory / f"{service}.exe"
        try:
            result = subprocess.run(
                ["go", "build", "-trimpath", "-o", str(destination), f"./cmd/{service}"],
                cwd=GO_ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=110,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(
                f"Offline Go build unavailable for {service}: {type(exc).__name__}"
            ) from exc
        if result.returncode != 0 or not destination.is_file():
            # Do not echo build logs or tokens from an unexpected environment.
            raise RuntimeError(f"Offline Go build failed for {service} (exit {result.returncode})")
        if destination.read_bytes()[:2] != b"MZ":
            raise RuntimeError(f"Non-Windows binary produced for {service}")
        binaries[service] = destination
    return binaries


def pinned_public_metadata() -> tuple[str, str]:
    """Only an ephemeral PUBLIC issuer key + syntactically valid root PEM."""
    issuer_public = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    encoded_pub = base64.urlsafe_b64encode(issuer_public).decode("ascii").rstrip("=")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "isolated-native-test-root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private, hashes.SHA256())
    )
    root = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return encoded_pub, root


def native_environment(
    service: str, port: int, mode: str, *, trust: tuple[str, str] | None = None
) -> dict[str, str]:
    if service not in SIX_NATIVE or mode not in {"unconfigured", "incomplete", "configured"}:
        raise ValueError("Explicit known native server and test mode required")
    if not 1024 <= port <= 65535:
        raise ValueError("Bounded test-local port required")
    env = clean_child_environment()
    override = (
        "OSOP_RECON_MCP_LOCAL_PORT" if service == "recon-mcp" else "OSOP_NATIVE_MCP_LOCAL_PORT"
    )
    env[override] = str(port)
    if mode != "unconfigured":
        if trust is None:
            raise ValueError("Ephemeral public trust fixture required")
        public, pem = trust
        env["OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON"] = json.dumps({"process-test-key": public})
        if mode == "configured":
            validator_port = choose_owned_port()
            if validator_port == port:
                raise RuntimeError("Native and intentionally unreachable validator ports collide")
            env["OSOP_NATIVE_MCP_REDEEM_URL"] = (
                f"https://127.0.0.1:{validator_port}/native-grants/redeem"
            )
            env["OSOP_NATIVE_MCP_REDEEM_ROOT_PEM"] = pem
            # Not an app/provider secret. Never authenticate to a live service.
            env["OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON"] = json.dumps(
                {service: "qualification-inert-only-" + service + "-no-provider"}
            )
    if mode == "unconfigured" and _APP_TRUST_KEYS.intersection(env):
        raise RuntimeError("Unexpected native trusted runtime inherited")
    return env


def _owner_listens(pid: int, port: int) -> bool:
    """Never mistake a different process already bound to the test port."""
    try:
        sockets = psutil.Process(pid).net_connections(kind="tcp")
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False
    return any(
        candidate.status == psutil.CONN_LISTEN
        and candidate.laddr.ip == "127.0.0.1"
        and candidate.laddr.port == port
        for candidate in sockets
    )


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise RuntimeError("Local test unexpectedly redirected")


def local_request(
    port: int, path: str, body: dict[str, Any] | None = None
) -> tuple[int, dict[str, Any]]:
    if path not in _SAFE_PATHS or not 1024 <= port <= 65535:
        raise ValueError("No arbitrary URL or route accepted by native test")
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("ascii")
    if data is not None and len(data) > 8192:
        raise ValueError("Native test request size exceeded")
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method="GET" if data is None else "POST",
    )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(request, timeout=0.75)
    except HTTPError as exc:
        response = exc
    with response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise RuntimeError("Oversized native process response")
        parsed = json.loads(raw)
        if type(parsed) is not dict:
            raise RuntimeError("Non-object native process response")
        return response.status, parsed


@dataclass
class OwnedGoProcess:
    service: str
    port: int
    process: subprocess.Popen[bytes]
    _stderr: BinaryIO

    @property
    def pid(self) -> int:
        return self.process.pid

    def safe_stderr_kind(self) -> str:
        """Only a bounded categorical diagnostic; never echo private logs."""
        self._stderr.flush()
        self._stderr.seek(0)
        lines = self._stderr.read(8192).decode("utf-8", "replace")
        if "panic:" in lines or "http: panic serving" in lines:
            return "go_http_panic"
        if "fatal error:" in lines:
            return "go_fatal_runtime"
        if "bind:" in lines or "Only one usage" in lines:
            return "bind_failed"
        if "trust" in lines or "credential" in lines:
            return "trust_configuration_failure"
        return "none_or_other"

    def wait_for_health(self, *, deadline: float = 4.0) -> tuple[int, dict[str, Any]]:
        stop = time.monotonic() + deadline
        while time.monotonic() < stop:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"Owned {self.service} Go process exited ({self.process.returncode})"
                )
            if _owner_listens(self.pid, self.port):
                try:
                    status, document = local_request(self.port, "/health")
                    if document.get("server_id") == self.service:
                        return status, document
                except (URLError, OSError, ValueError):
                    pass
            time.sleep(0.08)
        raise RuntimeError(f"Owned {self.service} process never bound its own loopback port")


@contextlib.contextmanager
def isolated_go_process(
    service: str, binary: Path, mode: str, *, trust: tuple[str, str] | None = None
) -> Iterator[OwnedGoProcess]:
    """Always terminate ONLY the fresh Popen PID, even on assertion failures."""
    ensure_windows_opt_in()
    if service not in SIX_NATIVE or not binary.is_file() or binary.suffix.lower() != ".exe":
        raise ValueError("Only a built, owned six-Go Windows executable is allowed")
    port = choose_owned_port()
    env = native_environment(service, port, mode, trust=trust)
    with tempfile.TemporaryFile(mode="w+b") as stderr_capture:
        process = subprocess.Popen(
            [str(binary)],
            cwd=GO_ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr_capture,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        instance = OwnedGoProcess(
            service=service, port=port, process=process, _stderr=stderr_capture
        )
        try:
            yield instance
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if process.poll() is None:
                raise RuntimeError(f"Owned {service} process remained after PID-only termination")
