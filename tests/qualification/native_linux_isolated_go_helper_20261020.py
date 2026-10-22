"""Real Linux Recon qualification in disposable, constrained Docker resources.

The native worker uses a private Docker --internal bridge and has no mounts,
published ports, privileged process, writable root or scanner authorization.
An optional bounded byte-stream tunnel uses docker exec stdin/stdout to join
Go's 127.0.0.1-only TLS dial to one Windows-hosted 127.0.0.1 FastAPI port.
No container network can reach the Windows host or internet. TLS remains
end-to-end; Go validates the REAL FastAPI certificate against its pinned PEM.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import socket
import struct
import subprocess
import tempfile
import threading
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Optional
from urllib.parse import urlsplit

from ai_osop.orchestrator.native_mcp_docker_supervisor import OWNER_LABEL as _HOST_SUPERVISOR_LABEL

_IMAGE = "python:3.11-slim"
_LABEL = "osop.native.linux.qualification"
_UID = "65534:65534"
_RELAY_PORT = 18443
_MAX_BINARY = 32 * 1024 * 1024
_TRUST_ENV = {
    "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
    "OSOP_NATIVE_MCP_REDEEM_URL",
    "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM",
    "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
    # The resource-bound native grant is NOT admissible without a distinct,
    # independently signed and source-fenced 0033 supervisor provision.
    "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON",
}
_ALLOWED_ENV = _TRUST_ENV | {
    "OSOP_RECON_MCP_LOCAL_PORT",
    "OSOP_NATIVE_MCP_LOCAL_TEST_TRACE",
    "OSOP_NATIVE_MCP_STAGE_ROOT",
    "OSOP_NATIVE_STAGE_RECEIPT_ED25519_SEED_B64",
    "OSOP_NATIVE_STAGE_RECEIPT_KID",
    # The independent supervisor signer private key/credential is NEVER
    # injected into the native Go container.
}

# The internal container accepts LOCAL TCP only. Fixed nine-byte binary
# messages relay raw TLS bytes over docker-exec stdin/stdout, with a bounded
# count of concurrent connections. Never executes HTTP, chooses a destination,
# loads a certificate, changes trust, or reaches any external network.
_TUNNEL_CODE = """
import socket
import struct
import sys
import threading

connections = {}
lock = threading.Lock()
write_lock = threading.Lock()
slots = threading.BoundedSemaphore(8)
counter = 0
header = struct.Struct("!cII")

def exact(stream, length):
    data = bytearray()
    while len(data) < length:
        part = stream.read(length - len(data))
        if not part:
            return None
        data.extend(part)
    return bytes(data)

def send(kind, ident, payload=b""):
    if len(payload) > 32768:
        return
    with write_lock:
        sys.stdout.buffer.write(header.pack(kind, ident, len(payload)) + payload)
        sys.stdout.buffer.flush()

def read_client(ident, peer):
    try:
        while True:
            data = peer.recv(32768)
            if not data:
                break
            send(b"D", ident, data)
    except OSError:
        pass
    finally:
        with lock:
            connections.pop(ident, None)
        peer.close()
        send(b"X", ident)
        slots.release()

def receive_host():
    while True:
        raw = exact(sys.stdin.buffer, 9)
        if raw is None:
            break
        kind, ident, length = header.unpack(raw)
        if length > 32768:
            break
        data = exact(sys.stdin.buffer, length)
        if data is None:
            break
        with lock:
            peer = connections.get(ident)
        if peer is None:
            continue
        try:
            if kind == b"D":
                peer.sendall(data)
            elif kind == b"X":
                peer.shutdown(socket.SHUT_WR)
        except OSError:
            pass

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 18443))
sock.listen(8)
threading.Thread(target=receive_host, daemon=True).start()
send(b"R", 0)
while True:
    peer, _ = sock.accept()
    if not slots.acquire(blocking=False):
        peer.close()
        continue
    counter += 1
    with lock:
        connections[counter] = peer
    send(b"O", counter)
    threading.Thread(target=read_client, args=(counter, peer), daemon=True).start()
"""

_POST_CODE = """
import json
import sys
import urllib.error
import urllib.request
try:
    item = json.loads(sys.stdin.buffer.read(32769))
    if item["path"] not in ("/mcp/initialize", "/mcp/execute", "/native-supervisor/provision"):
        raise ValueError()
    if item["path"] == "/native-supervisor/provision" and item["headers"]:
        raise ValueError()
    data = json.dumps(item["payload"], separators=(",", ":")).encode()
    if item["path"] == "/native-supervisor/provision" and len(data) > 4096:
        raise ValueError()
    req = urllib.request.Request(
        "http://127.0.0.1:8082" + item["path"],
        data=data, headers={"Content-Type": "application/json", **item["headers"]},
        method="POST",
    )
    try:
        # Go checks the actual TCP RemoteAddr, never X-Forwarded-For. Bypass
        # any inherited proxy environment so this is container-local TCP.
        res = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            req, timeout=4
        )
    except urllib.error.HTTPError as exc:
        res = exc
    with res:
        raw = res.read(65537)
        if len(raw) > 65536:
            raise ValueError()
        print(json.dumps({"status": res.status, "body": json.loads(raw)}))
except Exception:
    sys.exit(1)
"""

_HEALTH_CODE = """
import json
import urllib.error
import urllib.request
try:
    try:
        res = urllib.request.urlopen("http://127.0.0.1:8082/health", timeout=0.5)
    except urllib.error.HTTPError as exc:
        res = exc
    with res:
        print(json.dumps({"status": res.status, "body": json.loads(res.read(65536))}))
except Exception:
    raise SystemExit(1)
"""


def _port(number: int) -> int:
    if isinstance(number, bool) or not isinstance(number, int) or not 1024 <= number <= 65535:
        raise ValueError("Ephemeral validator port must be 1024..65535")
    return number


def _environment(native_env: dict[str, str], host_port: Optional[int]) -> dict[str, str]:
    if not isinstance(native_env, dict) or any(
        key not in _ALLOWED_ENV or not isinstance(value, str) for key, value in native_env.items()
    ):
        raise ValueError("Unexpected native Recon environment variable")
    clean = dict(native_env)
    clean["OSOP_RECON_MCP_LOCAL_PORT"] = "8082"
    if clean.get("OSOP_NATIVE_MCP_STAGE_ROOT") not in (None, "/run/osop-native-stage"):
        raise ValueError("Only dedicated native stage tmpfs root permitted")
    if host_port is None:
        if any(clean.get(key) for key in _TRUST_ENV):
            raise ValueError("Native trust without independently reachable validator")
    else:
        if any(not clean.get(key) for key in _TRUST_ENV):
            raise ValueError("Complete independent pinned HTTPS trust required")
        u = urlsplit(clean["OSOP_NATIVE_MCP_REDEEM_URL"])
        if (
            u.scheme != "https"
            or u.netloc != f"127.0.0.1:{_RELAY_PORT}"
            or u.path != "/native-grants/redeem"
            or u.query
            or u.fragment
            or u.username is not None
        ):
            raise ValueError("Native redemption must use pinned local TLS tunnel URL")
        if "-----BEGIN CERTIFICATE-----" not in clean["OSOP_NATIVE_MCP_REDEEM_ROOT_PEM"]:
            raise ValueError("Pinned FastAPI certificate required")
        try:
            secret = json.loads(clean["OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON"])
            public = json.loads(clean["OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON"])
            supervisor = json.loads(clean["OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"])
        except (ValueError, TypeError):
            raise ValueError("Malformed native trust configuration") from None
        if (
            not isinstance(secret, dict)
            or set(secret) != {"recon-mcp"}
            or not isinstance(secret["recon-mcp"], str)
            or not 20 <= len(secret["recon-mcp"]) <= 512
            or not isinstance(public, dict)
            or not public
            or not isinstance(supervisor, dict)
            or not 1 <= len(supervisor) <= 8
        ):
            raise ValueError("Independent native server identity required")
        if len(clean["OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"]) > 8192:
            raise ValueError("Independent native supervisor trust too large")
        issuer_values = set(public.values())
        for supervisor_id, identity in supervisor.items():
            if (
                not isinstance(supervisor_id, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,95}", supervisor_id) is None
                or not isinstance(identity, dict)
                or set(identity) != {"kid", "public_key", "secret_sha256"}
                or not isinstance(identity["kid"], str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identity["kid"]) is None
                or not isinstance(identity["public_key"], str)
                or not isinstance(identity["secret_sha256"], str)
                or re.fullmatch(r"[a-f0-9]{64}", identity["secret_sha256"]) is None
                or identity["public_key"] in issuer_values
            ):
                raise ValueError("Independent supervisor public trust required")
            encoded = identity["public_key"]
            try:
                key = base64.b64decode(
                    encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
                )
            except (ValueError, base64.binascii.Error):
                raise ValueError("Noncanonical independent supervisor key") from None
            if (
                len(key) != 32
                or base64.urlsafe_b64encode(key).decode("ascii").rstrip("=") != encoded
            ):
                raise ValueError("Noncanonical independent supervisor key")
    if sum(len(k) + len(v) for k, v in clean.items()) > 75000:
        raise ValueError("Native environment too large")
    return clean


def _verify_linux_elf(binary: Path) -> None:
    binary = Path(binary).resolve(strict=True)
    size = binary.stat().st_size
    if not binary.is_file() or not 1024 <= size <= _MAX_BINARY:
        raise ValueError("Bounded actual Linux executable required")
    with binary.open("rb") as stream:
        prefix = stream.read(20)
    if (
        prefix[:4] != b"\x7fELF"
        or prefix[4:6] != b"\x02\x01"
        or struct.unpack_from("<H", prefix, 18)[0] != 62
    ):
        raise ValueError("Only cross-compiled Linux amd64 ELF is accepted")


def build_linux_recon_binary(destination: Path) -> Path:
    """Build the real Go cmd/recon-mcp offline; caller owns the output path."""
    destination = Path(destination).resolve()
    if not destination.parent.is_dir() or destination.exists():
        raise ValueError("Fresh binary destination in an existing folder required")
    go_root = Path(__file__).resolve().parents[2] / "mcp-servers" / "go"
    env = os.environ.copy()
    env.update(
        {
            "GOOS": "linux",
            "GOARCH": "amd64",
            "CGO_ENABLED": "0",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
        }
    )
    try:
        subprocess.run(
            ["go", "build", "-trimpath", "-o", str(destination), "./cmd/recon-mcp"],
            cwd=go_root,
            env=env,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=100,
        )
        _verify_linux_elf(destination)
        return destination
    except Exception:
        destination.unlink(missing_ok=True)
        raise RuntimeError("Offline cross-compilation failed (output redacted)") from None


def _exec(
    name: str, command: list[str], *, data: Optional[bytes] = None, timeout: int = 10
) -> bytes:
    """Run bounded docker-exec command, never exposing secret stderr or args."""
    try:
        result = subprocess.run(
            ["docker", "exec", "-i", "--user", _UID, name, *command],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise RuntimeError("Isolated Docker exec unavailable (logs redacted)") from None
    if len(result.stdout) > 65536:
        raise RuntimeError("Isolated Docker output exceeded byte bound")
    return result.stdout


def _remove_owned(client: Any, container: Any, owner: str) -> None:
    if container is None:
        return
    try:
        current = client.containers.get(container.id)
    except Exception as exc:
        if exc.__class__.__name__ == "NotFound":
            return
        raise
    if current.labels.get(_LABEL) != owner:
        raise RuntimeError("Refusing to remove non-owned Docker container")
    current.remove(force=True, v=True)


def _remove_network(client: Any, network: Any, owner: str) -> None:
    if network is None:
        return
    try:
        current = client.networks.get(network.id)
    except Exception as exc:
        if exc.__class__.__name__ == "NotFound":
            return
        raise
    if (current.attrs.get("Labels") or {}).get(_LABEL) != owner:
        raise RuntimeError("Refusing to remove non-owned Docker network")
    current.reload()
    if current.containers:
        raise RuntimeError("Private Docker network has unexpected members")
    current.remove()


def _verify_docker_isolation(network: Any, container: Any, owner: str) -> None:
    """Inspect the daemon's ACTUAL constraints before executing the Go binary."""
    network.reload()
    container.reload()
    n = network.attrs
    attrs = container.attrs
    host = attrs["HostConfig"]
    config = attrs["Config"]
    links = attrs["NetworkSettings"]["Networks"]
    stage = (host.get("Tmpfs") or {}).get("/run/osop-native-stage", "")
    executable = (host.get("Tmpfs") or {}).get("/qual", "")
    required_stage = {
        "rw",
        "noexec",
        "nodev",
        "nosuid",
        "mode=0700",
        "uid=65534",
        "gid=65534",
    }
    required_qual = {"rw", "exec", "nodev", "nosuid", "uid=65534", "gid=65534"}
    if not (
        n.get("Internal") is True
        and n.get("Driver") == "bridge"
        and n.get("Labels", {}).get(_LABEL) == owner
        and n.get("Labels", {}).get(_HOST_SUPERVISOR_LABEL) == owner
        and set(links) == {network.name}
        and config.get("User") == _UID
        and config.get("Labels", {}).get(_LABEL) == owner
        and config.get("Labels", {}).get(_HOST_SUPERVISOR_LABEL) == owner
        and host.get("ReadonlyRootfs") is True
        and host.get("Privileged") is False
        and set(host.get("CapDrop") or []) == {"ALL"}
        and "no-new-privileges:true" in (host.get("SecurityOpt") or [])
        and host.get("PidsLimit") == 64
        and host.get("Memory", 0) <= 192 * 1024 * 1024
        and not host.get("Binds")
        and not host.get("Mounts")
        and not host.get("PortBindings")
        and not attrs.get("Mounts")
        and required_stage.issubset(set(stage.split(",")))
        and required_qual.issubset(set(executable.split(",")))
    ):
        raise RuntimeError("Docker daemon did not preserve isolated Recon constraints")


class _StdioTlsTunnel:
    """Fixed-port transparent TLS transport; no HTTP parser or external route."""

    _frame = struct.Struct("!cII")

    def __init__(self, container_name: str, host_port: int) -> None:
        self._host_port = _port(host_port)
        self._write_lock = threading.Lock()
        self._connections_lock = threading.Lock()
        self._connections: dict[int, socket.socket] = {}
        self._ready = threading.Event()
        self._failed = False
        self._process = subprocess.Popen(
            [
                "docker",
                "exec",
                "-i",
                "--user",
                _UID,
                container_name,
                "python3",
                "-u",
                "-c",
                _TUNNEL_CODE,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        self._reader = threading.Thread(target=self._receive, daemon=True)
        self._reader.start()

    @staticmethod
    def _exact(stream: Any, length: int) -> Optional[bytes]:
        output = bytearray()
        while len(output) < length:
            chunk = stream.read(length - len(output))
            if not chunk:
                return None
            output.extend(chunk)
        return bytes(output)

    def _send(self, kind: bytes, ident: int, payload: bytes = b"") -> None:
        if len(payload) > 32768:
            return
        with self._write_lock:
            if self._process.stdin is None:
                return
            try:
                self._process.stdin.write(self._frame.pack(kind, ident, len(payload)) + payload)
                self._process.stdin.flush()
            except (OSError, ValueError):
                self._failed = True

    def _read_host(self, ident: int, upstream: socket.socket) -> None:
        try:
            while True:
                data = upstream.recv(32768)
                if not data:
                    break
                self._send(b"D", ident, data)
        except OSError:
            pass
        finally:
            self._send(b"X", ident)

    def _receive(self) -> None:
        try:
            stdout = self._process.stdout
            if stdout is None:
                return
            while True:
                header = self._exact(stdout, self._frame.size)
                if header is None:
                    return
                kind, ident, length = self._frame.unpack(header)
                if length > 32768:
                    return
                data = self._exact(stdout, length)
                if data is None:
                    return
                if kind == b"R" and ident == 0 and length == 0:
                    self._ready.set()
                elif kind == b"O" and length == 0:
                    try:
                        # This host-side connection cannot dial anything except
                        # the exact explicitly supplied 127.0.0.1 FastAPI port.
                        upstream = socket.create_connection(
                            ("127.0.0.1", self._host_port), timeout=3
                        )
                        upstream.settimeout(7)
                        with self._connections_lock:
                            self._connections[ident] = upstream
                        threading.Thread(
                            target=self._read_host, args=(ident, upstream), daemon=True
                        ).start()
                    except OSError:
                        self._send(b"X", ident)
                elif kind in (b"D", b"X"):
                    with self._connections_lock:
                        upstream = self._connections.get(ident)
                    if upstream is None:
                        continue
                    try:
                        if kind == b"D":
                            upstream.sendall(data)
                        else:
                            upstream.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    if kind == b"X":
                        with self._connections_lock:
                            self._connections.pop(ident, None)
                        upstream.close()
                else:
                    return
        finally:
            self._failed = True
            self._ready.set()
            with self._connections_lock:
                streams = list(self._connections.values())
                self._connections.clear()
            for item in streams:
                item.close()

    def await_ready(self) -> None:
        if not self._ready.wait(timeout=8) or self._failed:
            raise RuntimeError("Loopback-only Docker TLS tunnel failed")

    def close(self) -> None:
        try:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            for stream in (self._process.stdin, self._process.stdout):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


@dataclass
class IsolatedLinuxGoWorker:
    """Real nonroot recon-mcp, queried only inside its Docker net namespace."""

    container_id: str
    network_id: str
    validator_url: Optional[str]
    _container_name: str

    async def post(
        self, path: str, payload: dict[str, Any], headers: Optional[dict[str, str]] = None
    ) -> tuple[int, dict[str, Any]]:
        if path not in (
            "/mcp/initialize",
            "/mcp/execute",
            "/native-supervisor/provision",
        ) or not isinstance(payload, dict):
            raise ValueError("Only real native MCP paths and JSON objects accepted")
        header_values = {} if headers is None else dict(headers)
        if path == "/native-supervisor/provision" and header_values:
            raise ValueError("Independent supervisor provision cannot use caller-supplied headers")
        if path == "/native-supervisor/provision" and set(payload) != {
            "claims",
            "kid",
            "signature",
        }:
            raise ValueError("Complete independent supervisor envelope required")
        if any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9-]+", key) is None
            or "\r" in value
            or "\n" in value
            for key, value in header_values.items()
        ):
            raise ValueError("Invalid native request headers")
        encoded = json.dumps(
            {"path": path, "payload": payload, "headers": header_values},
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > (4096 if path == "/native-supervisor/provision" else 32768):
            raise ValueError("MCP qualification request exceeds byte bound")
        output = await asyncio.to_thread(
            _exec,
            self._container_name,
            ["python3", "-c", _POST_CODE],
            data=encoded,
            timeout=12,
        )
        try:
            result = json.loads(output)
            if not isinstance(result["status"], int) or not isinstance(result["body"], dict):
                raise ValueError()
            return result["status"], result["body"]
        except (ValueError, KeyError, TypeError):
            raise RuntimeError("Invalid real native MCP result (redacted)") from None

    async def health(self) -> tuple[int, dict[str, Any]]:
        result = await asyncio.to_thread(
            _exec, self._container_name, ["python3", "-c", _HEALTH_CODE], timeout=6
        )
        try:
            parsed = json.loads(result)
            return parsed["status"], parsed["body"]
        except (ValueError, TypeError, KeyError):
            raise RuntimeError("Malformed native Linux health result") from None

    async def stage_root_info(self) -> dict[str, Any]:
        """Independently inspect the exact private stage mount and empty root."""
        inspector = """
import json, os, stat
root = "/run/osop-native-stage"
st = os.stat(root, follow_symlinks=False)
items = os.listdir(root)
mount = None
with open("/proc/self/mountinfo", encoding="utf-8") as stream:
    for line in stream:
        halves = line.split(" - ", 1)
        left = halves[0].split()
        right = halves[1].split() if len(halves) == 2 else []
        if len(left) > 5 and left[4] == root and len(right) > 2:
            mount = {"kind": right[0], "flags": sorted(set(
                left[5].split(",") + right[2].split(",")
            ))}
            break
print(json.dumps({
    "uid": st.st_uid, "gid": st.st_gid,
    "mode": stat.S_IMODE(st.st_mode), "items": sorted(items),
    "mount": mount,
}))
"""
        output = await asyncio.to_thread(
            _exec, self._container_name, ["python3", "-c", inspector], timeout=6
        )
        try:
            value = json.loads(output)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, TypeError):
            raise RuntimeError("Private stage inspection unavailable") from None

    async def stage_root_empty(self) -> bool:
        info = await self.stage_root_info()
        mount = info.get("mount") or {}
        return (
            info.get("items") == []
            and info.get("uid") == 65534
            and info.get("gid") == 65534
            and info.get("mode") == 0o700
            and mount.get("kind") == "tmpfs"
            and {"noexec", "nodev", "nosuid"}.issubset(set(mount.get("flags", [])))
        )


@asynccontextmanager
async def isolated_linux_go_worker(
    *,
    binary: Optional[Path] = None,
    native_env: dict[str, str],
    validator_host_port: Optional[int] = None,
) -> AsyncIterator[IsolatedLinuxGoWorker]:
    """Start real isolated Recon; route pinned HTTPS to REAL host FastAPI.

    Optional validator_host_port requires real uvicorn listening on Windows
    127.0.0.1 at that exact port. Its certificate needs IP SAN 127.0.0.1
    matching the pinned Go root PEM, checked end-to-end through opaque bytes.
    No external target/provider, synthetic validator or existing DB is used.
    """
    if validator_host_port is not None:
        _port(validator_host_port)
    child_env = _environment(native_env, validator_host_port)
    try:
        import docker

        client = docker.from_env(timeout=8)
        details = client.info()
        if details.get("OSType") != "linux" or details.get("Architecture") not in (
            "x86_64",
            "amd64",
        ):
            raise RuntimeError("Linux amd64 Docker engine required")
        image_id = client.images.get(_IMAGE).id  # Cached only; never pull.
    except Exception:
        raise RuntimeError("Cached Linux Docker engine unavailable") from None

    owner = "osop-native-linux-" + uuid.uuid4().hex
    network = recon = tunnel = None
    try:
        with tempfile.TemporaryDirectory(prefix="osop-native-linux-") as tmp:
            executable = (
                await asyncio.to_thread(build_linux_recon_binary, Path(tmp) / "recon-mcp")
                if binary is None
                else Path(binary).resolve()
            )
            await asyncio.to_thread(_verify_linux_elf, executable)
            network = client.networks.create(
                owner + "-private",
                driver="bridge",
                internal=True,
                attachable=False,
                labels={_LABEL: owner, _HOST_SUPERVISOR_LABEL: owner},
                check_duplicate=True,
            )
            restrictions = {
                "image": image_id,
                "detach": True,
                "auto_remove": False,
                "read_only": True,
                "user": _UID,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "pids_limit": 64,
                "mem_limit": "192m",
                "memswap_limit": "192m",
                "nano_cpus": 500_000_000,
                "privileged": False,
                "volumes": {},
                "ports": {},
                "tmpfs": {
                    "/run/osop-native-stage": "rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=65534,gid=65534",
                    "/qual": "rw,exec,nosuid,nodev,size=36m,mode=0700,uid=65534,gid=65534",
                    "/tmp": "rw,noexec,nosuid,nodev,size=4m,mode=1777",
                },
                "labels": {_LABEL: owner, _HOST_SUPERVISOR_LABEL: owner},
                "command": ["python3", "-c", "import time; time.sleep(600)"],
            }
            recon = client.containers.run(
                name=owner + "-recon",
                network=network.name,
                environment=child_env,
                **restrictions,
            )
            await asyncio.to_thread(_verify_docker_isolation, network, recon, owner)
            with executable.open("rb") as native:
                content = native.read(_MAX_BINARY + 1)
            if len(content) > _MAX_BINARY:
                raise ValueError("Native Linux binary exceeded byte bound")
            await asyncio.to_thread(
                _exec,
                recon.name,
                ["sh", "-c", "umask 077; cat > /qual/recon-mcp && chmod 500 /qual/recon-mcp"],
                data=content,
                timeout=20,
            )
            if validator_host_port is not None:
                # Tunnel is inside Recon's own 127.0.0.1 network namespace.
                # The ONLY host socket is a fixed 127.0.0.1 TCP destination;
                # Docker stays --internal, with no second network or proxy.
                tunnel = await asyncio.to_thread(_StdioTlsTunnel, recon.name, validator_host_port)
                await asyncio.to_thread(tunnel.await_ready)
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "-d",
                    "--user",
                    _UID,
                    recon.name,
                    "sh",
                    "-c",
                    "exec /qual/recon-mcp >/tmp/recon.log 2>&1",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
            )
            worker = IsolatedLinuxGoWorker(
                container_id=recon.id,
                network_id=network.id,
                validator_url=(
                    f"https://127.0.0.1:{_RELAY_PORT}/native-grants/redeem"
                    if validator_host_port is not None
                    else None
                ),
                _container_name=recon.name,
            )
            for _ in range(45):
                try:
                    status, answer = await worker.health()
                    safe = (
                        answer.get("server_id") == "recon-mcp"
                        and answer.get("execution_enabled") is False
                        and answer.get("authority_verified") is False
                    )
                    if validator_host_port is None and (
                        status == 503 and safe and answer.get("status") == "unavailable"
                    ):
                        break
                    if validator_host_port is not None and (
                        status == 200
                        and safe
                        and answer.get("status") == "configured_unverified"
                        and answer.get("native_scanners_enabled") is False
                    ):
                        break
                except RuntimeError:
                    pass
                await asyncio.sleep(0.12)
            else:
                raise RuntimeError("Isolated native Recon failed metadata health readiness")
            yield worker
    finally:
        # Explicitly delete only resources identified by our unique own label.
        # Bounded container remove and network remove; no prune/reset/cleanup.
        try:
            if tunnel is not None:
                await asyncio.to_thread(tunnel.close)
        finally:
            try:
                await asyncio.to_thread(_remove_owned, client, recon, owner)
            finally:
                try:
                    await asyncio.to_thread(_remove_network, client, network, owner)
                finally:
                    client.close()
