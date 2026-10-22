"""Disposable, local-only three-PROCESS target/owner/access qualification lab.

The fixture's local HTTP target serves one private record to two synthetic
sessions and denies an anonymous session. A different process stores the
owner-of-record and owns its signing key; a third process independently reads
the observed outcomes, verifies the owner's detached signature, and emits a
TLS witness envelope using its own private key. These test operators and their
in-memory session tokens are NOT deployed owners, production Task receipts or
independent evidence of any real-world authorization vulnerability.

Only ephemeral 127.0.0.1 ports are bound. All spawned processes are uniquely
owned by this test, and their state disappears when they exit.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

import psutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

HOSTNAME = "witness.lab.invalid"
_RECORD = {"owner": "account_a", "secret": "joined-fixture-confidential-20261019"}
_RESOURCE = "/api/record/123"
_SESSION_DOMAIN = b"AI-OSOP-JOINED-CONTROLLED-SESSION-EVENT-V1\x00"
# Identical wire domains to production; the test separately asserts equality.
# A child executable only needs cryptography and the standard library and
# deliberately must not import the platform or its live runtime dependencies.
_OWNER_DOMAIN = b"AI-OSOP-LIVE-TARGET-OWNER-OF-RECORD-V1\x00"
_EFFECT_DOMAIN = b"AI-OSOP-LIVE-INDEPENDENT-EFFECT-V1\x00"


def _canonical(document: dict[str, Any]) -> bytes:
    return json.dumps(document, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode()


def _url64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decoded(raw: str) -> bytes:
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def _public(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _signed(key: Ed25519PrivateKey, body: dict[str, Any], domain: bytes) -> dict[str, str]:
    raw = _canonical(body)
    return {"claims_b64url": _url64(raw), "signature_b64url": _url64(key.sign(domain + raw))}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: Any) -> None:
        pass

    def reply(self, status: int, content: bytes) -> None:
        # The production audit parser deliberately accepts the bounded exact
        # `HTTP/1.1 200\r\n` status line, without a free-form reason phrase.
        # Emit that precise wire contract rather than stdlib's `200 OK`.
        headers = (
            f"HTTP/1.1 {status}\r\n"
            "Content-Type: application/json\r\n"
            "Cache-Control: no-store\r\n"
            f"Content-Length: {len(content)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        self.wfile.write(headers + content)
        self.wfile.flush()


def _get_json(url: str) -> dict[str, Any]:
    with urlopen(url, timeout=2) as response:
        return json.loads(response.read(14000))


def _serve_target(scenario: str) -> None:
    from secrets import token_hex

    tokens = {"source": token_hex(24), "target": token_hex(24)}
    signed_session_key = Ed25519PrivateKey.generate()
    events: dict[str, dict[str, Any]] = {}
    private = _canonical(_RECORD)

    class Target(_Handler):
        def do_GET(self) -> None:
            url = urlsplit(self.path)
            if url.path.startswith("/__lab__/events/") and not url.query:
                nonce = url.path.rsplit("/", 1)[-1]
                observed = events.get(nonce, {})
                if set(observed) != {"source", "target", "anonymous"}:
                    self.reply(409, b'{"error":"incomplete"}')
                else:
                    self.reply(200, _canonical({"events": observed}))
                return
            params = parse_qs(url.query)
            if url.path != _RESOURCE or set(params) != {"nonce", "role"}:
                self.reply(404, b'{"error":"unknown"}')
                return
            nonce, role = params["nonce"][0], params["role"][0]
            if not re.fullmatch(r"[0-9a-f]{32}", nonce) or role not in {
                "source", "target", "anonymous"
            } or role in events.get(nonce, {}):
                self.reply(409, b'{"error":"invalid-run"}')
                return
            auth = self.headers.get("Authorization", "")
            expected = f"Bearer {tokens[role]}" if role != "anonymous" else ""
            authenticated = auth == expected and not (scenario == "rotated" and role == "target")
            identity = {"source": "account_a", "target": "account_b", "anonymous": None}[role]
            if not authenticated:
                status, body = 403, b'{"error":"invalid-session"}'
                identity = None
            elif role == "anonymous" and scenario == "public":
                status, body = 200, private
            elif role == "anonymous":
                status, body = 403, b'{"error":"anonymous-denied"}'
            else:
                status, body = 200, private
            session_hash = hashlib.sha256(auth.encode()).hexdigest() if identity else None
            session_event = {
                "nonce": nonce,
                "role": role,
                "identity": identity,
                "status": status,
                "response_sha256": hashlib.sha256(body).hexdigest(),
                "session_sha256": session_hash,
                "session_generation": 1 if identity is not None else None,
                "session_current": authenticated,
                "task_id": "task-joined-" + role,
                "event_id": "evt-joined-" + role,
                "method": "GET",
                "redirected": False,
            }
            events.setdefault(nonce, {})[role] = _signed(
                signed_session_key, session_event, _SESSION_DOMAIN
            )
            self.reply(status, body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    print(_canonical({"pid": os.getpid(), "port": server.server_port, "tokens": tokens,
                      "session_public": _public(signed_session_key)}).decode(), flush=True)
    server.serve_forever(poll_interval=0.05)


def _serve_owner() -> None:
    key = Ed25519PrivateKey.generate()
    digest = hashlib.sha256(_canonical(_RECORD)).hexdigest()

    class Owner(_Handler):
        def do_GET(self) -> None:
            url = urlsplit(self.path)
            nonce = url.path.removeprefix("/v1/owner/")
            if not url.path.startswith("/v1/owner/") or not re.fullmatch(r"[0-9a-f]{32}", nonce):
                self.reply(404, b'{"error":"unknown"}')
                return
            body = {
                "schema": "ai-osop.joined-local-owner-only.v1",
                "nonce": nonce,
                "resource_id": "123",
                "owner_identity": "account_a",
                "visibility": "private",
                "private_content_sha256": digest,
                "local_only": True,
            }
            self.reply(200, _canonical(_signed(key, body, _OWNER_DOMAIN)))

    server = ThreadingHTTPServer(("127.0.0.1", 0), Owner)
    print(_canonical({"pid": os.getpid(), "port": server.server_port, "public": _public(key)}).decode(), flush=True)
    server.serve_forever(poll_interval=0.05)


def _serve_access(target_port: int, owner_port: int, owner_public: str,
                  session_public: str, cert: str, key_path: str) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    access = Ed25519PrivateKey.generate()
    owner_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(owner_public))
    target_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(session_public))
    seen: set[str] = set()

    class Access(_Handler):
        def do_GET(self) -> None:
            url = urlsplit(self.path)
            nonce = url.path.removeprefix("/v1/approved-task-effects/")
            if not url.path.startswith("/v1/approved-task-effects/") or not re.fullmatch(r"[0-9a-f]{32}", nonce):
                self.reply(404, b'{"error":"unknown"}')
                return
            if nonce in seen:
                self.reply(409, b'{"error":"replay"}')
                return
            seen.add(nonce)
            try:
                snapshot = _get_json(f"http://127.0.0.1:{target_port}/__lab__/events/{nonce}")
                owner = _get_json(f"http://127.0.0.1:{owner_port}/v1/owner/{nonce}")
                owner_raw = _decoded(owner["claims_b64url"])
                owner_key.verify(_decoded(owner["signature_b64url"]), _OWNER_DOMAIN + owner_raw)
                record = json.loads(owner_raw)
                receipts = snapshot["events"]
                events = {}
                for role in ("source", "target", "anonymous"):
                    signed_event = receipts[role]
                    event_bytes = _decoded(signed_event["claims_b64url"])
                    target_key.verify(
                        _decoded(signed_event["signature_b64url"]),
                        _SESSION_DOMAIN + event_bytes,
                    )
                    events[role] = json.loads(event_bytes)
                source, target, anonymous = (events[k] for k in ("source", "target", "anonymous"))
                if not (
                    set(events) == {"source", "target", "anonymous"}
                    and source["status"] == target["status"] == 200
                    and anonymous["status"] == 403
                    and source["identity"] == record["owner_identity"] == "account_a"
                    and target["identity"] == "account_b"
                    and anonymous["identity"] is None
                    and all(events[role]["role"] == role and events[role]["nonce"] == nonce
                            and events[role]["session_current"] is True
                            for role in ("source", "target", "anonymous"))
                    and source["session_generation"] == target["session_generation"] == 1
                    and anonymous["session_generation"] is None
                    and anonymous["session_sha256"] is None
                    and source["session_sha256"] != target["session_sha256"]
                    and source["response_sha256"] == target["response_sha256"]
                    == record["private_content_sha256"]
                    and record["visibility"] == "private"
                    and record["nonce"] == nonce
                    and all(not value["redirected"] for value in events.values())
                ):
                    raise ValueError("No controlled private cross-account/anonymous denial evidence")
                body = {
                    "schema": "ai-osop.joined-controlled-fixture.v1",
                    "nonce": nonce,
                    "resource_id": "123",
                    "owner_signed": owner,
                    "observations": receipts,
                    "finding_verified": False,
                    "report_release_approved": False,
                    "authority_level": "synthetic_local_only",
                }
                raw = _canonical(body)
                envelope = {
                    "observer_claims_b64url": _url64(raw),
                    "observer_signature_b64url": _url64(access.sign(_EFFECT_DOMAIN + raw)),
                }
            except Exception:
                # A signing, owner, session or network failure can only
                # produce UNKNOWN in this deliberately isolated test service.
                self.reply(409, b'{"error":"unknown-or-untrusted"}')
                return
            self.reply(200, _canonical(envelope))

    server = ThreadingHTTPServer(("127.0.0.1", 0), Access)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(_canonical({"pid": os.getpid(), "port": server.server_port, "public": _public(access)}).decode(), flush=True)
    server.serve_forever(poll_interval=0.05)


def _certificates(folder: Path) -> tuple[Path, Path]:
    private = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private, hashes.SHA256())
    )
    cert_path = folder / "local-fixture-cert.pem"
    key_path = folder / "local-fixture-key.pem"
    cert_path.write_bytes(certificate.public_bytes(Encoding.PEM))
    key_path.write_bytes(private.private_bytes(
        Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    return cert_path, key_path


@dataclass
class JoinedLab:
    target: dict[str, Any]
    owner: dict[str, Any]
    access: dict[str, Any]
    cert: Path
    hostname: str = HOSTNAME

    async def roles(self, nonce: str) -> dict[str, tuple[int, bytes]]:
        def get(role: str) -> tuple[int, bytes]:
            endpoint = f"http://127.0.0.1:{self.target['port']}{_RESOURCE}?nonce={nonce}&role={role}"
            token = self.target["tokens"].get(role)
            headers = {"Authorization": "Bearer " + token} if token else {}
            try:
                with urlopen(Request(endpoint, headers=headers), timeout=3) as response:
                    return response.status, response.read(4096)
            except HTTPError as exc:
                return exc.code, exc.read(4096)

        result: dict[str, tuple[int, bytes]] = {}
        for role in ("source", "target", "anonymous"):
            result[role] = await asyncio.to_thread(get, role)
        return result


@asynccontextmanager
async def disposable_joined_witness(scenario: str = "private") -> AsyncIterator[JoinedLab]:
    """Own and terminate three independent processes and temporary TLS files."""
    created: list[subprocess.Popen[str]] = []
    owned_children: dict[int, int] = {}
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def attested_process_pid(proc: subprocess.Popen[str], reported: int, role: str) -> bool:
        """Prove child process is the actual executable launched by this test.

        Windows Python virtualenv launchers can spawn a second native Python
        process; Popen owns the launcher while the child prints its real PID.
        Never weaken the independent-process assertion to `pid != os.getpid()`.
        Verify exact parenthood, script and role before accepting or stopping
        that child; a forged stdout PID must never authorize arbitrary kills.
        """
        if type(reported) is not int or reported <= 0 or reported == os.getpid():
            return False
        try:
            process = psutil.Process(reported)
            if reported != proc.pid and (os.name != "nt" or process.ppid() != proc.pid):
                return False
            args = process.cmdline()
            script = str(Path(__file__).resolve()).casefold()
            if not any(arg.casefold() == script for arg in args):
                return False
            if role not in args:
                return False
            return process.is_running()
        except (psutil.Error, OSError, ValueError):
            return False

    async def launch(*args: str) -> dict[str, Any]:
        proc = subprocess.Popen(
            [sys.executable, "-u", str(Path(__file__).resolve()), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=flags,
        )
        created.append(proc)
        assert proc.stdout is not None
        line = await asyncio.wait_for(asyncio.to_thread(proc.stdout.readline), timeout=10)
        if not line:
            try:
                await asyncio.to_thread(proc.wait, 3)
            except subprocess.TimeoutExpired:
                pass
            detail = (proc.stderr.read(2500) if proc.poll() is not None and proc.stderr else "")
            raise RuntimeError(f"Joined disposable {args[0]} failed before startup: {detail}")
        info = json.loads(line)
        if not attested_process_pid(proc, info.get("pid"), args[0]):
            raise RuntimeError("Fixture did not establish independent process identity")
        owned_children[proc.pid] = info["pid"]
        if not 1024 <= info["port"] <= 65535:
            raise RuntimeError("Fixture port is not an isolated ephemeral listener")
        return info

    # Restrict all temporary artifacts to an explicitly owned new directory.
    with tempfile.TemporaryDirectory(prefix="joined-witness-", dir=Path(__file__).parent) as work:
        try:
            cert, key = _certificates(Path(work))
            target = await launch("target", scenario)
            owner = await launch("owner")
            access = await launch(
                "access", str(target["port"]), str(owner["port"]), owner["public"],
                target["session_public"], str(cert), str(key)
            )
            assert len({target["pid"], owner["pid"], access["pid"], os.getpid()}) == 4
            assert len({target["port"], owner["port"], access["port"]}) == 3
            assert owner["public"] != access["public"]
            yield JoinedLab(target=target, owner=owner, access=access, cert=cert)
        finally:
            for proc in reversed(created):
                actual = owned_children.get(proc.pid)
                if actual is not None and actual != proc.pid:
                    # Kill only the already-attested native child of our
                    # virtualenv launcher. No unrelated process is touched.
                    if attested_process_pid(proc, actual, "access") or any(
                        attested_process_pid(proc, actual, role) for role in ("owner", "target")
                    ):
                        try:
                            child = psutil.Process(actual)
                            child.terminate()
                            await asyncio.to_thread(child.wait, 5)
                        except psutil.NoSuchProcess:
                            pass
                        except psutil.TimeoutExpired:
                            child.kill()
                            await asyncio.to_thread(child.wait, 5)
                if proc.poll() is None:
                    proc.terminate()
                try:
                    await asyncio.to_thread(proc.wait, 5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    await asyncio.to_thread(proc.wait, 5)
                if proc.stdout is not None:
                    proc.stdout.close()
                if proc.stderr is not None:
                    proc.stderr.close()


if __name__ == "__main__":
    # Child invocations never access the application DB or external network.
    if sys.argv[1] == "target":
        _serve_target(sys.argv[2])
    elif sys.argv[1] == "owner":
        _serve_owner()
    elif sys.argv[1] == "access":
        _serve_access(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4],
                      sys.argv[5], sys.argv[6], sys.argv[7])
    else:
        raise SystemExit("Invalid disposable joined witness role")
