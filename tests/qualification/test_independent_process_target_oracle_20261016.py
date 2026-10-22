"""True loopback TCP against a separate disposable target process and two keys.

This is deliberately a *synthetic* owner-of-record fixture. A distinct process,
HTTP socket, and Ed25519 keys do NOT by themselves establish real target
ownership, independent deployment, PostgreSQL admission or verified findings.
Only 127.0.0.1 on an ephemeral port is used; no app DB or external provider.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import signal
import subprocess
import sys
from contextlib import contextmanager
from typing import Any, Iterator

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ai_osop.core.independent_target_effect_client import (
    IndependentTargetEffectDenied,
    LoopbackTargetEffectClient,
)

# A deliberately STANDALONE interpreter and HTTP server, not ASGITransport or
# a same-process fake: child can sign only target-observed requests and read its
# own server-side owner-of-record mapping. The parent receives public keys over
# stdout at process startup, NEVER from the untrusted HTTP response. For a
# deployed verifier, the keys MUST instead be established by a separate, real
# operator trust channel (not this disposable process).
_SERVER_SOURCE = r"""
import base64
import hashlib
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

scenario = sys.argv[1]
OWNER_DOMAIN = b"AI-OSOP-INDEPENDENT-LAB-OWNER-V1\x00"
ACCESS_DOMAIN = b"AI-OSOP-INDEPENDENT-LAB-ACCESS-V1\x00"
SESSION_DOMAIN = b"AI-OSOP-INDEPENDENT-LAB-SESSION-V1\x00"
REQUEST_DOMAIN = b"AI-OSOP-INDEPENDENT-LAB-REQUEST-V1\x00"
owner_key, access_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
owner_record = {"resource_id": "123", "owner_identity": (
    "account_b" if scenario == "not_owner" else "account_a"
), "visibility": "public" if scenario == "public_owner" else "private", "revision": 1}
session_tokens = {"source-test-session": "account_a", "target-test-session": "account_b"}
events = {}
run_nonce = None
record_body = json.dumps(
    {"owner": owner_record["owner_identity"], "data": "controlled-object-123"},
    sort_keys=True, separators=(",", ":"),
).encode("utf-8")

def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")

def signed(key, domain, claims):
    raw = canonical(claims)
    return {
        "claims_b64": base64.b64encode(raw).decode("ascii"),
        "signature_b64": base64.b64encode(key.sign(domain + raw)).decode("ascii"),
    }

def session_sha(token):
    return hashlib.sha256(SESSION_DOMAIN + token.encode("utf-8")).hexdigest()

def request_sha(nonce, path, role, sess):
    value = {
        "method": "GET",
        "path": path,
        "nonce": nonce,
        "role": role,
        "session_sha256": sess,
    }
    return hashlib.sha256(REQUEST_DOMAIN + canonical(value)).hexdigest()

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_args):
        pass

    def reply(self, code, content, location=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(content)
        self.wfile.flush()

    def do_GET(self):
        global run_nonce
        path = urlsplit(self.path).path
        if path.startswith("/__lab__/audit/"):
            nonce = path.rsplit("/", 1)[-1]
            if nonce != run_nonce or set(events) != {"source", "target", "anonymous"}:
                self.reply(409, b'{"error":"incomplete"}')
                return
            owner = {
                "schema": "ai-osop.independent-lab-owner.v1",
                "nonce": nonce,
                "owner_record": owner_record,
                "events_sha256": hashlib.sha256(canonical(events)).hexdigest(),
            }
            access = {
                "schema": "ai-osop.independent-lab-access.v1",
                "nonce": nonce,
                "resource_id": "123",
                "owner_record_sha256": hashlib.sha256(canonical(owner_record)).hexdigest(),
                "events": events,
            }
            owner_envelope = signed(owner_key, OWNER_DOMAIN, owner)
            access_envelope = signed(
                owner_key if scenario == "wrong_signer" else access_key,
                ACCESS_DOMAIN, access,
            )
            if scenario == "tamper_signature":
                access_envelope["signature_b64"] = base64.b64encode(b"z" * 64).decode("ascii")
            if scenario == "tamper_claim":
                access["events"]["target"]["status"] = 201
                access_envelope["claims_b64"] = base64.b64encode(canonical(access)).decode("ascii")
            if scenario == "signed_wrong_session":
                access["events"]["target"]["session_sha256"] = "f" * 64
                access_envelope = signed(access_key, ACCESS_DOMAIN, access)
            envelope = canonical({"ownership": owner_envelope, "access": access_envelope})
            self.reply(200, envelope)
            return
        if path != "/api/record/123" or self.path != path:
            self.reply(404, b'{"error":"unknown"}')
            return
        nonce = self.headers.get("X-Controlled-Run", "")
        slot = self.headers.get("X-Controlled-Role", "")
        if (
            len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce)
            or slot not in {"source", "target", "anonymous"}
            or (run_nonce is not None and run_nonce != nonce)
            or slot in events
        ):
            self.reply(409, b'{"error":"invalid-run"}')
            return
        run_nonce = nonce
        raw_authorization = self.headers.get("Authorization", "")
        token = (
            raw_authorization.removeprefix("Bearer ")
            if raw_authorization.startswith("Bearer ") else None
        )
        actor = session_tokens.get(token)
        expected_actor = {"source": "account_a", "target": "account_b", "anonymous": None}[slot]
        verified = actor == expected_actor and (
            (slot == "anonymous" and not raw_authorization)
            or (slot != "anonymous" and token in session_tokens)
        )
        if scenario == "unknown_session" and slot == "target":
            verified = False
        if scenario == "session_rotated" and slot == "target":
            session_tokens.pop("target-test-session", None)
            verified = False
        session = session_sha(token) if verified and slot != "anonymous" else None
        if slot == "anonymous" and scenario == "public":
            code, content, redirect = 200, record_body, None
        elif slot == "anonymous":
            code, content, redirect = 403, b'{"error":"unauthenticated"}', None
        elif not verified:
            code, content, redirect = 403, b'{"error":"unauthorized"}', None
        elif slot == "target" and scenario == "denied":
            code, content, redirect = 403, b'{"error":"not-your-object"}', None
        elif slot == "target" and scenario == "redirect":
            code, content, redirect = 302, b'{"redirected":true}', "/out-of-scope"
        else:
            code, content, redirect = 200, record_body, None
        events[slot] = {
            "method": "GET",
            "path": path,
            "role": slot,
            "identity": actor if verified else None,
            "status": code,
            "session_sha256": session,
            "request_sha256": request_sha(nonce, path, slot, session),
            "response_sha256": hashlib.sha256(content).hexdigest(),
            "redirected": bool(redirect),
        }
        self.reply(code, content, redirect)

server = HTTPServer(("127.0.0.1", 0), Handler)
print(json.dumps({
    "host": "127.0.0.1",
    "port": server.server_address[1],
    "pid": __import__("os").getpid(),
    "owner_public": base64.b64encode(owner_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)).decode("ascii"),
    "access_public": base64.b64encode(access_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)).decode("ascii"),
}), flush=True)
server.serve_forever(poll_interval=0.05)
"""


@contextmanager
def _disposable_process(scenario: str) -> Iterator[dict[str, Any]]:
    """Create a real OS process bound to an ephemeral numeric loopback port."""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", _SERVER_SOURCE, scenario],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=flags,
        close_fds=True,
    )
    child_pid: int | None = None
    try:
        assert process.stdout is not None
        line = process.stdout.readline()
        if not line:
            detail = process.stderr.read(2000) if process.stderr else b""
            pytest.fail(f"Disposable child failed startup: {detail!r}")
        info = json.loads(line)
        # Windows .venv launchers may delegate to a second Python executable.
        # Use the server's separately published PID, never the launcher PID as
        # proof of process identity, and terminate the actual server on exit.
        child_pid = info["pid"]
        assert isinstance(child_pid, int) and child_pid != os.getpid()
        assert info["host"] == "127.0.0.1"
        assert isinstance(info["port"], int) and 0 < info["port"] <= 65535
        yield info
    finally:
        if child_pid and child_pid != process.pid:
            try:
                os.kill(child_pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def _client(info: dict[str, Any]) -> LoopbackTargetEffectClient:
    return LoopbackTargetEffectClient(
        endpoint_url=f"http://127.0.0.1:{info['port']}/api/record/123",
        owner_public_key=Ed25519PublicKey.from_public_bytes(base64.b64decode(info["owner_public"])),
        access_public_key=Ed25519PublicKey.from_public_bytes(
            base64.b64decode(info["access_public"])
        ),
        source_identity="account_a",
        target_identity="account_b",
    )


def _nonce() -> str:
    return secrets.token_hex(16)


@pytest.mark.asyncio
async def test_true_separate_process_loopback_signers_report_only_lab_candidate() -> None:
    with _disposable_process("private_cross_identity") as info:
        client = _client(info)
        candidate = await client.observe_once(
            source_token="source-test-session",
            target_token="target-test-session",
            nonce=_nonce(),
        )
        assert candidate.source_status == 200
        assert candidate.target_status == 200
        assert candidate.anonymous_status == 403
        assert candidate.owner_identity == "account_a"
        assert candidate.resource_id == "123"
        assert candidate.owner_signature_verified is True
        assert candidate.access_signature_verified is True
        assert candidate.owner_and_effect_correlated is True
        assert candidate.authority_level == "controlled_lab_synthetic_not_deployable"
        assert candidate.validation_state == "candidate_only"
        assert candidate.finding_verified is False
        assert candidate.report_release_approved is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "public",
        "public_owner",
        "denied",
        "redirect",
        "session_rotated",
        "unknown_session",
        "not_owner",
        "tamper_signature",
        "tamper_claim",
        "signed_wrong_session",
        "wrong_signer",
    ],
)
async def test_loopback_independent_lab_denies_untrusted_effects(scenario: str) -> None:
    with _disposable_process(scenario) as info:
        client = _client(info)
        with pytest.raises(IndependentTargetEffectDenied):
            await client.observe_once(
                source_token="source-test-session",
                target_token="target-test-session",
                nonce=_nonce(),
            )


@pytest.mark.asyncio
async def test_uncertain_or_repeated_nonce_never_replays_requests() -> None:
    with _disposable_process("private_cross_identity") as info:
        client = _client(info)
        nonce = _nonce()
        first = await client.observe_once(
            source_token="source-test-session",
            target_token="target-test-session",
            nonce=nonce,
        )
        assert first.validation_state == "candidate_only"
        with pytest.raises(IndependentTargetEffectDenied, match="already used"):
            await client.observe_once(
                source_token="source-test-session",
                target_token="target-test-session",
                nonce=nonce,
            )


@pytest.mark.parametrize(
    "bad",
    [
        "http://localhost:8080/api/record/123",
        "http://127.0.0.2:8080/api/record/123",
        "http://127.0.0.1:8080@attacker.example/api/record/123",
        "http://127.0.0.1:8080/api/record/123?q=x",
        "http://127.0.0.1:8080/api/record/123#fragment",
        "https://127.0.0.1:8080/api/record/123",
        "http://127.0.0.1:8080/other/123",
        "http://127.0.0.1:8080/api/record/../123",
        "http://127.0.0.1:8080/api/record/%31%32%33",
    ],
)
def test_client_blocks_every_noncanonical_or_nonloopback_url(bad: str) -> None:
    key_a, key_b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    with pytest.raises(IndependentTargetEffectDenied):
        LoopbackTargetEffectClient(
            endpoint_url=bad,
            owner_public_key=key_a.public_key(),
            access_public_key=key_b.public_key(),
            source_identity="account_a",
            target_identity="account_b",
        )


def test_shared_owner_and_access_key_never_counts_as_independence() -> None:
    key = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(IndependentTargetEffectDenied):
        LoopbackTargetEffectClient(
            endpoint_url="http://127.0.0.1:34567/api/record/123",
            owner_public_key=key,
            access_public_key=key,
            source_identity="account_a",
            target_identity="account_b",
        )
