"""In-process controlled-target ASGI oracle for *candidate* audit receipts.

Target-owner integration:

* Wrap the disposable target ASGI app with ``ControlledTargetAuditOracle``.
* Supply ``session_for_scope(scope)`` backed by the TARGET's own validated
  session store. Return ``TargetSession(principal, opaque_handle, secret_version)``
  for a valid login, or ``None`` for a request without authentication. The
  opaque handle must be a non-secret lookup key; ``secret_version`` is bytes
  identifying that exact live session/generation and must never be logged.
* Supply ``current_session(opaque_handle)`` and ``owner_of_record(resource_id)``
  from independent TARGET stores. Ownership requires a versioned private record.
* Inject three independently provisioned keys: the target-proof public key and
  two distinct Ed25519 PRIVATE signer keys for ownership and access receipts.
* Run exactly one GET each as source, target and anonymous against the wrapper;
  persist/revalidate approved Task and ROE separately; verify the target proof
  and durably claim its nonce separately before calling ``attest``.

This test-only middleware makes NO external requests, retains no response
bodies or raw bearer credentials, and has NO finding/report release method.
Receipts use target_authority_corroboration's exact canonical JSON schema.
The independent verifier still requires PostgreSQL-backed authority/replay
guards in production. Never install this oracle on an unrelated live target.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.core import target_authority_corroboration as audit
from ai_osop.core import target_authority_proof as authority

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_RESOURCE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_SESSION_DOMAIN = b"AI-OSOP-CONTROLLED-SESSION-V1\x00"
_REQUEST_DOMAIN = b"AI-OSOP-CONTROLLED-REQUEST-V1\x00"
_MAX_RESPONSE_BYTES = 65536


class ControlledOracleDenied(PermissionError):
    """An observed target request, owner mapping or signed receipt is unsafe."""


@dataclass(frozen=True)
class TargetSession:
    """Trusted target session, supplied by the target's authenticating callback.

    The secret version bytes are used only to calculate a one-way fingerprint.
    They are never stored in any observation, receipt or exception message.
    """

    identity: str
    handle: str
    secret_version: bytes


@dataclass(frozen=True)
class OwnerRecord:
    """Immutable owner-of-record snapshot, never from a response or MCP output."""

    resource_id: str
    owner_identity: str
    visibility: str
    revision: int


@dataclass(frozen=True)
class TargetAuditBinding:
    """Target-operator configured immutable link to the approved replay context."""

    engagement_id: str
    flow_id: str
    flow_revision: int
    authorization_id: str
    authorization_version: int
    authorization_sha256: str
    original_source_task_id: str
    source_task_id: str
    target_task_id: str
    source_identity: str
    target_identity: str
    endpoint_url: str
    resource_id: str
    workflow_id: str
    step_id: str
    method: str = "GET"


@dataclass(frozen=True)
class TargetObservation:
    """No raw session/token, request body, response body or access header."""

    role: str
    identity: Optional[str]
    session_handle: Optional[str]
    session_sha256: Optional[str]
    request_sha256: Optional[str]
    response_sha256: Optional[str]
    status: int
    owner_snapshot: OwnerRecord


@dataclass(frozen=True)
class SignedTargetAuditReceipts:
    ownership_json: bytes
    ownership_signature: str
    access_json: bytes
    access_signature: str
    target_proof_sha256: str
    validation_state: str = "candidate_only"
    finding_verified: bool = False
    report_release_approved: bool = False


def _canonical(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _digest(domain: bytes, value: Dict[str, Any]) -> str:
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _session_digest(binding: TargetAuditBinding, session: TargetSession) -> str:
    if (
        type(session) is not TargetSession
        or not session.identity
        or not session.handle
        or type(session.secret_version) is not bytes
        or not 1 <= len(session.secret_version) <= 256
    ):
        raise ControlledOracleDenied("Current target session is invalid")
    return hashlib.sha256(
        _SESSION_DOMAIN
        + _canonical(
            {
                "engagement_id": binding.engagement_id,
                "identity": session.identity,
                "handle": session.handle,
            }
        )
        + b"\x00"
        + session.secret_version
    ).hexdigest()


def _request_digest(binding: TargetAuditBinding, role: str, session_sha: str) -> str:
    return _digest(
        _REQUEST_DOMAIN,
        {
            "flow_id": binding.flow_id,
            "method": binding.method,
            "url": binding.endpoint_url,
            "task_id": (binding.source_task_id if role == "source" else binding.target_task_id),
            "session_sha256": session_sha,
            "empty_body_sha256": hashlib.sha256(b"").hexdigest(),
        },
    )


def _response_digest(binding: TargetAuditBinding, data: bytes) -> str:
    """Match approved signed-replay canonical JSON digest, without retaining body."""
    if not 1 <= len(data) <= _MAX_RESPONSE_BYTES:
        raise ControlledOracleDenied("Controlled JSON response unavailable or too large")
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=audit._object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("NaN")),
        )
        if type(value) not in (dict, list):
            raise ValueError("Unexpected response type")
        canonical = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise ControlledOracleDenied("Controlled response is not strict JSON") from exc
    return hashlib.sha256(
        b"osop-signed-replay-v1:"
        + binding.engagement_id.encode()
        + b":"
        + binding.workflow_id.encode()
        + b":"
        + binding.step_id.encode()
        + b":"
        + canonical
    ).hexdigest()


class ControlledTargetAuditOracle:
    """Pure ASGI wrapper and read-only signer for ONE controlled target comparison.

    One observation per role; duplicates and unrecognized sessions poison the
    oracle. Callbacks must be target-owned, local, synchronous and read-only.
    Build a NEW oracle per comparison. The wrapper does not authorize requests,
    perform network I/O, inspect model testimony or change application responses.
    """

    def __init__(
        self,
        app: Any,
        *,
        binding: TargetAuditBinding,
        session_for_scope: Callable[[Dict[str, Any]], Optional[TargetSession]],
        current_session: Callable[[str], Optional[TargetSession]],
        owner_of_record: Callable[[str], Optional[OwnerRecord]],
        target_proof_public_key: Ed25519PublicKey,
        ownership_signer: Ed25519PrivateKey,
        access_signer: Ed25519PrivateKey,
    ) -> None:
        if (
            type(binding) is not TargetAuditBinding
            or binding.method != "GET"
            or binding.source_identity == binding.target_identity
            or not binding.source_identity
            or not binding.target_identity
            or binding.source_identity.casefold() in {"anonymous", "public", "guest"}
            or binding.target_identity.casefold() in {"anonymous", "public", "guest"}
            or not all(
                callable(func) for func in (session_for_scope, current_session, owner_of_record)
            )
            or not isinstance(target_proof_public_key, Ed25519PublicKey)
            or not isinstance(ownership_signer, Ed25519PrivateKey)
            or not isinstance(access_signer, Ed25519PrivateKey)
            or type(binding.flow_revision) is not int
            or type(binding.authorization_version) is not int
            or not _SHA.fullmatch(binding.authorization_sha256)
            or not _RESOURCE.fullmatch(binding.resource_id)
        ):
            raise ControlledOracleDenied("Controlled target configuration unavailable")
        try:
            endpoint, origin = authority._endpoint(binding.endpoint_url)
            parsed = urlsplit(endpoint)
            if (
                origin != "https://" + parsed.hostname
                or parsed.query
                or not parsed.path.endswith("/" + binding.resource_id)
            ):
                raise ValueError("Wrong owner-of-record path")
        except (authority.TargetAuthorityDenied, ValueError) as exc:
            raise ControlledOracleDenied("Invalid controlled endpoint") from exc
        public_keys = [
            target_proof_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw),
            ownership_signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            access_signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        ]
        if len(set(public_keys)) != 3:
            raise ControlledOracleDenied("Three independent signing keys required")
        self._app = app
        self._binding = binding
        self._session_for_scope = session_for_scope
        self._current_session = current_session
        self._owner_of_record = owner_of_record
        self._target_proof_public_key = target_proof_public_key
        self._ownership_signer = ownership_signer
        self._access_signer = access_signer
        self._observed: Dict[str, TargetObservation] = {}
        self._lock = asyncio.Lock()
        self._inflight: set[str] = set()
        self._poisoned = False
        self._sealed = False

    @property
    def observations(self) -> Dict[str, TargetObservation]:
        """Return already-redacted, immutable observations for approved Task intake."""
        return dict(self._observed)

    def _owner(self) -> OwnerRecord:
        record = self._owner_of_record(self._binding.resource_id)
        if (
            type(record) is not OwnerRecord
            or record.resource_id != self._binding.resource_id
            or record.owner_identity != self._binding.source_identity
            or record.visibility != "private"
            or type(record.revision) is not int
            or record.revision < 1
        ):
            raise ControlledOracleDenied("Target owner-of-record is unavailable or public")
        return record

    def _classify(self, scope: Dict[str, Any]) -> tuple[str, Optional[TargetSession]]:
        headers = scope.get("headers")
        if type(headers) is not list or any(
            type(item) is not tuple or len(item) != 2 for item in headers
        ):
            raise ControlledOracleDenied("Malformed target HTTP headers")
        host = [v for k, v in headers if k.lower() == b"host"]
        auth = [v for k, v in headers if k.lower() == b"authorization"]
        expected = urlsplit(self._binding.endpoint_url)
        if (
            len(host) != 1
            or host[0] != expected.hostname.encode("ascii")
            or len(auth) > 1
            or scope.get("method") != "GET"
            or scope.get("scheme") != "https"
            or scope.get("path") != expected.path
            or scope.get("raw_path", expected.path.encode("ascii")) != expected.path.encode("ascii")
            or scope.get("query_string", b"")
            or any(k.lower() in (b"transfer-encoding", b"content-encoding") for k, _ in headers)
            or any(k.lower() == b"content-length" and v != b"0" for k, v in headers)
        ):
            raise ControlledOracleDenied("Unexpected controlled endpoint or body")
        session = self._session_for_scope(scope)
        if session is None:
            if auth:
                raise ControlledOracleDenied("Invalid or rotated bearer session")
            return "anonymous", None
        if not auth or type(session) is not TargetSession:
            raise ControlledOracleDenied("Unvalidated target session")
        if session.identity == self._binding.source_identity:
            return "source", session
        if session.identity == self._binding.target_identity:
            return "target", session
        raise ControlledOracleDenied("Unrecognized controlled target identity")

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("path") != urlsplit(self._binding.endpoint_url).path
        ):
            await self._app(scope, receive, send)
            return
        role = "invalid"
        try:
            role, session = self._classify(scope)
            owner = self._owner()
            session_sha = _session_digest(self._binding, session) if session is not None else None
        except Exception:
            self._poisoned = True
            # The target still owns HTTP behavior. Refuse to certify its result.
            await self._app(scope, receive, send)
            return

        async with self._lock:
            if self._sealed or role in self._observed or role in self._inflight:
                self._poisoned = True
            self._inflight.add(role)

        # An empty Content-Length header alone cannot establish an empty GET
        # request: some ASGI apps never consume receive(). Inspect the actual
        # ASGI request frames and replay them unchanged to the target. HTTPX
        # legitimately sends an empty initial frame followed by an empty final
        # one; nonempty bodies or unbounded streaming poison the audit.
        preflight: list[Dict[str, Any]] = []
        try:
            for _ in range(3):
                frame = await asyncio.wait_for(receive(), timeout=3.0)
                preflight.append(frame)
                if frame.get("type") != "http.request" or frame.get("body"):
                    self._poisoned = True
                if not frame.get("more_body", False):
                    break
            else:
                self._poisoned = True
        except Exception:
            self._poisoned = True

        body = bytearray()
        response_status: Optional[int] = None
        complete = False
        disallowed_body = False
        redirected = False
        content_is_json = False

        async def observed_receive() -> Dict[str, Any]:
            nonlocal disallowed_body
            if preflight:
                message = preflight.pop(0)
            else:
                message = await receive()
            if message.get("type") == "http.request" and message.get("body"):
                disallowed_body = True
            return message

        async def observed_send(message: Dict[str, Any]) -> None:
            nonlocal response_status, complete, redirected, content_is_json
            if message.get("type") == "http.response.start":
                if response_status is not None:
                    self._poisoned = True
                response_status = message.get("status")
                response_headers = message.get("headers", [])
                redirected = any(k.lower() == b"location" for k, _ in response_headers)
                content_is_json = any(
                    k.lower() == b"content-type" and v.lower().startswith(b"application/json")
                    for k, v in response_headers
                )
            elif message.get("type") == "http.response.body":
                chunk = message.get("body", b"")
                if type(chunk) is not bytes or len(body) + len(chunk) > _MAX_RESPONSE_BYTES:
                    self._poisoned = True
                else:
                    body.extend(chunk)
                if not message.get("more_body", False):
                    complete = True
            await send(message)

        try:
            await self._app(scope, observed_receive, observed_send)
            digest = None
            if type(response_status) is not int or not complete or redirected or disallowed_body:
                raise ControlledOracleDenied("Incomplete or redirected controlled response")
            if response_status == 200:
                if not content_is_json:
                    raise ControlledOracleDenied("Controlled success must be JSON")
                digest = _response_digest(self._binding, bytes(body))
            request_sha = _request_digest(self._binding, role, session_sha) if session_sha else None
            observation = TargetObservation(
                role=role,
                identity=session.identity if session else None,
                session_handle=session.handle if session else None,
                session_sha256=session_sha,
                request_sha256=request_sha,
                response_sha256=digest,
                status=response_status,
                owner_snapshot=owner,
            )
            async with self._lock:
                if role in self._observed:
                    self._poisoned = True
                self._observed[role] = observation
        except ControlledOracleDenied:
            # HTTP response already reached the caller. Preserve the target's
            # actual 302/invalid result while irrevocably denying attestation.
            self._poisoned = True
        except Exception:
            self._poisoned = True
            raise
        finally:
            # Do not retain bytes after the HTTP response is complete.
            body.clear()
            preflight.clear()
            async with self._lock:
                self._inflight.discard(role)

    async def attest(
        self,
        *,
        target_claims_json: bytes,
        target_signature_b64url: str,
        verified_target_proof_sha256: str,
    ) -> SignedTargetAuditReceipts:
        """Sign bounded *candidate* receipts after separate target proof validation.

        Verify the target-owned detached signature and its digest even though
        the caller supplies a separately verified proof fingerprint. Crucially,
        compare every observable field against target-side measurement and live
        session/owner rechecks. Untrusted model/MCP owner assertions are ignored.
        """
        async with self._lock:
            if (
                self._sealed
                or self._poisoned
                or self._inflight
                or set(self._observed) != {"source", "target", "anonymous"}
            ):
                raise ControlledOracleDenied("Complete uncontaminated target trace required")
            try:
                claims = authority._strict_json(target_claims_json, max_bytes=4096)
                if (
                    set(claims) != authority._SIGNED_FIELDS
                    or target_claims_json != authority._canonical(claims)
                    or claims.get("schema") != "ai-osop.target-owned-authority.v1"
                    or type(target_signature_b64url) is not str
                    or not authority._SIGNATURE.fullmatch(target_signature_b64url)
                    or type(verified_target_proof_sha256) is not str
                    or not _SHA.fullmatch(verified_target_proof_sha256)
                ):
                    raise ControlledOracleDenied("Bounded verified target assertion required")
                signature = base64.urlsafe_b64decode(target_signature_b64url + "==")
                if (
                    len(signature) != 64
                    or base64.urlsafe_b64encode(signature).decode().rstrip("=")
                    != target_signature_b64url
                ):
                    raise ControlledOracleDenied("Invalid canonical target signature")
                self._target_proof_public_key.verify(
                    signature, authority._DOMAIN + target_claims_json
                )
                proof_digest = hashlib.sha256(
                    authority._DOMAIN + target_claims_json + signature
                ).hexdigest()
                if not hmac.compare_digest(proof_digest, verified_target_proof_sha256):
                    raise ControlledOracleDenied("Target proof digest differs")
            except (
                InvalidSignature,
                ValueError,
                TypeError,
                authority.TargetAuthorityDenied,
            ) as exc:
                raise ControlledOracleDenied("Target proof signature or shape untrusted") from exc

            source, target, anonymous = (
                self._observed[role] for role in ("source", "target", "anonymous")
            )
            binding = self._binding
            try:
                owner = self._owner()
                if any(
                    snapshot.owner_snapshot != owner for snapshot in (source, target, anonymous)
                ):
                    raise ControlledOracleDenied("Resource owner rotated after observation")
                for row in (source, target):
                    fresh = self._current_session(row.session_handle or "")
                    if (
                        type(fresh) is not TargetSession
                        or fresh.handle != row.session_handle
                        or fresh.identity != row.identity
                        or _session_digest(binding, fresh) != row.session_sha256
                    ):
                        raise ControlledOracleDenied("Target session revoked or rotated")
                if (
                    source.status != 200
                    or target.status != 200
                    or anonymous.status not in (401, 403, 404)
                    or anonymous.session_handle is not None
                    or source.response_sha256 is None
                    or source.response_sha256 != target.response_sha256
                    or source.session_sha256 == target.session_sha256
                ):
                    raise ControlledOracleDenied("Public, denied or incomparable object")
                expected: Dict[str, Any] = {
                    "engagement_id": binding.engagement_id,
                    "flow_id": binding.flow_id,
                    "flow_revision": binding.flow_revision,
                    "authorization_id": binding.authorization_id,
                    "authorization_version": binding.authorization_version,
                    "authorization_sha256": binding.authorization_sha256,
                    "original_source_task_id": binding.original_source_task_id,
                    "source_task_id": binding.source_task_id,
                    "target_task_id": binding.target_task_id,
                    "source_identity": binding.source_identity,
                    "target_identity": binding.target_identity,
                    "endpoint_url": binding.endpoint_url,
                    "method": binding.method,
                    "source_request_sha256": source.request_sha256,
                    "target_request_sha256": target.request_sha256,
                    "source_session_sha256": source.session_sha256,
                    "target_session_sha256": target.session_sha256,
                    "source_response_sha256": source.response_sha256,
                    "target_response_sha256": target.response_sha256,
                    "source_http_status": source.status,
                    "target_http_status": target.status,
                    "anonymous_http_status": anonymous.status,
                    "resource_visibility": owner.visibility,
                    "resource_owner_identity": owner.owner_identity,
                    "target_access_forbidden": True,
                }
                if any(
                    type(claims.get(k)) is not type(v) or claims.get(k) != v
                    for k, v in expected.items()
                ):
                    raise ControlledOracleDenied(
                        "Signed target assertion contradicts observed HTTP"
                    )
                if (
                    claims.get("public_access") is not False
                    or claims.get("redirected") is not False
                    or claims.get("denied") is not False
                    or claims.get("cross_identity_disclosure_confirmed") is not True
                ):
                    raise ControlledOracleDenied("Unsafe target assertion flags")
            except ControlledOracleDenied:
                raise
            except Exception as exc:
                raise ControlledOracleDenied(
                    "Target's local owner/session service unavailable"
                ) from exc

            now = int(time.time())
            receipts: Dict[str, tuple[bytes, str]] = {}
            for role, key in (
                ("ownership", self._ownership_signer),
                ("access", self._access_signer),
            ):
                claim: Dict[str, Any] = {k: claims[k] for k in audit._MATCHED_FIELDS}
                claim.update(
                    schema="ai-osop.target-independent-audit.v1",
                    role=role,
                    resource_id=owner.resource_id,
                    source_access_allowed=True,
                    target_proof_sha256=proof_digest,
                    nonce=role[0] + "-" + secrets.token_urlsafe(24),
                    issued_at=now,
                    expires_at=now + 60,
                )
                assert set(claim) == audit._FIELDS  # internal shape invariant
                canonical = _canonical(claim)
                signed = key.sign(audit._DOMAIN + canonical)
                receipts[role] = (
                    canonical,
                    base64.urlsafe_b64encode(signed).decode("ascii").rstrip("="),
                )
            self._sealed = True
            return SignedTargetAuditReceipts(
                ownership_json=receipts["ownership"][0],
                ownership_signature=receipts["ownership"][1],
                access_json=receipts["access"][0],
                access_signature=receipts["access"][1],
                target_proof_sha256=proof_digest,
            )
