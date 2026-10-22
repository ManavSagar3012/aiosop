"""Read-only, fail-closed 0039 global library -> Flow review staging boundary.

There is NO durable atomic 0039+0019/0038+0013 signed citation/bind API.
Consequently this module never calls the existing Flow note writer,
the Flow artifact uploader, signs a receipt, returns original text, publishes
prompts or approves Flow-local import. A separately host-enrolled four-root
verification can produce only an inert, operator-visible PENDING metadata
pointer. The independent signer services themselves are NOT implemented here.

Not mounted in main.py, routers, agents or orchestrator. This module does not
fetch signing keys from the environment or accept public roots from users.
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
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.memory.operator_global_library import OperatorGlobalLibrary

_DOMAIN = b"ai-osop-0039-flow-import-preflight-v1\x00"
_ROLES = ("principal", "reviewer", "flow", "roe")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_GLOBAL = re.compile(r"lib-[0-9a-f]{32}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._:-]{1,59}\Z")
_ENGAGEMENT = re.compile(r"eng-[A-Za-z0-9._:-]{1,60}\Z")
_TASK = re.compile(r"task-[A-Za-z0-9._:-]{1,123}\Z")
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+:-]{0,127}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_SHARED = frozenset(
    {
        "kind",
        "nonce",
        "issued_at",
        "expires_at",
        "issuer",
        "principal_owner_sha256",
        "principal_subject_sha256",
        "flow_owner",
        "engagement_id",
        "flow_id",
        "flow_revision",
        "task_id",
        "authorization_id",
        "authorization_version",
        "authorization_sha256",
        "global_document_id",
        "global_revision",
        "global_sha256",
    }
)
_EXTRA = {
    "principal": frozenset({"principal_authenticated", "owner_namespace_verified"}),
    "reviewer": frozenset(
        {
            "review_id",
            "reviewer_sub",
            "uploader_sub",
            "reviewer_role",
            "decision",
            "review_current",
            "source_original_reviewed",
        }
    ),
    "flow": frozenset({"flow_status", "tenant_owner_verified", "current_revision_verified"}),
    "roe": frozenset(
        {
            "authorization_current",
            "task_running",
            "task_flow_verified",
            "revocation_epoch",
        }
    ),
}


class ReviewedLibraryFlowImportDenied(PermissionError):
    """No current independent authority or durable atomic reviewed source bind."""


@dataclass(frozen=True)
class GlobalFlowImportRequest:
    """Proposal from an authenticated handler; still NOT an admission grant."""

    issuer: str
    principal_subject: str
    flow_owner: str
    engagement_id: str
    flow_id: str
    flow_revision: int
    task_id: str
    authorization_id: str
    authorization_version: int
    authorization_sha256: str
    global_document_id: str
    global_revision: int
    global_sha256: str


@dataclass(frozen=True)
class PendingLibraryFlowCitation:
    """Non-content, non-promotable proposed citation for an operator UI only."""

    source_id: str
    original_revision: int
    original_sha256: str
    source_kind: str
    engagement_id: str
    flow_id: str
    flow_revision: int
    status: str = "pending_atomic_reviewed_bind"
    signed_readbacks_current_at_preflight: bool = True
    approved_for_agent_context: bool = False
    verified_target_evidence: bool = False
    safe_for_execution: bool = False
    operator_knowledge_created: bool = False
    flow_local_document_id: Optional[str] = None


Reader = Callable[[GlobalFlowImportRequest, str], Awaitable[bytes]]


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode("ascii")


def _unique_members(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("Duplicate signed authority field")
        values[key] = value
    return values


def _scope(request: GlobalFlowImportRequest) -> tuple[str, Dict[str, Any]]:
    if type(request) is not GlobalFlowImportRequest:
        raise ReviewedLibraryFlowImportDenied("Complete reviewed import scope required")
    # 0039 accepts HTTPS/OIDC issuer strings and opaque principal subjects:
    # do not reject valid '/' or ':' characters in authenticated identities.
    if any(
        type(value) is not str
        or not 1 <= len(value) <= limit
        or any(ord(ch) < 33 or ord(ch) == 127 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value)
        for value, limit in (
            (request.issuer, 128),
            (request.principal_subject, 256),
        )
    ):
        raise ReviewedLibraryFlowImportDenied("Invalid authenticated principal namespace")
    for value in (
        request.flow_owner,
        request.engagement_id,
        request.authorization_id,
    ):
        if type(value) is not str or _IDENT.fullmatch(value) is None:
            raise ReviewedLibraryFlowImportDenied("Invalid independently bound identity")
    if (
        len(request.flow_owner) > 64
        or type(request.flow_id) is not str
        or _FLOW.fullmatch(request.flow_id) is None
        or _ENGAGEMENT.fullmatch(request.engagement_id) is None
        or type(request.task_id) is not str
        or _TASK.fullmatch(request.task_id) is None
        or type(request.global_document_id) is not str
        or _GLOBAL.fullmatch(request.global_document_id) is None
        or type(request.authorization_sha256) is not str
        or _SHA.fullmatch(request.authorization_sha256) is None
        or type(request.global_sha256) is not str
        or _SHA.fullmatch(request.global_sha256) is None
        or any(
            type(value) is not int or value < floor or value > 2147483646
            for value, floor in (
                (request.flow_revision, 0),
                (request.authorization_version, 1),
                (request.global_revision, 1),
            )
        )
    ):
        raise ReviewedLibraryFlowImportDenied("Incomplete source or current Flow authority")
    try:
        owner_hash = hashlib.sha256(
            (request.issuer + "\x00" + request.principal_subject).encode("utf-8", "strict")
        ).hexdigest()
    except UnicodeError:
        raise ReviewedLibraryFlowImportDenied("Invalid principal namespace") from None
    common = {
        "issuer": request.issuer,
        "principal_owner_sha256": owner_hash,
        "principal_subject_sha256": hashlib.sha256(
            request.principal_subject.encode("utf-8", "strict")
        ).hexdigest(),
        "flow_owner": request.flow_owner,
        "engagement_id": request.engagement_id,
        "flow_id": request.flow_id,
        "flow_revision": request.flow_revision,
        "task_id": request.task_id,
        "authorization_id": request.authorization_id,
        "authorization_version": request.authorization_version,
        "authorization_sha256": request.authorization_sha256,
        "global_document_id": request.global_document_id,
        "global_revision": request.global_revision,
        "global_sha256": request.global_sha256,
    }
    return owner_hash, common


def _original_signature(source: Any, request: GlobalFlowImportRequest) -> tuple[str, str, int]:
    """Check real 0039.get original byte hash; NEVER return original content."""
    if type(source) is not dict:
        raise ReviewedLibraryFlowImportDenied("Scoped current original unavailable")
    if set(source).intersection(
        {
            "principal_subject",
            "principal_issuer",
            "owner_id",
            "system_prompt",
            "approved_content",
            "model_authority",
            "safe_for_execution",
        }
    ):
        raise ReviewedLibraryFlowImportDenied("Source attempted to promote authority")
    content = source.get("content")
    try:
        raw = content.encode("utf-8", "strict") if type(content) is str else b""
    except UnicodeError:
        raise ReviewedLibraryFlowImportDenied("Original UTF-8 integrity unavailable") from None
    if (
        type(source.get("id")) is not str
        or source["id"] != request.global_document_id
        or type(source.get("revision")) is not int
        or source["revision"] != request.global_revision
        or source.get("deleted_at") is not None
        or source.get("status") == "tombstoned"
        or source.get("content_classification") != "untrusted_user_text"
        or source.get("approved_for_agent_context") is not False
        or source.get("verified_target_evidence") is not False
        or type(source.get("content_bytes")) is not int
        or not 1 <= len(raw) <= 8192
        or len(raw) != source["content_bytes"]
        or type(source.get("sha256")) is not str
        or _SHA.fullmatch(source["sha256"]) is None
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), source["sha256"])
        or not hmac.compare_digest(source["sha256"], request.global_sha256)
        or any((ord(ch) < 32 and ch not in "\t\r\n") or ord(ch) == 127 for ch in content)
        or type(source.get("doc_type")) is not str
        or source["doc_type"] not in {"guide", "answer", "code"}
    ):
        raise ReviewedLibraryFlowImportDenied("Global source revised, deleted or tampered")
    return source["sha256"], source["doc_type"], source["revision"]


class ReviewedLibraryFlowImport:
    """Independent signed *read-only* current metadata preflight, never import."""

    def __init__(
        self,
        *,
        library: Optional[OperatorGlobalLibrary] = None,
        independently_pinned_public_keys: Optional[Mapping[str, Ed25519PublicKey]] = None,
        authority_readers: Optional[Mapping[str, Reader]] = None,
        clock: Optional[Callable[[], int]] = None,
        timeout_seconds: float = 2.0,
    ) -> None:
        self._clock = clock or (lambda: int(time.time()))
        self._library = library
        self._keys = dict(independently_pinned_public_keys or {})
        self._readers = dict(authority_readers or {})
        self._timeout = timeout_seconds
        # The following is only configuration shape, NOT proof a service
        # exists or that the keys were enrolled by an independent operator.
        self._enrolled_shape = (
            isinstance(library, OperatorGlobalLibrary)
            and set(self._keys) == set(_ROLES)
            and set(self._readers) == set(_ROLES)
            and all(isinstance(value, Ed25519PublicKey) for value in self._keys.values())
            and all(callable(value) for value in self._readers.values())
            and len(
                {
                    key.public_bytes(Encoding.Raw, PublicFormat.Raw)
                    for key in self._keys.values()
                    if isinstance(key, Ed25519PublicKey)
                }
            )
            == 4
            and type(timeout_seconds) in (float, int)
            and 0.1 <= timeout_seconds <= 5.0
            and callable(self._clock)
        )

    @staticmethod
    def pending_status() -> Dict[str, Any]:
        """Safe to show when not enrolled: no user/Flow/source information."""
        return {
            "status": "pending_independent_authority_and_atomic_bind",
            "source_content_available": False,
            "review_approved_for_import": False,
            "approved_for_agent_context": False,
            "verified_target_evidence": False,
            "safe_for_execution": False,
            "flow_local_document_created": False,
        }

    def _verified_witness(
        self,
        role: str,
        raw: Any,
        *,
        common: Mapping[str, Any],
        nonce: str,
    ) -> Dict[str, Any]:
        try:
            if type(raw) is not bytes or not 0 < len(raw) <= 8192:
                raise ValueError("Signed readback unavailable")
            envelope = json.loads(
                raw,
                object_pairs_hook=_unique_members,
                parse_float=lambda *_: (_ for _ in ()).throw(ValueError()),
                parse_constant=lambda *_: (_ for _ in ()).throw(ValueError()),
            )
            if type(envelope) is not dict or set(envelope) != {"claims", "signature_b64"}:
                raise ValueError("Malformed signer envelope")
            claims = envelope["claims"]
            if type(claims) is not dict or set(claims) != _SHARED | _EXTRA[role]:
                raise ValueError("Unsigned, missing or extra authority field")
            now = self._clock()
            if (
                type(now) is not int
                or type(claims["issued_at"]) is not int
                or type(claims["expires_at"]) is not int
                or claims["kind"] != role
                or type(claims["nonce"]) is not str
                or not _NONCE.fullmatch(claims["nonce"])
                or not hmac.compare_digest(claims["nonce"], nonce)
                or not 1 <= claims["issued_at"] <= now + 1
                or now - claims["issued_at"] > 10
                or not now < claims["expires_at"] <= claims["issued_at"] + 12
                or any(
                    type(claims.get(key)) is not type(value) or claims[key] != value
                    for key, value in common.items()
                )
            ):
                raise ValueError("Stale or foreign signed witness")
            encoded = envelope["signature_b64"]
            if type(encoded) is not str or len(encoded) != 88:
                raise ValueError("Invalid signer envelope")
            signature = base64.b64decode(encoded, validate=True)
            if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
                raise ValueError("Invalid signed bytes")
            self._keys[role].verify(
                signature, _DOMAIN + role.encode("ascii") + b"\x00" + _canonical(claims)
            )
            if role == "principal" and (
                claims["principal_authenticated"] is not True
                or claims["owner_namespace_verified"] is not True
            ):
                raise ValueError("Principal issuer and owner namespace unavailable")
            if role == "reviewer" and (
                type(claims["review_id"]) is not str
                or _IDENT.fullmatch(claims["review_id"]) is None
                or type(claims["reviewer_sub"]) is not str
                or _IDENT.fullmatch(claims["reviewer_sub"]) is None
                or claims["reviewer_sub"] == common["flow_owner"]
                or claims["reviewer_sub"] == common["principal_owner_sha256"]
                or hmac.compare_digest(
                    hashlib.sha256(claims["reviewer_sub"].encode("utf-8")).hexdigest(),
                    common["principal_subject_sha256"],
                )
                or claims["uploader_sub"] != common["flow_owner"]
                or claims["reviewer_role"] != "senior_operator"
                or claims["decision"] != "approve"
                or claims["review_current"] is not True
                or claims["source_original_reviewed"] is not True
            ):
                raise ValueError("Separate current senior source review unavailable")
            if role == "flow" and (
                claims["flow_status"] not in {"pending", "running"}
                or claims["tenant_owner_verified"] is not True
                or claims["current_revision_verified"] is not True
            ):
                raise ValueError("Current Flow tenant/revision unavailable")
            if role == "roe" and (
                claims["authorization_current"] is not True
                or claims["task_running"] is not True
                or claims["task_flow_verified"] is not True
                or type(claims["revocation_epoch"]) is not int
                or claims["revocation_epoch"] < 1
            ):
                raise ValueError("Current signed ROE/Task authority unavailable")
            return claims
        except (
            ValueError,
            TypeError,
            KeyError,
            UnicodeError,
            RecursionError,
            OverflowError,
            InvalidSignature,
        ):
            raise ReviewedLibraryFlowImportDenied(
                "Independent signed source/reviewer/Flow/ROE witness unavailable"
            ) from None

    async def _current_round(
        self, request: GlobalFlowImportRequest, common: Mapping[str, Any]
    ) -> tuple[Dict[str, Any], ...]:
        nonce = secrets.token_hex(16)
        output = []
        for role in _ROLES:
            try:
                raw = await asyncio.wait_for(
                    self._readers[role](request, nonce), timeout=self._timeout
                )
            except Exception:
                raise ReviewedLibraryFlowImportDenied(
                    "Independently enrolled authority readback unavailable"
                ) from None
            output.append(self._verified_witness(role, raw, common=common, nonce=nonce))
        return tuple(output)

    async def inspect_pending_citation(
        self, request: GlobalFlowImportRequest
    ) -> PendingLibraryFlowCitation:
        """No content projection; two fresh signer rounds and three 0039 reads.

        A multi-table atomic citation that prevents mutation just AFTER the
        final read remains absent. Therefore even a fully signed preflight
        returns PENDING and nothing may be auto-copied into operator notes.
        """
        _, common = _scope(request)
        if not self._enrolled_shape:
            raise ReviewedLibraryFlowImportDenied(
                "Independent reviewer, principal, Flow and ROE roots not enrolled"
            )
        owner = common["principal_owner_sha256"]

        async def current() -> tuple[str, str, int]:
            try:
                snapshot = await asyncio.wait_for(
                    self._library.get(request.issuer, owner, request.global_document_id),
                    timeout=self._timeout,
                )
            except Exception:
                raise ReviewedLibraryFlowImportDenied(
                    "Current owner-scoped 0039 original unavailable"
                ) from None
            return _original_signature(snapshot, request)

        first = await current()
        witnesses_1 = await self._current_round(request, common)
        middle = await current()
        if first != middle:
            raise ReviewedLibraryFlowImportDenied("Global original changed during review")
        witnesses_2 = await self._current_round(request, common)
        # Compare only current *meaning*, not the fresh challenge/time stamp.
        excluded = {"nonce", "issued_at", "expires_at"}
        for one, two in zip(witnesses_1, witnesses_2):
            if {k: v for k, v in one.items() if k not in excluded} != {
                k: v for k, v in two.items() if k not in excluded
            }:
                raise ReviewedLibraryFlowImportDenied(
                    "Reviewer or signed source currentness changed during preflight"
                )
        last = await current()
        if first != last:
            raise ReviewedLibraryFlowImportDenied("Original revised before preflight returned")
        # NOT a reviewed-import grant, Task payload, target evidence, or
        # authorization to call a Flow-local note writer.
        return PendingLibraryFlowCitation(
            source_id=request.global_document_id,
            original_revision=request.global_revision,
            original_sha256=request.global_sha256,
            source_kind=first[1],
            engagement_id=request.engagement_id,
            flow_id=request.flow_id,
            flow_revision=request.flow_revision,
        )

    async def bind_to_flow(self, request: GlobalFlowImportRequest) -> None:
        """No atomic 0039 current-row + reviewed receipt + signed Flow writer."""
        _scope(request)
        raise ReviewedLibraryFlowImportDenied(
            "No durable atomic reviewed 0039-to-Flow citation/binding API exists"
        )
