"""Independent target-controlled Ed25519 ownership-assertion verifier.

Signed HTTP/provider receipts, response status, graph validation and report
envelopes do NOT authenticate the target. This standalone verifier accepts an
explicit target-owned signing key from a separately deployed operator-trust
configuration, never a key supplied by a target response or model.

An independently signed assertion is proof *of that assertion by the configured
key*, not proof that a vulnerability exists. No external HTTP, application DB,
provider, tool, or graph calls occur here. Callers must supply separately
authorized, freshly read PostgreSQL Task/Flow/ROE and session provenance, an
atomic durable nonce claimant, and a fresh independent authority check.

Current replay Task admission does not persist the required private
_authority_request_sha256 / _authority_session_sha256 fields and the durable
nonce/authority adapters are not yet wired. Those inputs are REQUIRED, so this
module cannot accidentally promote current provider-only comparisons.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict
from urllib.parse import urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_osop.core.models import FlowRecord, Task
from ai_osop.orchestrator.context_compaction import task_assignment_sha256


class TargetAuthorityDenied(PermissionError):
    """Independently target-signed source assertion cannot be verified."""


_DOMAIN = b"AI-OSOP-TARGET-OWNED-AUTHORITY-ASSERTION-V1\x00"
_SCHEMA = "ai-osop.target-owned-authority.v1"
_CONFIG = "OSOP_TARGET_AUTHORITY_KEYS_JSON"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}\Z")
_TASK = re.compile(r"task-[A-Za-z0-9._-]{1,78}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}\Z")
_FQDN = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_CONFIG_ENTRY_FIELDS = frozenset(
    {
        "key_id",
        "engagement_id",
        "flow_id",
        "origin",
        "owner_sub",
        "ed25519_public_key_b64",
    }
)
_SIGNED_FIELDS = frozenset(
    {
        "schema",
        "key_id",
        "nonce",
        "issued_at",
        "expires_at",
        "engagement_id",
        "flow_id",
        "flow_revision",
        "owner_sub",
        "authorization_id",
        "authorization_version",
        "authorization_sha256",
        "original_source_task_id",
        "original_source_task_sha256",
        "replay_parent_task_id",
        "source_task_id",
        "target_task_id",
        "source_task_sha256",
        "target_task_sha256",
        "source_identity",
        "target_identity",
        "workflow_id",
        "step_id",
        "endpoint_url",
        "method",
        "source_request_sha256",
        "target_request_sha256",
        "source_session_sha256",
        "target_session_sha256",
        "source_response_sha256",
        "target_response_sha256",
        "source_http_status",
        "target_http_status",
        "anonymous_http_status",
        "resource_visibility",
        "resource_owner_identity",
        "target_access_forbidden",
        "cross_identity_disclosure_confirmed",
        "redirected",
        "denied",
        "public_access",
    }
)


@dataclass(frozen=True)
class TargetAuthorityVerdict:
    """Only a scoped signed assertion; NEVER a verified finding or exploit."""

    engagement_id: str
    flow_id: str
    source_task_id: str
    target_task_id: str
    key_id: str
    proof_sha256: str
    target_controlled_signature_verified: bool = True
    independent_target_authority_verified: bool = True
    authorization_violation_verified: bool = False
    finding_verified: bool = False
    report_release_approved: bool = False


def _now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _object(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    seen: Dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("Duplicate signed field")
        seen[key] = value
    return seen


def _strict_json(blob: bytes, *, max_bytes: int) -> Dict[str, Any]:
    if type(blob) is not bytes or not 1 <= len(blob) <= max_bytes:
        raise TargetAuthorityDenied("Signed target assertion unavailable or oversized")
    try:
        document = json.loads(
            blob.decode("utf-8", errors="strict"),
            object_pairs_hook=_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON number")),
        )
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise TargetAuthorityDenied("Signed target assertion is malformed") from exc
    if type(document) is not dict:
        raise TargetAuthorityDenied("Signed target assertion object required")
    return document


def _canonical(document: Dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise TargetAuthorityDenied("Signed target assertion is not canonical") from exc


def _identifier(value: Any, pattern: re.Pattern[str] = _ID) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _digest(value: Any) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _endpoint(url: Any) -> tuple[str, str]:
    """Accept one canonical HTTPS endpoint, not credential/redirect aliases."""
    if type(url) is not str or not 12 <= len(url) <= 2048:
        raise TargetAuthorityDenied("Target endpoint is invalid")
    try:
        uri = urlsplit(url)
        host = uri.hostname
        if (
            uri.scheme != "https"
            or uri.username is not None
            or uri.password is not None
            or not host
            or not _FQDN.fullmatch(host)
            or uri.netloc != host
            or uri.port is not None
            or not uri.path.startswith("/")
            or uri.fragment
            or uri.path.startswith("//")
            or any(c in url for c in ("\\", "\r", "\n", "\t", " ", "#"))
            or urlunsplit(uri) != url
            or "%" in uri.path
            or "%" in uri.query
            or any(part in {".", ".."} for part in uri.path.split("/"))
        ):
            raise ValueError("Untrusted or non-canonical HTTPS authority")
    except (ValueError, AttributeError) as exc:
        raise TargetAuthorityDenied("Target endpoint is invalid") from exc
    return url, "https://" + host


def _keys() -> Dict[str, tuple[Dict[str, str], Ed25519PublicKey]]:
    """Keys MUST be independently deployed, never sourced from proof/provider."""
    raw = os.environ.get(_CONFIG, "")
    if not isinstance(raw, str) or not 1 <= len(raw.encode("utf-8")) <= 8192:
        raise TargetAuthorityDenied("Independently configured target authority key unavailable")
    config = _strict_json(raw.encode("utf-8"), max_bytes=8192)
    entries = config.get("keys")
    if (
        set(config) != {"version", "keys"}
        or type(config["version"]) is not int
        or config["version"] != 1
        or type(entries) is not list
        or not 1 <= len(entries) <= 8
    ):
        raise TargetAuthorityDenied("Independently configured target authority keys invalid")
    result: Dict[str, tuple[Dict[str, str], Ed25519PublicKey]] = {}
    for row in entries:
        if (
            type(row) is not dict
            or set(row) != _CONFIG_ENTRY_FIELDS
            or not all(
                _identifier(row.get(name))
                for name in (
                    "key_id",
                    "engagement_id",
                    "flow_id",
                )
            )
            or not _identifier(row.get("owner_sub"), _OWNER)
            or type(row.get("origin")) is not str
            or type(row.get("ed25519_public_key_b64")) is not str
        ):
            raise TargetAuthorityDenied("Configured target public key binding invalid")
        try:
            _, origin = _endpoint(row["origin"] + "/")
            if origin != row["origin"]:
                raise ValueError("Non-canonical trusted origin")
            pub = base64.b64decode(row["ed25519_public_key_b64"], validate=True)
            if len(pub) != 32 or base64.b64encode(pub).decode() != row["ed25519_public_key_b64"]:
                raise ValueError("Invalid configured Ed25519 key")
            public_key = Ed25519PublicKey.from_public_bytes(pub)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise TargetAuthorityDenied("Configured target public key invalid") from exc
        if row["key_id"] in result or any(
            known[0]["ed25519_public_key_b64"] == row["ed25519_public_key_b64"]
            for known in result.values()
        ):
            raise TargetAuthorityDenied("Duplicate target authority key")
        result[row["key_id"]] = (row, public_key)
    return result


def _task_lineage(
    *,
    source: Task,
    target: Task,
    original: Task,
    flow: FlowRecord,
    signed: Any,
    engagement_id: str,
) -> Dict[str, Any]:
    """Construct exact expected claim from separately read authoritative tasks."""
    if (
        not isinstance(flow, FlowRecord)
        or flow.engagement_id != engagement_id
        or flow.status not in {"pending", "running"}
        or type(flow.revision) is not int
        or flow.revision < 0
        or type(getattr(signed, "version", None)) is not int
        or signed.version < 1
        or not _identifier(getattr(signed, "authorization_id", None))
        or not _digest(getattr(signed, "policy_sha256", None))
        or not all(
            isinstance(task, Task) and isinstance(task.payload, dict)
            for task in (source, target, original)
        )
        or original.type != "map_workflow"
        or original.status != "completed"
        or original.engagement_id != engagement_id
        or original.flow_id not in {None, flow.id}
        or original.payload.get("_authorization_version") != signed.version
        or not _identifier(original.id, _TASK)
    ):
        raise TargetAuthorityDenied("Current signed source/Flow authority unavailable")
    payload_a, payload_b = source.payload, target.payload
    source_label, target_label = payload_a.get("user_label"), payload_b.get("user_label")
    if (
        not _identifier(source_label)
        or not _identifier(target_label)
        or source_label.casefold() in {"anonymous", "guest", "public", "unauthenticated"}
        or target_label.casefold() in {"anonymous", "guest", "public", "unauthenticated"}
        or source_label == target_label
        or original.payload.get("user_label") != source_label
        or not _identifier(source.parent_task_id, _TASK)
        or source.parent_task_id != target.parent_task_id
        or source.id == target.id
        or not all(
            _identifier(task.id, _TASK)
            and task.engagement_id == engagement_id
            and task.flow_id == flow.id
            and task.type == "navigate"
            and task.status == "completed"
            and task.approval_required is True
            and task.max_retries == 0
            and task.parent_task_id == source.parent_task_id
            and task.dependencies == [source.parent_task_id]
            for task in (source, target)
        )
        or not all(
            task.payload.get("_authorization_version") == signed.version
            and type(task.payload.get("_authorization_version")) is int
            and task.payload.get("_flow_revision") == flow.revision
            and type(task.payload.get("_flow_revision")) is int
            and task.payload.get("method") == "GET"
            and task.payload.get("operator_approved") is True
            and _identifier(task.payload.get("approval_id"))
            and task.payload.get("source_user_label") == source_label
            and task.payload.get("target_user_label") == target_label
            and _identifier(task.payload.get("workflow_id"))
            and _identifier(task.payload.get("step_id"))
            for task in (source, target)
        )
        or payload_a.get("_comparison_role") != "source"
        or payload_b.get("_comparison_role") != "target"
        or payload_a.get("workflow_id") != payload_b.get("workflow_id")
        or payload_a.get("step_id") != payload_b.get("step_id")
        or payload_a.get("url") != payload_b.get("url")
        or not all(
            _digest(task.payload.get(field))
            for task in (source, target)
            for field in ("_authority_request_sha256", "_authority_session_sha256")
        )
        or hmac.compare_digest(
            payload_a["_authority_session_sha256"], payload_b["_authority_session_sha256"]
        )
        or not isinstance(original.result, dict)
        or original.result.get("workflow_id") != payload_a["workflow_id"]
    ):
        raise TargetAuthorityDenied(
            "Distinct approved replay tasks or session provenance unavailable"
        )
    endpoint, _ = _endpoint(payload_a["url"])
    for task, role in ((source, "source"), (target, "target")):
        outcome = task.result
        if (
            type(outcome) is not dict
            or outcome.get("status") != "success"
            or outcome.get("comparison_role") != role
            or outcome.get("source_task_id") != original.id
            or outcome.get("replay_parent_task_id") != source.parent_task_id
            or outcome.get("redirected") is not False
            or type(outcome.get("http_status_code")) is not int
            or outcome["http_status_code"] != 200
            or not _digest(outcome.get("response_body_sha256"))
            or outcome.get("denied") is True
            or outcome.get("public_access") is True
            or not isinstance(outcome.get("provider_evidence"), dict)
            or outcome["provider_evidence"].get("source_authenticity_verified") is not False
        ):
            raise TargetAuthorityDenied("Replay response is denied, redirected or unauthenticated")
    if not hmac.compare_digest(
        source.result["response_body_sha256"], target.result["response_body_sha256"]
    ):
        raise TargetAuthorityDenied("Cross-identity owned object not comparable")
    try:
        assignment = {
            "original_source_task_sha256": task_assignment_sha256(original),
            "source_task_sha256": task_assignment_sha256(source),
            "target_task_sha256": task_assignment_sha256(target),
        }
    except Exception as exc:
        raise TargetAuthorityDenied("Signed Task assignment fingerprints unavailable") from exc
    return {
        "engagement_id": engagement_id,
        "flow_id": flow.id,
        "flow_revision": flow.revision,
        "authorization_id": signed.authorization_id,
        "authorization_version": signed.version,
        "authorization_sha256": signed.policy_sha256,
        "original_source_task_id": original.id,
        "replay_parent_task_id": source.parent_task_id,
        "source_task_id": source.id,
        "target_task_id": target.id,
        "source_identity": source_label,
        "target_identity": target_label,
        "workflow_id": payload_a["workflow_id"],
        "step_id": payload_a["step_id"],
        "endpoint_url": endpoint,
        "method": "GET",
        "source_request_sha256": payload_a["_authority_request_sha256"],
        "target_request_sha256": payload_b["_authority_request_sha256"],
        "source_session_sha256": payload_a["_authority_session_sha256"],
        "target_session_sha256": payload_b["_authority_session_sha256"],
        "source_response_sha256": source.result["response_body_sha256"],
        "target_response_sha256": target.result["response_body_sha256"],
        "source_http_status": 200,
        "target_http_status": 200,
        **assignment,
    }


def _live_state_fingerprint(
    original: Task, source: Task, target: Task, flow: FlowRecord, signed: Any
) -> tuple[Any, ...]:
    """Pin all candidate inputs before awaiting external durable guards.

    Task assignment hashes deliberately ignore mutable execution outcomes,
    so additionally bind full TaskORM-derived status/result fields and the
    in-memory signed Flow/ROE values. Callers must *also* re-read PostgreSQL
    authority in their independently implemented current_authority_check.
    """
    try:
        snapshots = []
        for task in (original, source, target):
            record = _canonical(task.model_dump(mode="json"))
            if len(record) > 65536:
                raise ValueError("Unbounded task evidence")
            snapshots.append(hashlib.sha256(record).hexdigest())
        return (
            *snapshots,
            flow.id,
            flow.engagement_id,
            flow.revision,
            flow.status,
            signed.authorization_id,
            signed.version,
            signed.policy_sha256,
        )
    except Exception as exc:
        raise TargetAuthorityDenied("Current signed Task/Flow snapshot unavailable") from exc


async def _checked(func: Callable[[], Awaitable[bool]], *, label: str) -> None:
    if not callable(func):
        raise TargetAuthorityDenied(f"Independent {label} verifier unavailable")
    try:
        result = await asyncio.wait_for(func(), timeout=3)
    except Exception as exc:
        raise TargetAuthorityDenied(f"Independent {label} verification unavailable") from exc
    if result is not True:
        raise TargetAuthorityDenied(f"Independent {label} verification unavailable")


async def verify_target_authority_proof(
    *,
    claims_json: bytes,
    signature_b64url: str,
    engagement_id: str,
    flow: FlowRecord,
    signed_authorization: Any,
    original_source_task: Task,
    source_task: Task,
    target_task: Task,
    owner_sub: str,
    replay_guard: Any,
    current_authority_check: Callable[[], Awaitable[bool]],
) -> TargetAuthorityVerdict:
    """Verify a target-owned detached signature over exact replay provenance.

    `current_authority_check` MUST recheck current signed PostgreSQL ROE, Flow
    revision/status, immutable source+target TaskORM, their human approvals and
    active identity/session provenance. This is a REQUIRED caller-supplied
    trusted operation; a True constant or provider callback is not sufficient.
    `replay_guard.claim_once` MUST be atomic durable insert-if-absent, shared
    across replicas. No in-process set or merely signed nonce is replay safety.
    The returned verdict is only evidence of target-controlled attestation.
    """
    if (
        not _identifier(engagement_id)
        or not _identifier(owner_sub, _OWNER)
        or not callable(getattr(replay_guard, "claim_once", None))
        or not callable(current_authority_check)
    ):
        raise TargetAuthorityDenied("Independent trusted target proof guards unavailable")
    expected = _task_lineage(
        source=source_task,
        target=target_task,
        original=original_source_task,
        flow=flow,
        signed=signed_authorization,
        engagement_id=engagement_id,
    )
    original_live_state = _live_state_fingerprint(
        original_source_task, source_task, target_task, flow, signed_authorization
    )
    _, origin = _endpoint(expected["endpoint_url"])
    claims = _strict_json(claims_json, max_bytes=4096)
    if (
        set(claims) != _SIGNED_FIELDS
        or claims.get("schema") != _SCHEMA
        or not _identifier(claims.get("key_id"))
        or not _identifier(claims.get("nonce"), _NONCE)
        or type(claims.get("issued_at")) is not int
        or type(claims.get("expires_at")) is not int
        or any(
            type(claims.get(name)) is not bool or claims[name] is not value
            for name, value in {
                "target_access_forbidden": True,
                "cross_identity_disclosure_confirmed": True,
                "redirected": False,
                "denied": False,
                "public_access": False,
            }.items()
        )
        or claims.get("resource_visibility") != "private"
        or claims.get("resource_owner_identity") != expected["source_identity"]
        or type(claims.get("anonymous_http_status")) is not int
        or claims["anonymous_http_status"] not in (401, 403, 404)
    ):
        raise TargetAuthorityDenied("Independent target assertion is invalid or public")
    now = _now_epoch()
    # A *subsequent* review of an already-committed immutable PostgreSQL
    # receipt must check original proof freshness against its DB admission
    # time, not pretend that an old historical receipt was newly issued.
    # The normal one-use insertion guard cannot select this mode.
    from ai_osop.memory.target_authority_receipts import (
        PersistedTargetAuthorityReceiptGuard,
    )

    if type(replay_guard) is PersistedTargetAuthorityReceiptGuard:
        recorded_time = replay_guard.verification_epoch
        if type(recorded_time) is not int or recorded_time > now + 5:
            raise TargetAuthorityDenied("Persisted proof admission time untrusted")
        now = recorded_time
    if (
        claims["issued_at"] > now + 5
        or claims["issued_at"] < now - 120
        or not claims["issued_at"] < claims["expires_at"] <= claims["issued_at"] + 120
        or now > claims["expires_at"]
    ):
        raise TargetAuthorityDenied("Target assertion expired or not yet issued")
    if (
        any(
            type(claims.get(name)) is not type(value) or claims.get(name) != value
            for name, value in expected.items()
        )
        or claims.get("owner_sub") != owner_sub
    ):
        raise TargetAuthorityDenied("Target assertion Task/Flow/ROE provenance differs")
    if claims_json != _canonical(claims):
        raise TargetAuthorityDenied("Detached target signature payload is not canonical")
    trusted = _keys().get(claims["key_id"])
    if trusted is None:
        raise TargetAuthorityDenied("Independently configured target owner key unavailable")
    binding, key = trusted
    if (
        binding["engagement_id"] != engagement_id
        or binding["flow_id"] != expected["flow_id"]
        or binding["owner_sub"] != owner_sub
        or binding["origin"] != origin
    ):
        raise TargetAuthorityDenied("Configured target-owned key is not bound to this Flow")
    if not _identifier(signature_b64url, _SIGNATURE):
        raise TargetAuthorityDenied("Detached target signature invalid")
    try:
        signature = base64.urlsafe_b64decode(signature_b64url + "==")
        if (
            len(signature) != 64
            or base64.urlsafe_b64encode(signature).decode().rstrip("=") != signature_b64url
        ):
            raise ValueError("Non-canonical detached signature")
        key.verify(signature, _DOMAIN + claims_json)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise TargetAuthorityDenied("Detached target signature is untrusted") from exc
    # The signer only establishes that the configured key signed these exact
    # claims. No provider or model testimony can replace durable approvals.
    await _checked(current_authority_check, label="signed Task/Flow/ROE")
    proof_sha = hashlib.sha256(_DOMAIN + claims_json + signature).hexdigest()
    try:
        admitted = await asyncio.wait_for(
            replay_guard.claim_once(
                engagement_id=engagement_id,
                flow_id=expected["flow_id"],
                key_id=claims["key_id"],
                nonce=claims["nonce"],
                proof_sha256=proof_sha,
            ),
            timeout=3,
        )
    except Exception as exc:
        # An ACK lost after an atomic claim is UNKNOWN. Never retry it.
        raise TargetAuthorityDenied("Durable target proof replay status UNKNOWN") from exc
    if admitted is not True:
        raise TargetAuthorityDenied("Target proof replayed or unconfirmed")
    # Prevent a revoked approval/Flow from being promoted after awaiting the
    # durable nonce transaction. This is still NOT an atomic report-release CAS.
    await _checked(current_authority_check, label="signed Task/Flow/ROE")
    if (
        _live_state_fingerprint(
            original_source_task, source_task, target_task, flow, signed_authorization
        )
        != original_live_state
    ):
        raise TargetAuthorityDenied("Signed target proof input changed during verification")
    return TargetAuthorityVerdict(
        engagement_id=engagement_id,
        flow_id=expected["flow_id"],
        source_task_id=expected["source_task_id"],
        target_task_id=expected["target_task_id"],
        key_id=claims["key_id"],
        proof_sha256=proof_sha,
    )
