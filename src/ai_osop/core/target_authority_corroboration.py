"""Corroborate target-owned assertions with separately trusted audit signers.

The owner-of-record ledger and HTTP authorization gateway MUST hold different
keys, independently configured by the operator. This authenticates records,
not a remotely observed vulnerability or permission to release a report.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_osop.core.target_authority_proof import _keys

_CONFIG_NAME = "OSOP_TARGET_AUDIT_KEYS_JSON"
_DOMAIN = b"AI-OSOP-TARGET-INDEPENDENT-AUDIT-V1\x00"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[a-zA-Z0-9_-]{16,128}\Z")
_SIG = re.compile(r"[A-Za-z0-9_-]{86}\Z")
_FIELDS = frozenset(
    {
        "schema",
        "role",
        "engagement_id",
        "flow_id",
        "authorization_id",
        "authorization_version",
        "authorization_sha256",
        "flow_revision",
        "original_source_task_id",
        "source_task_id",
        "target_task_id",
        "source_identity",
        "target_identity",
        "endpoint_url",
        "method",
        "source_request_sha256",
        "target_request_sha256",
        "source_session_sha256",
        "target_session_sha256",
        "source_response_sha256",
        "target_response_sha256",
        "target_proof_sha256",
        "resource_id",
        "resource_owner_identity",
        "resource_visibility",
        "source_http_status",
        "target_http_status",
        "anonymous_http_status",
        "source_access_allowed",
        "target_access_forbidden",
        "nonce",
        "issued_at",
        "expires_at",
    }
)
_MATCHED_FIELDS = _FIELDS - {
    "schema",
    "role",
    "resource_id",
    "source_access_allowed",
    "nonce",
    "issued_at",
    "expires_at",
    "target_proof_sha256",
}


class TargetAuditUnverified(PermissionError):
    """Corroborating independent audit evidence is missing or inconsistent."""


@dataclass(frozen=True)
class CorroboratedTargetAudit:
    engagement_id: str
    flow_id: str
    source_task_id: str
    target_task_id: str
    proof_sha256: str
    audit_sha256: str
    source_records_correlated: bool = True
    target_audit_signatures_verified: bool = True
    finding_verified: bool = False
    report_release_approved: bool = False


def _object(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate signed field")
        result[key] = value
    return result


def _parse(blob: bytes, limit: int) -> Dict[str, Any]:
    if type(blob) is not bytes or not 1 <= len(blob) <= limit:
        raise TargetAuditUnverified("Bounded signed audit source required")
    try:
        obj = json.loads(
            blob.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if type(obj) is not dict or _canonical(obj) != blob:
            raise ValueError("noncanonical")
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise TargetAuditUnverified("Malformed signed audit source") from exc
    return obj


def _canonical(obj: Dict[str, Any]) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _key_pair(engagement: str, flow_id: str, origin: str) -> Dict[str, Ed25519PublicKey]:
    raw = os.environ.get(_CONFIG_NAME, "")
    config = _parse(raw.encode("utf-8"), 4096)
    if set(config) != {"version", "engagement_id", "flow_id", "origin", "keys"} or (
        type(config["version"]) is not int
        or config["version"] != 1
        or config["engagement_id"] != engagement
        or config["flow_id"] != flow_id
        or config["origin"] != origin
        or type(config["keys"]) is not dict
        or set(config["keys"]) != {"ownership", "access"}
    ):
        raise TargetAuditUnverified("Trusted independent audit configuration unavailable")
    result = {}
    for role, encoded in config["keys"].items():
        try:
            if type(encoded) is not str:
                raise ValueError("key missing")
            key_bytes = base64.b64decode(encoded, validate=True)
            if len(key_bytes) != 32 or base64.b64encode(key_bytes).decode() != encoded:
                raise ValueError("invalid key")
            result[role] = Ed25519PublicKey.from_public_bytes(key_bytes)
        except (ValueError, TypeError) as exc:
            raise TargetAuditUnverified("Untrusted audit verification key") from exc
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw_keys = [k.public_bytes(Encoding.Raw, PublicFormat.Raw) for k in result.values()]
    if raw_keys[0] == raw_keys[1]:
        raise TargetAuditUnverified("Audit attestations require independent signing keys")
    target_keys = [k.public_bytes(Encoding.Raw, PublicFormat.Raw) for _, k in _keys().values()]
    if any(k in target_keys for k in raw_keys):
        raise TargetAuditUnverified("Audit signers must be separate from target assertion signer")
    return result


def _verify_record(
    blob: bytes,
    signature: str,
    key: Ed25519PublicKey,
    role: str,
    expected: Dict[str, Any],
    proof_sha256: str,
    now: int,
) -> Dict[str, Any]:
    claim = _parse(blob, 4096)
    if (
        set(claim) != _FIELDS
        or claim.get("schema") != "ai-osop.target-independent-audit.v1"
        or claim.get("role") != role
    ):
        raise TargetAuditUnverified("Unrecognized independent audit claim")
    if (
        type(claim.get("nonce")) is not str
        or _NONCE.fullmatch(claim["nonce"]) is None
        or type(claim.get("issued_at")) is not int
        or type(claim.get("expires_at")) is not int
        or not now - 120 <= claim["issued_at"] <= now + 5
        or not claim["issued_at"] < claim["expires_at"] <= claim["issued_at"] + 120
        or claim["expires_at"] < now
        or claim.get("target_proof_sha256") != proof_sha256
        or type(claim.get("resource_id")) is not str
        or not 1 <= len(claim["resource_id"]) <= 128
        or not re.fullmatch(r"[A-Za-z0-9._:-]+", claim["resource_id"])
        or claim.get("source_access_allowed") is not True
    ):
        raise TargetAuditUnverified("Independent audit freshness or object binding invalid")
    for field in _MATCHED_FIELDS:
        if type(claim.get(field)) is not type(expected.get(field)) or claim.get(
            field
        ) != expected.get(field):
            raise TargetAuditUnverified("Signed audit contradicts target authority source")
    if (
        claim["resource_visibility"] != "private"
        or claim["resource_owner_identity"] != claim["source_identity"]
        or claim["target_access_forbidden"] is not True
        or claim["source_http_status"] != 200
        or claim["target_http_status"] != 200
        or claim["anonymous_http_status"] not in (401, 403, 404)
    ):
        raise TargetAuditUnverified("Public or denied resource is not unauthorized access")
    if type(signature) is not str or _SIG.fullmatch(signature) is None:
        raise TargetAuditUnverified("Independent audit signature required")
    try:
        decoded = base64.urlsafe_b64decode(signature + "==")
        if (
            len(decoded) != 64
            or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != signature
        ):
            raise ValueError("noncanonical signature")
        key.verify(decoded, _DOMAIN + blob)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise TargetAuditUnverified("Independent audit signature invalid") from exc
    return claim


def corroborate_target_audits(
    *,
    target_claims_json: bytes,
    target_proof_sha256: str,
    ownership_json: bytes,
    ownership_signature: str,
    access_json: bytes,
    access_signature: str,
    trusted_receipt_epoch: int | None = None,
) -> CorroboratedTargetAudit:
    """Verify two independently signed target-side audit records, without promotion.

    Caller must separately verify the original target proof and durably admit its
    nonce in a signed PostgreSQL transaction. `trusted_receipt_epoch` may ONLY
    come from the immutable PostgreSQL assertion row when later rechecking
    archived evidence. Do NOT use this alone to release.
    """
    if type(target_proof_sha256) is not str or _SHA.fullmatch(target_proof_sha256) is None:
        raise TargetAuditUnverified("Verified target proof digest required")
    expected = _parse(target_claims_json, 4096)
    if expected.get("schema") != "ai-osop.target-owned-authority.v1":
        raise TargetAuditUnverified("Independently signed target claim required")
    for field in _MATCHED_FIELDS:
        if field not in expected:
            raise TargetAuditUnverified("Missing target source binding")
    try:
        from urllib.parse import urlsplit

        origin = "https://" + urlsplit(expected["endpoint_url"]).hostname
        if urlsplit(expected["endpoint_url"]).scheme != "https":
            raise ValueError("HTTPS only")
        keys = _key_pair(expected["engagement_id"], expected["flow_id"], origin)
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise TargetAuditUnverified("Target audit origin invalid") from exc
    now = int(time.time())
    if trusted_receipt_epoch is not None:
        if (
            type(trusted_receipt_epoch) is not int
            or trusted_receipt_epoch < 1
            or trusted_receipt_epoch > now + 5
        ):
            raise TargetAuditUnverified("Original immutable audit admission time invalid")
        now = trusted_receipt_epoch
    ownership = _verify_record(
        ownership_json,
        ownership_signature,
        keys["ownership"],
        "ownership",
        expected,
        target_proof_sha256,
        now,
    )
    access = _verify_record(
        access_json, access_signature, keys["access"], "access", expected, target_proof_sha256, now
    )
    if (
        ownership["resource_id"] != access["resource_id"]
        or ownership["nonce"] == access["nonce"]
        or ownership["resource_owner_identity"] != access["resource_owner_identity"]
    ):
        raise TargetAuditUnverified("Independent object and observation records disagree")
    # Independently signed *ownership* must identify the actual resource in
    # the exact approved request. A signer cannot arbitrarily name an unrelated
    # privately owned object and pair it with a public or neighboring URL.
    from urllib.parse import parse_qsl, urlsplit

    endpoint = urlsplit(expected["endpoint_url"])
    path_leaf = endpoint.path.rstrip("/").split("/")[-1]
    query_owners = [
        value
        for key, value in parse_qsl(endpoint.query, keep_blank_values=True)
        if key.lower() in {"id", "resource_id", "record_id", "object_id"}
    ]
    resource_id = ownership["resource_id"]
    if resource_id != path_leaf and (
        not query_owners or any(value != resource_id for value in query_owners)
    ):
        raise TargetAuditUnverified("Signed owner-of-record object not correlated to request")
    digest = hashlib.sha256(
        _DOMAIN
        + ownership_json
        + access_json
        + ownership_signature.encode("ascii")
        + access_signature.encode("ascii")
    ).hexdigest()
    return CorroboratedTargetAudit(
        engagement_id=expected["engagement_id"],
        flow_id=expected["flow_id"],
        source_task_id=expected["source_task_id"],
        target_task_id=expected["target_task_id"],
        proof_sha256=target_proof_sha256,
        audit_sha256=digest,
    )
