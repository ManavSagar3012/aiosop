"""Offline Ed25519 signed rules-of-engagement verification.

Envelope schema (no optional/extra fields):
  {"version": positive_int, "policy": POLICY, "signature": base64url_signature}
POLICY has the exact fields in _POLICY_KEYS; policy.version equals envelope.version.
Sign only canonical_json_bytes(POLICY), never the outer envelope.
Signature is unpadded base64url of 64 Ed25519 signature bytes (86 ASCII chars).

OSOP_ROE_TRUSTED_KEYS_JSON is required, exactly:
  {"prod-kid": "<standard padded base64 of RAW 32-byte Ed25519 public key>"}
Do not use DER/PEM, unpadded key encodings, or private keys here.
Key configuration is reloaded for every verification, without mutable caches.

Callers MUST separately check the durable authorization registry for revoked
authorization_id or signing KID, and against a monotonic policy version.
Cryptographic validity cannot establish either revocation or freshness.
"""

import base64
import binascii
import hashlib
import ipaddress
import json
import math
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class SignedROEError(ValueError):
    """Missing, invalid, untrusted, or mismatched authorization policy."""


_ENVELOPE_KEYS = frozenset({"version", "policy", "signature"})
_POLICY_KEYS = frozenset(
    {
        "engagement_id",
        "created_by",
        "domains",
        "ips",
        "exclusions",
        "allowed_techniques",
        "restrictions",
        "approval_required_for",
        "testing_window_start",
        "testing_window_end",
        "roe",
        "issued_at",
        "not_before",
        "expires_at",
        "version",
        "authorization_id",
        "key_id",
    }
)
_SCOPE_LISTS = (
    "domains",
    "ips",
    "exclusions",
    "allowed_techniques",
    "restrictions",
    "approval_required_for",
)
_SCOPE_DATES = ("testing_window_start", "testing_window_end")
_KID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z", re.ASCII)
_SIG_PATTERN = re.compile(r"[A-Za-z0-9_-]{86}\Z", re.ASCII)
_UTC_TIMESTAMP = re.compile(
    r"\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?Z\Z",
    re.ASCII,
)
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)


def _require_json(value: Any, depth: int = 0) -> None:
    if depth > 24:
        raise SignedROEError("Signed policy nesting limit exceeded")
    if value is None or type(value) in {str, int, bool}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise SignedROEError("Nonfinite numbers are forbidden in signed policy")
        return
    if type(value) is list:
        if len(value) > 1000:
            raise SignedROEError("Signed policy list limit exceeded")
        for item in value:
            _require_json(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > 1000 or any(type(key) is not str or len(key) > 256 for key in value):
            raise SignedROEError("Signed policy object keys must be bounded strings")
        for item in value.values():
            _require_json(item, depth + 1)
        return
    raise SignedROEError("Signed policy contains a non-JSON value")


def canonical_json_bytes(value: Any) -> bytes:
    """Deterministic UTF-8 JSON; no implicit data coercion or NaN."""
    _require_json(value)
    try:
        content = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise SignedROEError("Signed policy could not be encoded") from exc
    if len(content) > 262144:
        raise SignedROEError("Signed policy exceeds maximum size")
    return content


def _identifier(value: Any, label: str, *, kid: bool = False) -> str:
    pattern = _KID_PATTERN if kid else _IDENTIFIER_PATTERN
    if type(value) is not str or not pattern.fullmatch(value):
        raise SignedROEError(f"Invalid {label}")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if type(value) is not list or len(value) > 200:
        raise SignedROEError(f"Invalid {label} list")
    if any(type(item) is not str or not item or len(item) > 253 for item in value):
        raise SignedROEError(f"Invalid {label} item")
    if len(set(value)) != len(value):
        raise SignedROEError(f"Duplicate {label} item")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if type(value) is not str or not _UTC_TIMESTAMP.fullmatch(value):
        raise SignedROEError(f"{label} must be UTC RFC3339 ending in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SignedROEError(f"Invalid {label} date") from exc


def _expected_timestamp(value: Any, label: str) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        # Existing SessionState may contain naive UTC datetimes; never infer
        # a local timezone from the host machine.
        return (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None
            else value.astimezone(timezone.utc)
        )
    if type(value) is str:
        if value.endswith("Z"):
            return _timestamp(value, label)
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise SignedROEError(f"Invalid expected {label}") from exc
        if value.tzinfo is None:
            raise SignedROEError(f"Expected {label} must have a timezone")
        return value.astimezone(timezone.utc)
    raise SignedROEError(f"Invalid expected {label}")


def _validate_policy(policy: dict, version: int, now: datetime) -> Dict[str, datetime]:
    if frozenset(policy) != _POLICY_KEYS:
        raise SignedROEError("Missing or extra signed policy fields")
    if type(policy["version"]) is not int or policy["version"] <= 0 or policy["version"] != version:
        raise SignedROEError("Signed policy version mismatch")
    for field in ("engagement_id", "created_by", "authorization_id"):
        _identifier(policy[field], field)
    _identifier(policy["key_id"], "key_id", kid=True)
    for field in _SCOPE_LISTS:
        _string_list(policy[field], field)
    if not policy["domains"] and not policy["ips"]:
        raise SignedROEError("Signed target scope cannot be empty")
    for domain in policy["domains"]:
        labels = domain.split(".")
        if (
            domain != domain.lower()
            or len(labels) < 2
            or not all(_HOST_LABEL.fullmatch(label) for label in labels)
        ):
            raise SignedROEError("Invalid signed domain")
    for ip in policy["ips"]:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError as exc:
            raise SignedROEError("Invalid signed IP range") from exc
    roe = policy["roe"]
    if type(roe) is not dict:
        raise SignedROEError("Signed ROE must be an object")
    calls, dollars = roe.get("llm_call_budget_total"), roe.get("llm_cost_budget_usd")
    if calls is not None and (type(calls) is not int or calls <= 0):
        raise SignedROEError("LLM call budget must be a positive integer")
    if dollars is not None and (type(dollars) not in {int, float} or dollars <= 0):
        raise SignedROEError("LLM dollar budget must be a positive finite number")
    dates = {
        field: _timestamp(policy[field], field)
        for field in ("issued_at", "not_before", "expires_at", *_SCOPE_DATES)
    }
    if dates["issued_at"] > dates["not_before"] or dates["not_before"] >= dates["expires_at"]:
        raise SignedROEError("Invalid signed authorization validity interval")
    if dates["testing_window_start"] >= dates["testing_window_end"]:
        raise SignedROEError("Invalid signed testing window")
    if (
        now < dates["issued_at"]
        or now < dates["not_before"]
        or now >= dates["expires_at"]
        or now < dates["testing_window_start"]
        or now >= dates["testing_window_end"]
    ):
        raise SignedROEError("Signed authorization is not valid at this time")
    return dates


def _trusted_key(kid: str) -> Ed25519PublicKey:
    configured = os.environ.get("OSOP_ROE_TRUSTED_KEYS_JSON")
    if not configured:
        raise SignedROEError("Trusted ROE signing keys are not configured")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
        result: dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                raise SignedROEError("Duplicate signing key identifier in trust configuration")
            result[name] = value
        return result

    try:
        keys = json.loads(configured, object_pairs_hook=reject_duplicate_keys)
    except SignedROEError:
        raise
    except (TypeError, ValueError) as exc:
        raise SignedROEError("Malformed ROE trust configuration") from exc
    if type(keys) is not dict or not keys or len(keys) > 128:
        raise SignedROEError("Invalid ROE trust configuration")
    for name, encoded in keys.items():
        _identifier(name, "trusted key id", kid=True)
        if type(encoded) is not str or not encoded:
            raise SignedROEError("Invalid trusted key encoding")
    if kid not in keys:
        raise SignedROEError("Unknown or revoked signing key id")
    encoded = keys[kid]
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SignedROEError("Invalid trusted key base64") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != encoded:
        raise SignedROEError("Trusted key must be standard padded base64 of raw Ed25519 public key")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise SignedROEError("Invalid trusted Ed25519 key") from exc


def _scope_dict(scope: Any) -> dict:
    if isinstance(scope, Mapping):
        return dict(scope)
    dump = getattr(scope, "model_dump", None)
    if callable(dump):
        return dump()
    raise SignedROEError("Expected scope must be a ScopeDefinition or mapping")


@dataclass(frozen=True)
class VerifiedPolicy:
    """Verified immutable receipt; scope/roe accessors return fresh copies."""

    engagement_id: str
    created_by: str
    authorization_id: str
    kid: str
    signature: str
    version: int
    policy_digest: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    testing_window_start: datetime
    testing_window_end: datetime
    canonical_bytes: bytes

    @property
    def scope(self) -> Dict[str, Any]:
        policy = json.loads(self.canonical_bytes)
        return {
            "engagement_id": self.engagement_id,
            **{field: policy[field] for field in (*_SCOPE_LISTS, *_SCOPE_DATES)},
            "authorization_ref": self.authorization_id,
        }

    @property
    def roe(self) -> Dict[str, Any]:
        return json.loads(self.canonical_bytes)["roe"]


def verify_signed_roe(
    envelope: Any,
    expected_engagement_id: str,
    expected_owner: str,
    expected_scope: Any,
    expected_roe: Mapping[str, Any],
    now: datetime,
) -> VerifiedPolicy:
    """Verify policy signature, trusted key, current validity, and DB equality.

    This pure-in-process verifier does NOT validate durable revocation or
    monotonically increasing versions: callers must check their DB registry.
    """
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise SignedROEError("Verification time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if type(envelope) is not dict or frozenset(envelope) != _ENVELOPE_KEYS:
        raise SignedROEError("Malformed signed authorization envelope")
    version = envelope["version"]
    if type(version) is not int or version <= 0:
        raise SignedROEError("Invalid envelope version")
    policy = envelope["policy"]
    if type(policy) is not dict:
        raise SignedROEError("Signed policy must be an object")
    canonical = canonical_json_bytes(policy)
    dates = _validate_policy(policy, version, now)
    if _identifier(expected_engagement_id, "expected engagement") != policy["engagement_id"]:
        raise SignedROEError("Signed policy engagement does not match session")
    if _identifier(expected_owner, "expected owner") != policy["created_by"]:
        raise SignedROEError("Signed policy owner does not match session")
    scope = _scope_dict(expected_scope)
    if scope.get("engagement_id") != expected_engagement_id:
        raise SignedROEError("Persisted scope engagement does not match session")
    for field in _SCOPE_LISTS:
        if type(scope.get(field)) is not list or scope[field] != policy[field]:
            raise SignedROEError(f"Signed scope differs from persisted {field}")
    for field in _SCOPE_DATES:
        if _expected_timestamp(scope.get(field), field) != dates[field]:
            raise SignedROEError(f"Signed scope differs from persisted {field}")
    if scope.get("authorization_ref") not in {None, policy["authorization_id"]}:
        raise SignedROEError("Persisted authorization reference differs from signed authorization")
    if type(expected_roe) is not dict or canonical_json_bytes(expected_roe) != canonical_json_bytes(
        policy["roe"]
    ):
        raise SignedROEError("Signed ROE differs from persisted ROE")
    sig = envelope["signature"]
    if type(sig) is not str or not _SIG_PATTERN.fullmatch(sig):
        raise SignedROEError("Invalid strict unpadded base64url signature")
    try:
        raw_signature = base64.urlsafe_b64decode(sig + "==")
    except (ValueError, binascii.Error) as exc:
        raise SignedROEError("Invalid signature base64url") from exc
    if (
        len(raw_signature) != 64
        or base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode("ascii") != sig
    ):
        raise SignedROEError("Noncanonical signature base64url")
    key = _trusted_key(policy["key_id"])
    try:
        key.verify(raw_signature, canonical)
    except InvalidSignature as exc:
        raise SignedROEError("Invalid Ed25519 signature") from exc
    return VerifiedPolicy(
        engagement_id=policy["engagement_id"],
        created_by=policy["created_by"],
        authorization_id=policy["authorization_id"],
        kid=policy["key_id"],
        signature=sig,
        version=version,
        policy_digest=hashlib.sha256(canonical).hexdigest(),
        canonical_bytes=canonical,
        **dates,
    )
