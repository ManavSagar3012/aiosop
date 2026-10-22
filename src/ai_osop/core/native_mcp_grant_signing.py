"""One-purpose Ed25519 native MCP Action capability, never a target receipt.

An independently trusted native server must still consume this capability with
a durable, authenticated PostgreSQL-backed single-use redemption service before
running ANY handler. A valid signature alone is not runtime authorization.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from typing import Any, Dict, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DOMAIN = b"ai-osop/native-grant/v1\x00"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HEX = re.compile(r"[0-9a-f]{32}\Z")
_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_.:-]{2,95}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
CLAIM_FIELDS = frozenset(
    {
        "version",
        "grant_id",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "server_id",
        "tool_name",
        "parameters_sha256",
        "manifest_sha256",
        "authorization_version",
        "authorization_sha256",
        "lease_id",
        "resource_sha256",
        "issued_at",
        "expires_at",
        "side_effect_class",
    }
)


class NativeGrantDenied(ValueError):
    """Safe reason; never carries a secret or untrusted signed contents."""


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode(value: Any, size: int) -> bytes:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 512
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise NativeGrantDenied("Invalid native signature material")
    try:
        data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise NativeGrantDenied("Invalid native signature material") from exc
    if len(data) != size or _encode(data) != value:
        raise NativeGrantDenied("Invalid native signature material")
    return data


def canonical_claims(claims: Mapping[str, Any], *, now: Optional[int] = None) -> bytes:
    """Byte-identical Python/Go canonical JSON, bounded and no dynamic fields."""
    if type(claims) is not dict or set(claims) != CLAIM_FIELDS:
        raise NativeGrantDenied("Native grant fields are not complete")
    if (
        type(claims["version"]) is not int
        or claims["version"] != 1
        or claims["side_effect_class"] != "READ_ONLY"
        or claims["tool_name"] != "authority_status"
        or type(claims["authorization_version"]) is not int
        or claims["authorization_version"] < 1
        or type(claims["issued_at"]) is not int
        or type(claims["expires_at"]) is not int
    ):
        raise NativeGrantDenied("Unsupported native grant authority")
    for name in (
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "server_id",
        "lease_id",
    ):
        if type(claims[name]) is not str or _ID.fullmatch(claims[name]) is None:
            raise NativeGrantDenied("Invalid native grant scope identity")
    if (
        type(claims["request_id"]) is not str
        or re.fullmatch(r"req-[a-f0-9]{32,64}", claims["request_id"]) is None
        or type(claims["grant_id"]) is not str
        or not claims["grant_id"].startswith("ngr-")
        or _HEX.fullmatch(claims["grant_id"][4:]) is None
    ):
        raise NativeGrantDenied("Invalid native grant replay identity")
    for digest in ("parameters_sha256", "manifest_sha256", "authorization_sha256"):
        if type(claims[digest]) is not str or _SHA.fullmatch(claims[digest]) is None:
            raise NativeGrantDenied("Invalid native grant integrity digest")
    resource_sha = claims["resource_sha256"]
    if resource_sha is not None and (
        type(resource_sha) is not str or _SHA.fullmatch(resource_sha) is None
    ):
        raise NativeGrantDenied("Invalid native grant resource identity")
    issued = claims["issued_at"]
    expires = claims["expires_at"]
    if not (0 < issued < expires <= issued + 60):
        raise NativeGrantDenied("Native grant lifetime exceeds policy")
    if now is not None and (type(now) is not int or issued > now + 5 or expires <= now):
        raise NativeGrantDenied("Native grant is expired or not yet issued")
    try:
        body = json.dumps(
            claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise NativeGrantDenied("Invalid native grant JSON") from exc
    if len(body) > 2048:
        raise NativeGrantDenied("Native grant is oversized")
    return body


def claim_sha256(claims: Dict[str, Any]) -> str:
    # The Ed25519 signature is domain-separated. The immutable PostgreSQL
    # claims index and Go redemption response bind the SHA of canonical JSON.
    return hashlib.sha256(canonical_claims(claims)).hexdigest()


def sign_grant(
    claims: Dict[str, Any],
    *,
    kid: str,
    private_seed_b64url: str,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Pure signature; issuance authority and persistence must be checked first."""
    if type(kid) is not str or _KID.fullmatch(kid) is None:
        raise NativeGrantDenied("Trusted native grant issuer unavailable")
    body = canonical_claims(claims, now=int(time.time()) if now is None else now)
    key = Ed25519PrivateKey.from_private_bytes(_decode(private_seed_b64url, 32))
    return {
        "claims": dict(claims),
        "kid": kid,
        "signature": _encode(key.sign(DOMAIN + body)),
    }


def verify_grant(
    document: Any,
    *,
    public_keys: Mapping[str, str],
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Verify cryptography and shape; separately redeem in durable PG to run."""
    if (
        type(document) is not dict
        or set(document) != {"claims", "kid", "signature"}
        or type(document["kid"]) is not str
        or _KID.fullmatch(document["kid"]) is None
        or type(public_keys) is not dict
        or len(public_keys) > 16
        or document["kid"] not in public_keys
    ):
        raise NativeGrantDenied("Untrusted native MCP issuer")
    body = canonical_claims(document["claims"], now=int(time.time()) if now is None else now)
    key = Ed25519PublicKey.from_public_bytes(_decode(public_keys[document["kid"]], 32))
    signature = _decode(document["signature"], 64)
    try:
        key.verify(signature, DOMAIN + body)
    except Exception as exc:
        raise NativeGrantDenied("Native MCP signature cannot be trusted") from exc
    return dict(document["claims"])


def header_value(document: Any) -> str:
    """Opaque bounded HTTP header value, never put signed grants into URLs."""
    if type(document) is not dict or set(document) != {"claims", "kid", "signature"}:
        raise NativeGrantDenied("Invalid native MCP grant")
    canonical_claims(document["claims"])
    if type(document["kid"]) is not str or _KID.fullmatch(document["kid"]) is None:
        raise NativeGrantDenied("Invalid native MCP signer")
    _decode(document["signature"], 64)
    return _encode(
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
    )
