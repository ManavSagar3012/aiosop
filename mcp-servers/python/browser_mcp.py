"""
Browser MCP Server
Stateful browser automation and identity management using Playwright.
Supports multi-session capture, workflow mapping, differential testing,
and evidence persistence (screenshot, HAR, DOM, trace).
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import stat
import time
import uuid
import weakref
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, WebSocket
from fastapi.responses import JSONResponse
from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

app = FastAPI(title="Browser MCP Server")

# Evidence is written here so the workflow_agent and the API can find it.
EVIDENCE_ROOT = os.environ.get("OSOP_EVIDENCE_ROOT", os.path.abspath("evidence_vault"))
SERVER_ID = "browser-mcp"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9_.:@-]{1,96}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ORIGIN_HOST = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z")
_MAX_HAR_BYTES = 4 * 1024 * 1024
_MAX_SIGNED_SCREENSHOT_BYTES = 4 * 1024 * 1024
_MAX_SIGNED_DOM_BYTES = 1024 * 1024
_MAX_DESCRIPTOR_BYTES = 4096
_MAX_JOURNAL_BYTES = 2048
_MAX_CAPTURE_EVIDENCE_SIDECAR_BYTES = 8192
_MAX_STORAGE_STATE_BYTES = 128 * 1024
_MAX_STORAGE_COOKIES = 256
_MAX_STORAGE_ORIGINS = 128
_RECEIPT_FIELDS = {
    "request_id",
    "engagement_id",
    "task_id",
    "server_id",
    "status",
    "verified",
    "stopped",
    "issued_at",
}
_SOURCE_DOMAIN = b"ai-osop/browser-source-preflight/v1\x00"
_SOURCE_CLAIMS = frozenset(
    {
        "version",
        "preflight_id",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "owner_id",
        "server_id",
        "tool_name",
        "action",
        "user_label",
        "evidence_mode",
        "url_sha256",
        "origin",
        "authorization_version",
        "authorization_sha256",
        "approval_id",
        "lease_id",
        "issued_at",
        "expires_at",
    }
)
_SOURCE_REQUEST = frozenset(
    {
        "request_id",
        "engagement_id",
        "task_id",
        "server_id",
        "tool_name",
        "action",
        "user_label",
        "evidence_mode",
        "url_sha256",
        "origin",
    }
)
_EVIDENCE_MODES = frozenset({"none", "screenshot_dom_har"})


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate metadata field")
        result[key] = value
    return result


def _signed_storage_state_digest(state: Any) -> Optional[str]:
    """Bound and canonically fingerprint imported Playwright identity state.

    A digest, not cookie contents, is pinned to the lifetime of each signed
    context. The serialized bytes are never logged or returned. Missing state
    remains a distinct unauthenticated sentinel for existing signed guest flows.
    """
    if state is None:
        return None
    if (
        not isinstance(state, dict)
        or set(state) != {"cookies", "origins"}
        or not isinstance(state["cookies"], list)
        or not isinstance(state["origins"], list)
        or len(state["cookies"]) > _MAX_STORAGE_COOKIES
        or len(state["origins"]) > _MAX_STORAGE_ORIGINS
        or any(not isinstance(cookie, dict) for cookie in state["cookies"])
        or any(not isinstance(origin, dict) for origin in state["origins"])
    ):
        raise ValueError("Signed browser imported identity format unavailable")
    # Bound nesting, element counts, and individual strings *before* JSON
    # serialization to avoid allocating huge temporary cookie blobs.
    count = 0
    stack = [(state, 0)]
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > 4096 or depth > 12:
            raise ValueError("Signed browser imported identity exceeds resource bounds")
        if isinstance(item, dict):
            if len(item) > 256:
                raise ValueError("Signed browser imported identity exceeds resource bounds")
            for key, value in item.items():
                if not isinstance(key, str) or len(key) > 8192:
                    raise ValueError("Signed browser imported identity invalid")
                stack.append((value, depth + 1))
        elif isinstance(item, list):
            if len(item) > 512:
                raise ValueError("Signed browser imported identity exceeds resource bounds")
            stack.extend((value, depth + 1) for value in item)
        elif isinstance(item, str):
            if len(item) > _MAX_STORAGE_STATE_BYTES:
                raise ValueError("Signed browser imported identity exceeds resource bounds")
        elif item is not None and type(item) not in {bool, int, float}:
            raise ValueError("Signed browser imported identity invalid")
    try:
        raw = json.dumps(
            state,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ValueError("Signed browser imported identity invalid") from exc
    if not 2 <= len(raw) <= _MAX_STORAGE_STATE_BYTES:
        raise ValueError("Signed browser imported identity exceeds resource bounds")
    return hashlib.sha256(raw).hexdigest()


def _clean(value: Any, pattern=_IDENTIFIER) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError("Invalid browser execution identity")
    return value


def _production() -> bool:
    return os.getenv("OSOP_ENVIRONMENT", "").strip().lower() in {"production", "prod"}


def _legacy_signed_test_mode() -> bool:
    """Explicit test-only compatibility, never inferred from a test runner.

    Blank/dev/staging modes retain full independent source requirements.
    Only a deployment deliberately configured as the literal 'test' may use
    legacy signed fake-provider fixtures without a central database.
    """
    return os.getenv("OSOP_ENVIRONMENT", "") == "test"


def _bearer_authorized(authorization: Optional[str]) -> bool:
    expected = os.getenv("OSOP_BROWSER_MCP_BEARER_TOKEN", "")
    return bool(
        isinstance(expected, str)
        and 16 <= len(expected) <= 4096
        and isinstance(authorization, str)
        and authorization.startswith("Bearer ")
        and hmac.compare_digest(authorization[7:], expected)
    )


def _require_inbound_auth(authorization: Optional[str], *, signed: bool = False) -> None:
    if (signed or _production()) and not _bearer_authorized(authorization):
        raise HTTPException(status_code=401, detail="Browser provider authentication unavailable")


def _signer() -> tuple[Ed25519PrivateKey, str]:
    """Require deployment-owned private key AND independently enrolled public key."""
    raw = os.getenv("OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64", "")
    kid = _clean(os.getenv("OSOP_BROWSER_MCP_RECEIPT_KID", ""), _KEY_ID)
    keys_raw = os.getenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "")
    if not raw or len(raw) > 256 or not keys_raw or len(keys_raw) > 16384:
        raise ValueError("Provider receipt signer unavailable")
    key_bytes = base64.b64decode(raw, validate=True)
    if len(key_bytes) != 32:
        raise ValueError("Provider receipt signer unavailable")
    signer = Ed25519PrivateKey.from_private_bytes(key_bytes)
    enrolled = json.loads(keys_raw, object_pairs_hook=_unique)
    server_keys = enrolled.get(SERVER_ID) if isinstance(enrolled, dict) else None
    expected = (
        server_keys.get(kid) if isinstance(server_keys, dict) and len(server_keys) <= 32 else None
    )
    public = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if not isinstance(expected, str) or not hmac.compare_digest(
        base64.b64encode(public).decode("ascii"),
        expected,
    ):
        raise ValueError("Provider signing key is not independently enrolled")
    return signer, kid


def _signed_receipt(binding: Dict[str, str], status: str) -> Dict[str, Any]:
    signer, kid = _signer()
    if status not in {"running", "succeeded", "failed", "pending"}:
        raise ValueError("Invalid provider status")
    claims = {
        **binding,
        "status": status,
        "verified": status in {"succeeded", "failed"},
        "stopped": status in {"succeeded", "failed"},
        "issued_at": int(time.time()),
    }
    if set(claims) != _RECEIPT_FIELDS:
        raise ValueError("Invalid provider receipt fields")
    data = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    signature = signer.sign(data)
    return {
        **claims,
        "attestation": {
            "kid": kid,
            "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        },
    }


_COUPLED_EVIDENCE_DOMAIN = b"ai-osop/browser-reviewed-evidence/v1\x00"


def _signed_coupled_evidence(
    binding: Dict[str, str],
    source: Dict[str, Any],
    artifacts: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Signed *provider testimony* over already reread original artifact SHAs.

    This deliberately does not replace the existing task-status receipt, nor
    does it attest to the remote target's observed effects. Only independently
    sourced original Action identity and SHA/size/relative-path metadata are
    included. Every original byte must be verified BEFORE calling this.
    """
    if (
        not isinstance(binding, dict)
        or set(binding) != {"request_id", "engagement_id", "task_id", "server_id"}
        or source.get("request_id") != binding["request_id"]
        or source.get("engagement_id") != binding["engagement_id"]
        or source.get("task_id") != binding["task_id"]
        or source.get("server_id") != binding["server_id"]
        or source.get("evidence_mode") != "screenshot_dom_har"
        or type(source.get("preflight_id")) is not str
        or re.fullmatch(r"nbp-[a-f0-9]{32}", source["preflight_id"]) is None
        or type(source.get("action_id")) is not str
        or re.fullmatch(r"action-[a-f0-9]{32}", source["action_id"]) is None
        or type(source.get("authorization_sha256")) is not str
        or _SHA256.fullmatch(source["authorization_sha256"]) is None
        or set(artifacts) != {"screenshot", "dom", "har"}
    ):
        raise ValueError("Reviewed Browser evidence provenance unavailable")
    digest_rows = {}
    for name, item in artifacts.items():
        if (
            type(item) is not dict
            or type(item.get("resource_sha256")) is not str
            or _SHA256.fullmatch(item["resource_sha256"]) is None
            or type(item.get("size_bytes")) is not int
            or not 0 < item["size_bytes"] <= _MAX_HAR_BYTES
            or type(item.get("path")) is not str
            or not re.fullmatch(r"captures/[a-f0-9]{32}\.(png|html|har)", item["path"])
            or not item["path"].endswith(
                {"screenshot": ".png", "dom": ".html", "har": ".har"}[name]
            )
        ):
            raise ValueError("Reviewed Browser original artifact binding unavailable")
        digest_rows[name] = {
            "sha256": item["resource_sha256"],
            "size_bytes": item["size_bytes"],
            "path": item["path"],
        }
    claims = {
        "version": 1,
        **binding,
        "source_preflight_id": source["preflight_id"],
        "action_id": source["action_id"],
        "authorization_sha256": source["authorization_sha256"],
        "evidence_mode": "screenshot_dom_har",
        "artifacts": digest_rows,
        "issued_at": int(time.time()),
    }
    encoded = json.dumps(
        claims, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    if len(encoded) > 4096:
        raise ValueError("Reviewed Browser provenance too large")
    signer, kid = _signer()
    signature = signer.sign(_COUPLED_EVIDENCE_DOMAIN + encoded)
    return {
        "claims": claims,
        "kid": kid,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def _verify_local_original_coupled_evidence(
    attestation: Any, binding: Dict[str, str], *, max_age_seconds: int = 120
) -> Dict[str, Any]:
    """Re-read actual bytes; a provider signature alone does not attest current files.

    This is provider-local forensic integrity only. A central Action, reviewer,
    lease, cancellation and target-owner state must be independently checked
    before anyone can promote this observation to authorized target evidence.
    """
    if (
        type(attestation) is not dict
        or set(attestation) != {"claims", "kid", "signature"}
        or type(binding) is not dict
        or set(binding) != {"request_id", "engagement_id", "task_id", "server_id"}
        or binding["server_id"] != SERVER_ID
    ):
        raise ValueError("Original browser signed evidence unavailable")
    claims = attestation["claims"]
    kid = attestation["kid"]
    signature_text = attestation["signature"]
    if (
        type(claims) is not dict
        or set(claims)
        != {
            "version",
            "request_id",
            "engagement_id",
            "task_id",
            "server_id",
            "source_preflight_id",
            "action_id",
            "authorization_sha256",
            "evidence_mode",
            "artifacts",
            "issued_at",
        }
        or claims["version"] != 1
        or any(
            type(claims.get(key)) is not str or claims[key] != value
            for key, value in binding.items()
        )
        or claims["evidence_mode"] != "screenshot_dom_har"
        or not isinstance(claims["source_preflight_id"], str)
        or not re.fullmatch(r"nbp-[0-9a-f]{32}", claims["source_preflight_id"])
        or not isinstance(claims["action_id"], str)
        or not re.fullmatch(r"action-[0-9a-f]{32}", claims["action_id"])
        or not isinstance(claims["authorization_sha256"], str)
        or not _SHA256.fullmatch(claims["authorization_sha256"])
        or type(claims["issued_at"]) is not int
        or not 0 <= int(time.time()) - claims["issued_at"] <= max_age_seconds
        or type(kid) is not str
        or not _KEY_ID.fullmatch(kid)
        or type(signature_text) is not str
        or not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature_text)
    ):
        raise ValueError("Original browser evidence identity or freshness unavailable")
    encoded = json.dumps(
        claims, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    if len(encoded) > 4096:
        raise ValueError("Original browser evidence claims oversized")
    roots_raw = os.getenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "")
    if not roots_raw or len(roots_raw) > 16384:
        raise ValueError("Enrolled provider public root unavailable")
    roots = json.loads(roots_raw, object_pairs_hook=_unique)
    server_roots = roots.get(SERVER_ID) if type(roots) is dict else None
    public_b64 = (
        server_roots.get(kid) if type(server_roots) is dict and len(server_roots) <= 32 else None
    )
    if type(public_b64) is not str or len(public_b64) != 44:
        raise ValueError("Enrolled provider public root unavailable")
    public_raw = base64.b64decode(public_b64, validate=True)
    signature = base64.urlsafe_b64decode(signature_text + "==")
    if len(public_raw) != 32 or len(signature) != 64:
        raise ValueError("Provider evidence signature unavailable")
    Ed25519PublicKey.from_public_bytes(public_raw).verify(
        signature, _COUPLED_EVIDENCE_DOMAIN + encoded
    )
    entries = claims["artifacts"]
    if type(entries) is not dict or set(entries) != {"screenshot", "dom", "har"}:
        raise ValueError("Original browser evidence manifest unavailable")
    tenant, _, _ = _signed_mount(binding["engagement_id"])
    captures = tenant / "captures"
    if (
        captures.is_symlink()
        or not captures.is_dir()
        or captures.resolve(strict=True).parent != tenant.resolve(strict=True)
    ):
        raise ValueError("Reviewed capture directory unavailable")
    checked: Dict[str, Any] = {}
    for label, extension, limit in (
        ("screenshot", "png", _MAX_SIGNED_SCREENSHOT_BYTES),
        ("dom", "html", _MAX_SIGNED_DOM_BYTES),
        ("har", "har", _MAX_HAR_BYTES),
    ):
        row = entries[label]
        if (
            type(row) is not dict
            or set(row) != {"sha256", "size_bytes", "path"}
            or type(row["path"]) is not str
            or not re.fullmatch(r"captures/[0-9a-f]{32}\." + extension, row["path"])
            or type(row["sha256"]) is not str
            or not _SHA256.fullmatch(row["sha256"])
            or type(row["size_bytes"]) is not int
            or not 0 < row["size_bytes"] <= limit
        ):
            raise ValueError("Original browser artifact identity unavailable")
        path = tenant / row["path"]
        original_stat = path.lstat()
        if (
            path.resolve(strict=True).parent != captures.resolve(strict=True)
            or not stat.S_ISREG(original_stat.st_mode)
            or original_stat.st_nlink != 1
        ):
            raise ValueError("Original browser artifact escaped capture mount")
        original = _regular_blob(path, limit)
        if len(original) != row["size_bytes"] or not hmac.compare_digest(
            hashlib.sha256(original).hexdigest(), row["sha256"]
        ):
            raise ValueError("Original browser artifact bytes changed")
        checked[label] = dict(row)
    return checked


def _execution_binding(req: Any, params: Dict[str, Any]) -> Optional[Dict[str, str]]:
    source = getattr(req, "execution_binding", None)
    if source is None:
        return None
    if not isinstance(source, dict) or set(source) != {
        "request_id",
        "engagement_id",
        "task_id",
        "server_id",
    }:
        raise ValueError("Invalid original execution binding")
    record = {
        key: _clean(value, _REQUEST_ID if key == "request_id" else _IDENTIFIER)
        for key, value in source.items()
    }
    if (
        record["request_id"] != req.request_id
        or record["server_id"] != SERVER_ID
        or ("engagement_id" in params and record["engagement_id"] != params["engagement_id"])
        or (req.session_id and req.session_id != record["engagement_id"])
        or not record["engagement_id"].startswith("eng-")
        or not record["task_id"].startswith("task-")
    ):
        raise ValueError("Original execution binding disagrees with request")
    return record


def _exact_browser_origin(raw: Any) -> str:
    """Normalize one absolute origin without inheriting URL parser ambiguity."""
    if (
        type(raw) is not str
        or not 8 <= len(raw) <= 2048
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in raw)
        or "\\" in raw
    ):
        raise ValueError("Signed browser origin unavailable")
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Signed browser origin unavailable") from exc
    if (
        scheme not in {"https", "http"}
        or not host
        or not _ORIGIN_HOST.fullmatch(host)
        or host.endswith(".")
        or ".." in host
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.netloc
        or parsed.fragment
        or (scheme == "http" and host not in {"127.0.0.1", "localhost"})
    ):
        raise ValueError("Signed browser origin unavailable")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Signed browser origin unavailable")
    normalized_port = port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{normalized_port}"


def _signed_allowed_origins(engagement_id: str) -> frozenset[str]:
    """Deployment-owned tenant destination pins; caller parameters cannot grant scope.

    This is a local destination fence. It is NOT independent verification of
    current Flow/Task/ROE authorization or permission to contact a real target.
    """
    _clean(engagement_id)
    raw = os.getenv("OSOP_BROWSER_MCP_SIGNED_ORIGINS_JSON", "")
    if not raw or len(raw) > 16384:
        raise ValueError("Signed browser destination authorization unavailable")
    try:
        source = json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, TypeError) as exc:
        raise ValueError("Signed browser destination authorization unavailable") from exc
    if not isinstance(source, dict) or len(source) > 128:
        raise ValueError("Signed browser destination authorization unavailable")
    origins = source.get(engagement_id)
    if not isinstance(origins, list) or not 1 <= len(origins) <= 16:
        raise ValueError("Signed browser destination authorization unavailable")
    normalized = frozenset(_exact_browser_origin(item) for item in origins)
    if len(normalized) != len(origins) or any(
        urlsplit(item).path or urlsplit(item).query or urlsplit(item).fragment for item in origins
    ):
        raise ValueError("Signed browser destination authorization unavailable")
    return normalized


def _verified_navigation_chain(
    response: Any,
    requested_origin: str,
    allowed: frozenset[str],
    requested_url: str,
) -> None:
    """Inspect every completed Playwright redirect predecessor before signing."""
    request = getattr(response, "request", None)
    if request is None:
        raise ValueError("Signed browser navigation request provenance unavailable")
    seen: set[int] = set()
    chain: list[str] = []
    while request is not None:
        if id(request) in seen or len(chain) >= 16:
            raise ValueError("Signed browser redirect chain unavailable")
        seen.add(id(request))
        hop_url = getattr(request, "url", None)
        if type(hop_url) is not str or hop_url != requested_url:
            # Approved Action binds the exact URL bytes, not only an origin.
            # Same-origin path/query redirects are not silently approved.
            raise ValueError("Signed browser redirect changed exact reviewed destination")
        chain.append(_exact_browser_origin(hop_url))
        request = getattr(request, "redirected_from", None)
    if not chain or chain[-1] != requested_origin or any(origin not in allowed for origin in chain):
        raise ValueError("Signed browser redirect changed authorized origin")


def _source_configuration() -> tuple[str, str, str, dict[str, bytes]]:
    """Load only deployment-owned HTTPS/source trust, never request metadata."""
    endpoint = os.getenv("OSOP_BROWSER_SOURCE_URL", "")
    certificate = os.getenv("OSOP_BROWSER_SOURCE_CA_BUNDLE", "")
    token = os.getenv("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", "")
    roots_raw = os.getenv("OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON", "")
    if (
        type(endpoint) is not str
        or not 12 <= len(endpoint) <= 2048
        or any(ord(c) < 33 or ord(c) > 126 for c in endpoint)
        or "\\" in endpoint
        or type(token) is not str
        or not 20 <= len(token) <= 512
        or any(ord(c) < 33 or ord(c) > 126 for c in token)
        or type(certificate) is not str
        or not 1 <= len(certificate) <= 2048
        or not 2 <= len(roots_raw) <= 8192
    ):
        raise ValueError("Independent browser source authority unavailable")
    try:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.query
            or parsed.path != "/native-browser/source-preflight"
            or not parsed.hostname
            or not _ORIGIN_HOST.fullmatch(parsed.hostname)
            or parsed.hostname.endswith(".")
            or ".." in parsed.hostname
            or parsed.port is None
            and parsed.netloc != parsed.hostname
            or parsed.port is not None
            and not 1 <= parsed.port <= 65535
        ):
            raise ValueError("Source endpoint unavailable")
        ca = Path(certificate)
        if (
            not ca.is_absolute()
            or ca.is_symlink()
            or not ca.is_file()
            or ca.stat().st_size < 100
            or ca.stat().st_size > 128 * 1024
        ):
            raise ValueError("Source TLS root unavailable")
        with ca.open("rb") as stream:
            if b"-----BEGIN CERTIFICATE-----" not in stream.read(128 * 1024):
                raise ValueError("Source TLS root unavailable")
        trusted = json.loads(roots_raw, object_pairs_hook=_unique)
        if type(trusted) is not dict or not 1 <= len(trusted) <= 16:
            raise ValueError("Source signer trust unavailable")
        keys = {}
        for kid, encoded in trusted.items():
            _clean(kid, _KEY_ID)
            if type(encoded) is not str or not 40 <= len(encoded) <= 48:
                raise ValueError("Source signer trust unavailable")
            pub = base64.b64decode(encoded, validate=True)
            if len(pub) != 32:
                raise ValueError("Source signer trust unavailable")
            keys[kid] = pub
        return endpoint, certificate, token, keys
    except (ValueError, TypeError, OSError, UnicodeError, KeyError) as exc:
        raise ValueError("Independent browser source authority unavailable") from exc


def _verify_source_preflight(
    envelope: Any,
    expected: dict[str, Any],
    keys: dict[str, bytes],
) -> dict[str, Any]:
    """Cryptographically verify original current 0027 Action decision claims."""
    if (
        type(envelope) is not dict
        or set(envelope) != {"claims", "kid", "signature"}
        or type(envelope["claims"]) is not dict
        or set(envelope["claims"]) != _SOURCE_CLAIMS
        or type(envelope["kid"]) is not str
        or envelope["kid"] not in keys
    ):
        raise ValueError("Signed browser source proof unavailable")
    claims = envelope["claims"]
    for name in _SOURCE_REQUEST:
        if claims[name] != expected[name] or type(claims[name]) is not str:
            raise ValueError("Signed browser source binding changed")
    if (
        type(claims["version"]) is not int
        or claims["version"] != 1
        or type(claims["authorization_version"]) is not int
        or claims["authorization_version"] < 1
        or type(claims["issued_at"]) is not int
        or type(claims["expires_at"]) is not int
        or not 0 < claims["expires_at"] - claims["issued_at"] <= 10
        or claims["issued_at"] > int(time.time()) + 2
        or claims["issued_at"] < int(time.time()) - 5
        or claims["expires_at"] <= int(time.time())
        or type(claims["preflight_id"]) is not str
        or re.fullmatch(r"nbp-[0-9a-f]{32}", claims["preflight_id"]) is None
        or type(claims["authorization_sha256"]) is not str
        or _SHA256.fullmatch(claims["authorization_sha256"]) is None
    ):
        raise ValueError("Signed browser source authority expired or incomplete")
    for name in ("flow_id", "subtask_id", "action_id", "owner_id", "approval_id", "lease_id"):
        if type(claims[name]) is not str or not _IDENTIFIER.fullmatch(claims[name]):
            raise ValueError("Signed browser source authority incomplete")
    try:
        message = json.dumps(
            claims,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        signature = envelope["signature"]
        if (
            type(signature) is not str
            or len(signature) != 86
            or re.fullmatch(r"[A-Za-z0-9_-]{86}", signature) is None
        ):
            raise ValueError("Source signature unavailable")
        raw = base64.urlsafe_b64decode(signature + "==")
        if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != signature:
            raise ValueError("Source signature unavailable")
        Ed25519PublicKey.from_public_bytes(keys[envelope["kid"]]).verify(
            raw,
            _SOURCE_DOMAIN + message,
        )
    except Exception as exc:
        raise ValueError("Signed browser source signature untrusted") from exc
    return claims


async def _redeem_browser_navigation_source(
    binding: dict[str, str],
    target: str,
    user_label: str,
    evidence_mode: str = "none",
) -> dict[str, Any]:
    """One consequential POST per reserved request; no automatic retry ever.

    The central source independently checks durable Flow/Task/ROE/reviewer,
    currently approved target and lease, and one-shot PG redemption. The
    provider never trusts the caller to provide those authorization claims.
    """
    if type(target) is not str or not 8 <= len(target.encode("utf-8")) <= 2048:
        raise ValueError("Signed browser target unavailable")
    origin = _exact_browser_origin(target)
    _clean(user_label)
    if type(evidence_mode) is not str or evidence_mode not in _EVIDENCE_MODES:
        raise ValueError("Signed browser evidence authorization unavailable")
    expected = {
        **binding,
        "tool_name": "execute",
        "action": "navigate",
        "user_label": user_label,
        "evidence_mode": evidence_mode,
        "url_sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
        "origin": origin,
    }
    if set(expected) != _SOURCE_REQUEST:
        raise ValueError("Signed source request unavailable")
    endpoint, certificate, secret, keys = _source_configuration()
    try:
        # SSL certificate trust is independently pinned via deployment CA,
        # never peer-returned certs or environment/system proxy settings.
        async with httpx.AsyncClient(
            verify=certificate,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(3.0),
        ) as client:
            response = await client.post(
                endpoint,
                json=expected,
                headers={
                    "Authorization": f"Bearer {secret}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
        if (
            response.status_code != 200
            or response.headers.get("content-type", "").split(";", 1)[0].lower()
            != "application/json"
            or len(response.content) > 4096
            or response.headers.get("content-length", "0").strip()
            not in {
                "",
                "0",
                str(len(response.content)),
            }
        ):
            raise ValueError("Current signed browser source not confirmed")
        document = json.loads(
            response.content.decode("utf-8", "strict"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Bad JSON")),
        )
        return _verify_source_preflight(document, expected, keys)
    except Exception as exc:
        # An ACK may be lost AFTER durable central redemption: never repeat
        # this call, never retry navigation, leave journal UNKNOWN.
        raise ValueError("Current signed browser source authority unavailable") from exc


def _regular_blob(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Signed capture resource unavailable")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        before = os.fstat(source.fileno())
        leaf = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(leaf.st_mode)
            or (before.st_dev, before.st_ino) != (leaf.st_dev, leaf.st_ino)
            or not 0 < before.st_size <= limit
        ):
            raise ValueError("Signed capture resource unavailable")
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
        if not 0 < len(data) <= limit or (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise ValueError("Signed capture resource changed")
        return data


def _reviewed_capture_metadata(
    result: Any,
    *,
    engagement_id: str,
    user_label: str,
    task_id: str,
    suffix: str,
    limit: int,
) -> Dict[str, Any]:
    """Independent post-write original-byte readback for this reviewed Action.

    Only bounded metadata is returned to the MCP client. The original bytes
    remain exclusively in the authenticated tenant mount, never the receipt.
    """
    if (
        type(result) is not dict
        or result.get("exists") is not True
        or result.get("engagement_id") != engagement_id
        or result.get("user_label") != user_label
        or result.get("capture_task_id") != task_id
        or type(result.get("resource_sha256")) is not str
        or _SHA256.fullmatch(result["resource_sha256"]) is None
        or type(result.get("size_bytes")) is not int
        or not 0 < result["size_bytes"] <= limit
    ):
        raise ValueError("Reviewed browser capture identity unavailable")
    path = result.get("path")
    if type(path) is not str or re.fullmatch(r"captures/[0-9a-f]{32}\." + suffix, path) is None:
        raise ValueError("Reviewed browser capture path unavailable")
    tenant, mount_digest, container_digest = _signed_mount(engagement_id)
    if (
        result.get("mount_sha256") != mount_digest
        or result.get("container_image_sha256") != container_digest
    ):
        raise ValueError("Reviewed browser capture tenant changed")
    directory = tenant / "captures"
    resource = tenant / path
    if (
        directory.is_symlink()
        or not directory.is_dir()
        or directory.resolve(strict=True).parent != tenant.resolve(strict=True)
        or resource.resolve(strict=True).parent != directory.resolve(strict=True)
    ):
        raise ValueError("Reviewed browser capture resource changed")
    original = _regular_blob(resource, limit)
    if len(original) != result["size_bytes"] or not hmac.compare_digest(
        hashlib.sha256(original).hexdigest(), result["resource_sha256"]
    ):
        raise ValueError("Reviewed browser original-byte hash changed")
    return {
        "path": path,
        "size_bytes": len(original),
        "resource_sha256": hashlib.sha256(original).hexdigest(),
        "capture_task_id": task_id,
        "mount_sha256": mount_digest,
        "container_image_sha256": container_digest,
    }


def _sync_directory(path: Path) -> None:
    """Make new reservation/artifact names crash-durable on POSIX.

    Windows does not offer directory fsync through the portable os interface;
    its file handles are still flushed, but power-loss directory durability is
    an unverified deployment property there.
    """
    if os.name == "posix":
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _signed_mount(engagement_id: str) -> tuple[Path, str, str]:
    """Pin local producer HAR bytes to the same deployment-owned tenant mount."""
    _clean(engagement_id)
    root_raw = os.getenv("OSOP_AUTHENTICATED_HAR_ROOT", "")
    pins_raw = os.getenv("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS", "")
    if not root_raw or not pins_raw or len(pins_raw) > 16384:
        raise ValueError("Signed capture mount unavailable")
    root = Path(root_raw)
    tenant = root / engagement_id
    if (
        not root.is_absolute()
        or root.is_symlink()
        or tenant.is_symlink()
        or not root.is_dir()
        or not tenant.is_dir()
    ):
        raise ValueError("Signed capture mount unavailable")
    pins = json.loads(pins_raw, object_pairs_hook=_unique)
    if not isinstance(pins, dict) or len(pins) > 128:
        raise ValueError("Signed capture mount pin unavailable")
    pinned = pins.get(engagement_id)
    if not isinstance(pinned, str) or not _SHA256.fullmatch(pinned):
        raise ValueError("Signed capture mount pin unavailable")
    descriptor = _regular_blob(tenant / ".osop-har-mount.json", _MAX_DESCRIPTOR_BYTES)
    digest = hashlib.sha256(descriptor).hexdigest()
    if not hmac.compare_digest(digest, pinned):
        raise ValueError("Signed capture mount digest mismatch")
    declaration = json.loads(descriptor.decode("utf-8"), object_pairs_hook=_unique)
    if (
        not isinstance(declaration, dict)
        or set(declaration) != {"engagement_id", "mount_id", "container_image_sha256"}
        or declaration["engagement_id"] != engagement_id
        or not isinstance(declaration["mount_id"], str)
        or not _IDENTIFIER.fullmatch(declaration["mount_id"])
        or not isinstance(declaration["container_image_sha256"], str)
        or not _SHA256.fullmatch(declaration["container_image_sha256"])
    ):
        raise ValueError("Signed capture mount identity unavailable")
    return tenant, digest, declaration["container_image_sha256"]


class RequestJournal:
    """Local durable one-shot request reservation; unknown is never replayed."""

    def __init__(self, binding: Dict[str, str]) -> None:
        raw = os.getenv("OSOP_BROWSER_MCP_JOURNAL_ROOT", "")
        if not raw or len(raw) > 2048:
            raise ValueError("Durable browser request journal unavailable")
        root = Path(raw)
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise ValueError("Durable browser request journal unavailable")
        self.path = root / (
            hashlib.sha256(binding["request_id"].encode("utf-8")).hexdigest() + ".json"
        )
        self.binding = binding

    def _record(self, status: str) -> bytes:
        return json.dumps(
            {"binding": self.binding, "status": status},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def reserve(self) -> bool:
        # O_EXCL atomically reserves the original request across processes.
        # A partially written record is UNKNOWN, never safe for a replay.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileExistsError:
            return False
        try:
            with os.fdopen(fd, "wb") as writer:
                writer.write(self._record("unknown"))
                writer.flush()
                os.fsync(writer.fileno())
            _sync_directory(self.path.parent)
        except Exception:
            # Keep even an incomplete reservation as a no-replay tombstone.
            raise
        return True

    def read(self) -> str:
        record = self._read_record()
        return record["status"] if record is not None else "unknown"

    def commit_evidence(self, attestation: Dict[str, Any]) -> None:
        """One-write provider forensic sidecar; never a grant or retry record."""
        # A missing, forged or partially written journal is UNKNOWN for
        # recovery, but must NEVER authorize creating forensic proof. Require
        # the exact original durable reservation to exist first.
        reservation = self._read_record()
        if reservation is None or reservation["status"] != "unknown":
            raise ValueError("Original browser evidence must precede terminal journal")
        if type(attestation) is not dict or set(attestation) != {"claims", "kid", "signature"}:
            raise ValueError("Original browser evidence attestation unavailable")
        # Verify actual captures again before irrevocably recording the signed
        # provider assertion. Future readback must independently reread them.
        _verify_local_original_coupled_evidence(attestation, self.binding)
        raw = json.dumps(
            {"binding": self.binding, "attestation": attestation},
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        if len(raw) > _MAX_CAPTURE_EVIDENCE_SIDECAR_BYTES:
            raise ValueError("Original browser evidence sidecar exceeds bound")
        filename = self.path.with_suffix(".evidence.json")
        fd = os.open(
            filename,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(fd, "wb") as writer:
            writer.write(raw)
            writer.flush()
            os.fsync(writer.fileno())
        _sync_directory(filename.parent)

    def current_evidence(self) -> Dict[str, Any]:
        """Current local original bytes; no present ROE, lease or target authority."""
        if self.read() != "succeeded":
            raise ValueError("Original browser captured outcome is UNKNOWN")
        sidecar = self.path.with_suffix(".evidence.json")
        observed = sidecar.lstat()
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or (os.name == "posix" and (observed.st_uid != os.getuid() or observed.st_mode & 0o077))
        ):
            raise ValueError("Original browser forensic sidecar lacks private ownership")
        raw = _regular_blob(sidecar, _MAX_CAPTURE_EVIDENCE_SIDECAR_BYTES)
        stored = json.loads(
            raw.decode("ascii", "strict"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite evidence")),
        )
        if (
            type(stored) is not dict
            or set(stored) != {"binding", "attestation"}
            or stored["binding"] != self.binding
        ):
            raise ValueError("Original browser evidence sidecar identity changed")
        return _verify_local_original_coupled_evidence(stored["attestation"], self.binding)

    def _read_record(self) -> Optional[Dict[str, Any]]:
        try:
            record = json.loads(
                _regular_blob(self.path, _MAX_JOURNAL_BYTES), object_pairs_hook=_unique
            )
        except (OSError, ValueError, UnicodeError):
            return None
        if (
            not isinstance(record, dict)
            or set(record) != {"binding", "status"}
            or record.get("binding") != self.binding
            or record.get("status") not in {"unknown", "succeeded", "failed"}
        ):
            return None
        return record

    def finish(self, status: str) -> None:
        original = self._read_record()
        if (
            status not in {"succeeded", "failed"}
            or original is None
            or original["status"] != "unknown"
        ):
            raise ValueError("Signed browser request terminal state unavailable")
        temp = self.path.with_suffix("." + uuid.uuid4().hex + ".tmp")
        try:
            with open(temp, "xb") as writer:
                writer.write(self._record(status))
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(temp, self.path)
            _sync_directory(self.path.parent)
        finally:
            if temp.exists():
                temp.unlink()


# ================= Models =================


class BrowserActionRequest(BaseModel):
    url: str
    action: str  # navigate, click, fill, capture_state, screenshot, dom_snapshot, flush_har
    selector: Optional[str] = None
    value: Optional[str] = None
    user_label: str = "guest"
    engagement_id: str


# ================= State Manager =================


def _safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in (s or "unknown"))


def _ensure_dir(p: str) -> str:
    os.makedirs(p, exist_ok=True)
    return p


def _evidence_dir(engagement_id: str, workflow_id: str = "") -> str:
    parts = [EVIDENCE_ROOT, _safe_name(engagement_id or "no-engagement")]
    if workflow_id:
        parts.append(_safe_name(workflow_id))
    return _ensure_dir(os.path.join(*parts))


class BrowserManager:
    def __init__(self):
        self.playwright = None
        self.browser: Optional[Browser] = None
        # Never reuse imported identity cookies or HAR contexts across tenants.
        self.contexts: Dict[tuple[str, str], BrowserContext] = {}
        self.pages: Dict[tuple[str, str], Page] = {}
        self.meta: Dict[tuple[str, str], Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        # Weak values avoid an unbounded lock cache for ended engagements;
        # active waiters/holders keep a lock alive until their turn completes.
        self._page_locks: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self._action_locks: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self._started = False

    def action_lock(self, label: str, engagement_id: str) -> asyncio.Lock:
        key = (engagement_id or "default", label)
        lock = self._action_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._action_locks[key] = lock
        return lock

    def _page_lock(self, key: tuple[str, str]) -> asyncio.Lock:
        lock = self._page_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._page_locks[key] = lock
        return lock

    @staticmethod
    def _check_signed_state(
        meta: Dict[str, Any],
        storage_state: Optional[Dict[str, Any]],
        *,
        require_fresh_state: bool,
    ) -> None:
        digest = _signed_storage_state_digest(storage_state)
        pinned = meta.get("storage_state_sha256")
        if (require_fresh_state or storage_state is not None) and digest != pinned:
            raise ValueError("Signed browser identity changed; fresh context required")

    async def start(self):
        if self._started:
            return
        # A production listener must not launch a reusable browser process
        # without the trust anchor, bearer and durable reservation directory.
        if _production() and not _signed_provider_global_ready():
            raise ValueError("Signed browser runtime prerequisites unavailable")
        playwright = await async_playwright().start()
        try:
            browser = await playwright.chromium.launch(headless=True)
        except BaseException:
            # A failed Chromium launch otherwise leaves the Playwright driver
            # running even though /health can never become ready.
            await playwright.stop()
            raise
        self.playwright = playwright
        self.browser = browser
        self._started = True

    async def get_context(
        self,
        label: str,
        engagement_id: str = "",
        storage_state: Optional[Dict[str, Any]] = None,
        *,
        signed: bool = False,
        require_fresh_state: bool = False,
        evidence_mode: str = "none",
    ) -> BrowserContext:
        if type(evidence_mode) is not str or evidence_mode not in _EVIDENCE_MODES:
            raise ValueError("Signed browser evidence mode invalid")
        key = (engagement_id or "default", label)
        authorized_origins = (
            _signed_allowed_origins(engagement_id)
            if signed and not _legacy_signed_test_mode()
            else None
        )
        async with self._lock:
            if key not in self.contexts:
                pinned_digest = _signed_storage_state_digest(storage_state) if signed else None
                if signed:
                    tenant, mount_sha256, container_sha256 = _signed_mount(engagement_id)
                    if evidence_mode == "none" and not _legacy_signed_test_mode():
                        # A reviewed navigate without evidence consent must
                        # not silently create any HAR/trace/snapshot artifacts.
                        relative, har_path = None, ""
                    else:
                        capture_dir = tenant / "captures"
                        if capture_dir.is_symlink():
                            raise ValueError("Signed capture directory unavailable")
                        capture_dir.mkdir(exist_ok=True)
                        if capture_dir.is_symlink() or not capture_dir.is_dir():
                            raise ValueError("Signed capture directory unavailable")
                        _sync_directory(tenant)
                        relative = f"captures/{uuid.uuid4().hex}.har"
                        har_path = str(tenant / relative.replace("/", os.sep))
                        if Path(har_path).exists():
                            raise ValueError("Signed HAR destination was already occupied")
                else:
                    _ensure_dir(EVIDENCE_ROOT)
                    eng_dir = _evidence_dir(engagement_id or "default")
                    har_path = os.path.join(eng_dir, f"{_safe_name(label)}.har")
                    relative, mount_sha256, container_sha256 = None, None, None
                ctx_kwargs: Dict[str, Any] = {
                    "user_agent": "Mozilla/5.0 AI-OSOP/V2 (Playwright)",
                }
                if har_path:
                    ctx_kwargs.update(
                        {
                            "record_har_path": har_path,
                            "record_har_content": "embed",
                        }
                    )
                if authorized_origins is not None:
                    # Playwright route handlers do not intercept all requests
                    # performed by service workers. Disable them before any
                    # signed page/context is created to preserve the origin fence.
                    ctx_kwargs["service_workers"] = "block"
                # Authenticated-session import (Phase 1 Bug Bounty Upgrade): when the
                # caller supplies a Playwright storage_state ({cookies, origins}) we
                # seed the context so navigation runs as the imported user.
                if storage_state is not None:
                    ctx_kwargs["storage_state"] = storage_state
                ctx = await self.browser.new_context(**ctx_kwargs)
                if authorized_origins is not None:

                    async def signed_destination_guard(route):
                        # Installed BEFORE opening the first page. Check every
                        # outbound request, including redirects and subresources.
                        try:
                            origin = _exact_browser_origin(route.request.url)
                            if origin not in authorized_origins:
                                await route.abort("blockedbyclient")
                                return
                        except ValueError:
                            await route.abort("blockedbyclient")
                            return
                        await route.continue_()

                    try:
                        await ctx.route("**/*", signed_destination_guard)
                    except BaseException:
                        await ctx.close()
                        raise
                self.contexts[key] = ctx
                self.meta[key] = {
                    "har_path": har_path,
                    "engagement_id": engagement_id,
                    "user_label": label,
                    "signed": signed,
                    "relative_path": relative,
                    "mount_sha256": mount_sha256,
                    "container_image_sha256": container_sha256,
                    "storage_state_sha256": pinned_digest,
                    "authorized_origins": authorized_origins,
                    "evidence_mode": evidence_mode,
                    "tracing_active": False,
                }
                if not signed or _legacy_signed_test_mode():
                    # A second Playwright trace ZIP is not part of the
                    # centrally reviewed screenshot/DOM/HAR evidence bundle.
                    try:
                        await self.contexts[key].tracing.start(
                            screenshots=True, snapshots=True, sources=False
                        )
                        self.meta[key]["tracing_active"] = True
                    except Exception:
                        self.meta[key]["tracing_active"] = False
            elif self.meta[key].get("signed") is not signed:
                # Never adopt a manual page for an authenticated request OR
                # expose signed cookies to an unsigned request for that label.
                raise ValueError("Browser context authority does not match original dispatch")
            elif signed:
                if self.meta[key].get("authorized_origins") != authorized_origins:
                    raise ValueError("Signed browser destination authorization changed")
                if self.meta[key].get("evidence_mode", "none") != evidence_mode:
                    raise ValueError("Signed browser evidence mode changed")
                self._check_signed_state(
                    self.meta[key],
                    storage_state,
                    require_fresh_state=require_fresh_state,
                )
            return self.contexts[key]

    async def get_page(
        self,
        label: str,
        engagement_id: str = "",
        storage_state: Optional[Dict[str, Any]] = None,
        *,
        signed: bool = False,
        require_fresh_state: bool = False,
        evidence_mode: str = "none",
    ) -> Page:
        key = (engagement_id or "default", label)
        async with self._page_lock(key):
            # Always recheck the pinned authority on a cached page. The caller
            # must not skip rotation detection merely because get_page was
            # already completed by a different concurrent request.
            context = await self.get_context(
                label,
                engagement_id=engagement_id,
                storage_state=storage_state,
                signed=signed,
                require_fresh_state=require_fresh_state,
                evidence_mode=evidence_mode,
            )
            if key not in self.pages:
                self.pages[key] = await context.new_page()
            return self.pages[key]

    async def screenshot(
        self,
        label: str,
        engagement_id: str,
        workflow_id: str = "",
        step_id: str = "",
        *,
        signed: bool = False,
        task_id: str = "",
        evidence_mode: str = "none",
    ) -> Dict[str, Any]:
        if signed and (engagement_id, label) not in self.pages:
            raise ValueError("Signed screenshot requires an existing browser page")
        page = await self.get_page(
            label,
            engagement_id=engagement_id,
            signed=signed,
            evidence_mode=evidence_mode,
        )
        if signed:
            # Never write signed evidence through EVIDENCE_ROOT, whose path is
            # unrelated to the signed tenant HAR mount and cannot be attested.
            blob = await page.screenshot(full_page=True)
            if type(blob) is not bytes or not blob.startswith(b"\x89PNG\r\n\x1a\n"):
                raise ValueError("Signed browser screenshot bytes unavailable")
            return self._persist_signed_capture(
                label,
                engagement_id,
                task_id,
                blob,
                "png",
                _MAX_SIGNED_SCREENSHOT_BYTES,
            )
        eng_dir = _evidence_dir(engagement_id or "default", workflow_id)
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
        name = f"shot_{_safe_name(label)}_{_safe_name(step_id) or 'auto'}_{stamp}.png"
        path = os.path.join(eng_dir, name)
        try:
            await page.screenshot(path=path, full_page=True)
            return {"path": path, "url": page.url, "size_bytes": os.path.getsize(path)}
        except Exception as e:
            return {"path": "", "error": str(e), "url": page.url if page else ""}

    async def dom_snapshot(
        self,
        label: str,
        engagement_id: str,
        workflow_id: str = "",
        step_id: str = "",
        *,
        signed: bool = False,
        task_id: str = "",
        evidence_mode: str = "none",
    ) -> Dict[str, Any]:
        if signed and (engagement_id, label) not in self.pages:
            raise ValueError("Signed DOM snapshot requires an existing browser page")
        page = await self.get_page(
            label,
            engagement_id=engagement_id,
            signed=signed,
            evidence_mode=evidence_mode,
        )
        if signed:
            content = await page.content()
            if type(content) is not str:
                raise ValueError("Signed browser DOM content unavailable")
            blob = content.encode("utf-8", errors="strict")
            return self._persist_signed_capture(
                label,
                engagement_id,
                task_id,
                blob,
                "html",
                _MAX_SIGNED_DOM_BYTES,
            )
        eng_dir = _evidence_dir(engagement_id or "default", workflow_id)
        stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
        name = f"dom_{_safe_name(label)}_{_safe_name(step_id) or 'auto'}_{stamp}.html"
        path = os.path.join(eng_dir, name)
        try:
            content = await page.content()
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(content)
            return {"path": path, "url": page.url, "size_bytes": os.path.getsize(path)}
        except Exception as e:
            return {"path": "", "error": str(e), "url": page.url if page else ""}

    def _persist_signed_capture(
        self,
        label: str,
        engagement_id: str,
        task_id: str,
        blob: bytes,
        suffix: str,
        max_bytes: int,
    ) -> Dict[str, Any]:
        """Write original capture bytes into the pinned tenant mount, then read back.

        The signed receipt represents only locally persisted bytes. A page
        capture is neither independently signed target scope nor target effect.
        """
        key = (engagement_id, label)
        meta = self.meta.get(key)
        if (
            not isinstance(meta, dict)
            or meta.get("signed") is not True
            or meta.get("engagement_id") != engagement_id
            or meta.get("user_label") != label
            or key not in self.contexts
            or key not in self.pages
            or type(blob) is not bytes
            or not 0 < len(blob) <= max_bytes
            or suffix not in {"png", "html"}
        ):
            raise ValueError("Signed browser capture unavailable")
        tenant, mount_digest, container_digest = _signed_mount(engagement_id)
        if (
            meta.get("mount_sha256") != mount_digest
            or meta.get("container_image_sha256") != container_digest
        ):
            raise ValueError("Signed browser capture mount changed")
        capture_dir = tenant / "captures"
        if (
            capture_dir.is_symlink()
            or not capture_dir.is_dir()
            or capture_dir.resolve(strict=True).parent != tenant.resolve(strict=True)
        ):
            raise ValueError("Signed browser capture directory unavailable")
        relative = f"captures/{uuid.uuid4().hex}.{suffix}"
        artifact = tenant / relative
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        with os.fdopen(os.open(artifact, flags, 0o600), "wb") as writer:
            writer.write(blob)
            writer.flush()
            os.fsync(writer.fileno())
        _sync_directory(capture_dir)
        # Revalidate the independently pinned mount and read the exact original
        # regular file after persistence, including replacement/symlink checks.
        current_tenant, current_mount, current_container = _signed_mount(engagement_id)
        if (
            current_tenant != tenant
            or current_mount != mount_digest
            or current_container != container_digest
            or capture_dir.is_symlink()
            or artifact.resolve(strict=True).parent != capture_dir.resolve(strict=True)
        ):
            raise ValueError("Signed browser capture mount changed")
        original = _regular_blob(artifact, max_bytes)
        if original != blob:
            raise ValueError("Signed browser capture bytes changed")
        return {
            "path": relative,
            "exists": True,
            "engagement_id": engagement_id,
            "user_label": label,
            "capture_task_id": task_id,
            "resource_sha256": hashlib.sha256(original).hexdigest(),
            "size_bytes": len(original),
            "mount_sha256": mount_digest,
            "container_image_sha256": container_digest,
        }

    async def flush_har(
        self,
        label: str,
        workflow_id: str = "",
        *,
        engagement_id: str = "",
        signed: bool = False,
        task_id: str = "",
    ) -> Dict[str, Any]:
        """Close the context so Playwright flushes the HAR to disk, then return path."""
        key = (engagement_id or "default", label)
        meta = self.meta.get(key)
        if not meta:
            return {"path": "", "exists": False, "error": "Browser capture context unavailable"}
        if (
            meta.get("signed") is not signed
            or meta.get("engagement_id") != engagement_id
            or meta.get("user_label") != label
        ):
            raise ValueError("Signed browser context identity unavailable")
        har_path = meta.get("har_path", "")
        trace_path = ""
        try:
            ctx = self.contexts.pop(key, None)
            self.pages.pop(key, None)
            if ctx is not None:
                if meta.get("tracing_active"):
                    eng = meta.get("engagement_id", "default")
                    trace_dir = (
                        str(Path(har_path).parent) if signed else _evidence_dir(eng, workflow_id)
                    )
                    trace_path = os.path.join(
                        trace_dir,
                        f"trace_{_safe_name(label)}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}.zip",
                    )
                    try:
                        await ctx.tracing.stop(path=trace_path)
                    except Exception as te:
                        meta["tracing_stop_error"] = str(te)
                        trace_path = ""
                await ctx.close()
            result: Dict[str, Any] = {
                "path": har_path,
                "trace_path": trace_path,
                "exists": os.path.exists(har_path) if har_path else False,
            }
            if signed:
                tenant, mount_digest, container_digest = _signed_mount(engagement_id)
                if (
                    mount_digest != meta.get("mount_sha256")
                    or container_digest != meta.get("container_image_sha256")
                    or not isinstance(meta.get("relative_path"), str)
                ):
                    raise ValueError("Signed browser shared mount changed during capture")
                relative = meta["relative_path"]
                original = tenant / relative
                if (
                    original != Path(har_path)
                    or original.parent.is_symlink()
                    or not original.parent.is_dir()
                    or not original.resolve(strict=True).is_relative_to(tenant.resolve(strict=True))
                ):
                    raise ValueError("Signed browser HAR path changed")
                data = _regular_blob(original, _MAX_HAR_BYTES)
                try:
                    parsed = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_unique)
                    entries = parsed["log"]["entries"]
                    if not isinstance(entries, list) or len(entries) > 2000:
                        raise ValueError()
                except (ValueError, KeyError, TypeError, UnicodeError) as exc:
                    raise ValueError("Signed browser HAR contents unavailable") from exc
                result = {
                    "path": relative,
                    "exists": True,
                    "engagement_id": engagement_id,
                    "user_label": label,
                    "workflow_id": workflow_id,
                    "resource_sha256": hashlib.sha256(data).hexdigest(),
                    "mount_sha256": mount_digest,
                    "container_image_sha256": container_digest,
                    "capture_task_id": task_id,
                    "size_bytes": len(data),
                }
            elif har_path and os.path.exists(har_path):
                result["size_bytes"] = os.path.getsize(har_path)
            return result
        finally:
            # context was popped on success too; drop meta
            self.meta.pop(key, None)

    async def capture_state(
        self,
        label: str,
        engagement_id: str = "",
        *,
        signed: bool = False,
    ) -> Dict[str, Any]:
        context = await self.get_context(label, engagement_id=engagement_id, signed=signed)
        page = await self.get_page(label, engagement_id=engagement_id, signed=signed)

        cookies = await context.cookies()

        # Diagnostic capture
        try:
            diag = await page.evaluate(
                """
                () => ({
                    url: window.location.href,
                    origin: window.location.origin,
                    readyState: document.readyState,
                    title: document.title,
                    isMainFrame: window === window.top,
                    localStorageType: typeof localStorage,
                    localStorageKeys: localStorage ? Object.keys(localStorage) : null,
                    error: null
                })
                """
            )
        except Exception as e:
            diag = {"error": str(e)}

        state = {"cookies": cookies, "url": page.url, "diagnostics": diag}

        # Resilient capture per storage type — never abort workflow on storage errors.
        for storage_type in ["localStorage", "sessionStorage"]:
            try:
                data = await page.evaluate(
                    f"""
                    () => {{
                        const out = {{}};
                        try {{
                            for (let i = 0; i < {storage_type}.length; i++) {{
                                const k = {storage_type}.key(i);
                                out[k] = {storage_type}.getItem(k);
                            }}
                        }} catch (e) {{
                            return {{ __error: e.toString() }};
                        }}
                        return out;
                    }}
                    """
                )
                state[storage_type] = data
            except Exception as e:
                state[f"{storage_type}_error"] = str(e)

        return state

    async def stop(self):
        for engagement_id, label in list(self.contexts.keys()):
            try:
                await self.flush_har(
                    label,
                    engagement_id=engagement_id,
                    signed=self.meta.get((engagement_id, label), {}).get("signed", False),
                )
            except Exception:
                pass
        try:
            if self.browser:
                await self.browser.close()
        finally:
            try:
                if self.playwright:
                    await self.playwright.stop()
            finally:
                # A restart must never adopt browser contexts/pages from a
                # killed driver or retain imported tenant identity objects.
                self.browser = None
                self.playwright = None
                self.contexts.clear()
                self.pages.clear()
                self.meta.clear()
                self._started = False


manager = BrowserManager()

# ================= Endpoints =================


@app.on_event("startup")
async def startup():
    await manager.start()


@app.on_event("shutdown")
async def shutdown():
    await manager.stop()


@app.get("/health")
async def health():
    # Mark not-ready until Playwright has actually started — closes the historical
    # startup race where the port bound before the browser was launchable.
    signed_ready = _signed_provider_global_ready()
    ready = manager._started and (not _production() or signed_ready)
    report = {
        "status": "ready" if ready else "starting" if not manager._started else "unhealthy",
        "server": "browser-mcp",
        "playwright_started": manager._started,
        # Global provider prerequisites only. Every real tenant still needs
        # its own independently pinned mount before any signed execution.
        "signed_provider_ready": signed_ready,
    }
    # The main MCP client uses HTTP /health to decide whether to connect.
    # Return non-200 in production if the provider cannot authenticate/sign,
    # rather than representing an unusable provider as healthy.
    if _production() and not ready:
        return JSONResponse(status_code=503, content=report)
    return report


# ================= MCP Endpoints =================


class MCPInitializeRequest(BaseModel):
    server_id: Optional[str] = None
    scope: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None


class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    execution_binding: Optional[Dict[str, str]] = None


class MCPStatusRequest(BaseModel):
    request_id: str
    engagement_id: str
    task_id: str
    server_id: str


def _signed_provider_global_ready() -> bool:
    try:
        configured_token = os.getenv("OSOP_BROWSER_MCP_BEARER_TOKEN", "")
        if not isinstance(configured_token, str) or not 16 <= len(configured_token) <= 4096:
            return False
        _signer()
        if not _legacy_signed_test_mode():
            _source_configuration()
        raw = os.getenv("OSOP_BROWSER_MCP_JOURNAL_ROOT", "")
        directory = Path(raw)
        return directory.is_absolute() and directory.is_dir() and not directory.is_symlink()
    except (ValueError, TypeError, OSError):
        return False


@app.post("/mcp/initialize")
async def mcp_initialize(
    req: MCPInitializeRequest,
    authorization: Optional[str] = Header(default=None),
):
    _require_inbound_auth(authorization)
    # Advertise bound capabilities only if this provider can actually validate
    # the sender, persist the first request and sign an independently trusted
    # terminal outcome. Never promote an echo-only tool to signed capability.
    bound = _bearer_authorized(authorization) and _signed_provider_global_ready()
    if bound and req.session_id != "api-bootstrap":
        try:
            if not req.session_id:
                raise ValueError("Missing signed engagement mount identity")
            _signed_mount(req.session_id)
        except (ValueError, TypeError, OSError):
            bound = False
    if _production() and not bound:
        raise HTTPException(status_code=503, detail="Signed browser provider unavailable")
    return {
        "server_id": "browser-mcp",
        "version": "1.1",
        "capabilities": [
            "browser",
            "stateful",
            "evidence",
            *(
                [
                    "mcp_bound_receipts_v1",
                    "mcp_request_status_v1",
                ]
                if bound
                else []
            ),
        ],
        "tools": [
            {
                "name": "execute",
                "description": "Execute browser action",
                # Browser navigation/clicks can alter target state. An MCP
                # declaration is not independent ROE or human approval.
                "side_effect_class": "RECON_ACTIVE",
                "requires_approval": True,
                "scope_check": True,
                "parameters": [
                    {
                        "name": "url",
                        "type": "string",
                        "description": "Target URL",
                        "required": False,
                    },
                    {
                        "name": "action",
                        "type": "string",
                        "description": "Browser action",
                        "required": True,
                    },
                    {
                        "name": "user_label",
                        "type": "string",
                        "description": "Identity label",
                        "required": True,
                    },
                    {
                        "name": "evidence_mode",
                        "type": "string",
                        "description": "Explicit reviewed capture mode: none or screenshot_dom_har",
                        "required": False,
                    },
                ],
                "returns": {"status": "string", "result": "object"},
            }
        ],
    }


@app.post("/mcp/execute")
async def mcp_execute(
    req: MCPExecuteRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Serialize complete browser actions for each tenant and imported user."""
    params = req.parameters or {}
    original = req.execution_binding
    engagement = (
        original.get("engagement_id")
        if isinstance(original, dict)
        else params.get("engagement_id", "")
    )
    label = params.get("user_label", "guest")
    if (
        not isinstance(label, str)
        or len(label) > 128
        or not isinstance(engagement, str)
        or len(engagement) > 128
    ):
        return {
            "request_id": req.request_id or "",
            "status": "error",
            "error": "Browser execution identity unavailable",
        }
    async with manager.action_lock(label, engagement):
        return await _mcp_execute_serial(req, authorization)


async def _mcp_execute_serial(
    req: MCPExecuteRequest,
    authorization: Optional[str] = Header(default=None),
):
    request_id = req.request_id or "req-" + str(uuid.uuid4())
    params = req.parameters or {}
    bound = req.execution_binding is not None
    _require_inbound_auth(authorization, signed=bound)
    if _production() and not bound:
        raise HTTPException(status_code=403, detail="Signed browser execution required")
    if req.tool_name != "execute":
        return {"request_id": request_id, "status": "error", "error": "Unsupported browser tool"}

    action = params.get("action", "navigate")
    user_label = params.get("user_label", "guest")
    evidence_mode = params.get("evidence_mode", "none")
    engagement_id = params.get("engagement_id", "")
    workflow_id = params.get("workflow_id", "")
    step_id = params.get("step_id", "")
    # Phase 1 Bug Bounty Upgrade: optional Playwright storage_state ({cookies, origins})
    # forwarded by the agent so the browser context runs as an authenticated user.
    storage_state = params.get("storage_state")

    journal = None
    binding = None
    try:
        if bound:
            binding = _execution_binding(req, params)
            engagement_id = binding["engagement_id"]
            _clean(user_label)
            if type(evidence_mode) is not str or evidence_mode not in _EVIDENCE_MODES:
                raise ValueError("Signed browser reviewed capture mode unavailable")
            if not isinstance(workflow_id, str) or (
                workflow_id and not _IDENTIFIER.fullmatch(workflow_id)
            ):
                raise ValueError("Invalid signed workflow identity")
            if action not in {
                "navigate",
                "click",
                "fill",
                "capture_session",
                "capture_state",
                "screenshot",
                "dom_snapshot",
                "flush_har",
            }:
                # Arbitrary page JavaScript is not an independently scoped
                # signed task and can read cookies or secret storage.
                raise ValueError("Invalid signed browser action")
            if not _legacy_signed_test_mode() and (
                action != "navigate"
                or set(params)
                not in (
                    {"url", "action", "user_label"},
                    {"url", "action", "user_label", "evidence_mode"},
                )
            ):
                # Current 0027 signed original Action supports only this exact
                # reviewed navigation shape. Separate signed capture/click/
                # replay source admission is not implemented or implied.
                raise ValueError("Independent signed browser Action unavailable")
            _signer()
            # Preflight the exact mount before ANY browser effect. A removed
            # operator pin must not navigate, close or adopt an old context.
            _signed_mount(engagement_id)
            if not _legacy_signed_test_mode():
                # No caller-provided URL or claimed Flow scope can substitute
                # for the separately provisioned per-tenant origin policy.
                authorized_origins = _signed_allowed_origins(engagement_id)
                if (
                    action == "navigate"
                    and _exact_browser_origin(params.get("url")) not in authorized_origins
                ):
                    raise ValueError("Signed browser navigation origin unauthorized")
            journal = RequestJournal(binding)
            if not journal.reserve():
                # A retry after crash or an in-flight parallel request has an
                # UNKNOWN outcome. Do not execute again, even if bytes match.
                return {
                    "request_id": request_id,
                    "status": "duplicate_request",
                    "error": "Browser request already reserved; reconcile status",
                }
            if action == "navigate" and not _legacy_signed_test_mode():
                # This single-use durable central redemption must PRECEDE
                # even the creation of a new Playwright context or page. It
                # checks current original approved Action, Flow, Task, ROE,
                # reviewer, lease and exact full destination. Any lost ACK
                # leaves the original provider journal UNKNOWN.
                source_preflight = await _redeem_browser_navigation_source(
                    binding,
                    params["url"],
                    user_label,
                    evidence_mode,
                )
        # flush_har must NOT create a new context before closing the original.
        if action == "flush_har":
            har = await manager.flush_har(
                user_label,
                workflow_id,
                engagement_id=engagement_id,
                signed=bound,
                task_id=binding["task_id"] if bound else "",
            )
            if bound and har.get("exists") is not True:
                raise ValueError("Signed browser HAR flush unavailable")
            result = har
        else:
            if (
                bound
                and not _legacy_signed_test_mode()
                and evidence_mode == "screenshot_dom_har"
                and (
                    (engagement_id, user_label) in manager.contexts
                    or (engagement_id, user_label) in manager.pages
                )
            ):
                # A new reviewed Action cannot silently reuse a previously
                # captured identity, page, HAR, or Task provenance.
                raise ValueError("Reviewed browser capture requires a fresh context")
            if (
                bound
                and action in {"screenshot", "dom_snapshot"}
                and (engagement_id, user_label) not in manager.pages
            ):
                # Reading an existing capture must never initialize a fresh
                # browser/context (and therefore an unapproved blank page).
                raise ValueError("Signed capture requires an existing page")
            page = await manager.get_page(
                user_label,
                engagement_id=engagement_id,
                storage_state=storage_state,
                signed=bound,
                require_fresh_state=bound and action == "navigate",
                evidence_mode=evidence_mode if bound and not _legacy_signed_test_mode() else "none",
            )

            if action == "navigate":
                url = params.get("url", "")
                requested_origin = _exact_browser_origin(url) if bound else None
                if (
                    bound
                    and not _legacy_signed_test_mode()
                    and (
                        source_preflight["expires_at"] <= int(time.time())
                        or source_preflight["origin"] != requested_origin
                        or source_preflight["user_label"] != user_label
                        or source_preflight["evidence_mode"] != evidence_mode
                        or source_preflight["url_sha256"]
                        != hashlib.sha256(url.encode("utf-8")).hexdigest()
                        or requested_origin not in _signed_allowed_origins(engagement_id)
                    )
                ):
                    raise ValueError("Signed browser source preflight expired or changed")
                navigation_response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=60000,
                )
                try:
                    await page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    pass
                # Signed controls return only inert URL metadata. Do not
                # serialize session cookies or local storage into status logs.
                status_code = getattr(navigation_response, "status", None)
                if bound and (
                    type(status_code) is not int
                    or not 200 <= status_code <= 299
                    or _exact_browser_origin(page.url) != requested_origin
                    or page.url != url
                ):
                    raise ValueError("Signed navigation HTTP receipt unavailable")
                if bound and not _legacy_signed_test_mode():
                    # Playwright's final response may report a successful
                    # status after cross-origin redirects. Verify each hop.
                    _verified_navigation_chain(
                        navigation_response,
                        requested_origin,
                        _signed_allowed_origins(engagement_id),
                        url,
                    )
                result = (
                    {
                        "current_url": page.url,
                        "status_code": status_code if type(status_code) is int else 0,
                    }
                    if bound
                    else {
                        "current_url": page.url,
                        "state": await manager.capture_state(
                            user_label,
                            engagement_id=engagement_id,
                            signed=False,
                        ),
                    }
                )
                if (
                    bound
                    and not _legacy_signed_test_mode()
                    and evidence_mode == "screenshot_dom_har"
                ):
                    # Only this original reviewed navigation and the original
                    # one-shot central admission may trigger the 3 captures.
                    # No second MCP dispatch, Task, source grant, JS/click or
                    # externally exposed raw HTML, PNG, HAR or trace ZIP.
                    def still_original() -> None:
                        if (
                            page.url != url
                            or _exact_browser_origin(page.url) != requested_origin
                            or requested_origin not in _signed_allowed_origins(engagement_id)
                        ):
                            raise ValueError("Reviewed browser page changed during capture")
                        _signed_mount(engagement_id)

                    still_original()
                    screenshot = await manager.screenshot(
                        user_label,
                        engagement_id,
                        signed=True,
                        task_id=binding["task_id"],
                        evidence_mode=evidence_mode,
                    )
                    still_original()
                    png = _reviewed_capture_metadata(
                        screenshot,
                        engagement_id=engagement_id,
                        user_label=user_label,
                        task_id=binding["task_id"],
                        suffix="png",
                        limit=_MAX_SIGNED_SCREENSHOT_BYTES,
                    )
                    dom = await manager.dom_snapshot(
                        user_label,
                        engagement_id,
                        signed=True,
                        task_id=binding["task_id"],
                        evidence_mode=evidence_mode,
                    )
                    still_original()
                    html = _reviewed_capture_metadata(
                        dom,
                        engagement_id=engagement_id,
                        user_label=user_label,
                        task_id=binding["task_id"],
                        suffix="html",
                        limit=_MAX_SIGNED_DOM_BYTES,
                    )
                    har = await manager.flush_har(
                        user_label,
                        engagement_id=engagement_id,
                        signed=True,
                        task_id=binding["task_id"],
                    )
                    original_har = _reviewed_capture_metadata(
                        har,
                        engagement_id=engagement_id,
                        user_label=user_label,
                        task_id=binding["task_id"],
                        suffix="har",
                        limit=_MAX_HAR_BYTES,
                    )
                    result = {
                        **result,
                        "evidence_mode": evidence_mode,
                        "evidence": {
                            "screenshot": png,
                            "dom": html,
                            "har": original_har,
                        },
                    }
                    result["evidence_attestation"] = _signed_coupled_evidence(
                        binding, source_preflight, result["evidence"]
                    )
                    if journal is None:
                        raise ValueError("Original Browser one-shot journal unavailable")
                    # A failed/ambiguous durable sidecar leaves journal UNKNOWN.
                    # Do not retry navigation or imply current target-owner proof.
                    journal.commit_evidence(result["evidence_attestation"])
            elif action == "click":
                await page.click(params.get("selector"))
                result = {"current_url": page.url}
            elif action == "fill":
                await page.fill(params.get("selector"), params.get("value"))
                result = {"current_url": page.url}
            elif action in {"capture_session", "capture_state"}:
                result = (
                    {"current_url": page.url, "state": "redacted"}
                    if bound
                    else {
                        "state": await manager.capture_state(
                            user_label,
                            engagement_id=engagement_id,
                            signed=False,
                        ),
                        "current_url": page.url,
                    }
                )
            elif action == "eval":
                result = {
                    "result": await page.evaluate(params.get("expression")),
                    "current_url": page.url,
                }
            elif action == "screenshot":
                result = await manager.screenshot(
                    user_label,
                    engagement_id,
                    workflow_id,
                    step_id,
                    signed=bound,
                    task_id=binding["task_id"] if bound else "",
                )
            elif action == "dom_snapshot":
                result = await manager.dom_snapshot(
                    user_label,
                    engagement_id,
                    workflow_id,
                    step_id,
                    signed=bound,
                    task_id=binding["task_id"] if bound else "",
                )
            else:
                return {"request_id": request_id, "status": "error", "error": "Unsupported action"}
            if (
                bound
                and not _legacy_signed_test_mode()
                and (_exact_browser_origin(page.url) not in _signed_allowed_origins(engagement_id))
            ):
                raise ValueError("Signed browser page escaped authorized origin")
        if bound and (
            not isinstance(result, dict)
            or result.get("error")
            or (
                action in {"screenshot", "dom_snapshot", "flush_har"}
                and (
                    result.get("exists") is not True
                    or not isinstance(result.get("resource_sha256"), str)
                    or not _SHA256.fullmatch(result["resource_sha256"])
                )
            )
        ):
            raise ValueError("Signed browser artifact unavailable")
        response = {
            "request_id": request_id,
            "status": "success",
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if journal is not None:
            journal.finish("succeeded")
            response["provider_receipt"] = _signed_receipt(binding, "succeeded")
        return response
    except asyncio.CancelledError:
        raise
    except Exception:
        # External effects may have occurred before the exception: retain
        # UNKNOWN in the durable journal. Never claim a terminal failure or
        # replay the request automatically.
        return {
            "request_id": request_id,
            "status": "error",
            "error": "Browser provider action unavailable; remote outcome unconfirmed",
        }


@app.post("/mcp/request/status")
async def mcp_request_status(
    req: MCPStatusRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Read persisted original dispatch, not caller-asserted terminal evidence."""
    _require_inbound_auth(authorization, signed=True)
    try:
        binding = {
            "request_id": _clean(req.request_id, _REQUEST_ID),
            "engagement_id": _clean(req.engagement_id),
            "task_id": _clean(req.task_id),
            "server_id": _clean(req.server_id),
        }
        if (
            binding["server_id"] != SERVER_ID
            or not binding["engagement_id"].startswith("eng-")
            or not binding["task_id"].startswith("task-")
        ):
            raise ValueError()
        _signer()
        journal = RequestJournal(binding)
        state = journal.read()
        if state not in {"succeeded", "failed"}:
            return {
                "request_id": req.request_id,
                "status": "success",
                "result": {**binding, "status": "unknown", "verified": False},
            }
        return {
            "request_id": req.request_id,
            "status": "success",
            "result": _signed_receipt(binding, state),
        }
    except Exception:
        return {
            "request_id": req.request_id,
            "status": "success",
            "result": {"status": "unknown", "verified": False},
        }


@app.post("/mcp/request/evidence/readback")
async def mcp_request_evidence_readback(
    req: MCPStatusRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Read ONLY original local bytes against durable signed provider hashes.

    This is not current reviewer/ROE/lease proof, target-owner evidence, a
    scanner result, or permission to repeat the original browser Action.
    """
    _require_inbound_auth(authorization, signed=True)
    try:
        binding = {
            "request_id": _clean(req.request_id, _REQUEST_ID),
            "engagement_id": _clean(req.engagement_id),
            "task_id": _clean(req.task_id),
            "server_id": _clean(req.server_id),
        }
        if (
            binding["server_id"] != SERVER_ID
            or not binding["engagement_id"].startswith("eng-")
            or not binding["task_id"].startswith("task-")
        ):
            raise ValueError("Original browser evidence binding unavailable")
        evidence = RequestJournal(binding).current_evidence()
        return {
            "request_id": req.request_id,
            "status": "success",
            "result": {
                **binding,
                "status": "current_provider_local_original_bytes_match",
                "provider_signed_evidence_currently_matches": True,
                "current_authorization_verified": False,
                "independent_target_effect_verified": False,
                "safe_to_automatically_retry": False,
                "artifacts": evidence,
            },
        }
    except Exception:
        return {
            "request_id": req.request_id,
            "status": "success",
            "result": {
                "status": "unknown",
                "provider_signed_evidence_currently_matches": False,
                "current_authorization_verified": False,
                "independent_target_effect_verified": False,
                "safe_to_automatically_retry": False,
            },
        }


if __name__ == "__main__":
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Native browser MCP port must be in 1024..65535")
    uvicorn.run(app, host="127.0.0.1", port=args.port)
