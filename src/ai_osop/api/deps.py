"""AI-OSOP API Dependencies and Shared State

Centralized auth, shared module-level singletons, and request/response models
so that routers can import them without circular imports from main.py.
"""

import asyncio
import base64
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from typing import Literal

from ai_osop.core.config import settings
from ai_osop.core.models import SessionState

# ============== Pydantic Models for API ==============


class CreateEngagementRequest(BaseModel):
    engagement_id: str
    domains: List[str]
    ips: List[str] = Field(default_factory=list)
    exclusions: List[str] = Field(default_factory=list)
    allowed_techniques: List[str] = Field(default_factory=list)
    restrictions: List[str] = Field(default_factory=list)
    approval_required_for: List[str] = Field(default_factory=list)
    testing_window_start: Optional[datetime] = None
    testing_window_end: Optional[datetime] = None
    authorization_ref: Optional[str] = None
    roe: Dict[str, Any] = Field(default_factory=dict)
    # The authorization reference alone is NOT proof of signed ROE.
    # Submit a detached Ed25519 signature of the canonical policy instead.
    signed_roe: Optional[Dict[str, Any]] = None


class RevokeAuthorizationRequest(BaseModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)


class CreateTaskRequest(BaseModel):
    task_type: str
    priority: int = Field(5, ge=1, le=10)
    agent_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    dependencies: List[str] = Field(default_factory=list)
    approval_required: bool = False
    engagement_id: str


class ApprovalDecisionRequest(BaseModel):
    request_id: str
    decision: Literal["approved", "rejected"]
    # Legacy clients may include this field, but it is never the identity
    # recorded on the approval: that comes from the authenticated bearer.
    operator_id: Optional[str] = None
    notes: Optional[str] = None
    # Required for internal paid planner approval. The API never silently
    # substitutes a newer Flow or signer revision during a stale UI decision.
    expected_authorization_version: Optional[int] = Field(default=None, ge=1)
    expected_flow_revision: Optional[int] = Field(default=None, ge=0)


class AgentStatusResponse(BaseModel):
    agent_id: str
    agent_type: str
    status: str
    current_task: Optional[str]
    task_queue_depth: int
    last_heartbeat: str


class UserSessionImportRequest(BaseModel):
    """Operator imports captured cookies + tokens for a user under engagement.

    Cookie shape follows Playwright's BrowserContext.add_cookies format:
        [{name, value, domain, path, expires?, httpOnly?, secure?, sameSite?}, ...]
    """

    user_label: str = Field(..., description="logical label, e.g. user_a, admin, viewer")
    cookies: List[Dict[str, Any]] = Field(default_factory=list)
    bearer_token: str = ""
    local_storage: Dict[str, Any] = Field(default_factory=dict)
    session_storage: Dict[str, Any] = Field(default_factory=dict)
    csrf_token: str = ""
    extra_headers: Dict[str, str] = Field(default_factory=dict)
    user_agent: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class UserSessionResponse(BaseModel):
    engagement_id: str
    user_label: str
    cookie_count: int
    has_bearer: bool
    has_csrf: bool
    has_local_storage: bool
    captured_at: str
    expires_at: Optional[str]
    metadata: Dict[str, Any]


# ============== Global State ==============

# Mutable state container so routers and main.py share live values.
# Routers access state["orchestrator"] at request time (not import time)
# to avoid stale references when main.py binds the real instances in lifespan().
state = {
    "orchestrator": None,
    "session_store": None,
    "skill_engine": None,
}

# Backwards-compatible aliases (used by the old monolithic main.py pattern)
# NOTE: routers should import `state` and use state["orchestrator"]
# instead of importing these directly, because direct imports capture the
# initial None value and never see the updated binding from lifespan().

# ============== Authentication ==============

_OIDC_ALLOWED_ALGORITHMS = frozenset({
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
})
_LOCAL_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
_OIDC_ROLES = frozenset({"operator", "senior_operator"})
_OIDC_KID = re.compile(r"^[\x21-\x7e]{1,128}$")
_JWKS_LOCK = asyncio.Lock()
_JWKS_CACHE: Dict[str, Any] = {}


def _unique_jwt_fields(pairs: list) -> Dict[str, Any]:
    obj: Dict[str, Any] = {}
    for name, value in pairs:
        if name in obj:
            raise ValueError("Ambiguous JWT field")
        obj[name] = value
    return obj


def _jwt_header_without_ambiguity(encoded: str) -> Dict[str, Any]:
    """Reject duplicate JOSE header/claim names before library decoding."""
    try:
        segments = encoded.split(".")
        if len(segments) != 3:
            raise ValueError("Not a compact JWS")
        for part in segments[:2]:
            if not 1 <= len(part) <= 12000 or not re.fullmatch(r"[A-Za-z0-9_-]+", part):
                raise ValueError("Unsafe compact JWS encoding")
        values = []
        for part in segments[:2]:
            decoded = base64.b64decode(
                part + "=" * (-len(part) % 4), altchars=b"-_", validate=True,
            )
            content = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_unique_jwt_fields,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JWT field")),
            )
            if not isinstance(content, dict):
                raise ValueError("JWT envelope must contain JSON objects")
            values.append(content)
        return values[0]
    except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
        raise HTTPException(status_code=401, detail="Invalid bearer token") from exc


def _oidc_config() -> Optional[Dict[str, Any]]:
    """Validate the complete, administrator-supplied IdP trust boundary."""
    # Some local-only API tests and older embedded clients supply a minimal
    # settings stub with only JWT fields. An absent optional OIDC configuration
    # must not break their local-token verification.
    raw = (
        getattr(settings, "oidc_issuer", None),
        getattr(settings, "oidc_audience", None),
        getattr(settings, "oidc_jwks_url", None),
    )
    if not any(raw):
        return None
    if not all(isinstance(value, str) and value.strip() == value and value for value in raw):
        raise HTTPException(status_code=503, detail="OIDC authentication is misconfigured")
    issuer, audience, jwks_url = raw
    try:
        parts = urlsplit(issuer)
        keys_url = urlsplit(jwks_url)
        if any(
            parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.port not in {None, 443}
            for parsed in (parts, keys_url)
        ) or any(len(value) > 2048 for value in raw):
            raise ValueError()
        algorithms = getattr(settings, "oidc_algorithms", "RS256").split(",")
        if (
            not algorithms or len(algorithms) > 6
            or len(algorithms) != len(set(algorithms))
            or not set(algorithms) <= _OIDC_ALLOWED_ALGORITHMS
        ):
            raise ValueError()
        token_typ = getattr(settings, "oidc_token_typ", "at+jwt")
        if token_typ not in {"at+jwt", "JWT"}:
            raise ValueError()
        claim = getattr(settings, "oidc_role_claim", "groups")
        if not isinstance(claim, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", claim):
            raise ValueError()
        mapping = json.loads(getattr(settings, "oidc_role_map_json", "{}"))
        if (
            not isinstance(mapping, dict) or not 1 <= len(mapping) <= 64
            or any(
                not isinstance(key, str) or not 0 < len(key) <= 128
                or not isinstance(value, str) or value not in _OIDC_ROLES
                for key, value in mapping.items()
            )
        ):
            raise ValueError()
        cache_seconds = getattr(settings, "oidc_jwks_cache_seconds", 300)
        max_token_seconds = getattr(settings, "oidc_max_token_seconds", 3600)
        if (
            type(cache_seconds) is not int or not 30 <= cache_seconds <= 3600
            or type(max_token_seconds) is not int or not 60 <= max_token_seconds <= 86400
        ):
            raise ValueError()
        introspection = (
            getattr(settings, "oidc_introspection_url", None),
            getattr(settings, "oidc_introspection_client_id", None),
            getattr(settings, "oidc_introspection_client_secret", None),
        )
        if any(introspection):
            endpoint, client_id, client_secret = introspection
            if (
                not all(isinstance(v, str) and v for v in introspection)
                or not 0 < len(endpoint) <= 2048
                or not 0 < len(client_id) <= 256
                or not 0 < len(client_secret) <= 4096
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in client_id)
                or any(ch in "\r\n" for ch in client_secret)
            ):
                raise ValueError()
            endpoint_url = urlsplit(endpoint)
            if (
                endpoint_url.scheme != "https"
                or not endpoint_url.hostname
                or endpoint_url.port not in {None, 443}
                or endpoint_url.username or endpoint_url.password
                or endpoint_url.fragment
                or endpoint_url.query
            ):
                raise ValueError()
        else:
            introspection = None
    except (ValueError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="OIDC authentication is misconfigured") from exc
    return {
        "issuer": issuer, "audience": audience, "jwks_url": jwks_url,
        "algorithms": tuple(algorithms), "role_claim": claim,
        "role_map": mapping, "cache_seconds": cache_seconds,
        "token_typ": token_typ,
        "max_token_seconds": max_token_seconds,
        "introspection": introspection,
    }


def _jwks_http_client() -> httpx.AsyncClient:
    """No proxy-injected alternate origins, authentication, or redirects."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(3.0), follow_redirects=False,
        trust_env=False,
    )


def _oidc_introspection_http_client() -> httpx.AsyncClient:
    """Use the explicitly configured IdP only; never network/proxy redirects."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(3.0), follow_redirects=False,
        trust_env=False,
    )


async def _require_active_oidc_token(
    token_value: str, claims: Dict[str, Any], config: Dict[str, Any],
) -> None:
    """Request real IdP token status on every bearer admission when enabled.

    Key rotations and JWT expiry do not prove an already-issued token is
    active. Introspection must never fall back to locally cached 'active'
    state or accept a response bound to another principal.
    """
    credentials = config.get("introspection")
    if credentials is None:
        return  # Explicit JWT-only deployment; no revocation claim.
    url, client_id, client_secret = credentials
    try:
        async with _oidc_introspection_http_client() as client:
            async with client.stream(
                "POST", url,
                data={"token": token_value, "token_type_hint": "access_token"},
                auth=(client_id, client_secret),
                headers={"Accept": "application/json"},
            ) as response:
                if response.status_code != 200:
                    raise ValueError("IdP status unavailable")
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 8192:
                        raise ValueError("Oversized IdP response")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_jwt_fields)
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="OIDC token status unavailable",
        ) from exc
    if not isinstance(document, dict) or type(document.get("active")) is not bool:
        raise HTTPException(status_code=503, detail="OIDC token status unavailable")
    if document["active"] is False:
        raise HTTPException(status_code=401, detail="OIDC bearer token inactive")
    # RFC 7662 allows providers to omit optional metadata, but a successful
    # response with no subject cannot bind the result to the verified actor.
    if (
        document.get("sub") != claims["sub"]
        or ("iss" in document and document["iss"] != config["issuer"])
        or ("jti" in document and document["jti"] != claims.get("jti"))
        or (
            "exp" in document
            and (
                type(document["exp"]) is not int
                or document["exp"] != claims["exp"]
            )
        )
    ):
        raise HTTPException(status_code=401, detail="OIDC token status identity mismatch")
    observed_audience = document.get("aud")
    if observed_audience is not None and (
        observed_audience != config["audience"]
        and not (
            isinstance(observed_audience, list)
            and config["audience"] in observed_audience
        )
    ):
        raise HTTPException(status_code=401, detail="OIDC token status audience mismatch")


def _validate_jwks(body: Any) -> Dict[str, Dict[str, Any]]:
    """Retain only supported public signature keys with unambiguous key IDs."""
    if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
        raise ValueError("Invalid JWKS")
    values = body["keys"]
    if not 1 <= len(values) <= 32:
        raise ValueError("Invalid JWKS size")
    keys: Dict[str, Dict[str, Any]] = {}
    for record in values:
        if not isinstance(record, dict):
            raise ValueError("Invalid JWKS key")
        kid = record.get("kid")
        if not isinstance(kid, str) or not _OIDC_KID.fullmatch(kid) or kid in keys:
            raise ValueError("Duplicate or invalid JWKS key ID")
        if (
            record.get("use", "sig") != "sig"
            or ("key_ops" in record and record["key_ops"] != ["verify"])
            or any(field in record for field in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"))
        ):
            raise ValueError("Unsafe JWKS key metadata")
        kty = record.get("kty")
        if kty == "RSA":
            if not isinstance(record.get("n"), str) or not isinstance(record.get("e"), str):
                raise ValueError("Incomplete RSA JWKS key")
            from cryptography.hazmat.primitives.asymmetric import rsa
            from jose.utils import base64url_decode
            modulus = int.from_bytes(base64url_decode(record["n"].encode()), "big")
            exponent = int.from_bytes(base64url_decode(record["e"].encode()), "big")
            if modulus.bit_length() < 2048 or modulus.bit_length() > 8192:
                raise ValueError("Weak RSA JWKS key")
            rsa.RSAPublicNumbers(exponent, modulus).public_key()
        elif kty == "EC":
            from cryptography.hazmat.primitives.asymmetric import ec
            from jose.utils import base64url_decode
            curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}.get(record.get("crv"))
            if curve is None:
                raise ValueError("Unsupported EC JWKS curve")
            for field in ("x", "y"):
                if not isinstance(record.get(field), str):
                    raise ValueError("Invalid EC JWKS coordinate")
            length = {"P-256": 32, "P-384": 48, "P-521": 66}[record["crv"]]
            x_bytes = base64url_decode(record["x"].encode())
            y_bytes = base64url_decode(record["y"].encode())
            if len(x_bytes) != length or len(y_bytes) != length:
                raise ValueError("Invalid EC JWKS point length")
            x = int.from_bytes(x_bytes, "big")
            y = int.from_bytes(y_bytes, "big")
            ec.EllipticCurvePublicNumbers(x, y, curve()).public_key()
        else:
            raise ValueError("Unsupported JWKS key type")
        keys[kid] = record
    return keys


async def _download_jwks(config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    try:
        async with _jwks_http_client() as client:
            async with client.stream("GET", config["jwks_url"], headers={"Accept": "application/json"}) as response:
                if response.status_code != 200:
                    raise ValueError("JWKS unavailable")
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 65536:
                        raise ValueError("JWKS exceeds maximum response size")
        parsed = json.loads(raw.decode("utf-8"))
        return _validate_jwks(parsed)
    except Exception as exc:
        # A transport, decode, crypto parser or unexpected client failure
        # never licenses reuse of an expired key nor leaks provider details.
        raise HTTPException(status_code=503, detail="OIDC signing keys unavailable") from exc


async def _oidc_key(config: Dict[str, Any], kid: str, alg: str) -> Dict[str, Any]:
    # Serialize expiration and unknown-kid refetch across simultaneous HTTP
    # requests. Never serve a stale cached key after a failed refresh.
    fingerprint = (
        config["jwks_url"], config["issuer"], config["audience"],
        config["algorithms"], config["cache_seconds"],
    )
    async with _JWKS_LOCK:
        now = time.monotonic()
        if (
            _JWKS_CACHE.get("fingerprint") != fingerprint
            or _JWKS_CACHE.get("expires", 0) <= now
        ):
            keys = await _download_jwks(config)
            _JWKS_CACHE.clear()
            _JWKS_CACHE.update({
                "fingerprint": fingerprint, "keys": keys,
                "expires": time.monotonic() + config["cache_seconds"],
                "misses": {},
            })
        record = _JWKS_CACHE["keys"].get(kid)
        if record is None:
            if _JWKS_CACHE["misses"].get(kid, 0) > now:
                raise HTTPException(status_code=401, detail="Unknown OIDC signing key")
            # Newly rotated KID: refresh once instead of relying on stale
            # discovery, but a missing KID can never fall back to another key.
            keys = await _download_jwks(config)
            recent_misses = _JWKS_CACHE.get("misses", {})
            _JWKS_CACHE.clear()
            _JWKS_CACHE.update({
                "fingerprint": fingerprint, "keys": keys,
                "expires": time.monotonic() + config["cache_seconds"],
                "misses": {k: expiry for k, expiry in recent_misses.items()
                           if expiry > now and len(k) <= 128},
            })
            record = keys.get(kid)
        if record is None:
            # Bound the rejection cache to prevent an attacker with random
            # KIDs from allocating unbounded per-process state.
            misses = _JWKS_CACHE["misses"]
            if len(misses) >= 64:
                misses.pop(next(iter(misses)))
            misses[kid] = time.monotonic() + 10.0
            raise HTTPException(status_code=401, detail="Unknown OIDC signing key")
        if (record.get("alg") is not None and record["alg"] != alg) or (
            alg.startswith("RS") and record["kty"] != "RSA"
        ) or (
            alg.startswith("ES") and (
                record["kty"] != "EC"
                or record.get("crv") != {
                    "ES256": "P-256", "ES384": "P-384", "ES512": "P-521",
                }.get(alg)
            )
        ):
            raise HTTPException(status_code=401, detail="OIDC signing key algorithm mismatch")
        return record.copy()


async def _verify_oidc_token(token_value: str, header: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    from jose import JWTError, jwt
    alg, kid = header.get("alg"), header.get("kid")
    if (
        alg not in config["algorithms"]
        or not isinstance(kid, str) or not _OIDC_KID.fullmatch(kid)
        or any(name in header for name in ("jku", "x5u", "jwk", "x5c", "crit"))
        or header.get("typ") != config["token_typ"]
    ):
        raise HTTPException(status_code=401, detail="Invalid OIDC JWT header")
    key = await _oidc_key(config, kid, alg)
    try:
        claims = jwt.decode(
            token_value, key, algorithms=[alg],
            issuer=config["issuer"], audience=config["audience"],
            options={
                "require_exp": True, "require_nbf": True,
                "require_iat": True, "require_sub": True,
                "require_iss": True, "require_aud": True,
                "leeway": 0,
            },
        )
        now = int(datetime.now(timezone.utc).timestamp())
        if (
            not isinstance(claims, dict)
            or any(type(claims.get(name)) is not int for name in ("exp", "nbf", "iat"))
            or claims["exp"] <= now
            or claims["iat"] > now
            or claims["nbf"] > now
            or claims["iat"] > claims["exp"]
            or claims["nbf"] > claims["exp"]
            or claims["exp"] - claims["iat"] > config["max_token_seconds"]
            or not isinstance(claims.get("sub"), str)
            or not 0 < len(claims["sub"].strip()) <= 256
            or any(ord(ch) < 32 for ch in claims["sub"])
        ):
            raise ValueError("Invalid OIDC required claims")
        aud = claims.get("aud")
        if (
            isinstance(aud, list) and len(aud) > 1
            and claims.get("azp") != config["audience"]
        ) or (
            "azp" in claims and claims["azp"] != config["audience"]
        ):
            raise ValueError("OIDC authorized party does not match audience")
        roles = claims.get(config["role_claim"])
        role_values = [roles] if isinstance(roles, str) else roles
        if (
            not isinstance(role_values, list)
            or not 1 <= len(role_values) <= 64
            or any(not isinstance(value, str) for value in role_values)
        ):
            raise ValueError("OIDC operator group claim missing")
        trusted = {config["role_map"].get(value) for value in role_values}
        trusted.discard(None)
        if not trusted:
            raise ValueError("No trusted OIDC operator group")
        role = "senior_operator" if "senior_operator" in trusted else "operator"
        await _require_active_oidc_token(token_value, claims, config)
        # Owner IDs are shared across local JWT and IdP sources. A plain `sub`
        # would allow a foreign OIDC account named 'alice' to inherit an
        # unrelated local account's engagements. Give each issuer+subject a
        # stable, bounded namespace suitable for the durable created_by field.
        actor = "oidc-" + hashlib.sha256(
            (config["issuer"] + "\0" + claims["sub"]).encode("utf-8")
        ).hexdigest()[:48]
        return {"sub": actor, "role": role, "claims": claims}
    except (JWTError, TypeError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=401, detail="Invalid OIDC bearer token") from exc


async def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    token: Optional[str] = Query(None),
):
    """Verify a local HMAC JWT, optional trusted OIDC JWT, or dev-only token.

    JWT-only mode verifies signatures and times but cannot provide early
    revocation. When OSOP_OIDC_INTROSPECTION_* is configured, each OIDC bearer
    also requires live authenticated provider status, without an active cache.
    """
    if type(credentials).__name__ == "Depends":
        credentials = None
    production = settings.environment.strip().lower() in {"production", "prod"}
    oidc = _oidc_config()
    if production and not settings.jwt_secret and oidc is None:
        # A global API token has no independently attributable operator/tenant
        # identity and previously granted unconditional senior_operator access.
        # Production flow authorization requires a signed JWT subject/role.
        raise HTTPException(
            status_code=503,
            detail="Production authentication requires OSOP_JWT_SECRET or configured OSOP_OIDC_*",
        )
    if (production or oidc is not None) and token is not None:
        # Query credentials leak through browser history, reverse-proxy access
        # logs and link referrers. Require an Authorization header.
        raise HTTPException(status_code=403, detail="Bearer header required")
    if not credentials and not token:
        raise HTTPException(status_code=403, detail="Not authenticated")
    if credentials is not None and credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer header required")
    presented = credentials.credentials if credentials else token

    if settings.jwt_secret or oidc:
        from jose import ExpiredSignatureError, JWTError, jwt
        if not isinstance(presented, str) or len(presented) > 16384:
            raise HTTPException(status_code=401, detail="Invalid bearer token")
        header = _jwt_header_without_ambiguity(presented)
        alg = header.get("alg")
        if oidc is not None and alg in oidc["algorithms"]:
            principal = await _verify_oidc_token(presented, header, oidc)
            await _assert_operator_not_revoked(presented, principal)
            return principal
        if not settings.jwt_secret:
            raise HTTPException(status_code=401, detail="Invalid bearer token")
        if settings.jwt_algorithm not in _LOCAL_JWT_ALGORITHMS:
            raise HTTPException(status_code=503, detail="Local JWT algorithm misconfigured")
        if alg != settings.jwt_algorithm:
            raise HTTPException(status_code=401, detail="Invalid bearer token")
        decode_kwargs: Dict[str, Any] = {
            "key": settings.jwt_secret,
            "algorithms": [settings.jwt_algorithm],
            "options": {
                "require_exp": True,
                "verify_exp": True,
                "require_sub": True,
            },
        }
        if settings.jwt_audience:
            decode_kwargs["audience"] = settings.jwt_audience
            decode_kwargs["options"]["require_aud"] = True
        if settings.jwt_issuer:
            decode_kwargs["issuer"] = settings.jwt_issuer
            decode_kwargs["options"]["require_iss"] = True
        try:
            payload = jwt.decode(presented, **decode_kwargs)
        except ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except JWTError as exc:
            raise HTTPException(status_code=401, detail="Invalid bearer token") from exc
        sub = payload.get("sub")
        role = payload.get("role")
        if (
            not isinstance(sub, str) or not 0 < len(sub.strip()) <= 256
            or role not in (_OIDC_ROLES | {"viewer"})
            or type(payload.get("exp")) is not int
            or payload["exp"] <= int(datetime.now(timezone.utc).timestamp())
        ):
            raise HTTPException(status_code=401, detail="JWT identity or expiry invalid")
        principal = {"sub": sub, "role": role, "claims": payload}
        await _assert_operator_not_revoked(presented, principal)
        return principal

    if settings.api_token:
        import hmac

        if not hmac.compare_digest(presented or "", settings.api_token):
            raise HTTPException(status_code=401, detail="Invalid bearer token")
        # Shared development credentials do not identify a human owner and
        # cannot grant senior/operator privileges through require_role().
        return {"sub": "shared-development-token", "role": "dev_api_token"}

    import logging

    logging.getLogger("ai_osop.auth").critical(
        "AIOSOP-SEC-001: neither local JWT, OIDC, nor development API token is configured. "
        "Provision signed bearer authentication before exposing operator routes."
    )
    raise HTTPException(
        status_code=401,
        detail="Authentication is not configured. Configure local JWT or OIDC operator credentials.",
    )


def _operator_revocation_ledger() -> Any:
    """Get the already-connected authoritative PostgreSQL session pool."""
    from ai_osop.memory.operator_revocation import (
        OperatorRevocationLedger, OperatorRevocationUnavailable,
    )

    session_store = state.get("session_store")
    memory = getattr(session_store, "sm", None)
    if memory is None:
        orchestrator = state.get("orchestrator")
        memory = getattr(orchestrator, "session_memory", None)
    if memory is None or not callable(getattr(memory, "_async_session", None)):
        raise OperatorRevocationUnavailable("Operator revocation database unavailable")
    return OperatorRevocationLedger(memory)


async def _assert_operator_not_revoked(token_value: str, principal: Dict[str, Any]) -> None:
    if not getattr(settings, "operator_revocation_required", False):
        return
    from ai_osop.memory.operator_revocation import (
        OperatorRevoked, OperatorRevocationUnavailable,
    )

    try:
        await _operator_revocation_ledger().assert_active(token_value, principal)
    except OperatorRevoked as exc:
        raise HTTPException(status_code=401, detail="Operator credential revoked") from exc
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid operator subject") from exc
    except OperatorRevocationUnavailable as exc:
        raise HTTPException(status_code=503, detail="Operator revocation status unavailable") from exc


async def assert_engagement_access(operator: Dict[str, Any], session_id: str) -> SessionState:
    """Verify the operator is authorized to access the engagement.

    Authorization rules:
      - senior_operator role: global access
      - operator role: access only if they created the engagement

    Raises HTTPException 403 if unauthorized, 404 if engagement not found.
    """
    from ai_osop.core.models import SessionState

    orch = state.get("orchestrator")
    if orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    session: Optional[SessionState] = orch._sessions.get(session_id)
    if not session:
        # Fallback to warm storage so restarts don't break authorization
        try:
            session = await orch.session_memory.load_session_state(session_id)
        except Exception:
            session = None

    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")

    role = operator.get("role", "")
    if role == "senior_operator":
        return session

    if session.created_by is None:
        raise HTTPException(
            status_code=403, detail="Engagement has no owner and cannot be accessed"
        )

    if session.created_by == operator.get("sub"):
        return session

    raise HTTPException(
        status_code=403, detail="You do not have permission to access this engagement"
    )


# ============== Request ID / Correlation Middleware ==============


class RequestContext:
    """Lightweight request-scoped context holder for correlation IDs."""

    _store: Dict[str, Any] = {}

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        return cls._store.get(key, default)

    @classmethod
    def set(cls, key: str, value: Any) -> None:
        cls._store[key] = value

    @classmethod
    def clear(cls) -> None:
        cls._store.clear()


def require_role(*allowed_roles: str):
    """Dependency factory: 403 unless operator.role in allowed_roles."""

    async def _guard(operator: Dict[str, Any] = Depends(verify_token)) -> Dict[str, Any]:
        if operator.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=403, detail=f"Role '{operator.get('role')}' not permitted"
            )
        return operator

    return _guard


def update_active_agents(count: int) -> None:
    """Update Prometheus-style active agents metric (placeholder)."""
    pass
