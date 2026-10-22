"""Bounded independent-*process* controlled target effect client.

The ONLY allowed transport is an explicit numeric 127.0.0.1 HTTP endpoint.
The caller must obtain distinct owner-ledger and access-gateway Ed25519 public
keys from an OUT-OF-BAND trusted channel, not the HTTP response or a model.

This is a lab oracle, NOT a production target-authority verifier: a second
process and distinct keys do not prove independent operator ownership or
persisted Flow/ROE/Task authorization. No finding/report is ever verified.

Contract:
    client = LoopbackTargetEffectClient(
        endpoint_url="http://127.0.0.1:<ephemeral>/api/record/123",
        owner_public_key=<out-of-band Ed25519PublicKey>,
        access_public_key=<out-of-band Ed25519PublicKey>,
        source_identity="account_a", target_identity="account_b",
    )
    candidate = await client.observe_once(
        source_token=<controlled fixture credential>,
        target_token=<different controlled fixture credential>,
        nonce=<fresh 32-character lowercase hex>,
    )

The target's /__lab__/audit/<nonce> responds with canonical detached-signed
ownership and access records generated from actual target-side HTTP events.
Do not attach this to arbitrary URLs or elevate candidate evidence to VERIFIED.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Dict
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_OWNER_DOMAIN = b"AI-OSOP-INDEPENDENT-LAB-OWNER-V1\x00"
_ACCESS_DOMAIN = b"AI-OSOP-INDEPENDENT-LAB-ACCESS-V1\x00"
_SESSION_DOMAIN = b"AI-OSOP-INDEPENDENT-LAB-SESSION-V1\x00"
_REQUEST_DOMAIN = b"AI-OSOP-INDEPENDENT-LAB-REQUEST-V1\x00"
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_RESOURCE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_MAX_BODY = 8192


class IndependentTargetEffectDenied(PermissionError):
    """Controlled lab effects are missing, altered or outside the approved scope."""


def _canonical(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _hash(domain: bytes, value: Dict[str, Any]) -> str:
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _strict_json(blob: bytes, max_bytes: int = _MAX_BODY) -> Dict[str, Any]:
    if type(blob) is not bytes or not 1 <= len(blob) <= max_bytes:
        raise IndependentTargetEffectDenied("Bounded lab attestation required")

    def _unique(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            blob.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
        if type(parsed) is not dict or _canonical(parsed) != blob:
            raise ValueError("noncanonical")
        return parsed
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise IndependentTargetEffectDenied("Malformed or noncanonical lab evidence") from exc


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _verify_signed(envelope: Any, *, key: Ed25519PublicKey, domain: bytes) -> Dict[str, Any]:
    if type(envelope) is not dict or set(envelope) != {"claims_b64", "signature_b64"}:
        raise IndependentTargetEffectDenied("Detached signed lab envelope required")
    try:
        raw = base64.b64decode(envelope["claims_b64"], validate=True)
        sig = base64.b64decode(envelope["signature_b64"], validate=True)
        if (
            base64.b64encode(raw).decode("ascii") != envelope["claims_b64"]
            or base64.b64encode(sig).decode("ascii") != envelope["signature_b64"]
            or len(sig) != 64
        ):
            raise ValueError("noncanonical signature encoding")
        claims = _strict_json(raw)
        key.verify(sig, domain + raw)
        return claims
    except (ValueError, TypeError, KeyError, InvalidSignature) as exc:
        raise IndependentTargetEffectDenied("Untrusted target-side Ed25519 signature") from exc


def _session_sha(token: str) -> str:
    return hashlib.sha256(_SESSION_DOMAIN + token.encode("utf-8")).hexdigest()


def _request_sha(*, nonce: str, path: str, role: str, session_sha: str | None) -> str:
    return _hash(
        _REQUEST_DOMAIN,
        {
            "method": "GET",
            "path": path,
            "nonce": nonce,
            "role": role,
            "session_sha256": session_sha,
        },
    )


@dataclass(frozen=True)
class ControlledLabEffect:
    """Signed, correlated *synthetic-lab* observations. Never a verified finding."""

    resource_id: str
    owner_identity: str
    nonce: str
    source_status: int
    target_status: int
    anonymous_status: int
    owner_signature_verified: bool = True
    access_signature_verified: bool = True
    owner_and_effect_correlated: bool = True
    authority_level: str = "controlled_lab_synthetic_not_deployable"
    validation_state: str = "candidate_only"
    finding_verified: bool = False
    report_release_approved: bool = False


class LoopbackTargetEffectClient:
    """A single client that cannot contact any host except numeric 127.0.0.1."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        owner_public_key: Ed25519PublicKey,
        access_public_key: Ed25519PublicKey,
        source_identity: str,
        target_identity: str,
    ) -> None:
        try:
            parsed = urlsplit(endpoint_url)
            if (
                type(endpoint_url) is not str
                or parsed.scheme != "http"
                or parsed.hostname != "127.0.0.1"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.netloc != f"127.0.0.1:{parsed.port}"
                or parsed.port is None
                or not 1 <= parsed.port <= 65535
                or not parsed.path.startswith("/api/record/")
                or parsed.path.count("/") != 3
                or parsed.query
                or parsed.fragment
                or parsed.path.startswith("//")
                or "%" in endpoint_url
                or "\\" in endpoint_url
                or any(c.isspace() for c in endpoint_url)
                or urlunsplit(parsed) != endpoint_url
                or not _RESOURCE.fullmatch(parsed.path.split("/")[-1])
            ):
                raise ValueError("unsupported origin")
            if (
                not isinstance(owner_public_key, Ed25519PublicKey)
                or not isinstance(access_public_key, Ed25519PublicKey)
                or hmac.compare_digest(
                    _public_bytes(owner_public_key), _public_bytes(access_public_key)
                )
                or not isinstance(source_identity, str)
                or not isinstance(target_identity, str)
                or not _IDENTITY.fullmatch(source_identity)
                or not _IDENTITY.fullmatch(target_identity)
                or source_identity == target_identity
                or {source_identity.casefold(), target_identity.casefold()}
                & {"anonymous", "public", "guest"}
            ):
                raise ValueError("independent target evidence binding")
        except (ValueError, TypeError, AttributeError) as exc:
            raise IndependentTargetEffectDenied(
                "Only explicit controlled loopback and separate trusted keys allowed"
            ) from exc
        self._endpoint = endpoint_url
        self._origin = f"http://127.0.0.1:{parsed.port}"
        self._path = parsed.path
        self._resource_id = parsed.path.split("/")[-1]
        self._source_identity = source_identity
        self._target_identity = target_identity
        self._owner_key = owner_public_key
        self._access_key = access_public_key
        self._seen: set[str] = set()
        self._lock = asyncio.Lock()

    async def observe_once(
        self, *, source_token: str, target_token: str, nonce: str
    ) -> ControlledLabEffect:
        """GET three roles and retrieve two distinct signed target-side records.

        A failed or uncertain attempt burns its nonce for this client; never
        retry an unknown outcome or interpret returned HTTP 200 as authority.
        Only controlled fixture credentials belong here, never production.
        """
        if (
            type(nonce) is not str
            or not _NONCE.fullmatch(nonce)
            or type(source_token) is not str
            or type(target_token) is not str
            or not 1 <= len(source_token) <= 256
            or not 1 <= len(target_token) <= 256
            or source_token == target_token
            or any(ord(c) < 33 or ord(c) > 126 for c in source_token + target_token)
        ):
            raise IndependentTargetEffectDenied(
                "Fresh nonce and distinct controlled credentials required"
            )
        async with self._lock:
            if nonce in self._seen:
                raise IndependentTargetEffectDenied("Controlled nonce already used")
            self._seen.add(nonce)
            observations: Dict[str, Dict[str, Any]] = {}
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(3.0),
                    follow_redirects=False,
                    trust_env=False,
                    max_redirects=0,
                    limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
                ) as client:
                    for role, token in (
                        ("source", source_token),
                        ("target", target_token),
                        ("anonymous", None),
                    ):
                        headers = {
                            "X-Controlled-Run": nonce,
                            "X-Controlled-Role": role,
                        }
                        if token is not None:
                            headers["Authorization"] = f"Bearer {token}"
                        response = await client.get(self._endpoint, headers=headers)
                        if len(response.content) > _MAX_BODY:
                            raise IndependentTargetEffectDenied("Oversized target response")
                        session = _session_sha(token) if token is not None else None
                        observations[role] = {
                            "method": "GET",
                            "path": self._path,
                            "role": role,
                            "identity": (
                                self._source_identity
                                if role == "source"
                                else self._target_identity if role == "target" else None
                            ),
                            "status": response.status_code,
                            "session_sha256": session,
                            "request_sha256": _request_sha(
                                nonce=nonce, path=self._path, role=role, session_sha=session
                            ),
                            "response_sha256": hashlib.sha256(response.content).hexdigest(),
                            "redirected": response.is_redirect or "location" in response.headers,
                        }
                    response = await client.get(
                        f"{self._origin}/__lab__/audit/{nonce}",
                        headers={"X-Controlled-Run": nonce},
                    )
                    if response.status_code != 200 or len(response.content) > _MAX_BODY:
                        raise IndependentTargetEffectDenied(
                            "Signed independent lab receipts unavailable"
                        )
                    envelope = _strict_json(response.content)
                if set(envelope) != {"ownership", "access"}:
                    raise IndependentTargetEffectDenied("Independent signing records missing")
                owner = _verify_signed(
                    envelope["ownership"], key=self._owner_key, domain=_OWNER_DOMAIN
                )
                access = _verify_signed(
                    envelope["access"], key=self._access_key, domain=_ACCESS_DOMAIN
                )
                owner_record = {
                    "resource_id": self._resource_id,
                    "owner_identity": self._source_identity,
                    "visibility": "private",
                    "revision": 1,
                }
                if (
                    set(owner) != {"schema", "nonce", "owner_record", "events_sha256"}
                    or owner.get("schema") != "ai-osop.independent-lab-owner.v1"
                    or owner.get("nonce") != nonce
                    or owner.get("owner_record") != owner_record
                    or set(access)
                    != {"schema", "nonce", "resource_id", "owner_record_sha256", "events"}
                    or access.get("schema") != "ai-osop.independent-lab-access.v1"
                    or access.get("nonce") != nonce
                    or access.get("resource_id") != self._resource_id
                    or access.get("owner_record_sha256")
                    != hashlib.sha256(_canonical(owner_record)).hexdigest()
                    or access.get("events") != observations
                    or owner.get("events_sha256")
                    != hashlib.sha256(_canonical(observations)).hexdigest()
                ):
                    raise IndependentTargetEffectDenied(
                        "Owner-of-record and exact HTTP events disagree"
                    )
                source, target, anonymous = (
                    observations[role] for role in ("source", "target", "anonymous")
                )
                if (
                    source["status"] != 200
                    or target["status"] != 200
                    or anonymous["status"] not in {401, 403, 404}
                    or any(item["redirected"] for item in observations.values())
                    or source["response_sha256"] != target["response_sha256"]
                    or source["session_sha256"] == target["session_sha256"]
                ):
                    raise IndependentTargetEffectDenied(
                        "Private cross-identity outcome not corroborated"
                    )
                return ControlledLabEffect(
                    resource_id=self._resource_id,
                    owner_identity=self._source_identity,
                    nonce=nonce,
                    source_status=source["status"],
                    target_status=target["status"],
                    anonymous_status=anonymous["status"],
                )
            except IndependentTargetEffectDenied:
                raise
            except (httpx.HTTPError, ValueError, TypeError, KeyError, RecursionError) as exc:
                raise IndependentTargetEffectDenied(
                    "Independent controlled target receipt status UNKNOWN"
                ) from exc
