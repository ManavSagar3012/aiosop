"""Read-only provider credential rotation readiness from independent attestations.

This module does not retrieve secrets, activate routes or authorize model calls.
Each snapshot must be freshly produced by a separately trusted authority against
the same locally generated nonce. There are currently no production readers
registered: absence of even one authority fails closed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class CredentialLifecycleDenied(Exception):
    """An independent current readiness proof was unavailable or inconsistent."""


_KINDS = ("profile", "flow", "principal", "policy", "vault", "budget")
_DOMAIN = b"ai-osop-provider-credential-readiness-v1\x00"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._:-]{1,59}\Z")
_ENGAGEMENT = re.compile(r"eng-[A-Za-z0-9._:-]{1,60}\Z")
_REF = re.compile(r"pcref-[0-9a-f]{32}\Z")
_REVIEW = re.compile(r"provider-review-[0-9a-f]{32}\Z")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,89}\Z")
_CALL = re.compile(r"task-[A-Za-z0-9._:-]{1,123}\Z")
_PROVIDERS = frozenset(("openai", "anthropic", "gemini", "deepseek"))
_CAPABILITIES = frozenset(("text_completion", "tool_calls", "json_mode", "reasoning", "embeddings"))
_POLICY_FIELDS = frozenset(
    (
        "provider",
        "model",
        "operations",
        "allowed_roles",
        "capabilities",
        "max_output_tokens",
        "budget_source",
    )
)
_BAD_LABEL = re.compile(
    r"(?i)(?:sk[-_](?:live|test)|gh[pousr]_|bearer|password|credential|"
    r"secret|token|api[_-]?key)"
)


# The caller must supply these from a *trusted local* operator/Flow context,
# never from a request body or a provider's purported metadata.
@dataclass(frozen=True)
class CredentialReadinessRequest:
    engagement_id: str
    flow_id: str
    flow_revision: int
    authorization_version: int
    authorization_id: str
    authorization_sha256: str
    owner_sub: str
    actor_sub: str
    task_id: str
    agent_role: str
    ref_id: str
    reference_sha256: str
    reference_revision: int
    generation: int
    provider: str
    slot: str
    policy_review_id: str
    policy_sha256: str
    model: str
    operation: str
    cost_request_micro_usd: int
    purpose: str = "activate"


@dataclass(frozen=True)
class CredentialReadinessDecision:
    ref_id: str
    reference_revision: int
    generation: int
    purpose: str
    proof_expires_at: int
    independently_attested_vault_presence: bool = True
    rotation_readiness_verified: bool = True
    provider_accepts_credential_verified: bool = False
    provider_contacted: bool = False
    budget_reserved: bool = False
    dispatch_authorized: bool = False


# Readers independently authenticate their backend service before returning
# bounded signed bytes. In particular the vault reader must inspect actual
# material in a protected vault, not a symbolic reference or caller flag.
Reader = Callable[[CredentialReadinessRequest, str], Awaitable[bytes]]


def _id(value: Any, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _integer(value: Any, minimum: int, maximum: int = 2147483647) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _require_request(r: CredentialReadinessRequest) -> None:
    if not isinstance(r, CredentialReadinessRequest) or (
        not _id(r.engagement_id, _ENGAGEMENT)
        or not _id(r.flow_id, _FLOW)
        or not _id(r.ref_id, _REF)
        or not _id(r.policy_review_id, _REVIEW)
        or not all(
            _id(v, _SHA) for v in (r.authorization_sha256, r.reference_sha256, r.policy_sha256)
        )
        or not all(
            _id(v, _ID) for v in (r.owner_sub, r.actor_sub, r.authorization_id, r.agent_role)
        )
        or not _id(r.task_id, _CALL)
        or not _id(r.model, _MODEL)
        or type(r.provider) is not str
        or r.provider not in _PROVIDERS
        or r.slot not in ("primary", "backup")
        or r.operation not in ("completion", "embedding")
        or r.purpose not in ("activate", "rotate")
        or not _integer(r.flow_revision, 0)
        or not _integer(r.authorization_version, 1)
        or not _integer(r.reference_revision, 1)
        or not _integer(r.generation, 1)
        or not _integer(r.cost_request_micro_usd, 1, 10000000000)
        or (r.purpose == "rotate" and r.generation < 2)
        or ("/" in r.model and r.model.split("/", 1)[0] != r.provider)
        or ("/" not in r.model and r.provider != "openai")
    ):
        raise CredentialLifecycleDenied("Invalid bounded authenticated readiness request")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    obj: Dict[str, Any] = {}
    for name, value in pairs:
        if name in obj:
            raise ValueError("Duplicate signed evidence member")
        obj[name] = value
    return obj


def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _policy_digest(value: Any) -> str:
    """Recompute the existing reviewed policy's canonical digest in isolation.

    Does not import the storage package (which eagerly loads DB/Neo4j). Accepts
    exactly the already-normalized policy format persisted in the review store.
    """
    if type(value) is not dict or set(value) != _POLICY_FIELDS:
        raise CredentialLifecycleDenied("Canonical reviewed policy required")
    provider, model = value["provider"], value["model"]
    operations, roles, capabilities = (
        value["operations"],
        value["allowed_roles"],
        value["capabilities"],
    )
    if (
        type(provider) is not str
        or provider not in _PROVIDERS
        or not _id(model, _MODEL)
        or _BAD_LABEL.search(model)
        or any(part in ("", ".", "..") for part in model.split("/"))
        or ("/" in model and model.split("/", 1)[0] != provider)
        or ("/" not in model and provider != "openai")
        or type(operations) is not list
        or not 1 <= len(operations) <= 2
        or any(op not in ("completion", "embedding") for op in operations)
        or operations != sorted(set(operations))
        or type(roles) is not list
        or not 1 <= len(roles) <= 24
        or any(not _id(role, _ID) or len(role) > 64 for role in roles)
        or roles != sorted(set(roles))
        or type(capabilities) is not list
        or not 1 <= len(capabilities) <= 5
        or any(type(cap) is not str or cap not in _CAPABILITIES for cap in capabilities)
        or capabilities != sorted(set(capabilities))
        or ("completion" in operations and "text_completion" not in capabilities)
        or ("embedding" in operations and "embeddings" not in capabilities)
        or ("embedding" not in operations and "embeddings" in capabilities)
        or (
            "completion" not in operations
            and any(
                cap in capabilities
                for cap in ("text_completion", "tool_calls", "json_mode", "reasoning")
            )
        )
        or not _integer(value["max_output_tokens"], 1, 16384)
        or value["budget_source"] != "signed_postgres_roe"
    ):
        raise CredentialLifecycleDenied("Invalid canonical reviewed route")
    raw = _canonical(value)
    if len(raw) > 2048:
        raise CredentialLifecycleDenied("Bounded reviewed route required")
    return hashlib.sha256(b"ai-osop-provider-review-intent-v1\x00" + raw).hexdigest()


def _matches(data: Dict[str, Any], fields: Mapping[str, Any]) -> bool:
    return all(
        type(data.get(key)) is type(value) and data.get(key) == value
        for key, value in fields.items()
    )


def _reference_digest(r: CredentialReadinessRequest) -> str:
    fields = {
        "engagement_id": r.engagement_id,
        "flow_id": r.flow_id,
        "provider": r.provider,
        "slot": r.slot,
        "policy_review_id": r.policy_review_id,
        "policy_sha256": r.policy_sha256,
        "generation": r.generation,
        "owner": r.owner_sub,
        "flow_revision": r.flow_revision,
        "authorization_version": r.authorization_version,
        "authorization_id": r.authorization_id,
        "authorization_sha256": r.authorization_sha256,
    }
    return hashlib.sha256(
        b"ai-osop-provider-credential-reference-v1\x00" + _canonical(fields)
    ).hexdigest()


def _decode_proof(
    raw: Any,
    kind: str,
    key: Ed25519PublicKey,
    nonce: str,
    now: int,
    max_age: int,
    r: CredentialReadinessRequest,
) -> Dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= 8192:
        raise CredentialLifecycleDenied("Bounded signed current evidence unavailable")
    try:
        envelope = json.loads(
            raw,
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite evidence")),
            parse_float=lambda _: (_ for _ in ()).throw(ValueError("Floating evidence")),
        )
        if type(envelope) is not dict or set(envelope) != {"claims", "signature_b64"}:
            raise ValueError("Unknown evidence envelope")
        claims = envelope["claims"]
        if type(claims) is not dict or len(claims) > 36:
            raise ValueError("Bounded claim object required")
        canonical = _canonical(claims)
        if len(canonical) > 4096:
            raise ValueError("Evidence claims too large")
        signature_text = envelope["signature_b64"]
        if type(signature_text) is not str or len(signature_text) != 88:
            raise ValueError("Invalid evidence signature")
        signature = base64.b64decode(signature_text, validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_text:
            raise ValueError("Noncanonical signature")
        key.verify(signature, _DOMAIN + kind.encode("ascii") + b"\x00" + canonical)
        if not _matches(
            claims,
            {
                "nonce": nonce,
                "engagement_id": r.engagement_id,
                "flow_id": r.flow_id,
            },
        ):
            raise ValueError("Mismatched proof challenge and tenant Flow")
        issued, expires = claims.get("issued_at"), claims.get("expires_at")
        if (
            not _integer(issued, 1, 4102444800)
            or not _integer(expires, 1, 4102444800)
            or issued > now + 2
            or now - issued > max_age
            or expires <= now
            or expires > issued + max_age
        ):
            raise ValueError("Expired or future-dated service observation")
        return claims
    except (
        ValueError,
        TypeError,
        KeyError,
        InvalidSignature,
        OverflowError,
        UnicodeError,
        RecursionError,
    ) as exc:
        raise CredentialLifecycleDenied(
            "Signed current " + kind + " authority observation untrusted"
        ) from exc


def _check_claims(
    r: CredentialReadinessRequest, proofs: Dict[str, Dict[str, Any]], now: int
) -> None:
    profile = proofs["profile"]
    binding = {
        "ref_id": r.ref_id,
        "reference_sha256": r.reference_sha256,
        "reference_revision": r.reference_revision,
        "generation": r.generation,
        "provider": r.provider,
        "slot": r.slot,
        "owner_sub": r.owner_sub,
        "policy_review_id": r.policy_review_id,
        "policy_sha256": r.policy_sha256,
        "flow_revision": r.flow_revision,
        "authorization_version": r.authorization_version,
        "authorization_id": r.authorization_id,
        "authorization_sha256": r.authorization_sha256,
        "status": "approved",
        "revoked": False,
    }
    if (
        not _matches(profile, {**binding, "senior_active": True})
        or not _id(profile.get("senior_sub"), _ID)
        or not _integer(profile.get("profile_valid_until"), now + 1, 4102444800)
    ):
        raise CredentialLifecycleDenied("Current approved profile version unavailable")
    if profile["senior_sub"] == r.owner_sub or not hmac.compare_digest(
        _reference_digest(r), r.reference_sha256
    ):
        raise CredentialLifecycleDenied("Independent reference review or integrity unavailable")

    flow = proofs["flow"]
    if not _matches(
        flow,
        {
            "owner_sub": r.owner_sub,
            "flow_revision": r.flow_revision,
            "authorization_version": r.authorization_version,
            "authorization_id": r.authorization_id,
            "authorization_sha256": r.authorization_sha256,
            "status": "running",
            "revoked": False,
        },
    ):
        raise CredentialLifecycleDenied("Current signed running Flow unavailable")

    principal = proofs["principal"]
    if (
        not _matches(principal, {"actor_sub": r.actor_sub, "disabled": False})
        or principal.get("role") not in ("operator", "senior_operator")
        or not _integer(principal.get("bearer_expires_at"), now + 1, 4102444800)
        or r.actor_sub != r.owner_sub
    ):
        raise CredentialLifecycleDenied("Current owner operator or role unavailable")

    policy = proofs["policy"]
    if (
        not _matches(
            policy,
            {
                "review_id": r.policy_review_id,
                "policy_sha256": r.policy_sha256,
                "creator_sub": r.owner_sub,
                "provider": r.provider,
                "status": "approved",
                "revoked": False,
                "senior_active": True,
            },
        )
        or not _id(policy.get("senior_sub"), _ID)
        or policy["senior_sub"] == r.owner_sub
    ):
        raise CredentialLifecycleDenied("Current independent provider intent unavailable")
    reviewed_policy = policy.get("policy")
    digest = _policy_digest(reviewed_policy)
    if (
        not hmac.compare_digest(digest, r.policy_sha256)
        or reviewed_policy["provider"] != r.provider
        or reviewed_policy["model"] != r.model
        or r.operation not in reviewed_policy["operations"]
        or r.agent_role not in reviewed_policy["allowed_roles"]
        or reviewed_policy["budget_source"] != "signed_postgres_roe"
    ):
        raise CredentialLifecycleDenied("Approved role, model or budget policy changed")

    vault = proofs["vault"]
    if (
        not _matches(
            vault,
            {
                "ref_id": r.ref_id,
                "reference_revision": r.reference_revision,
                "generation": r.generation,
                "provider": r.provider,
                "slot": r.slot,
                "credential_material": "present",
                "vault_state": "active",
            },
        )
        or not _id(vault.get("credential_version_sha256"), _SHA)
        or not _integer(vault.get("credential_valid_until"), now + 1, 4102444800)
        or vault.get("credential_version_sha256")
        in (r.reference_sha256, r.policy_sha256, r.authorization_sha256, "0" * 64)
    ):
        raise CredentialLifecycleDenied("External vault credential presence unverified")
    # Rotation must attest different live material and that the *external
    # vault* has disabled its prior credential version. Provider invalidation
    # remains unverified without provider-side support.
    if r.generation > 1 and (
        not _matches(
            vault,
            {
                "previous_generation": r.generation - 1,
                "previous_vault_state": "revoked",
            },
        )
        or not _id(vault.get("previous_credential_version_sha256"), _SHA)
        or hmac.compare_digest(
            vault["credential_version_sha256"], vault["previous_credential_version_sha256"]
        )
    ):
        raise CredentialLifecycleDenied("External vault rotation completion unverified")
    if r.generation == 1 and not _matches(
        vault, {"previous_generation": 0, "previous_vault_state": "none"}
    ):
        raise CredentialLifecycleDenied("Initial credential provenance inconsistent")

    budget = proofs["budget"]
    if (
        not _matches(
            budget,
            {
                "task_id": r.task_id,
                "agent_role": r.agent_role,
                "model": r.model,
                "operation": r.operation,
                "budget_source": "signed_postgres_roe",
                "budget_state": "within_current_limit",
                "authorization_version": r.authorization_version,
                "authorization_sha256": r.authorization_sha256,
                "flow_revision": r.flow_revision,
            },
        )
        or not _integer(budget.get("available_micro_usd"), 0, 10000000000)
        or budget["available_micro_usd"] < r.cost_request_micro_usd
    ):
        raise CredentialLifecycleDenied("Current signed PostgreSQL budget unavailable")


class CredentialLifecycleVerifier:
    """Evaluate signed current observations from six separately pinned services.

    Construct only from trusted host configuration and authenticated service
    readers; never allow caller-supplied public keys or readers at an API route.
    The decision is an advisory operator-readiness observation and cannot
    authorize vault access, provider calls or model spending.
    """

    def __init__(
        self,
        *,
        public_keys: Mapping[str, Ed25519PublicKey],
        readers: Mapping[str, Reader],
        max_age_seconds: int = 15,
        timeout_seconds: float = 2.0,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        if (
            type(public_keys) is not dict
            or type(readers) is not dict
            or set(public_keys) != set(_KINDS)
            or set(readers) != set(_KINDS)
            or not _integer(max_age_seconds, 1, 30)
            or type(timeout_seconds) not in (int, float)
            or not 0.1 <= timeout_seconds <= 5.0
            or any(not isinstance(k, Ed25519PublicKey) for k in public_keys.values())
            or any(not callable(reader) for reader in readers.values())
            or (clock is not None and not callable(clock))
        ):
            raise CredentialLifecycleDenied("Six independent trusted service authorities required")
        fingerprints = [
            key.public_bytes(Encoding.Raw, PublicFormat.Raw) for key in public_keys.values()
        ]
        if len(set(fingerprints)) != len(_KINDS):
            raise CredentialLifecycleDenied("Authority signing identities must be distinct")
        self._keys = dict(public_keys)
        self._readers = dict(readers)
        self._max_age = max_age_seconds
        self._timeout = float(timeout_seconds)
        self._clock = clock or (lambda: int(time.time()))

    async def assess(self, request: CredentialReadinessRequest) -> CredentialReadinessDecision:
        _require_request(request)
        nonce = secrets.token_hex(16)
        now = self._clock()
        if not _integer(now, 1, 4102444800):
            raise CredentialLifecycleDenied("Trusted current time unavailable")
        proofs: Dict[str, Dict[str, Any]] = {}
        for kind in _KINDS:
            try:
                body = await asyncio.wait_for(
                    self._readers[kind](request, nonce), timeout=self._timeout
                )
                proofs[kind] = _decode_proof(
                    body, kind, self._keys[kind], nonce, self._clock(), self._max_age, request
                )
            except CredentialLifecycleDenied:
                raise
            except Exception as exc:
                raise CredentialLifecycleDenied(
                    "Current " + kind + " authority unavailable"
                ) from exc
        _check_claims(request, proofs, self._clock())
        if any(p["expires_at"] <= self._clock() for p in proofs.values()):
            raise CredentialLifecycleDenied("Readiness evidence expired during verification")
        return CredentialReadinessDecision(
            ref_id=request.ref_id,
            reference_revision=request.reference_revision,
            generation=request.generation,
            purpose=request.purpose,
            proof_expires_at=min(p["expires_at"] for p in proofs.values()),
        )


# These are independently host-provisioned **read-only** witness services, not
# a provider/vault secret API. Production must enroll their TLS trust anchors
# and two different Ed25519 signing roots out of band. The full six-authority
# verifier above still supplies the other five current observations.
_VAULT_MATERIAL_PATH = "/v1/provider-credentials/material-readback"
_VAULT_REVOCATION_PATH = "/v1/provider-credentials/revocation-readback"
_HOSTNAME = re.compile(
    r"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_MAX_HOST_PROOF_BYTES = 8192
_HOST_COMMON_PROOF_FIELDS = frozenset((
    "nonce", "engagement_id", "flow_id", "issued_at", "expires_at",
    "ref_id", "reference_sha256", "reference_revision", "generation",
    "provider", "slot", "policy_sha256", "flow_revision",
    "authorization_version", "authorization_sha256",
))
_HOST_MATERIAL_FIELDS = frozenset((
    "material_source", "credential_material", "vault_state",
    "credential_version_sha256", "credential_valid_until",
    "previous_generation", "previous_vault_state",
    "vault_revision", "observed_revocation_revision",
))
_HOST_REVOCATION_FIELDS = frozenset((
    "revocation_source", "credential_revoked", "credential_version_sha256",
    "vault_revision", "revocation_revision", "previous_generation",
    "previous_credential_revoked",
))


@dataclass(frozen=True)
class HostVaultReadbackChannel:
    """Explicit host-side HTTPS trust and separate read-only service identity.

    The service bearer authenticates *this host* to its witness; it is never a
    provider API key or a vault material handle. All fields are host-only
    configuration, never a request-body override. Repr excludes auth material.
    """

    url: str
    ca_pem: bytes = field(repr=False)
    service_bearer: str = field(repr=False)
    _tls: ssl.SSLContext = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            parts = urlsplit(self.url)
            if (
                type(self.url) is not str
                or len(self.url) > 350
                or parts.scheme != "https"
                or parts.port not in (None, 443)
                or not _id(parts.hostname, _HOSTNAME)
                or parts.username is not None
                or parts.password is not None
                or parts.netloc not in (parts.hostname, parts.hostname + ":443")
                or parts.path not in (_VAULT_MATERIAL_PATH, _VAULT_REVOCATION_PATH)
                or bool(parts.query or parts.fragment)
                or urlunsplit(parts) != self.url
                or any(c.isspace() for c in self.url)
                or "%" in self.url
                or "\\" in self.url
                or type(self.ca_pem) is not bytes
                or not 400 <= len(self.ca_pem) <= 32768
                or b"-----BEGIN CERTIFICATE-----" not in self.ca_pem
                or type(self.service_bearer) is not str
                or not 24 <= len(self.service_bearer) <= 256
                or any(ord(c) < 33 or ord(c) > 126 for c in self.service_bearer)
            ):
                raise ValueError("Unsafe host-only vault trust enrollment")
            try:
                ipaddress.ip_address(parts.hostname)
            except ValueError:
                pass
            else:
                raise ValueError("Literal IP host denied")
        except ValueError:
            raise CredentialLifecycleDenied(
                "Pinned HTTPS host vault readback configuration required"
            ) from None
        except (TypeError, AttributeError):
            raise CredentialLifecycleDenied(
                "Pinned HTTPS host vault readback configuration required"
            ) from None
        try:
            context = ssl.create_default_context(cadata=self.ca_pem.decode("ascii"))
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            object.__setattr__(self, "_tls", context)
        except (ValueError, UnicodeError, ssl.SSLError, OSError):
            raise CredentialLifecycleDenied(
                "Explicit enrolled vault TLS CA unavailable"
            ) from None


class HostVaultRuntimeReadinessAdapter:
    """Join independent signed host-vault material and revocation witnesses.

    This opt-in, *unmounted* adapter requires five other independent signed
    authorities and two extra, separately enrolled vault material/revocation
    roots. HTTP GET, provider secrets, provider calls, route activation and
    spending are all out of scope. Every call is a fresh read-only POST with
    bounded metadata and challenge, and neither witness may supply the other's
    identity. Positive results remain advisory.

    Vault revisions and revocation epochs must be *global monotonic sequences*
    maintained by those host services; trusted host floors and a local
    high-water mark prevent observed rollback inside this process. Cross-
    process rollback resistance needs its own shared durable high-water source.
    """

    def __init__(
        self,
        *,
        other_public_keys: Mapping[str, Ed25519PublicKey],
        other_readers: Mapping[str, Reader],
        vault_public_key: Ed25519PublicKey,
        revocation_public_key: Ed25519PublicKey,
        material_channel: HostVaultReadbackChannel,
        revocation_channel: HostVaultReadbackChannel,
        minimum_vault_revision: int,
        minimum_revocation_revision: int,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        other = set(_KINDS) - {"vault"}
        if (
            type(other_public_keys) is not dict
            or set(other_public_keys) != other
            or type(other_readers) is not dict
            or set(other_readers) != other
            or not isinstance(vault_public_key, Ed25519PublicKey)
            or not isinstance(revocation_public_key, Ed25519PublicKey)
            or not isinstance(material_channel, HostVaultReadbackChannel)
            or not isinstance(revocation_channel, HostVaultReadbackChannel)
            or urlsplit(material_channel.url).path != _VAULT_MATERIAL_PATH
            or urlsplit(revocation_channel.url).path != _VAULT_REVOCATION_PATH
            or urlsplit(material_channel.url).hostname
            == urlsplit(revocation_channel.url).hostname
            or material_channel.service_bearer == revocation_channel.service_bearer
            or not _integer(minimum_vault_revision, 1)
            or not _integer(minimum_revocation_revision, 1)
            or (transport is not None and not isinstance(transport, httpx.AsyncBaseTransport))
        ):
            raise CredentialLifecycleDenied(
                "Distinct enrolled material and revocation host authorities required"
            )
        enrolled = dict(other_public_keys)
        enrolled["vault"] = vault_public_key
        enrolled["vault_revocation"] = revocation_public_key
        key_fingerprints = [
            key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            for key in enrolled.values()
            if isinstance(key, Ed25519PublicKey)
        ]
        if len(key_fingerprints) != 7 or len(set(key_fingerprints)) != 7:
            raise CredentialLifecycleDenied("Seven distinct pinned evidence roots required")
        self._material = material_channel
        self._revocation = revocation_channel
        self._revocation_key = revocation_public_key
        self._transport = transport
        self._clock = clock or (lambda: int(time.time()))
        self._vault_floor = minimum_vault_revision
        self._revocation_floor = minimum_revocation_revision
        self._current_pair: Optional[tuple[int, int, int]] = None
        self._lock = asyncio.Lock()
        self._verifier = CredentialLifecycleVerifier(
            public_keys={k: enrolled[k] for k in _KINDS},
            readers={**other_readers, "vault": self._read_current_host_vault},
            max_age_seconds=15,
            timeout_seconds=5.0,
            clock=self._clock,
        )

    async def _read_channel(
        self,
        channel: HostVaultReadbackChannel,
        request: CredentialReadinessRequest,
        nonce: str,
    ) -> bytes:
        payload = _canonical(
            {
                "nonce": nonce,
                "engagement_id": request.engagement_id,
                "flow_id": request.flow_id,
                "flow_revision": request.flow_revision,
                "authorization_version": request.authorization_version,
                "authorization_sha256": request.authorization_sha256,
                "ref_id": request.ref_id,
                "reference_sha256": request.reference_sha256,
                "reference_revision": request.reference_revision,
                "generation": request.generation,
                "provider": request.provider,
                "slot": request.slot,
                "policy_sha256": request.policy_sha256,
            }
        )
        if len(payload) > 2048:
            raise CredentialLifecycleDenied("Bounded vault authority request required")
        try:
            async with httpx.AsyncClient(
                verify=channel._tls,
                follow_redirects=False,
                trust_env=False,
                timeout=httpx.Timeout(1.5),
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
                transport=self._transport,
            ) as client:
                async with client.stream(
                    "POST",
                    channel.url,
                    content=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Authorization": "Bearer " + channel.service_bearer,
                        "Cache-Control": "no-store",
                    },
                ) as response:
                    if (
                        response.status_code != 200
                        or response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                        != "application/json"
                    ):
                        raise ValueError("Invalid readback status/content type")
                    length = response.headers.get("Content-Length")
                    if length is not None and (
                        not length.isdigit() or int(length) > _MAX_HOST_PROOF_BYTES
                    ):
                        raise ValueError("Invalid content length")
                    body = bytearray()
                    async for fragment in response.aiter_bytes():
                        if len(body) + len(fragment) > _MAX_HOST_PROOF_BYTES:
                            raise ValueError("Oversized readback")
                        body.extend(fragment)
                    if not body:
                        raise ValueError("Missing signed readback")
                    return bytes(body)
        except Exception:
            # Never expose URL, host-only service bearer, TLS diagnostics,
            # provider hints, opaque hashes or raw witness response.
            raise CredentialLifecycleDenied("Independent host vault readback unavailable") from None

    async def _read_current_host_vault(
        self, request: CredentialReadinessRequest, nonce: str
    ) -> bytes:
        material = await self._read_channel(self._material, request, nonce)
        vault = _decode_proof(
            material, "vault", self._verifier._keys["vault"],
            nonce, self._clock(), 15, request,
        )
        revocation_raw = await self._read_channel(self._revocation, request, nonce)
        revoked = _decode_proof(
            revocation_raw, "vault_revocation", self._revocation_key,
            nonce, self._clock(), 15, request,
        )
        # Vault metadata is a narrow nonsecret DTO. Reject unexpected keys,
        # including inadvertently copied key material or secret handles, even
        # if a compromised host service signs the additional fields.
        previous_field = (
            {"previous_credential_version_sha256"} if request.generation > 1 else set()
        )
        if (
            set(vault) != _HOST_COMMON_PROOF_FIELDS | _HOST_MATERIAL_FIELDS | previous_field
            or set(revoked) != (
                _HOST_COMMON_PROOF_FIELDS | _HOST_REVOCATION_FIELDS | previous_field
            )
        ):
            raise CredentialLifecycleDenied("Host vault readback contained unapproved metadata")
        shared = {
            "ref_id": request.ref_id,
            "reference_sha256": request.reference_sha256,
            "reference_revision": request.reference_revision,
            "generation": request.generation,
            "provider": request.provider,
            "slot": request.slot,
            "policy_sha256": request.policy_sha256,
            "flow_revision": request.flow_revision,
            "authorization_version": request.authorization_version,
            "authorization_sha256": request.authorization_sha256,
        }
        if (
            not _matches(vault, shared)
            or not _matches(revoked, shared)
            or not _matches(vault, {
                "material_source": "vault_material_store_current",
                "credential_material": "present", "vault_state": "active",
            })
            or not _matches(revoked, {
                "revocation_source": "independent_current_revocation_ledger",
                "credential_revoked": False,
            })
            or not _id(vault.get("credential_version_sha256"), _SHA)
            or not _matches(revoked, {
                "credential_version_sha256": vault["credential_version_sha256"]
            })
            or not _integer(vault.get("vault_revision"), 1)
            or not _integer(vault.get("observed_revocation_revision"), 1)
            or not _integer(revoked.get("vault_revision"), 1)
            or not _integer(revoked.get("revocation_revision"), 1)
            or revoked["vault_revision"] != vault["vault_revision"]
            or revoked["revocation_revision"] < vault["observed_revocation_revision"]
            or vault["vault_revision"] < self._vault_floor
            or revoked["revocation_revision"] < self._revocation_floor
        ):
            raise CredentialLifecycleDenied(
                "Independent current vault revision/revocation join unavailable"
            )
        if request.generation > 1:
            if (
                not _matches(revoked, {
                    "previous_generation": request.generation - 1,
                    "previous_credential_revoked": True,
                    "previous_credential_version_sha256":
                        vault.get("previous_credential_version_sha256"),
                })
                or not _id(revoked.get("previous_credential_version_sha256"), _SHA)
            ):
                raise CredentialLifecycleDenied(
                    "Independent vault previous-version revocation unavailable"
                )
        elif not _matches(revoked, {
            "previous_generation": 0, "previous_credential_revoked": False,
        }):
            raise CredentialLifecycleDenied("Initial vault revision mismatch")
        # Only the serialized assess call may commit a high-water mark after
        # all other (five) independently signed authorities have passed.
        self._current_pair = (
            vault["vault_revision"],
            revoked["revocation_revision"],
            revoked["expires_at"],
        )
        return material

    async def assess(
        self, request: CredentialReadinessRequest
    ) -> CredentialReadinessDecision:
        _require_request(request)
        async with self._lock:
            self._current_pair = None
            try:
                decision = await self._verifier.assess(request)
                current = self._current_pair
                if current is None or current[2] <= self._clock():
                    raise CredentialLifecycleDenied("Current host revocation proof unavailable")
                self._vault_floor = max(self._vault_floor, current[0])
                self._revocation_floor = max(self._revocation_floor, current[1])
                return CredentialReadinessDecision(
                    ref_id=decision.ref_id,
                    reference_revision=decision.reference_revision,
                    generation=decision.generation,
                    purpose=decision.purpose,
                    proof_expires_at=min(decision.proof_expires_at, current[2]),
                )
            finally:
                self._current_pair = None
