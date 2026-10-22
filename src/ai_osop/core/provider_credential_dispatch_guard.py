"""Unwired, injectable, fail-closed pre-send guard for LiteLLM dispatch.

Real dispatch currently uses a host environment credential; the nonsecret
profile and approved provider policy are not wired to it. This guard never
reads, receives, logs or returns that credential, does not call a provider and
does not reserve model budget. It verifies *separately enrolled* current signed
host observations of vault material/version, revocation, deployed key binding
and the already-committed ModelUsageLedger reservation. The existing seven-key
HostVaultRuntimeReadinessAdapter remains an independent prerequisite.

Only the owner of the actual LiteLLM dispatch boundary may later install and
invoke this host-only guard. Never instantiate using public API inputs, mock
proofs, symbolic references or keys discovered from provider responses.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.core.provider_credential_lifecycle import (
    CredentialReadinessRequest,
    CredentialLifecycleDenied,
    HostVaultRuntimeReadinessAdapter,
)


class ProviderDispatchDenied(Exception):
    """Dispatch gate cannot establish independently current signed authority."""


_KINDS = ("vault_material", "vault_revocation", "route_key", "reservation")
_DOMAIN = b"ai-osop-provider-dispatch-current-v1\x00"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_CALL = re.compile(r"call-[A-Za-z0-9_-]{1,59}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_MAX_PROOF_BYTES = 8192
_MAX_LOCAL_OUTSTANDING = 10000

# The public values below are opaque version/route fingerprints, never a hash
# of an API key. A deployed key authority must derive a safe key commitment
# *inside its isolated protected service*, and attest its mapping to the
# vault's material-version ID without returning an exportable key fingerprint.
_SHARED = frozenset({
    "nonce", "engagement_id", "flow_id", "flow_revision",
    "authorization_id", "authorization_version", "authorization_sha256",
    "owner_sub", "actor_sub", "task_id", "agent_role",
    "ref_id", "reference_sha256", "reference_revision", "generation",
    "provider", "slot", "policy_review_id", "policy_sha256",
    "model", "operation", "cost_request_micro_usd",
    "route_policy_sha256", "route_deployment_sha256", "call_id",
    "issued_at", "expires_at",
})
_FIELDS = {
    "vault_material": frozenset({
        "credential_version_sha256", "vault_revision",
        "observed_revocation_revision", "material_state",
    }),
    "vault_revocation": frozenset({
        "credential_version_sha256", "vault_revision",
        "revocation_revision", "current_revoked",
        "previous_generation", "previous_revoked",
    }),
    "route_key": frozenset({
        "credential_version_sha256", "vault_revision",
        "revocation_revision", "key_binding_state",
        "runtime_route_generation",
    }),
    "reservation": frozenset({
        "reservation_status", "usage_revision", "lease_generation",
        "reserved_micro_usd", "ledger_issuer",
    }),
}


def _strict_pairs(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate proof field")
        result[key] = value
    return result


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _positive(value: Any, minimum: int = 1, maximum: int = 2147483647) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _exact(got: Mapping[str, Any], wanted: Mapping[str, Any]) -> bool:
    return all(type(got.get(k)) is type(v) and got.get(k) == v for k, v in wanted.items())


@dataclass(frozen=True)
class DispatchBinding:
    """Host-resolved *nonsecret* identity from current Task, route and ROE.

    Caller fields are never themselves authoritative: independent current
    signed services must bind all fields. Host code must resolve these from
    trusted, freshly checked runtime context, not a client-supplied object.
    """

    readiness_request: CredentialReadinessRequest
    route_policy_sha256: str
    route_deployment_sha256: str
    call_id: str


@dataclass(frozen=True)
class DispatchPermit:
    """One-shot in-process proof handle, not a secret or provider key."""

    call_id: str
    route_policy_sha256: str
    route_deployment_sha256: str
    proof_expires_at: int
    _token: str = field(repr=False)


ProofReader = Callable[[DispatchBinding, str], Awaitable[bytes]]


class ProviderCredentialDispatchGuard:
    """Read-only post-reservation, pre-LiteLLM authority barrier.

    The host must already have a genuine PG ModelUsageLedger.reserve call ID.
    The guard verifies that reservation with a separately pinned ledger signer;
    callers cannot self-assert reserved=True. It independently verifies a
    deployed-runtime key/version binding with a host service which actually
    checks the outbound route, not the symbolic profile. Each proof is
    separately signed over the exact same nonce and full authority tuple.

    Completion of authorize_reserved alone DOES NOT call a provider. PRIME must
    consume_for_send immediately before the *single* send. After consumption
    or any ambiguity, the call ID is burned: no fallback/retry without a
    newly committed durable reservation and authoritative reconciliation.
    """

    def __init__(
        self,
        *,
        readiness: HostVaultRuntimeReadinessAdapter,
        signer_keys: Mapping[str, Ed25519PublicKey],
        readers: Mapping[str, ProofReader],
        max_age_seconds: int = 10,
        timeout_seconds: float = 2.0,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        if (
            not isinstance(readiness, HostVaultRuntimeReadinessAdapter)
            or type(signer_keys) is not dict
            or type(readers) is not dict
            or set(signer_keys) != set(_KINDS)
            or set(readers) != set(_KINDS)
            or any(not isinstance(k, Ed25519PublicKey) for k in signer_keys.values())
            or any(not callable(reader) for reader in readers.values())
            or not _positive(max_age_seconds, 1, 20)
            or type(timeout_seconds) not in (float, int)
            or not 0.1 <= timeout_seconds <= 5.0
            or (clock is not None and not callable(clock))
        ):
            raise ProviderDispatchDenied("Host-enrolled independent dispatch roots unavailable")
        keys = list(signer_keys.values())
        # Signing roots for the extra four observations MUST NOT be able to
        # mint the existing six readiness proofs or independent vault revocation.
        prior_keys = list(readiness._verifier._keys.values()) + [readiness._revocation_key]
        fingerprints = [
            key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            for key in keys + prior_keys
        ]
        if len(fingerprints) != 11 or len(set(fingerprints)) != 11:
            raise ProviderDispatchDenied("Eleven distinct enrolled authority roots required")
        self._readiness = readiness
        self._keys = dict(signer_keys)
        self._readers = dict(readers)
        self._max_age = max_age_seconds
        self._timeout = float(timeout_seconds)
        self._clock = clock or (lambda: int(time.time()))
        self._burned: set[str] = set()
        self._issued: dict[str, DispatchPermit] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _shared(binding: DispatchBinding, nonce: str) -> Dict[str, Any]:
        r = binding.readiness_request
        return {
            "nonce": nonce,
            "engagement_id": r.engagement_id,
            "flow_id": r.flow_id,
            "flow_revision": r.flow_revision,
            "authorization_id": r.authorization_id,
            "authorization_version": r.authorization_version,
            "authorization_sha256": r.authorization_sha256,
            "owner_sub": r.owner_sub,
            "actor_sub": r.actor_sub,
            "task_id": r.task_id,
            "agent_role": r.agent_role,
            "ref_id": r.ref_id,
            "reference_sha256": r.reference_sha256,
            "reference_revision": r.reference_revision,
            "generation": r.generation,
            "provider": r.provider,
            "slot": r.slot,
            "policy_review_id": r.policy_review_id,
            "policy_sha256": r.policy_sha256,
            "model": r.model,
            "operation": r.operation,
            "cost_request_micro_usd": r.cost_request_micro_usd,
            "route_policy_sha256": binding.route_policy_sha256,
            "route_deployment_sha256": binding.route_deployment_sha256,
            "call_id": binding.call_id,
        }

    def _read_signed(
        self,
        raw: Any,
        *,
        kind: str,
        nonce: str,
        shared: Mapping[str, Any],
    ) -> Dict[str, Any]:
        try:
            if type(raw) is not bytes or not 0 < len(raw) <= _MAX_PROOF_BYTES:
                raise ValueError("Missing bounded signed witness")
            doc = json.loads(
                raw, object_pairs_hook=_strict_pairs,
                parse_constant=lambda *_: (_ for _ in ()).throw(ValueError()),
                parse_float=lambda *_: (_ for _ in ()).throw(ValueError()),
            )
            if type(doc) is not dict or set(doc) != {"claims", "signature_b64"}:
                raise ValueError("Ambiguous witness envelope")
            claims = doc["claims"]
            if type(claims) is not dict or set(claims) != _SHARED | _FIELDS[kind]:
                raise ValueError("Unknown or missing witness fields")
            stamp = claims["issued_at"]
            expiry = claims["expires_at"]
            now = self._clock()
            if (
                not _positive(now, 1, 4102444800)
                or not _positive(stamp, 1, 4102444800)
                or not _positive(expiry, 1, 4102444800)
                or stamp > now + 1
                or now - stamp > self._max_age
                or expiry <= now
                or expiry > stamp + self._max_age
                or not _exact(claims, shared)
            ):
                raise ValueError("Current authority tuple mismatch")
            sig64 = doc["signature_b64"]
            if type(sig64) is not str or len(sig64) != 88:
                raise ValueError("Invalid signature length")
            signature = base64.b64decode(sig64, validate=True)
            if len(signature) != 64 or base64.b64encode(signature).decode() != sig64:
                raise ValueError("Noncanonical signature")
            body = _canonical(claims)
            if len(body) > 4096:
                raise ValueError("Oversized signed witness claims")
            self._keys[kind].verify(
                signature, _DOMAIN + kind.encode("ascii") + b"\x00" + body
            )
            return claims
        except (ValueError, TypeError, KeyError, InvalidSignature, UnicodeError,
                RecursionError, OverflowError) as exc:
            raise ProviderDispatchDenied(
                "Independent current signed dispatch witness unavailable"
            ) from None

    async def authorize_reserved(self, binding: DispatchBinding) -> DispatchPermit:
        """Require complete signed admission; burn IDs even on lost ACK.

        In a production installation the ledger's own atomic PG CAS must fence
        the call ID across replicas; this local burn is deliberately not a
        distributed replay guarantee. This guard never reserves or cancels PG
        entries and intentionally performs *no paid provider I/O*.
        """
        if (
            not isinstance(binding, DispatchBinding)
            or not isinstance(binding.readiness_request, CredentialReadinessRequest)
            or type(binding.call_id) is not str
            or _CALL.fullmatch(binding.call_id) is None
            or type(binding.route_policy_sha256) is not str
            or _HEX64.fullmatch(binding.route_policy_sha256) is None
            or type(binding.route_deployment_sha256) is not str
            or _HEX64.fullmatch(binding.route_deployment_sha256) is None
        ):
            raise ProviderDispatchDenied("Current explicit provider/Task/reservation binding required")
        async with self._lock:
            if binding.call_id in self._burned:
                raise ProviderDispatchDenied("Dispatch reservation is consumed or uncertain")
            if len(self._burned) >= _MAX_LOCAL_OUTSTANDING:
                # Never evict used call IDs: doing so would silently re-enable
                # a replay. Prime must use a durable shared replay fence.
                raise ProviderDispatchDenied("Local dispatch replay fence capacity exhausted")
            self._burned.add(binding.call_id)
            try:
                ready = await asyncio.wait_for(
                    self._readiness.assess(binding.readiness_request),
                    timeout=self._timeout * 7,
                )
                r = binding.readiness_request
                if (
                    type(ready.proof_expires_at) is not int
                    or ready.proof_expires_at <= self._clock()
                    or ready.ref_id != r.ref_id
                    or ready.reference_revision != r.reference_revision
                    or ready.generation != r.generation
                    or ready.purpose != r.purpose
                    or ready.independently_attested_vault_presence is not True
                    or ready.rotation_readiness_verified is not True
                    or ready.dispatch_authorized is not False
                    or ready.budget_reserved is not False
                    or ready.provider_contacted is not False
                    or ready.provider_accepts_credential_verified is not False
                ):
                    raise ProviderDispatchDenied("Vault advisory observation is not current")
                nonce = secrets.token_hex(16)
                shared = self._shared(binding, nonce)
                proofs: Dict[str, Dict[str, Any]] = {}
                for kind in _KINDS:
                    try:
                        raw = await asyncio.wait_for(
                            self._readers[kind](binding, nonce),
                            timeout=self._timeout,
                        )
                    except Exception:
                        raise ProviderDispatchDenied(
                            "Independent dispatch authority unavailable"
                        ) from None
                    proofs[kind] = self._read_signed(
                        raw, kind=kind, nonce=nonce, shared=shared
                    )
                material = proofs["vault_material"]
                revocation = proofs["vault_revocation"]
                key = proofs["route_key"]
                reserve = proofs["reservation"]
                version = material.get("credential_version_sha256")
                vr = material.get("vault_revision")
                rr = revocation.get("revocation_revision")
                if (
                    type(version) is not str or _HEX64.fullmatch(version) is None
                    or version in (r.reference_sha256, r.authorization_sha256, r.policy_sha256,
                                   binding.route_policy_sha256, binding.route_deployment_sha256,
                                   "0" * 64)
                    or not _positive(vr)
                    or not _positive(rr)
                    or not _positive(material.get("observed_revocation_revision"))
                    or material["observed_revocation_revision"] > rr
                    # Existing signed seven-root vault readiness recorded
                    # globally monotonic source floors in this process. The
                    # independent post-reserve material/revocation join must
                    # not silently read back older source revisions.
                    or vr < self._readiness._vault_floor
                    or rr < self._readiness._revocation_floor
                    or not _exact(material, {"material_state": "active"})
                    or not _exact(revocation, {
                        "credential_version_sha256": version,
                        "vault_revision": vr, "current_revoked": False,
                        "previous_generation": r.generation - 1,
                        "previous_revoked": r.generation > 1,
                    })
                    or not _exact(key, {
                        "credential_version_sha256": version,
                        "vault_revision": vr,
                        "revocation_revision": rr,
                        "key_binding_state": "live_runtime_credential_version_matches_vault",
                        "runtime_route_generation": r.generation,
                    })
                    or not _exact(reserve, {
                        "reservation_status": "committed",
                        "ledger_issuer": "signed_postgres_model_usage",
                    })
                    or not _positive(reserve.get("usage_revision"))
                    or not _positive(reserve.get("lease_generation"))
                    or not _positive(reserve.get("reserved_micro_usd"), r.cost_request_micro_usd,
                                     10000000000)
                ):
                    raise ProviderDispatchDenied(
                        "Current material/revocation/route key/budget reservation join unavailable"
                    )
                expiry = min(
                    ready.proof_expires_at, *[p["expires_at"] for p in proofs.values()]
                )
                if expiry <= self._clock():
                    raise ProviderDispatchDenied("Dispatch authority expired during join")
                permit = DispatchPermit(
                    call_id=binding.call_id,
                    route_policy_sha256=binding.route_policy_sha256,
                    route_deployment_sha256=binding.route_deployment_sha256,
                    proof_expires_at=expiry,
                    _token=secrets.token_hex(32),
                )
                self._issued[binding.call_id] = permit
                return permit
            except ProviderDispatchDenied:
                raise
            except (CredentialLifecycleDenied, asyncio.TimeoutError) as exc:
                raise ProviderDispatchDenied("Current vault readiness unavailable") from None
            except Exception:
                raise ProviderDispatchDenied(
                    "Dispatch authority unavailable"
                ) from None

    async def consume_for_send(self, permit: DispatchPermit) -> None:
        """One-shot, local permit consumption *before* any attempted send.

        Not an ACK or receipt for an upstream provider request. Unknown send
        outcome must be handled by existing ModelUsageLedger.settle and never
        retried automatically, including when this function already consumed.
        """
        async with self._lock:
            if not isinstance(permit, DispatchPermit):
                raise ProviderDispatchDenied("Issued guard permit required")
            registered = self._issued.pop(permit.call_id, None)
            if (
                registered is None
                or registered is not permit
                or not hmac.compare_digest(permit._token, registered._token)
                or permit.proof_expires_at <= self._clock()
            ):
                raise ProviderDispatchDenied("Dispatch guard permit expired or already consumed")
