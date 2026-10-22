"""Opt-in host-only join for an enrolled vault guard and a durable call fence.

Production has no installed host fence service yet. In that case callers get
the mandatory pending LiteLLM client. This module is a *consumer* of externally
enrolled authorities; it does not create signers, credentials or reservations.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_osop.core import host_vault_guard_admission as host
from ai_osop.core.host_vault_guard_admission import (
    HostVaultAdmissionDenied,
    HostVaultGuardAdmission,
    pending_guarded_client,
)
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.provider_credential_dispatch_guard import (
    DispatchBinding,
    ProviderCredentialDispatchGuard,
)
from ai_osop.core.provider_routing import configured_routes
from ai_osop.memory.model_usage import ModelUsageLedger


_FENCE_ENROLL_DOMAIN = b"ai-osop-host-provider-once-enrollment-v1\x00"
_FENCE_RECEIPT_DOMAIN = b"ai-osop-host-provider-once-receipt-v1\x00"
_FENCE_SCHEMA = "ai-osop-host-provider-once-v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_CALL = re.compile(r"call-[A-Za-z0-9_-]{1,59}\Z")
_EXTRA_ENROLL = frozenset(
    {
        "schema",
        "deployment_id",
        "ledger_public_root_sha256",
        "ledger_readback_service_sha256",
        "shared_revocation_fence_sha256",
        "issued_at",
        "expires_at",
    }
)
_EXTRA_RECEIPT = frozenset(
    {
        "schema",
        "deployment_id",
        "ledger_readback_service_sha256",
        "shared_revocation_fence_sha256",
        "claim_state",
        "usage_revision",
        "vault_revision",
        "revocation_revision",
        "credential_version_sha256",
        "previous_generation",
        "previous_revoked",
        "issued_at",
        "expires_at",
    }
)


class ProviderVaultRuntimeDenied(RuntimeError):
    """Required, independent host authorization is missing or ambiguous."""


def _strict_pairs(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate signed field")
        result[key] = value
    return result


def _parse_signed(raw: bytes, max_bytes: int) -> tuple[Dict[str, Any], bytes]:
    if type(raw) is not bytes or not 0 < len(raw) <= max_bytes:
        raise ValueError("Missing bounded signed host receipt")
    doc = json.loads(
        raw,
        object_pairs_hook=_strict_pairs,
        parse_float=lambda *_: (_ for _ in ()).throw(ValueError()),
        parse_constant=lambda *_: (_ for _ in ()).throw(ValueError()),
    )
    if type(doc) is not dict or set(doc) != {"claims", "signature_b64"}:
        raise ValueError("Ambiguous signed host receipt")
    claims = doc["claims"]
    encoded = doc["signature_b64"]
    if type(claims) is not dict or type(encoded) is not str or len(encoded) != 88:
        raise ValueError("Invalid signed host receipt")
    signature = base64.b64decode(encoded, validate=True)
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
        raise ValueError("Noncanonical signed host receipt")
    return claims, signature


def _public_sha(key: Ed25519PublicKey) -> str:
    return host._hash_public(key)


def _canonical(claims: Mapping[str, Any]) -> bytes:
    return host._canonical(claims)


@dataclass(frozen=True)
class ProviderVaultJoinHealth:
    """Conservative nonsecret operator health. Never a provider-readiness grant."""

    code: str
    next_action: str
    host_enrollment_verified: bool = False
    shared_call_fence_enrolled: bool = False
    provider_dispatch_authorized: bool = False
    provider_contacted: bool = False
    credential_exported: bool = False


ClaimReader = Callable[[DispatchBinding, str], Awaitable[bytes]]


class EnrolledOneUseCallFence:
    """Verify a signed post-CAS claim from a separate host ledger service.

    The service must enforce atomic, persistent claim-once for (deployment,
    call_id) across all replicas, including lost ACKs. This client validates
    the receipt but cannot certify that a remote service implements that CAS.
    Signed fixture receipts are therefore test evidence only.
    """

    def __init__(
        self,
        *,
        admission: HostVaultGuardAdmission,
        ledger_public_key: Ed25519PublicKey,
        ledger_root_sha256: str,
        signed_host_enrollment: bytes,
        claim_reader: ClaimReader,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        if (
            type(admission) is not HostVaultGuardAdmission
            or not isinstance(ledger_public_key, Ed25519PublicKey)
            or type(ledger_root_sha256) is not str
            or not hmac.compare_digest(_public_sha(ledger_public_key), ledger_root_sha256)
            or not callable(claim_reader)
        ):
            raise ProviderVaultRuntimeDenied("Separately enrolled durable ledger unavailable")
        try:
            admission._check_current()
            claims, signature = _parse_signed(signed_host_enrollment, 4096)
            if set(claims) != _EXTRA_ENROLL:
                raise ValueError()
            now = (clock or (lambda: int(time.time())))()
            if (
                claims["schema"] != _FENCE_SCHEMA
                or claims["deployment_id"] != admission._claims["deployment_id"]
                or claims["ledger_public_root_sha256"] != ledger_root_sha256
                or claims["ledger_readback_service_sha256"]
                != admission._claims["ledger_readback_service_sha256"]
                or claims["shared_revocation_fence_sha256"]
                != admission._claims["shared_revocation_fence_sha256"]
                or type(now) is not int
                or type(claims["issued_at"]) is not int
                or type(claims["expires_at"]) is not int
                or not now - 10 <= claims["issued_at"] <= now + 1
                or not now
                < claims["expires_at"]
                <= min(claims["issued_at"] + 15, admission._claims["expires_at"])
                or ledger_root_sha256
                in {
                    host._hash_public(admission._root),
                    *host._existing_authority_roots(admission._guard).values(),
                }
            ):
                raise ValueError()
            admission._root.verify(signature, _FENCE_ENROLL_DOMAIN + _canonical(claims))
        except (
            HostVaultAdmissionDenied,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            UnicodeError,
            OverflowError,
            InvalidSignature,
        ):
            raise ProviderVaultRuntimeDenied(
                "Fresh independent host ledger enrollment unavailable"
            ) from None
        self._admission = admission
        self._key = ledger_public_key
        self._enrollment = claims
        self._reader = claim_reader
        self._clock = clock or (lambda: int(time.time()))
        self._burned: set[str] = set()
        self._lock = asyncio.Lock()

    def _check_current(self) -> None:
        try:
            self._admission._check_current()
            now = self._clock()
            if (
                type(now) is not int
                or now >= self._enrollment["expires_at"]
                or now < self._enrollment["issued_at"] - 1
            ):
                raise ValueError()
        except (HostVaultAdmissionDenied, ValueError, TypeError, KeyError):
            raise ProviderVaultRuntimeDenied("Independent ledger enrollment expired") from None

    async def claim_once(self, binding: DispatchBinding) -> None:
        """Burn locally before requesting a host CAS; UNKNOWN can never retry."""
        from ai_osop.core.provider_credential_dispatch_guard import (
            ProviderCredentialDispatchGuard,
        )

        self._check_current()
        if (
            type(binding) is not DispatchBinding
            or type(binding.call_id) is not str
            or _CALL.fullmatch(binding.call_id) is None
        ):
            raise ProviderVaultRuntimeDenied("Current bounded call identity required")
        async with self._lock:
            if binding.call_id in self._burned or len(self._burned) >= 10000:
                raise ProviderVaultRuntimeDenied("Call ID already claimed or uncertain")
            self._burned.add(binding.call_id)
            nonce = secrets.token_hex(16)
            shared = ProviderCredentialDispatchGuard._shared(binding, nonce)
            try:
                raw = await asyncio.wait_for(self._reader(binding, nonce), timeout=2.0)
                claims, signature = _parse_signed(raw, 8192)
                if set(claims) != set(shared) | _EXTRA_RECEIPT:
                    raise ValueError()
                now = self._clock()
                guard = self._admission._guard
                readiness = guard._readiness
                request = binding.readiness_request
                if (
                    any(
                        type(claims.get(k)) is not type(v) or claims[k] != v
                        for k, v in shared.items()
                    )
                    or claims["schema"] != _FENCE_SCHEMA
                    or claims["deployment_id"] != self._enrollment["deployment_id"]
                    or claims["ledger_readback_service_sha256"]
                    != self._enrollment["ledger_readback_service_sha256"]
                    or claims["shared_revocation_fence_sha256"]
                    != self._enrollment["shared_revocation_fence_sha256"]
                    or claims["claim_state"] != "committed_atomic_one_use"
                    or type(claims["usage_revision"]) is not int
                    or claims["usage_revision"] < 1
                    or type(claims["vault_revision"]) is not int
                    or claims["vault_revision"] < readiness._vault_floor
                    or type(claims["revocation_revision"]) is not int
                    or claims["revocation_revision"] < readiness._revocation_floor
                    or type(claims["credential_version_sha256"]) is not str
                    or _HEX.fullmatch(claims["credential_version_sha256"]) is None
                    or claims["credential_version_sha256"] == "0" * 64
                    or type(claims["previous_generation"]) is not int
                    or claims["previous_generation"] != request.generation - 1
                    or type(claims["previous_revoked"]) is not bool
                    or claims["previous_revoked"] is not (request.generation > 1)
                    or type(claims["issued_at"]) is not int
                    or type(claims["expires_at"]) is not int
                    or not now - 5 <= claims["issued_at"] <= now + 1
                    or not now
                    < claims["expires_at"]
                    <= min(claims["issued_at"] + 5, self._enrollment["expires_at"])
                ):
                    raise ValueError()
                body = _canonical(claims)
                if len(body) > 4096:
                    raise ValueError()
                self._key.verify(signature, _FENCE_RECEIPT_DOMAIN + body)
                # Require the one-use CAS receipt to agree with separate
                # CURRENT independently signed vault, revocation and deployed
                # runtime-key witnesses. This check does not replace the
                # guard's fresh post-binding full eleven-root authorization.
                current: Dict[str, Dict[str, Any]] = {}
                for kind in ("vault_material", "vault_revocation", "route_key"):
                    raw_current = await asyncio.wait_for(
                        guard._readers[kind](binding, nonce), timeout=2.0
                    )
                    current[kind] = guard._read_signed(
                        raw_current, kind=kind, nonce=nonce, shared=shared
                    )
                material = current["vault_material"]
                revocation = current["vault_revocation"]
                deployed = current["route_key"]
                version = claims["credential_version_sha256"]
                vault_epoch = claims["vault_revision"]
                revoke_epoch = claims["revocation_revision"]
                if (
                    material["credential_version_sha256"] != version
                    or material["vault_revision"] != vault_epoch
                    or material["material_state"] != "active"
                    or material["observed_revocation_revision"] > revoke_epoch
                    or revocation["credential_version_sha256"] != version
                    or revocation["vault_revision"] != vault_epoch
                    or revocation["revocation_revision"] != revoke_epoch
                    or revocation["current_revoked"] is not False
                    or revocation["previous_generation"] != request.generation - 1
                    or revocation["previous_revoked"] is not (request.generation > 1)
                    or deployed["credential_version_sha256"] != version
                    or deployed["vault_revision"] != vault_epoch
                    or deployed["revocation_revision"] != revoke_epoch
                    or deployed["runtime_route_generation"] != request.generation
                    or deployed["key_binding_state"]
                    != "live_runtime_credential_version_matches_vault"
                ):
                    raise ValueError()
            except (Exception, asyncio.CancelledError):
                # Cancellation and a lost post-CAS acknowledgment both burn
                # this local call ID. The service MUST burn it durably too.
                raise ProviderVaultRuntimeDenied(
                    "Durable provider call fence claim unavailable or uncertain"
                ) from None


class ProviderVaultRuntimeJoin:
    """Host bootstrap wrapper joining signed enrollment with claim-once fence."""

    def __init__(
        self,
        *,
        admission: Optional[HostVaultGuardAdmission] = None,
        call_fence: Optional[EnrolledOneUseCallFence] = None,
    ) -> None:
        if admission is not None and type(admission) is not HostVaultGuardAdmission:
            raise ProviderVaultRuntimeDenied("Trusted host admission required")
        if call_fence is not None and (
            type(call_fence) is not EnrolledOneUseCallFence
            or admission is None
            or call_fence._admission is not admission
        ):
            raise ProviderVaultRuntimeDenied("Fence is not enrolled for this host")
        self._admission = admission
        self._fence = call_fence

    def health(self) -> ProviderVaultJoinHealth:
        if self._admission is None:
            return ProviderVaultJoinHealth(
                "PENDING_HOST_ENROLLMENT",
                "Enroll an independently signed host guard and all eleven authority roots.",
            )
        try:
            self._admission.preflight()
            if self._fence is None:
                return ProviderVaultJoinHealth(
                    "PENDING_DURABLE_CALL_FENCE",
                    "Enroll a host-signed independent atomic one-use PostgreSQL call fence.",
                    host_enrollment_verified=True,
                )
            self._fence._check_current()
        except (HostVaultAdmissionDenied, ProviderVaultRuntimeDenied):
            return ProviderVaultJoinHealth(
                "PENDING_CURRENT_HOST_AUTHORITY",
                "Renew the signed host enrollment and durable call-fence lease.",
            )
        return ProviderVaultJoinHealth(
            "HOST_ENROLLED_DISPATCH_UNPROVEN",
            "Qualify real current vault, revocation, route-key and committed-usage signers.",
            host_enrollment_verified=True,
            shared_call_fence_enrolled=True,
        )

    async def binding_factory(
        self,
        engagement_id: str,
        task_id: str,
        model: str,
        operation: str,
        route: Any,
        call_id: str,
    ) -> DispatchBinding:
        if self._admission is None or self._fence is None:
            raise ProviderVaultRuntimeDenied("Host dispatch and durable call fence pending")
        self._fence._check_current()
        binding = await self._admission.binding_factory(
            engagement_id, task_id, model, operation, route, call_id
        )
        await self._fence.claim_once(binding)
        return binding

    def construct_client(self, *, usage_store: Any, **ordinary_config: Any) -> LiteLLMClient:
        """Return a safe pending client unless every host-only gate is enrolled."""
        blocked = {
            "vault_guard_required",
            "vault_guard",
            "vault_binding_factory",
            "usage_store",
            "api_key",
            "credential_env",
        }
        if blocked.intersection(ordinary_config):
            raise ProviderVaultRuntimeDenied("Protected client configuration cannot be overridden")
        if self._admission is None or self._fence is None:
            return pending_guarded_client(usage_store=usage_store, **ordinary_config)
        self._fence._check_current()
        self._admission._check_current()
        if type(usage_store) is not ModelUsageLedger:
            raise ProviderVaultRuntimeDenied("Actual signed PostgreSQL usage ledger required")
        routes = configured_routes()
        if (
            routes is None
            or routes.version != 2
            or routes.policy_sha256 != self._admission._claims["route_policy_sha256"]
            or type(self._admission._guard) is not ProviderCredentialDispatchGuard
        ):
            raise ProviderVaultRuntimeDenied("Exact enrolled signed route policy unavailable")
        kwargs = self._admission.constructor_kwargs()
        kwargs["vault_binding_factory"] = self.binding_factory
        # Same protected host-owned constructor indirection used by the
        # independently gated HostVaultGuardAdmission. Only api/main.py may
        # construct an unguarded direct LiteLLMClient in dev/test mode.
        client_type = LiteLLMClient
        return client_type(usage_store=usage_store, **ordinary_config, **kwargs)


__all__ = [
    "EnrolledOneUseCallFence",
    "ProviderVaultJoinHealth",
    "ProviderVaultRuntimeDenied",
    "ProviderVaultRuntimeJoin",
]
