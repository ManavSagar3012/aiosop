"""Host-only bootstrap admission for the optional LiteLLM vault dispatch guard.

NOT mounted. A guard object, a client flag, or an approved credential profile
is not evidence of provider readiness. The trusted app bootstrap must pin the
host control-plane root *outside* request data, verify its fresh enrollment
manifest, supply real protected binding readback, and require the 11 separately
enrolled roots in ProviderCredentialDispatchGuard. Every actual provider send
still needs its own post-commit signed ledger/material/route join in that guard.

No provider request, environment/API-key read, DB operation, secret material,
or remote vault read is performed in this module.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.core.llm_client import LiteLLMClient, _vault_route_deployment_sha256
from ai_osop.core.provider_credential_dispatch_guard import (
    DispatchBinding,
    ProviderCredentialDispatchGuard,
)
from ai_osop.core.provider_routing import configured_routes
from ai_osop.memory.model_usage import ModelUsageLedger

_DOMAIN = b"ai-osop-host-vault-guard-enrollment-v1\x00"
_SCHEMA = "ai-osop-host-vault-guard-enrollment-v1"
_AUDIENCE = "ai-osop-litellm-guarded-host"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_IDENT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{1,95}\Z")
_CALL = re.compile(r"call-[A-Za-z0-9_-]{1,59}\Z")
_AUTHORITY = frozenset(
    {
        "readiness.profile",
        "readiness.flow",
        "readiness.principal",
        "readiness.policy",
        "readiness.vault",
        "readiness.budget",
        "readiness.vault_revocation",
        "dispatch.vault_material",
        "dispatch.vault_revocation",
        "dispatch.route_key",
        "dispatch.reservation",
    }
)
_CLAIMS = frozenset(
    {
        "schema",
        "audience",
        "deployment_id",
        "issued_at",
        "expires_at",
        "route_policy_sha256",
        "binding_source_sha256",
        "runtime_key_service_sha256",
        "ledger_readback_service_sha256",
        "shared_revocation_fence_sha256",
        "authority_root_sha256",
    }
)


class HostVaultAdmissionDenied(RuntimeError):
    """A real, pinned and current host enrollment is not demonstrated."""


def _strict_pairs(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    found: Dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise ValueError("Duplicate signed enrollment key")
        found[key] = value
    return found


def _hash_public(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _existing_authority_roots(guard: ProviderCredentialDispatchGuard) -> Dict[str, str]:
    """Capture root identities only, never a signing key or secret."""
    verifier = guard._readiness._verifier
    roots = {"readiness." + kind: _hash_public(key) for kind, key in verifier._keys.items()}
    roots["readiness.vault_revocation"] = _hash_public(guard._readiness._revocation_key)
    roots.update({"dispatch." + kind: _hash_public(key) for kind, key in guard._keys.items()})
    if (
        set(roots) != _AUTHORITY
        or len(set(roots.values())) != 11
        or any(_HEX.fullmatch(value) is None for value in roots.values())
    ):
        raise HostVaultAdmissionDenied("Eleven distinct pinned host authorities required")
    return roots


@dataclass(frozen=True)
class HostVaultEnrollmentStatus:
    """Bootstrap signature status, explicitly NOT provider dispatch readiness."""

    deployment_id: str
    valid_until: int
    root_count: int = 11
    host_enrollment_signature_verified: bool = True
    provider_ready_verified: bool = False
    provider_contacted: bool = False
    budget_reserved: bool = False
    dispatch_authorized: bool = False


TrustedBindingReader = Callable[[str, str, str, str, Any, str], Awaitable[DispatchBinding]]


class HostVaultGuardAdmission:
    """Pin *another* independently enrolled host root before injecting guard.

    Constructor parameters are host-only trusted configuration, not HTTP JSON
    request fields or dynamic per-model kwargs. A fresh Ed25519 signed
    enrollment manifest binds all 11 existing evidence roots, the trusted
    binding/route policy and independent backend/fence identity commitments.
    Even its success cannot prove the actual host attestors are reachable,
    that PG committed, or that the vault-key version is current at dispatch.
    """

    def __init__(
        self,
        *,
        pinned_host_public_key: Optional[Ed25519PublicKey] = None,
        pinned_host_root_sha256: Optional[str] = None,
        signed_enrollment: Optional[bytes] = None,
        guard: Optional[ProviderCredentialDispatchGuard] = None,
        trusted_binding_reader: Optional[TrustedBindingReader] = None,
        expected_deployment_id: Optional[str] = None,
        expected_binding_source_sha256: Optional[str] = None,
        expected_runtime_key_service_sha256: Optional[str] = None,
        expected_ledger_readback_service_sha256: Optional[str] = None,
        expected_shared_revocation_fence_sha256: Optional[str] = None,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        self._clock = clock or (lambda: int(time.time()))
        self._guard: Optional[ProviderCredentialDispatchGuard] = None
        self._reader: Optional[TrustedBindingReader] = None
        self._claims: Optional[Dict[str, Any]] = None
        self._authority: Optional[Dict[str, str]] = None
        self._root: Optional[Ed25519PublicKey] = None
        self._signature: Optional[bytes] = None
        if (
            not isinstance(pinned_host_public_key, Ed25519PublicKey)
            or type(pinned_host_root_sha256) is not str
            or _HEX.fullmatch(pinned_host_root_sha256) is None
            or _hash_public(pinned_host_public_key) != pinned_host_root_sha256
            or type(guard) is not ProviderCredentialDispatchGuard
            or not callable(trusted_binding_reader)
            or type(expected_deployment_id) is not str
            or _IDENT.fullmatch(expected_deployment_id) is None
            or type(expected_binding_source_sha256) is not str
            or _HEX.fullmatch(expected_binding_source_sha256) is None
            or type(expected_runtime_key_service_sha256) is not str
            or _HEX.fullmatch(expected_runtime_key_service_sha256) is None
            or type(expected_ledger_readback_service_sha256) is not str
            or _HEX.fullmatch(expected_ledger_readback_service_sha256) is None
            or type(expected_shared_revocation_fence_sha256) is not str
            or _HEX.fullmatch(expected_shared_revocation_fence_sha256) is None
            or type(signed_enrollment) is not bytes
            or not 0 < len(signed_enrollment) <= 8192
            or not callable(self._clock)
        ):
            raise HostVaultAdmissionDenied(
                "Independently pinned host admission root or readback unavailable"
            )
        roots = _existing_authority_roots(guard)
        if pinned_host_root_sha256 in roots.values():
            raise HostVaultAdmissionDenied("Host controller must be independently enrolled")
        try:
            envelope = json.loads(
                signed_enrollment,
                object_pairs_hook=_strict_pairs,
                parse_float=lambda value: (_ for _ in ()).throw(ValueError()),
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError()),
            )
            if type(envelope) is not dict or set(envelope) != {"claims", "signature_b64"}:
                raise ValueError()
            claims = envelope["claims"]
            if type(claims) is not dict or set(claims) != _CLAIMS:
                raise ValueError()
            if (
                claims["schema"] != _SCHEMA
                or claims["audience"] != _AUDIENCE
                or claims["deployment_id"] != expected_deployment_id
                or claims["binding_source_sha256"] != expected_binding_source_sha256
                or claims["runtime_key_service_sha256"] != expected_runtime_key_service_sha256
                or claims["ledger_readback_service_sha256"]
                != expected_ledger_readback_service_sha256
                or claims["shared_revocation_fence_sha256"]
                != expected_shared_revocation_fence_sha256
                or type(claims["issued_at"]) is not int
                or type(claims["expires_at"]) is not int
                or not 1 <= claims["issued_at"] <= self._clock() + 1
                or self._clock() - claims["issued_at"] > 10
                or not self._clock() < claims["expires_at"] <= claims["issued_at"] + 15
                or any(
                    type(claims[field]) is not str
                    or _HEX.fullmatch(claims[field]) is None
                    or claims[field] == "0" * 64
                    for field in (
                        "route_policy_sha256",
                        "binding_source_sha256",
                        "runtime_key_service_sha256",
                        "ledger_readback_service_sha256",
                        "shared_revocation_fence_sha256",
                    )
                )
                or type(claims["authority_root_sha256"]) is not dict
                or claims["authority_root_sha256"] != roots
            ):
                raise ValueError()
            raw64 = envelope["signature_b64"]
            if type(raw64) is not str or len(raw64) != 88:
                raise ValueError()
            signature = base64.b64decode(raw64, validate=True)
            if len(signature) != 64 or base64.b64encode(signature).decode() != raw64:
                raise ValueError()
            pinned_host_public_key.verify(signature, _DOMAIN + _canonical(claims))
        except (
            ValueError,
            TypeError,
            KeyError,
            UnicodeError,
            OverflowError,
            RecursionError,
            InvalidSignature,
        ):
            raise HostVaultAdmissionDenied(
                "Fresh independent host enrollment unavailable"
            ) from None
        self._guard = guard
        self._reader = trusted_binding_reader
        self._claims = claims
        self._authority = roots
        self._root = pinned_host_public_key
        self._signature = signature

    def _check_current(self) -> None:
        """Fail if the signed bootstrap lease or roots have changed."""
        if (
            self._claims is None
            or self._root is None
            or self._signature is None
            or self._guard is None
            or self._authority is None
            or type(self._guard) is not ProviderCredentialDispatchGuard
        ):
            raise HostVaultAdmissionDenied("Protected host guard enrollment unavailable")
        try:
            self._root.verify(self._signature, _DOMAIN + _canonical(self._claims))
            now = self._clock()
            if (
                type(now) is not int
                or now < self._claims["issued_at"] - 1
                or now - self._claims["issued_at"] > 10
                or now >= self._claims["expires_at"]
                or _existing_authority_roots(self._guard) != self._authority
            ):
                raise HostVaultAdmissionDenied("Host root enrollment expired or changed")
        except (InvalidSignature, ValueError, TypeError, AttributeError):
            raise HostVaultAdmissionDenied(
                "Independent current host enrollment unavailable"
            ) from None

    def constructor_kwargs(self) -> Dict[str, Any]:
        """Protected bootstrap-only args, never a public JSON API interface."""
        self._check_current()
        return {
            "vault_guard_required": True,
            "vault_guard": self._guard,
            "vault_binding_factory": self.binding_factory,
        }

    def construct_client(self, *, usage_store: Any, **ordinary_config: Any) -> LiteLLMClient:
        """Construct guarded client only with genuine ledger class and lease.

        Does NOT reserve budget, load a credential, contact a signer or
        mark a provider ready. If no host root, use pending_client below.
        """
        self._check_current()
        if type(usage_store) is not ModelUsageLedger:
            raise HostVaultAdmissionDenied("Actual ModelUsageLedger required")
        if set(ordinary_config).intersection(
            {
                "usage_store",
                "vault_guard",
                "vault_guard_required",
                "vault_binding_factory",
                "api_key",
                "credential_env",
            }
        ):
            raise HostVaultAdmissionDenied("Protected constructor arguments cannot be overridden")
        routes = configured_routes()
        if (
            routes is None
            or routes.version != 2
            or type(routes.policy_sha256) is not str
            or routes.policy_sha256 != self._claims["route_policy_sha256"]
        ):
            raise HostVaultAdmissionDenied("Exact enrolled signed-v2 route policy unavailable")
        # This unmounted factory is not the application's active constructor
        # (api/main.py owns that); no client is created without a host caller.
        client_type = LiteLLMClient
        return client_type(
            usage_store=usage_store,
            **ordinary_config,
            **self.constructor_kwargs(),
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
        """Fresh protected read of exact postcommit Task/route binding.

        Only ProviderCredentialDispatchGuard can admit this proposal using
        independent current signed material, revocation, runtime-key and
        committed-ledger proofs. This factory NEVER fabricates those proofs.
        """
        self._check_current()
        if (
            not all(
                type(value) is str and 0 < len(value) <= 128
                for value in (engagement_id, task_id, model, operation, call_id)
            )
            or _CALL.fullmatch(call_id) is None
            or operation not in {"completion", "embedding"}
            or route is None
            or route.model != model
            or route.provider not in {"openai", "anthropic", "gemini", "deepseek"}
            or operation not in route.operations
        ):
            raise HostVaultAdmissionDenied(
                "Trusted current Task/provider route binding unavailable"
            )
        routes = configured_routes()
        if (
            routes is None
            or routes.version != 2
            or routes.policy_sha256 != self._claims["route_policy_sha256"]
            or routes.resolve(model, operation) is not route
        ):
            raise HostVaultAdmissionDenied("Pinned provider route changed")
        deployment_sha256 = _vault_route_deployment_sha256(route)
        try:
            result = await self._reader(engagement_id, task_id, model, operation, route, call_id)
        except Exception:
            raise HostVaultAdmissionDenied("Protected binding readback unavailable") from None
        if type(result) is not DispatchBinding:
            raise HostVaultAdmissionDenied("Signed current binding was not read back")
        current = result.readiness_request
        if (
            result.call_id != call_id
            or result.route_policy_sha256 != self._claims["route_policy_sha256"]
            or result.route_deployment_sha256 != deployment_sha256
            or current.engagement_id != engagement_id
            or current.task_id != task_id
            or current.model != model
            or current.operation != operation
            or current.provider != route.provider
            or current.agent_role not in route.allowed_roles
        ):
            raise HostVaultAdmissionDenied("Protected binding differs from current route or Task")
        return result

    def preflight(self) -> HostVaultEnrollmentStatus:
        """Verify enrollment only; NEVER claim provider ready or budget held."""
        self._check_current()
        return HostVaultEnrollmentStatus(
            deployment_id=self._claims["deployment_id"],
            valid_until=self._claims["expires_at"],
        )

    async def require_provider_ready_without_reservation(self) -> None:
        """Deliberate denial: no pre-spend provider grant can be inferred."""
        raise HostVaultAdmissionDenied(
            "Provider readiness requires a separately signed committed call reservation"
        )


def pending_guarded_client(
    *,
    usage_store: Any = None,
    **ordinary_config: Any,
) -> LiteLLMClient:
    """Explicit mandatory guarded-deny mode while host enrollment is missing.

    Unlike the default LiteLLMClient constructor this is never unguarded.
    It does not construct a fake guard, a fake signature, or touch a provider.
    """
    if (
        "vault_guard_required" in ordinary_config
        or "vault_guard" in ordinary_config
        or ("vault_binding_factory" in ordinary_config)
    ):
        raise HostVaultAdmissionDenied("Host vault guard status cannot be caller-selected")
    client_type = LiteLLMClient
    mandatory_pending = {"vault_guard_required": True}
    return client_type(usage_store=usage_store, **mandatory_pending, **ordinary_config)
