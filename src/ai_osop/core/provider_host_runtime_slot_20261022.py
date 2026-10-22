"""Process-local, host-ONLY enrollment hook for the guarded provider runtime.

This is NOT an enrollment interface. A separately authenticated deployment
process must construct an independently verified ProviderVaultRuntimeJoin and
install it BEFORE FastAPI lifespan starts. No HTTP, env var, route reference,
symbolic profile or user-controlled config can install keys here.

Each worker needs its own enrollment, while the signed durable one-use CAS
service must be shared across replicas. Missing trust stays PENDING/DENIED.
"""

from __future__ import annotations

from threading import Lock
from typing import Optional

from ai_osop.core.provider_vault_runtime_join import (
    ProviderVaultRuntimeDenied,
    ProviderVaultRuntimeJoin,
)


_lock = Lock()
_join: Optional[ProviderVaultRuntimeJoin] = None


def install_independent_host_provider_runtime(join: ProviderVaultRuntimeJoin) -> None:
    """One-time in-process trusted host install; never exposed as a route."""
    global _join
    if type(join) is not ProviderVaultRuntimeJoin:
        raise ProviderVaultRuntimeDenied("Independently verified host join required")
    # A symbolic reviewed provider ref or test-issued status is NOT sufficient.
    # Health verifies signed host admission and current externally witnessed
    # one-use fence prerequisites, but does not itself authorize any provider.
    current = join.health()
    if (
        current.code != "HOST_ENROLLED_DISPATCH_UNPROVEN"
        or current.host_enrollment_verified is not True
        or current.shared_call_fence_enrolled is not True
        or current.provider_dispatch_authorized is not False
    ):
        raise ProviderVaultRuntimeDenied("Current independent host enrollment unavailable")
    with _lock:
        if _join is not None:
            raise ProviderVaultRuntimeDenied("Host provider runtime already enrolled")
        _join = join


def host_enrolled_provider_runtime() -> Optional[ProviderVaultRuntimeJoin]:
    """Read the one process-local host slot; caller must recheck on each call."""
    with _lock:
        return _join


__all__ = ["install_independent_host_provider_runtime", "host_enrolled_provider_runtime"]
