"""Multi-tenant boundary primitives for engineering the last "E" dimension.

Where this fits in the bigger plan:
- Until now, the graph, memory, and session chains operated in a single global namespace indexed
  by engagement_id only. For production SaaS, that's not acceptable — one tenant's evidence must
  never appear pathwise for another.
- This module gives us a `tenant_id` dimension we can pivot on, and a deterministic
  `tenant_scope()` that selectively maps a tenant to a memory lock key prefix so Redis queues and
  Postgres keys stay separate. It deliberately splits a shareable default for predictable demo use
  with protected namespaces so we can *demand* isolation at the API boundary.
"""

from __future__ import annotations

from typing import Optional


def tenant_scope(tenant_id: Optional[str]) -> str:
    """Return the canonical scope for a tenant, or the default shared scope."""
    if not tenant_id:
        return "default"
    return f"tenant/{tenant_id}"


def tenant_prefixed_key(tenant_id: Optional[str], key: str) -> str:
    """Namespace-encode any platform key so storage is partitioned by tenant."""
    return f"{tenant_scope(tenant_id)}::{key}"


def tenant_can_access(tenant_id: Optional[str], resource_tenant: Optional[str]) -> bool:
    """Authorize a tenant against a resource that carries a tenant progenitor."""
    return tenant_scope(tenant_id) == tenant_scope(resource_tenant)
