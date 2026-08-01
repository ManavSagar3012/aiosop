"""Multi-tenant groundwork: org boundary enforcement on Task/Scope/Engagement plus
per-finding isolation at the storage layer (scenarios repo can prove)."""

from typing import Any

import pytest

from ai_osop.core.models import ScopeDefinition, Task


def test_scope_definition_has_org_key():
    scope = ScopeDefinition(engagement_id="e-1", domains=["example.local"], organization_id="org-a")
    assert scope.organization_id == "org-a"


def test_scope_definition_defaults_to_single_org():
    scope = ScopeDefinition(engagement_id="e-2", domains=["example.local"])
    assert scope.organization_id == "default"


def test_task_carries_engagement_org_bucket():
    task = Task(type="x", agent_type="recon", payload={}, engagement_id="e-3")
    assert task.engagement_id == "e-3"


def test_scope_definition_serializes_org():
    scope = ScopeDefinition(
        engagement_id="e-4", domains=["example.local"], organization_id="org-b"
    )
    dumped = scope.model_dump()
    assert dumped["organization_id"] == "org-b"


def test_tenant_queue_key_partitions_by_tenant():
    from ai_osop.core.tenant_isolation import tenant_queue_key

    k_a = tenant_queue_key("org-blue", "tasks:eng-1")
    k_b = tenant_queue_key("org-red", "tasks:eng-1")
    k_default = tenant_queue_key(None, "tasks:eng-1")
    assert k_a.startswith("tenant/org-blue::")
    assert k_b.startswith("tenant/org-red::")
    assert k_default.startswith("default::")
    assert k_a != k_b
