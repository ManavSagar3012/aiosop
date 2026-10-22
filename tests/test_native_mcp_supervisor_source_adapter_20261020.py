"""Read-only true 0027/0029 PostgreSQL preflight and adversarial source loss.

The test retains the native execution grant's real signed token, transaction,
Action lineage, SHA-verified resource/reviewer fixtures. The existing 0027
Task/Flow validation hooks are controlled to model current revocation, while
guard_sql is a separately injected signed-policy result, never caller truth.
No app PG, Docker, target or provider is accessed.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace
from typing import Any

import pytest

from ai_osop.orchestrator import native_mcp_supervisor_source_adapter as adapter_module
from ai_osop.orchestrator.native_mcp_supervisor_source_adapter import (
    NativeMCPSupervisorSourceAdapter,
)
from ai_osop.safety.native_mcp_worker_supervisor import (
    NativeSupervisorDenied,
    SourceAuthorityDecision,
    SupervisorBinding,
)
from tests.test_native_mcp_execution_grants_20261020 import (
    ACTION,
    REQ,
    SHA,
    Result,
    binding as source_binding,
    harness,
)
from tests.test_supervisor_bound_native_grants_20261020 import _configure_resource


@pytest.fixture
def source(monkeypatch: Any) -> SimpleNamespace:
    store, db, controls = harness(monkeypatch)
    digest = _configure_resource(db)
    roe = {"active": True, "sha": SHA, "owner": "owner-current", "id": "signed-3"}
    issue_event = {"present": True}
    original_execute = db.execute

    async def guarded(sql: Any, params: Any = None) -> Result:
        query = str(sql)
        if query.startswith("SELECT 1 FROM native_mcp_execution_grant_events"):
            db.calls.append(query)
            assert (
                params is not None
                and params["sha"] == next(iter(db.grants.values()))["claims_sha256"]
            )
            return Result(1 if issue_event["present"] else None)
        return await original_execute(sql, params)

    db.execute = guarded

    async def policy_guard(_db: Any, engagement: str, *, expected_version: int) -> Any:
        assert _db is db
        assert engagement == "eng-durable"
        assert expected_version == 3
        if not roe["active"]:
            raise ValueError("revoked signed authorization")
        return SimpleNamespace(
            policy_sha256=roe["sha"],
            authorization_id=roe["id"],
            policy={"created_by": roe["owner"]},
        )

    monkeypatch.setattr(adapter_module, "guard_sql", policy_guard)
    return SimpleNamespace(
        store=store,
        db=db,
        controls=controls,
        resource_digest=digest,
        roe=roe,
        event=issue_event,
    )


async def _prepared(source: SimpleNamespace, *, resource: bool = True) -> SimpleNamespace:
    issued = await source.store.issue(
        source_binding(),
        "owner-current",
        ACTION,
        REQ,
        resource_sha256=source.resource_digest if resource else None,
    )
    token = issued["token"]
    claims = token["claims"]
    fixed_binary = "f" * 64
    preflight = NativeMCPSupervisorSourceAdapter(
        source.store.actions,
        protected_grant=token,
        protected_owner_id="owner-current",
        trusted_binary_sha256=fixed_binary,
    )
    supervisor_binding = SupervisorBinding(
        request_id=claims["request_id"],
        engagement_id=claims["engagement_id"],
        flow_id=claims["flow_id"],
        task_id=claims["task_id"],
        subtask_id=claims["subtask_id"],
        action_id=claims["action_id"],
        approval_id=source.db.dispatch["approval_id"],
        lease_id=claims["lease_id"],
        issuer_kid=token["kid"],
        signed_roe_sha256=SHA,
        authorization_sha256=SHA,
        manifest_sha256=claims["manifest_sha256"],
        binary_sha256=fixed_binary,
    )
    return SimpleNamespace(
        adapter=preflight,
        binding=supervisor_binding,
        token=token,
        claims=claims,
    )


@pytest.mark.asyncio
async def test_exact_live_signed_roe_reviewed_bytes_lease_and_issued_grant_pass(
    source: Any,
) -> None:
    p = await _prepared(source)
    baseline = len(source.db.calls)
    before = copy.deepcopy(source.db.grants)
    events = copy.deepcopy(source.db.events)
    decision = await p.adapter(p.binding)
    assert type(decision) is SourceAuthorityDecision
    assert decision.binding is p.binding
    assert decision.authority_version == 3
    assert decision.checked_at == source.db.clock
    assert decision.expires_at == min(p.claims["expires_at"], source.db.clock + 10)
    assert decision.issuer_trusted is True
    assert decision.signed_roe_valid is True
    assert decision.task_active is True
    assert decision.approval_current is True
    assert decision.lease_active is True
    reads = source.db.calls[baseline:]
    assert all(query.startswith("SELECT ") for query in reads)
    assert sum("FROM native_mcp_execution_grants" in sql for sql in reads) == 2
    assert any("flow_mcp_action_dispatch_events" in sql for sql in reads)
    assert any("native_mcp_execution_grant_events" in sql for sql in reads)
    assert any("FROM flow_artifacts" in sql for sql in reads)
    assert any("FROM flow_artifact_reviews" in sql for sql in reads)
    assert source.db.grants == before
    assert source.db.events == events
    assert await p.adapter(p.binding) == decision  # Fresh repeated source read, no consuming.
    assert source.db.grants == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,changed",
    (
        ("request_id", "req-" + "0" * 48),
        ("engagement_id", "eng-foreign"),
        ("flow_id", "flow-foreign"),
        ("task_id", "task-foreign"),
        ("subtask_id", "subtask-foreign"),
        ("action_id", "action-" + "0" * 32),
        ("approval_id", "apr-foreign"),
        ("lease_id", "lease-foreign"),
        ("issuer_kid", "kid-foreign"),
        ("signed_roe_sha256", "0" * 64),
        ("authorization_sha256", "0" * 64),
        ("manifest_sha256", "0" * 64),
        ("binary_sha256", "0" * 64),
    ),
)
async def test_forged_binding_denied_before_valid_authority(
    source: Any, field: str, changed: str
) -> None:
    from dataclasses import replace

    p = await _prepared(source)
    with pytest.raises(NativeSupervisorDenied):
        await p.adapter(replace(p.binding, **{field: changed}))
    assert next(iter(source.db.grants.values()))["status"] == "issued"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "revoked",
    (
        "authority",
        "approval",
        "lease",
        "signed_roe",
        "signed_roe_sha",
        "signed_roe_owner",
        "signed_roe_id",
        "reviewer_disabled",
        "review_decision",
        "review_owner",
        "task_digest",
        "artifacts_missing",
        "artifact_contents",
        "original_action",
        "original_dispatch_event",
        "issued_event",
        "grant_consumed",
        "grant_revoked",
        "grant_expired",
        "grant_approval",
        "grant_resource",
        "grant_signature",
    ),
)
async def test_revoked_source_original_bytes_or_grant_always_fails_closed(
    source: Any, revoked: str
) -> None:
    p = await _prepared(source)
    grant = next(iter(source.db.grants.values()))
    if revoked in {"authority", "approval", "lease"}:
        source.controls[revoked] = False
    elif revoked == "signed_roe":
        source.roe["active"] = False
    elif revoked == "signed_roe_sha":
        source.roe["sha"] = "0" * 64
    elif revoked == "signed_roe_owner":
        source.roe["owner"] = "foreign-owner"
    elif revoked == "signed_roe_id":
        source.roe["id"] = "foreign-policy-id"
    elif revoked == "reviewer_disabled":
        source.db.reviewer_disabled = True
    elif revoked == "review_decision":
        source.db.review["decision"] = "reject"
    elif revoked == "review_owner":
        source.db.review["reviewer_sub"] = "owner-current"
    elif revoked == "task_digest":
        source.db.pinned_resource = "0" * 64
    elif revoked == "artifacts_missing":
        source.db.artifacts = []
    elif revoked == "artifact_contents":
        source.db.artifacts[0]["content"] = b"tampered independently reviewed bytes"
    elif revoked == "original_action":
        source.db.dispatch["status"] = "finished"
    elif revoked == "original_dispatch_event":
        source.db.dispatched_event = False
    elif revoked == "issued_event":
        source.event["present"] = False
    elif revoked == "grant_consumed":
        grant["status"] = "redeemed"
    elif revoked == "grant_revoked":
        grant["status"] = "revoked"
    elif revoked == "grant_expired":
        source.db.clock = grant["expires_at"]
    elif revoked == "grant_approval":
        grant["approval_id"] = "apr-foreign"
    elif revoked == "grant_resource":
        grant["resource_sha256"] = "0" * 64
    elif revoked == "grant_signature":
        grant["signature_sha256"] = "0" * 64
    with pytest.raises(NativeSupervisorDenied):
        await p.adapter(p.binding)
    assert not any(event["kind"] == "redeemed" for event in source.db.events)


@pytest.mark.asyncio
async def test_only_protected_original_and_owner_can_be_used(source: Any) -> None:
    p = await _prepared(source)
    protected = copy.deepcopy(p.token)
    protected["claims"]["task_id"] = "task-foreign"
    with pytest.raises(NativeSupervisorDenied):
        await NativeMCPSupervisorSourceAdapter(
            source.store.actions,
            protected_grant=protected,
            protected_owner_id="owner-current",
            trusted_binary_sha256="f" * 64,
        )(p.binding)
    with pytest.raises(NativeSupervisorDenied):
        await NativeMCPSupervisorSourceAdapter(
            source.store.actions,
            protected_grant=p.token,
            protected_owner_id="foreign-owner",
            trusted_binary_sha256="f" * 64,
        )(p.binding)
    original = copy.deepcopy(p.token)
    p.token["claims"]["engagement_id"] = "eng-foreign"
    assert p.adapter._protected_grant == original
    assert (await p.adapter(p.binding)).issuer_trusted is True


@pytest.mark.asyncio
async def test_resource_null_is_denied_for_production_supervised_stage(source: Any) -> None:
    p = await _prepared(source, resource=False)
    with pytest.raises(NativeSupervisorDenied):
        await p.adapter(p.binding)


@pytest.mark.asyncio
async def test_missing_real_signed_roe_guard_never_accepts_assertion(
    source: Any, monkeypatch: Any
) -> None:
    p = await _prepared(source)

    async def unavailable(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("signed authority backend unavailable")

    monkeypatch.setattr(adapter_module, "guard_sql", unavailable)
    with pytest.raises(NativeSupervisorDenied):
        await p.adapter(p.binding)


@pytest.mark.asyncio
async def test_lost_postgresql_read_denies_without_grant_or_action_mutation(source: Any) -> None:
    p = await _prepared(source)
    before = copy.deepcopy(source.db.grants)
    original = source.db.execute

    async def fail_on_event(sql: Any, params: Any = None) -> Any:
        if "native_mcp_execution_grant_events" in str(sql):
            raise TimeoutError("PG read lost")
        return await original(sql, params)

    source.db.execute = fail_on_event
    with pytest.raises(NativeSupervisorDenied):
        await p.adapter(p.binding)
    assert source.db.grants == before
