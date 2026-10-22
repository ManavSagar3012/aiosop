"""No-provider/no-DB adversarial qualification of opt-in model admission.

Model capability, tool use and served-model claims in v2 are locally declared
UNKNOWN, never remote/provider verified. Runtime permission requires the real
source contract (authoritative task lookup + later signed PG reservation), with
no network calls, cost probes or unverified provider capability promotion.
"""

from __future__ import annotations

import copy
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from ai_osop.core.config import AgentType
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.provider_routing import (
    ProviderRouteDenied,
    ProviderRoutes,
    configured_routes,
)
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.model_usage import ModelUsageLedger
from ai_osop.memory.session_memory import SessionMemory


_ENV = "OSOP_VERIFIED_PROVIDER_ROUTES_JSON"
_ROW = {
    "provider": "openai",
    "model": "openai/model-one",
    "operations": ["completion"],
    "credential_env": "OPENAI_API_KEY",
    "allowed_roles": ["vuln_analysis"],
    "capabilities": ["text_completion", "tool_calls"],
    "max_output_tokens": 4096,
    "budget_source": "signed_postgres_roe",
}


@pytest.fixture(autouse=True)
def _reset_policy(monkeypatch):
    monkeypatch.delenv(_ENV, raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    RequestContext.clear()
    yield
    RequestContext.clear()


def _policy(monkeypatch, *rows):
    monkeypatch.setenv(_ENV, json.dumps({"version": 2, "routes": list(rows or [_ROW])}))


def _ledger(*, role=AgentType.VULN_ANALYSIS, status="running", same_engagement=True):
    started = datetime.utcnow()
    task = SimpleNamespace(
        id="task-pinned",
        engagement_id="eng-pinned" if same_engagement else "eng-foreign",
        agent_type=role,
        status=status,
        assigned_agent_id="agent-dispatched",
        started_at=started,
        completed_at=None,
        flow_id="flow-pinned",
        payload={"_authorization_version": 4, "_flow_revision": 2},
    )
    # In production session_memory is a true PostgreSQL warm-store instance;
    # using a spec-constrained mock here is explicitly not DB verification.
    memory = Mock(spec=SessionMemory)
    memory.load_task_authoritative = AsyncMock(return_value=task)
    locked = SimpleNamespace(**vars(task))
    locked.agent_type = role.value if isinstance(role, AgentType) else role
    flow = SimpleNamespace(status="running", revision=2)
    lease = SimpleNamespace(
        state="dispatched",
        owner_id="worker-authorized",
        lease_id="lease-current",
        expires_at=datetime.utcnow() + timedelta(minutes=5),
    )
    db = Mock(spec=AsyncSession)
    db.authorized_pair = (SimpleNamespace(scope={}, roe={}), locked)
    db.flow = flow
    db.lease = lease

    # A real AsyncSession is required in production; spec-constrained fixture
    # keeps SQL reads local and deterministic without claiming live PG proof.
    @asynccontextmanager
    async def transaction():
        yield

    db.begin = transaction
    db.execute = AsyncMock(
        side_effect=[
            SimpleNamespace(scalar_one_or_none=lambda: db.flow),
            SimpleNamespace(scalar_one_or_none=lambda: db.lease),
        ]
    )

    @asynccontextmanager
    async def sessions():
        yield db

    ledger = Mock(spec=ModelUsageLedger)
    ledger.session_memory = memory
    ledger.reserve = AsyncMock(return_value="call-one")
    ledger.settle = AsyncMock(return_value=True)
    ledger._sessions = sessions
    ledger._test_db = db
    ledger._test_task = task
    return ledger


@pytest.fixture(autouse=True)
def _mock_real_guard_with_sql_fixture(monkeypatch):
    async def signed_guard(db, engagement_id, task_id, require_window=False):
        assert engagement_id == "eng-pinned"
        assert task_id == "task-pinned"
        assert require_window is True
        if getattr(db, "signed_guard_unavailable", False):
            raise TimeoutError("signed PG source unavailable")
        return db.authorized_pair

    monkeypatch.setattr(ModelUsageLedger, "_guard", signed_guard)


def _scope_kwargs(ledger):
    return {
        "model": "openai/model-one",
        "operation": "completion",
        "ledger": ledger,
        "engagement_id": "eng-pinned",
        "task_id": "task-pinned",
        "required_capabilities": ("text_completion", "tool_calls"),
        "max_output_tokens": 2048,
    }


def test_v1_routes_preserve_existing_optin_and_v2_requires_new_admission(monkeypatch):
    monkeypatch.setenv(
        _ENV,
        json.dumps(
            {
                "version": 1,
                "routes": [
                    {k: _ROW[k] for k in ("provider", "model", "operations", "credential_env")}
                ],
            }
        ),
    )
    routes = configured_routes()
    assert isinstance(routes, ProviderRoutes)
    assert routes.version == 1
    assert routes.resolve("openai/model-one", "completion").provider == "openai"
    _policy(monkeypatch)
    routes = configured_routes()
    assert routes.version == 2
    with pytest.raises(ProviderRouteDenied, match="Authoritative"):
        routes.resolve("openai/model-one", "completion")


@pytest.mark.asyncio
async def test_exact_pg_owned_role_scope_accepts_only_operator_claims_not_served_verification(
    monkeypatch,
):
    _policy(monkeypatch)
    ledger = _ledger()
    RequestContext.bind(engagement_id="eng-pinned", task_id="task-pinned")
    routes = configured_routes()
    async with routes.authorize_task(**_scope_kwargs(ledger)) as observation:
        assert routes.resolve("openai/model-one", "completion").model == _ROW["model"]
        # Each active client resolves from the environment again; the same
        # authority scope still gates this new instance.
        assert configured_routes().resolve("openai/model-one", "completion").provider == "openai"
        assert observation == {
            "model": _ROW["model"],
            "provider": "openai",
            "operation": "completion",
            "authoritative_task_role": "vuln_analysis",
            "claimed_task_state": "running",
            "current_flow_revision": 2,
            "lease_observation": "dispatched_at_preflight_only",
            "signed_roe_observation": "current_at_preflight_only",
            "capabilities": ["text_completion", "tool_calls"],
            "capability_provenance": "operator_declared_not_provider_verified",
            "provider_served_model_verified": False,
            "provider_capability_verified": False,
            "provider_native_cost_ceiling_verified": False,
            "budget_source": "signed_postgres_roe",
            "budget_state": "signed_postgres_lease_fenced_reservation_still_required",
        }
    with pytest.raises(ProviderRouteDenied, match="Authoritative"):
        routes.resolve("openai/model-one", "completion")
    ledger.session_memory.load_task_authoritative.assert_awaited_once_with("task-pinned")
    ledger.reserve.assert_not_awaited()
    ledger.settle.assert_not_awaited()
    report = routes.capability_report()[0]
    assert report["provider_served_model_verified"] is False
    assert report["provider_capability_verified"] is False
    assert report["provider_native_cost_ceiling_verified"] is False
    assert report["budget_state"] == "signed_postgres_reservation_still_required"
    assert "api_key" not in str(report)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "wrong_role",
        "missing_role",
        "stopped",
        "foreign_tenant",
        "missing_memory",
        "ledger_without_settle",
        "wrong_task_context",
        "wrong_engagement_context",
        "unknown_capability",
        "missing_tool_capability",
        "understated_capabilities",
        "over_max_tokens",
        "invalid_max_tokens_bool",
        "malformed_task_id",
        "lookup_failure",
        "queued",
        "dispatching",
        "unassigned",
        "not_started",
        "already_completed",
        "flowless",
        "no_pinned_flow_revision",
    ],
)
async def test_untrusted_role_budget_and_capability_preflight_denies_without_provider(
    monkeypatch,
    case,
):
    _policy(monkeypatch)
    ledger = _ledger()
    RequestContext.bind(engagement_id="eng-pinned", task_id="task-pinned")
    kwargs = _scope_kwargs(ledger)
    if case == "wrong_role":
        ledger = _ledger(role=AgentType.RECON)
    elif case == "missing_role":
        ledger = _ledger(role="vuln_analysis")
    elif case == "stopped":
        ledger = _ledger(status="completed")
    elif case == "foreign_tenant":
        ledger = _ledger(same_engagement=False)
    elif case == "missing_memory":
        ledger.session_memory = None
    elif case == "ledger_without_settle":
        ledger.settle = None
    elif case == "wrong_task_context":
        RequestContext.bind(engagement_id="eng-pinned", task_id="task-foreign")
    elif case == "wrong_engagement_context":
        RequestContext.bind(engagement_id="eng-foreign", task_id="task-pinned")
    elif case == "unknown_capability":
        kwargs["required_capabilities"] = ("text_completion", "execute_shell")
    elif case == "missing_tool_capability":
        kwargs["required_capabilities"] = ("text_completion", "reasoning")
    elif case == "understated_capabilities":
        kwargs["required_capabilities"] = ("text_completion",)
    elif case == "over_max_tokens":
        kwargs["max_output_tokens"] = 4097
    elif case == "invalid_max_tokens_bool":
        kwargs["max_output_tokens"] = True
    elif case == "malformed_task_id":
        kwargs["task_id"] = "task-foreign/../../"
    elif case == "lookup_failure":
        ledger.session_memory.load_task_authoritative.side_effect = TimeoutError("db")
    elif case == "queued":
        ledger._test_task.status = "scheduled"
    elif case == "dispatching":
        ledger._test_task.status = "dispatching"
    elif case == "unassigned":
        ledger._test_task.assigned_agent_id = None
    elif case == "not_started":
        ledger._test_task.started_at = None
    elif case == "already_completed":
        ledger._test_task.completed_at = datetime.utcnow()
    elif case == "flowless":
        ledger._test_task.flow_id = None
    elif case == "no_pinned_flow_revision":
        ledger._test_task.payload.pop("_flow_revision")
    kwargs["ledger"] = ledger
    routes = configured_routes()
    with pytest.raises(ProviderRouteDenied):
        async with routes.authorize_task(**kwargs):
            pytest.fail("unauthorized admission must not yield")
    with pytest.raises(ProviderRouteDenied):
        routes.resolve("openai/model-one", "completion")
    ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "signed_guard_unavailable",
        "stale_locked_status",
        "stale_locked_assignment",
        "stale_locked_authorization",
        "flow_suspended",
        "flow_revision_changed",
        "lease_missing",
        "lease_reserved_not_dispatched",
        "lease_expired",
        "lease_revoked",
        "lease_no_owner",
        "lease_no_id",
        "sql_unavailable",
    ],
)
async def test_current_signed_flow_and_dispatched_pg_lease_required(monkeypatch, scenario):
    _policy(monkeypatch)
    ledger = _ledger()
    RequestContext.bind(engagement_id="eng-pinned", task_id="task-pinned")
    db = ledger._test_db
    locked = db.authorized_pair[1]
    if scenario == "signed_guard_unavailable":
        db.signed_guard_unavailable = True
    elif scenario == "stale_locked_status":
        locked.status = "scheduled"
    elif scenario == "stale_locked_assignment":
        locked.assigned_agent_id = "agent-other"
    elif scenario == "stale_locked_authorization":
        locked.payload = {"_authorization_version": 5, "_flow_revision": 2}
    elif scenario == "flow_suspended":
        db.flow.status = "paused"
    elif scenario == "flow_revision_changed":
        db.flow.revision = 3
    elif scenario == "lease_missing":
        db.lease = None
    elif scenario == "lease_reserved_not_dispatched":
        db.lease.state = "reserved"
    elif scenario == "lease_expired":
        db.lease.expires_at = datetime.utcnow() - timedelta(seconds=2)
    elif scenario == "lease_revoked":
        db.lease.state = "released"
    elif scenario == "lease_no_owner":
        db.lease.owner_id = None
    elif scenario == "lease_no_id":
        db.lease.lease_id = None
    elif scenario == "sql_unavailable":
        db.execute.side_effect = RuntimeError("PG gone")
    routes = configured_routes()
    with pytest.raises(ProviderRouteDenied):
        async with routes.authorize_task(**_scope_kwargs(ledger)):
            pytest.fail("untrusted persisted task/flow/lease must never authorize")
    ledger.reserve.assert_not_awaited()
    with pytest.raises(ProviderRouteDenied):
        routes.resolve("openai/model-one", "completion")


@pytest.mark.asyncio
async def test_route_rotation_and_scope_switch_revokes_resolution_without_network(monkeypatch):
    _policy(monkeypatch)
    ledger = _ledger()
    RequestContext.bind(engagement_id="eng-pinned", task_id="task-pinned")
    routes = configured_routes()
    async with routes.authorize_task(**_scope_kwargs(ledger)):
        routes.resolve("openai/model-one", "completion")
        RequestContext.bind(engagement_id="eng-pinned", task_id="task-other")
        with pytest.raises(ProviderRouteDenied):
            routes.resolve("openai/model-one", "completion")
        RequestContext.bind(engagement_id="eng-pinned", task_id="task-pinned")
        modified = dict(_ROW, max_output_tokens=4095)
        _policy(monkeypatch, modified)
        with pytest.raises(ProviderRouteDenied):
            routes.resolve("openai/model-one", "completion")
        with pytest.raises(ProviderRouteDenied):
            configured_routes().resolve("openai/model-one", "completion")


@pytest.mark.asyncio
async def test_deleted_v2_policy_during_authorized_task_does_not_revert_to_legacy(
    monkeypatch,
):
    _policy(monkeypatch)
    ledger = _ledger()
    RequestContext.bind(engagement_id="eng-pinned", task_id="task-pinned")
    routes = configured_routes()
    async with routes.authorize_task(**_scope_kwargs(ledger)):
        routes.resolve("openai/model-one", "completion")
        monkeypatch.delenv(_ENV)
        with pytest.raises(ProviderRouteDenied, match="revoked"):
            configured_routes()
        with pytest.raises(ProviderRouteDenied, match="Authoritative"):
            routes.resolve("openai/model-one", "completion")


@pytest.mark.asyncio
async def test_downgraded_v2_policy_during_scope_cannot_revert_to_v1_dispatch(
    monkeypatch,
):
    _policy(monkeypatch)
    ledger = _ledger()
    RequestContext.bind(engagement_id="eng-pinned", task_id="task-pinned")
    routes = configured_routes()
    async with routes.authorize_task(**_scope_kwargs(ledger)):
        monkeypatch.setenv(
            _ENV,
            json.dumps(
                {
                    "version": 1,
                    "routes": [
                        {
                            key: _ROW[key]
                            for key in ("provider", "model", "operations", "credential_env")
                        }
                    ],
                }
            ),
        )
        with pytest.raises(ProviderRouteDenied, match="replaced"):
            configured_routes()


@pytest.mark.parametrize(
    "broken",
    [
        {"allowed_roles": ["vuln_analysis", "vuln_analysis"]},
        {"allowed_roles": []},
        {"allowed_roles": ["not_a_real_agent"]},
        {"allowed_roles": [None]},
        {"capabilities": ["text_completion", "text_completion"]},
        {"capabilities": ["text_completion", "anything"]},
        {"capabilities": ["tool_calls"]},
        {"capabilities": ["text_completion", "embeddings"]},
        {"max_output_tokens": 0},
        {"max_output_tokens": True},
        {"max_output_tokens": 999999},
        {"budget_source": "provider_reported"},
        {"budget_source": "unknown"},
        {"budget_source": None},
        {"role": "vuln_analysis"},
        {"model": "openai/../model"},
    ],
)
def test_v2_malformed_or_ambiguous_operator_capability_policy_fail_closed(
    monkeypatch,
    broken,
):
    _policy(monkeypatch, dict(_ROW, **broken))
    with pytest.raises(ProviderRouteDenied, match="invalid"):
        configured_routes()


@pytest.mark.parametrize(
    "missing",
    [
        "allowed_roles",
        "capabilities",
        "max_output_tokens",
        "budget_source",
    ],
)
def test_v2_missing_provenance_requirements_fail_closed(monkeypatch, missing):
    row = copy.deepcopy(_ROW)
    row.pop(missing)
    _policy(monkeypatch, row)
    with pytest.raises(ProviderRouteDenied):
        configured_routes()


@pytest.mark.asyncio
async def test_active_litellm_complete_cannot_bypass_v2_with_unclaimed_task(monkeypatch):
    _policy(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "fake-for-tests-not-billable")
    monkeypatch.setattr("ai_osop.core.llm_client.settings.mock_llm", False)
    RequestContext.bind(engagement_id="eng-pinned", task_id="task-pinned")
    ledger = _ledger()
    ledger._test_task.status = "scheduled"
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ProviderRouteDenied):
            await client.complete([{"role": "user", "content": "test fixture only"}])
        provider.assert_not_awaited()
        ledger.reserve.assert_not_awaited()


def test_v2_empty_or_unknown_requested_route_is_never_served(monkeypatch):
    _policy(monkeypatch)
    routes = configured_routes()
    with pytest.raises(ProviderRouteDenied):
        routes.resolve("openai/other-model", "completion")
    with pytest.raises(ProviderRouteDenied):
        routes.resolve("openai/model-one", "embedding")
