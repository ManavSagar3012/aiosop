"""Real v2 LiteLLM dispatch, signed guard and reservation SQL against a fixture.

Exercise the *production* SupervisionStore._guard and ModelUsageLedger.reserve;
only the external PostgreSQL transport, cryptographic signer and LiteLLM
network response are deterministic surrogates. A stubbed signature is NOT an
independently verified live ROE. No app DB, paid provider, or target is used.
"""

import copy
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from ai_osop.core.config import AgentType
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.provider_routing import ProviderRouteDenied
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory import authorization_store
from ai_osop.memory.authorization_store import AuthorizationDenied, VerifiedAuthorization
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelUsageLedger
from ai_osop.memory.session_memory import SessionMemory
from tests.test_atomic_model_lease_reservation_20261018 import _Database, _Result
from tests.test_provider_capability_admission_20261016 import _ROW, _policy


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    RequestContext.clear()
    monkeypatch.delenv("OSOP_VERIFIED_PROVIDER_ROUTES_JSON", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("ai_osop.core.llm_client.settings.mock_llm", False)
    monkeypatch.setattr("ai_osop.core.llm_client.configured_model_role_policy", lambda: None)
    monkeypatch.setattr("ai_osop.core.llm_client.catalog_mode", lambda: "disabled")
    yield
    RequestContext.clear()


class _JoinedDatabase(_Database):
    """Records the real SQL guard/query order without opening PostgreSQL."""

    def __init__(self):
        super().__init__()
        self.task.id = "task-pinned"
        self.task.engagement_id = "eng-pinned"
        self.task.flow_id = "flow-pinned"
        self.task.payload = {"_authorization_version": 4, "_flow_revision": 2}
        self.task.agent_type = "vuln_analysis"
        self.flow.revision = 2
        self.engagement.phase = "active"
        self.engagement.created_by = "fixture-operator"
        now = datetime.utcnow()
        self.engagement.scope = {
            "engagement_id": "eng-pinned",
            "domains": ["test.invalid"],
            "authorization_ref": "signed-lab-roe-fixture",
            "testing_window_start": now - timedelta(minutes=2),
            "testing_window_end": now + timedelta(minutes=5),
        }
        self.engagement.roe = {
            "llm_call_budget_total": 3,
            "llm_cost_budget_usd": 1.0,
            "llm_precharge_max_call_usd": 0.2,
        }
        self.signed_version = 4
        self.signer_active = True
        self.signed_checks = 0
        self.task_query_count = 0
        self.locked_task_reads = 0
        self.guard_task = copy.deepcopy(self.task)

    async def execute(self, statement):
        assert self.active_transaction, "All admission reads must share one transaction"
        sql = str(statement)
        if "FROM session_states" in sql:
            self.queries.append(sql)
            assert "FOR UPDATE" in sql, "Signed engagement must be row-locked"
            return _Result(self.engagement)
        if "FROM tasks" in sql:
            self.queries.append(sql)
            self.task_query_count += 1
            # SQLAlchemy's generic str(statement) can omit dialect-specific
            # lock syntax: inspect the SELECT's actual PostgreSQL compilation.
            # The signed guard initially loads Task without this lock; reserve
            # MUST re-read the Task with FOR UPDATE in that same transaction.
            pg_sql = str(statement.compile(dialect=postgresql.dialect()))
            is_locked = getattr(statement, "_for_update_arg", None) is not None
            if is_locked:
                assert "FOR UPDATE" in pg_sql
                self.locked_task_reads += 1
                assert self.guard_seen, "Signed ROE must precede the reservation Task lock"
            return _Result(self.task)
        # Actual Flow and DISPATCHED lease SELECTs are still executed by the
        # v2 preflight AND the atomic reservation path, not mocked away.
        return await super().execute(statement)


def _joined_ledger(monkeypatch, *, role=AgentType.VULN_ANALYSIS):
    state = _JoinedDatabase()
    # SQLAlchemy's AsyncSession type check in the real capability gate must
    # still run. Only its network transport/transactions are replaced here.
    db = AsyncMock(spec=AsyncSession)
    db.__aenter__.return_value = db
    db.__aexit__.return_value = False
    db.execute = AsyncMock(side_effect=state.execute)
    db.begin = state.begin
    db.add = state.add
    memory = Mock(spec=SessionMemory)
    memory._async_session = lambda: db

    async def authoritative_task(task_id):
        assert task_id == "task-pinned"
        task = copy.deepcopy(state.task)
        task.agent_type = role
        return task

    memory.load_task_authoritative = AsyncMock(side_effect=authoritative_task)

    async def signed_guard(session, engagement_id, expected_version=None, expected_digest=None):
        assert session is db and state.active_transaction
        assert engagement_id == "eng-pinned"
        assert expected_digest is None
        state.guard_seen = True
        state.signed_checks += 1
        if not state.signer_active:
            raise AuthorizationDenied("Controlled signer revoked")
        if expected_version is not None and expected_version != state.signed_version:
            raise AuthorizationDenied("Controlled signature version mismatch")
        return VerifiedAuthorization(
            session_id="eng-pinned",
            authorization_id="authorization-lab",
            version=state.signed_version,
            kid="test-key-not-a-live-signer",
            policy_sha256="a" * 64,
            policy={"kind": "deterministic-trusted-signature-fixture"},
        )

    # This is the ONLY authority stub: the actual SupervisionStore._guard
    # continues to enforce phase, scope, clock window, signer version, and
    # current Task. No `_guard` or `reserve` monkeypatch is allowed here.
    monkeypatch.setattr(authorization_store, "guard_sql", signed_guard)
    ledger = ModelUsageLedger(memory)
    original_reserve = ledger.reserve
    ledger.reserve = AsyncMock(wraps=original_reserve)
    ledger.settle = AsyncMock(return_value=True)  # No provider settlement database.

    async def precharge(session, engagement_id, task_id, kind, actor, payload, *, idempotency_key):
        assert session is db and state.active_transaction and state.guard_seen
        assert (engagement_id, task_id, kind, actor) == (
            "eng-pinned",
            "task-pinned",
            "llm.precharge_reserved",
            "model-ledger",
        )
        assert idempotency_key == "model-precharge:" + payload["call_id"]
        state.precharges.append(dict(payload))
        return True

    ledger._append_event = AsyncMock(side_effect=precharge)
    ledger._invoice_events = AsyncMock(return_value=[])
    ledger._precharge_events = AsyncMock(return_value={})
    ledger._joined_db = state
    ledger._joined_session = db
    return ledger


def _ready(monkeypatch, *, row=None, ledger=None):
    _policy(monkeypatch, row or _ROW)
    monkeypatch.setenv("OPENAI_API_KEY", "controlled-test-credential-no-provider")
    RequestContext.bind(engagement_id="eng-pinned", task_id="task-pinned")
    return ledger if ledger is not None else _joined_ledger(monkeypatch)


@pytest.mark.asyncio
async def test_v2_complete_uses_real_client_role_gate_then_signed_pg_reservation(monkeypatch):
    ledger = _ready(monkeypatch)
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    fake = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="controlled response"))],
        usage=SimpleNamespace(prompt_tokens=3, completion_tokens=4),
    )
    with patch(
        "ai_osop.core.llm_client.litellm.acompletion",
        new_callable=AsyncMock,
        return_value=fake,
    ) as provider:
        output = await client.complete([{"role": "user", "content": "lab model only"}])
    assert output == "controlled response"
    ledger.session_memory.load_task_authoritative.assert_awaited_once_with("task-pinned")
    ledger.reserve.assert_awaited_once_with(
        "eng-pinned", "task-pinned", "openai/model-one", "completion"
    )
    ledger.settle.assert_awaited_once()
    provider.assert_awaited_once()
    assert provider.call_args.kwargs["num_retries"] == 0
    assert provider.call_args.kwargs["api_key"] == "controlled-test-credential-no-provider"
    db = ledger._joined_db
    assert db.commits == 2 and db.rollbacks == 0
    assert len(db.model_calls) == len(db.precharges) == 1
    assert db.model_calls[0].status == "reserved"
    assert db.precharges[0]["version"] == 4
    assert db.precharges[0]["source"] == "signed_operator_worst_case"
    assert db.locked_task_reads == 1
    assert db.signed_checks == 2, "Preflight and reserve must both check signed ROE"
    # Preflight AND the reservation independently perform actual signed ROE,
    # current Task, pinned Flow and dispatched lease verification.
    sql = "\n".join(db.queries)
    for name in ("session_states", "tasks", "execution_flows", "supervision_execution_leases"):
        assert sql.count("FROM " + name) >= 2


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [AgentType.RECON, "vuln_analysis", None])
async def test_v2_untrusted_role_never_reaches_provider_or_charges(monkeypatch, role):
    ledger = _ready(monkeypatch, ledger=_joined_ledger(monkeypatch, role=role))
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ProviderRouteDenied):
            await client.complete([{"role": "user", "content": "lab model only"}])
    provider.assert_not_awaited()
    ledger.reserve.assert_not_awaited()
    assert ledger._joined_db.precharges == []


@pytest.mark.asyncio
async def test_v2_capability_output_bound_checked_before_pg_or_remote(monkeypatch):
    ledger = _ready(monkeypatch)
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ProviderRouteDenied):
            await client.complete([{"role": "user", "content": "lab only"}], max_tokens=4097)
    ledger.reserve.assert_not_awaited()
    provider.assert_not_awaited()


@pytest.mark.asyncio
async def test_v2_embedding_uses_original_pg_task_role_gate(monkeypatch):
    emb = copy.deepcopy(_ROW)
    emb.update(
        model="text-embedding-3-small",
        operations=["embedding"],
        capabilities=["embeddings"],
    )
    ledger = _ready(monkeypatch, row=emb)
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch(
        "ai_osop.core.llm_client.litellm.aembedding",
        new_callable=AsyncMock,
        return_value={"data": [{"embedding": [0.25, 0.5]}]},
    ) as provider:
        output = await client.get_embedding("this is only a controlled lab vector")
    assert output == [0.25, 0.5]
    ledger.reserve.assert_awaited_once_with(
        "eng-pinned", "task-pinned", "text-embedding-3-small", "embedding"
    )
    provider.assert_awaited_once()
    assert len(ledger._joined_db.precharges) == 1
    assert ledger._joined_db.task_query_count == 3
    assert ledger._joined_db.locked_task_reads == 1
    assert ledger._joined_db.signed_checks == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_authority",
    [
        "engagement_halted",
        "engagement_completed",
        "scope_missing_authorization_ref",
        "scope_missing_target",
        "window_not_started",
        "window_expired",
        "signed_authorization_revoked",
        "signed_version_changed",
        "flow_stopped",
        "flow_revision_changed",
        "lease_reserved_not_dispatched",
        "lease_expired",
    ],
)
async def test_real_client_denies_untrusted_current_authority_before_spend_or_provider(
    monkeypatch, bad_authority
):
    ledger = _ready(monkeypatch)
    state = ledger._joined_db
    if bad_authority == "engagement_halted":
        state.engagement.phase = "halted"
    elif bad_authority == "engagement_completed":
        state.engagement.phase = "completed"
    elif bad_authority == "scope_missing_authorization_ref":
        state.engagement.scope.pop("authorization_ref")
    elif bad_authority == "scope_missing_target":
        state.engagement.scope["domains"] = []
    elif bad_authority == "window_not_started":
        state.engagement.scope["testing_window_start"] = datetime.utcnow() + timedelta(hours=2)
    elif bad_authority == "window_expired":
        state.engagement.scope["testing_window_end"] = datetime.utcnow() - timedelta(hours=2)
    elif bad_authority == "signed_authorization_revoked":
        state.signer_active = False
    elif bad_authority == "signed_version_changed":
        state.signed_version += 1
    elif bad_authority == "flow_stopped":
        state.flow.status = "paused"
    elif bad_authority == "flow_revision_changed":
        state.flow.revision += 1
    elif bad_authority == "lease_reserved_not_dispatched":
        state.lease.state = "reserved"
    elif bad_authority == "lease_expired":
        state.lease.expires_at = datetime.utcnow() - timedelta(seconds=5)

    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ModelBudgetExceeded):
            await client.complete([{"role": "user", "content": "controlled fixture"}])
    provider.assert_not_awaited()
    ledger.reserve.assert_not_awaited()
    assert state.model_calls == state.precharges == []


@pytest.mark.asyncio
async def test_lease_revocation_after_preflight_is_blocked_by_actual_reserve_transaction(
    monkeypatch,
):
    ledger = _ready(monkeypatch)
    state = ledger._joined_db
    # The first signed Task/Flow/lease preflight genuinely succeeds. Immediately
    # BEFORE the real ModelUsageLedger.reserve, simulate durable revocation.
    # The reserve transaction must independently reject the stale lease.
    real_reserve = ledger.reserve

    async def revoked_during_dispatch(*args, **kwargs):
        assert state.signed_checks == 1
        assert state.commits == 1
        state.lease.state = "released"
        return await real_reserve(*args, **kwargs)

    ledger.reserve = AsyncMock(side_effect=revoked_during_dispatch)
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ModelBudgetExceeded):
            await client.complete([{"role": "user", "content": "controlled fixture"}])
    provider.assert_not_awaited()
    ledger.reserve.assert_awaited_once()
    assert state.signed_checks == 2
    assert state.rollbacks == 1
    assert state.model_calls == state.precharges == []


@pytest.mark.asyncio
async def test_v2_denies_missing_source_task_without_paid_probe(monkeypatch):
    ledger = _ready(monkeypatch)
    RequestContext.clear()
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ProviderRouteDenied):
            await client.complete([{"role": "user", "content": "lab only"}])
    ledger.reserve.assert_not_awaited()
    provider.assert_not_awaited()
