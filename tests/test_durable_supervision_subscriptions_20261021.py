"""Deterministic PostgreSQL transaction model, NOT an actual PG qualification.

The fake executes the real store's SQL operation shapes with a shared lock,
snapshot rollback, simulated database clock and mutually exclusive replicas.
It does not substitute for 0040 DDL execution on isolated PostgreSQL.
"""

from __future__ import annotations

import asyncio
import copy
import importlib.util
import sys
import types
import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest

# Loading the isolated module avoids ai_osop.memory.__init__ importing optional
# graph/LLM providers. On a stripped qualification host, the only SQLAlchemy
# primitive this file uses is text(); a string shim is enough for the fake.
# Real PostgreSQL execution remains a separate qualification, never implied.
if importlib.util.find_spec("sqlalchemy") is None:
    _sqlalchemy = types.ModuleType("sqlalchemy")
    _sqlalchemy.text = lambda statement: statement
    sys.modules.setdefault("sqlalchemy", _sqlalchemy)
_path = Path(__file__).resolve().parents[1] / "src/ai_osop/memory/durable_supervision_subscriptions.py"
_spec = importlib.util.spec_from_file_location("_isolated_durable_supervision_subscriptions", _path)
assert _spec is not None and _spec.loader is not None
_module = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)
DurableSupervisionSubscriptions = _module.DurableSupervisionSubscriptions
SubscriberPrincipal = _module.SubscriberPrincipal
SubscriptionDenied = _module.SubscriptionDenied


def _run_async(fn):
    @wraps(fn)
    def runner(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))
    return runner


class Result:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def mappings(self) -> "Result":
        return self

    def one_or_none(self) -> Optional[Dict[str, Any]]:
        return self.value

    def all(self) -> list[Dict[str, Any]]:
        return self.value

    def scalar_one_or_none(self) -> Any:
        return self.value


class SimulatedPostgres:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.now = datetime.now(timezone.utc)
        self.rows: dict[tuple[str, str], Dict[str, Any]] = {}
        self.owners = {"eng-a": "operator-a", "eng-b": "operator-b"}
        self.tasks = {("eng-a", "task-a"), ("eng-b", "task-b")}
        self.events = [
            {"sequence": 12, "id": "evt-a12", "engagement_id": "eng-a",
             "task_id": "task-a", "kind": "agent.message", "actor_id": "operator-a",
             "payload": {"message": "ok"}, "created_at": self.now},
            {"sequence": 13, "id": "evt-b13", "engagement_id": "eng-b",
             "task_id": "task-b", "kind": "agent.message", "actor_id": "operator-b",
             "payload": {"message": "other tenant"}, "created_at": self.now},
            {"sequence": 18, "id": "evt-a18", "engagement_id": "eng-a",
             "task_id": "task-a", "kind": "agent.message", "actor_id": "operator-a",
             "payload": {"message": "next"}, "created_at": self.now},
        ]
        self.statements: list[str] = []
        # These are simulated PG transaction settings only. This fake does
        # NOT establish a cross-process PostgreSQL table-lock guarantee.
        self.isolation = "read committed"
        self.revocation_table_available = True
        self.revocation_table_lock_conflict = False
        self.revocation_table_share_queries = 0

    def session(self) -> "Session":
        return Session(self)

    def _matched(self, p: dict[str, Any]) -> Optional[Dict[str, Any]]:
        row = self.rows.get((p["engagement"], p["subscriber"]))
        if row is None or any(row[key] != p[param] for key, param in (
            ("issuer", "issuer"), ("subject", "subject"),
            ("task", "task"), ("auth_version", "auth_version"),
            ("auth_sha", "auth_sha"),
        )):
            return None
        return row

    def _leased(self, p: dict[str, Any]) -> Optional[Dict[str, Any]]:
        row = self._matched(p)
        if (row is None or row["revoked_at"] is not None
            or row["lease_owner"] != p["replica"]
            or row["lease_id"] != p["lease_id"]
            or row["lease_generation"] != p["generation"]
            or row["lease_until"] is None or row["lease_until"] <= self.now):
            return None
        return row

    def _events(self, params: dict[str, Any]) -> list[Dict[str, Any]]:
        return sorted((e for e in self.events if
                       e["engagement_id"] == params["engagement"]
                       and e["sequence"] > params["cursor"]
                       and (params["task"] is None or e["task_id"] == params["task"])),
                      key=lambda event: event["sequence"])

    def execute(self, sql: str, params: dict[str, Any]) -> Result:
        self.statements.append(sql)
        if sql == "SELECT current_setting('transaction_isolation')":
            return Result(self.isolation)
        if sql.startswith("LOCK TABLE operator_token_revocations, operator_subject_controls"):
            assert sql == (
                "LOCK TABLE operator_token_revocations, operator_subject_controls "
                "IN SHARE MODE NOWAIT"
            )
            if not self.revocation_table_available:
                raise RuntimeError("Missing simulated operator revocation table")
            if self.revocation_table_lock_conflict:
                raise RuntimeError("Simulated revocation writer blocks SHARE NOWAIT")
            self.revocation_table_share_queries += 1
            return Result()
        if sql.startswith("SELECT created_by FROM session_states"):
            owner = self.owners.get(params["engagement"])
            return Result({"created_by": owner} if owner is not None else None)
        if sql.startswith("SELECT id FROM tasks"):
            ok = (params["engagement"], params["task"]) in self.tasks
            return Result(params["task"] if ok else None)
        if sql.startswith("INSERT INTO supervision_durable_subscriptions"):
            key = (params["engagement"], params["subscriber"])
            if key not in self.rows:
                self.rows[key] = {
                    "issuer": params["issuer"], "subject": params["subject"],
                    "task": params["task"], "auth_version": params["auth_version"],
                    "auth_sha": params["auth_sha"], "cursor_sequence": 0,
                    "lease_owner": None, "lease_id": None, "lease_until": None,
                    "lease_generation": 0, "revoked_at": None,
                }
            return Result()
        if sql.startswith("SELECT cursor_sequence,lease_owner"):
            row = self._matched(params)
            return Result(copy.deepcopy(row)) if row else Result()
        if sql.startswith("UPDATE supervision_durable_subscriptions SET lease_owner=:replica"):
            row = self._matched(params)
            if (row is None or row["revoked_at"] is not None
                or row["lease_generation"] != params["prior"]
                or (row["lease_id"] is not None and row["lease_until"] > self.now)):
                return Result()
            row.update(lease_owner=params["replica"], lease_id=params["lease_id"],
                       lease_generation=row["lease_generation"] + 1,
                       lease_until=self.now + timedelta(seconds=params["ttl"]))
            return Result(copy.deepcopy(row))
        if sql.startswith("SELECT 1 FROM supervision_durable_subscriptions"):
            return Result(1 if self._leased(params) else None)
        if sql.startswith("UPDATE supervision_durable_subscriptions SET lease_until="):
            row = self._leased(params)
            if row is None:
                return Result()
            row["lease_until"] = self.now + timedelta(seconds=params["ttl"])
            return Result(copy.deepcopy(row))
        if sql.startswith("SELECT sequence,id,engagement_id"):
            return Result(copy.deepcopy(self._events(params)[:params["limit"]]))
        if sql.startswith("SELECT pg_advisory_xact_lock"):
            return Result(1)
        if sql.startswith("SELECT sequence FROM supervision_events"):
            events = self._events(params)
            return Result(events[0]["sequence"] if events else None)
        if sql.startswith("UPDATE supervision_durable_subscriptions SET cursor_sequence=:next"):
            row = self._leased(params)
            if row is None or row["cursor_sequence"] != params["cursor"]:
                return Result()
            row["cursor_sequence"] = params["next"]
            return Result(copy.deepcopy(row))
        if sql.startswith("UPDATE supervision_durable_subscriptions SET lease_owner=NULL"):
            row = self._leased(params)
            if row is None:
                return Result()
            row.update(lease_owner=None, lease_id=None, lease_until=None,
                       lease_generation=row["lease_generation"] + 1)
            return Result(row["lease_generation"])
        if sql.startswith("UPDATE supervision_durable_subscriptions SET revoked_at="):
            row = self._matched(params)
            if row is None or row["revoked_at"] is not None:
                return Result()
            row.update(revoked_at=self.now, lease_owner=None, lease_id=None,
                       lease_until=None, lease_generation=row["lease_generation"] + 1)
            return Result(row["lease_generation"])
        raise AssertionError("Unmodeled SQL operation: " + sql[:100])


class Session:
    def __init__(self, pg: SimulatedPostgres) -> None:
        self.pg = pg
        # This simulated dialect is strictly a test fixture capability. The
        # production store refuses an unbound or non-PostgreSQL session.
        self.bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    async def __aenter__(self) -> "Session":
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    @asynccontextmanager
    async def begin(self):
        async with self.pg.lock:
            before = copy.deepcopy(self.pg.rows)
            try:
                yield
            except BaseException:
                self.pg.rows = before
                raise

    async def execute(self, query: Any, params: Optional[dict[str, Any]] = None) -> Result:
        return self.pg.execute(str(query), params or {})


class Memory:
    def __init__(self, pg: SimulatedPostgres) -> None:
        self._async_session = pg.session


def principal(engagement: str = "eng-a", subject: str = "operator-a",
              *, subscriber: Optional[str] = None, task: Optional[str] = None,
              role: str = "operator") -> SubscriberPrincipal:
    return SubscriberPrincipal(
        engagement_id=engagement,
        subscriber_id=subscriber or "subscr-" + uuid.uuid4().hex,
        issuer="signed-issuer", subject=subject, role=role,
        expires_at=int(datetime.now(timezone.utc).timestamp()) + 3600,
        authorization_version=4, authorization_sha256="a" * 64,
        task_id=task,
    )


def adapter(pg: SimulatedPostgres, *, revoked: Optional[set[str]] = None,
            access_block: Optional[asyncio.Event] = None) -> DurableSupervisionSubscriptions:
    async def guard(db: Any, identity: SubscriberPrincipal) -> bool:
        if access_block is not None:
            await access_block.wait()
        return identity.subject not in (revoked or set())

    async def roe_guard(db: Any, engagement: str, *, expected_version: int,
                        expected_digest: str) -> object:
        if engagement not in pg.owners or expected_version != 4 or expected_digest != "a" * 64:
            return None
        return object()

    return DurableSupervisionSubscriptions(Memory(pg), credential_guard=guard,
                                           roe_guard=roe_guard)


@_run_async
async def test_two_replicas_race_exclusive_claim_and_recover_after_deadline():
    pg = SimulatedPostgres()
    owner = principal()
    one, two = adapter(pg), adapter(pg)
    result = await asyncio.gather(
        one.acquire(owner, "replica-one"), two.acquire(owner, "replica-two"),
        return_exceptions=True,
    )
    winners = [r for r in result if not isinstance(r, BaseException)]
    denials = [r for r in result if isinstance(r, SubscriptionDenied)]
    assert len(winners) == len(denials) == 1
    first = winners[0]
    pg.now += timedelta(seconds=31)
    second = await two.acquire(owner, "replica-recovery")
    assert second.lease_id != first.lease_id
    assert second.generation == first.generation + 1
    with pytest.raises(SubscriptionDenied, match="replaced"):
        await one.read_batch(owner, first)
    with pytest.raises(SubscriptionDenied, match="replaced"):
        await one.acknowledge(owner, first, expected_cursor=0, next_sequence=12)


@_run_async
async def test_contiguous_scoped_cursor_cas_survives_restart_and_filters_other_tenant():
    pg = SimulatedPostgres()
    owner = principal(task="task-a")
    store = adapter(pg)
    lease = await store.acquire(owner, "replica-one")
    events = await store.read_batch(owner, lease)
    assert [e["sequence"] for e in events] == [12, 18]
    with pytest.raises(SubscriptionDenied, match="skipped"):
        await store.acknowledge(owner, lease, expected_cursor=0, next_sequence=18)
    assert pg.rows[(owner.engagement_id, owner.subscriber_id)]["cursor_sequence"] == 0
    after = await store.acknowledge(owner, lease, expected_cursor=0, next_sequence=12)
    assert after.cursor == 12
    with pytest.raises(SubscriptionDenied, match="Stale"):
        await store.acknowledge(owner, lease, expected_cursor=0, next_sequence=12)
    after2 = await store.acknowledge(owner, after, expected_cursor=12, next_sequence=18)
    assert after2.cursor == 18
    await store.release(owner, after2)
    replacement = await adapter(pg).acquire(owner, "replica-recovered")
    assert replacement.cursor == 18
    assert await adapter(pg).read_batch(owner, replacement) == []
    assert any("pg_advisory_xact_lock(hashtextextended(:engagement, 8044))" in stmt
               for stmt in pg.statements)


@_run_async
async def test_expired_lease_cannot_ack_or_renew_even_if_same_owner():
    pg = SimulatedPostgres()
    owner = principal()
    store = adapter(pg)
    lease = await store.acquire(owner, "replica-one", lease_seconds=5)
    pg.now += timedelta(seconds=6)
    for action in (
        store.read_batch(owner, lease),
        store.acknowledge(owner, lease, expected_cursor=0, next_sequence=12),
        store.renew(owner, lease),
        store.release(owner, lease),
    ):
        with pytest.raises(SubscriptionDenied, match="expired"):
            await action
    assert pg.rows[(owner.engagement_id, owner.subscriber_id)]["cursor_sequence"] == 0


@_run_async
async def test_revocation_is_permanent_and_fences_current_and_future_replicas():
    pg = SimulatedPostgres()
    owner = principal()
    store = adapter(pg)
    lease = await store.acquire(owner, "replica-one")
    await store.revoke(owner)
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.read_batch(owner, lease)
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await adapter(pg).acquire(owner, "replica-new")
    assert pg.rows[(owner.engagement_id, owner.subscriber_id)]["revoked_at"] == pg.now
    with pytest.raises(SubscriptionDenied):
        await store.revoke(owner)


@_run_async
async def test_immutable_subscriber_owner_tenant_task_and_signed_roe():
    pg = SimulatedPostgres()
    owner = principal(task="task-a")
    store = adapter(pg)
    await store.acquire(owner, "replica-one")
    mutants = (
        replace(owner, engagement_id="eng-b"),
        replace(owner, subject="operator-b"),
        replace(owner, issuer="other-issuer"),
        replace(owner, task_id="task-b"),
        replace(owner, authorization_version=5),
        replace(owner, authorization_sha256="b" * 64),
    )
    for mutant in mutants:
        with pytest.raises(SubscriptionDenied):
            await store.acquire(mutant, "replica-rogue")
    assert len(pg.rows) == 1
    assert pg.rows[(owner.engagement_id, owner.subscriber_id)]["lease_generation"] == 1


@_run_async
async def test_revoked_signed_principal_rolls_back_mutation():
    pg = SimulatedPostgres()
    revoked: set[str] = set()
    owner = principal()
    store = adapter(pg, revoked=revoked)
    first = await store.acquire(owner, "replica-one")
    revoked.add(owner.subject)
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.acknowledge(owner, first, expected_cursor=0, next_sequence=12)
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.renew(owner, first)
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.revoke(owner)
    assert pg.rows[(owner.engagement_id, owner.subscriber_id)]["cursor_sequence"] == 0


@_run_async
async def test_guard_revocation_after_ack_update_rolls_back_cursor_commit():
    pg = SimulatedPostgres()
    owner = principal()
    store = adapter(pg)
    lease = await store.acquire(owner, "replica-one")
    checks = 0

    async def expires_mid_transaction(db: Any, identity: SubscriberPrincipal) -> bool:
        nonlocal checks
        checks += 1
        return checks < 2

    store._credential_guard = expires_mid_transaction
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.acknowledge(owner, lease, expected_cursor=0, next_sequence=12)
    assert checks == 2
    assert pg.rows[(owner.engagement_id, owner.subscriber_id)]["cursor_sequence"] == 0


@_run_async
async def test_revocation_and_ack_race_serializes_and_tombstone_stays_revoked():
    pg = SimulatedPostgres()
    owner = principal()
    store = adapter(pg)
    lease = await store.acquire(owner, "replica-one")
    results = await asyncio.gather(
        store.revoke(owner),
        store.acknowledge(owner, lease, expected_cursor=0, next_sequence=12),
        return_exceptions=True,
    )
    assert results[0] is None
    assert isinstance(results[1], (SubscriptionDenied, type(lease)))
    row = pg.rows[(owner.engagement_id, owner.subscriber_id)]
    assert row["revoked_at"] is not None
    assert row["cursor_sequence"] in {0, 12}
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.acknowledge(owner, lease, expected_cursor=0, next_sequence=12)


@_run_async
async def test_event_envelopes_are_bounded_before_returning_to_sse_emitter():
    pg = SimulatedPostgres()
    owner = principal()
    store = adapter(pg)
    lease = await store.acquire(owner, "replica-one")
    pg.events[0]["payload"] = {"oversized": "x" * 9000}
    with pytest.raises(SubscriptionDenied, match="Oversized"):
        await store.read_batch(owner, lease)
    assert pg.rows[(owner.engagement_id, owner.subscriber_id)]["cursor_sequence"] == 0


@_run_async
async def test_fail_closed_invalid_cursor_lease_identity_and_missing_credential_guard():
    pg = SimulatedPostgres()
    owner = principal()
    with pytest.raises(SubscriptionDenied, match="verifier"):
        DurableSupervisionSubscriptions(Memory(pg), credential_guard=None)
    store = adapter(pg)
    lease = await store.acquire(owner, "replica-one")
    for cursor in (-1, 2**63, True):
        with pytest.raises(SubscriptionDenied, match="cursor"):
            await store.acknowledge(owner, lease, expected_cursor=cursor, next_sequence=12)
    with pytest.raises(SubscriptionDenied, match="Foreign"):
        await store.read_batch(replace(owner, subscriber_id="subscr-" + "f" * 32), lease)
    with pytest.raises(SubscriptionDenied, match="scoped"):
        await store.acquire(replace(owner, expires_at=1), "replica-two")
    with pytest.raises(SubscriptionDenied, match="scoped"):
        await store.acquire(replace(owner, task_id="task-" + "x" * 60), "replica-two")
    assert pg.rows[(owner.engagement_id, owner.subscriber_id)]["cursor_sequence"] == 0


def test_sql_contract_contains_recheck_fences_without_app_database():
    import inspect

    source = inspect.getsource(DurableSupervisionSubscriptions)
    assert "ON CONFLICT (engagement_id,subscriber_id) DO NOTHING" in source
    assert "authorization_version=:auth_version AND authorization_sha256=:auth_sha" in source
    assert "task_id IS NOT DISTINCT FROM :task" in source
    assert "lease_generation=:generation AND revoked_at IS NULL" in source
    assert "lease_until>clock_timestamp()" in source
    assert "cursor_sequence=:cursor" in source
    assert "pg_advisory_xact_lock(hashtextextended(:engagement, 8044))" in source
    assert "await self._authorize(db, principal)" in source
