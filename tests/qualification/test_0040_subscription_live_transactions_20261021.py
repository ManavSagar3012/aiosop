"""Opt-in real PG16 *worker42 store SQL* concurrency qualification.

Unlike the separate 0040 migration-only qualification, this imports the real
DurableSupervisionSubscriptions class and executes its original async methods
with PostgreSQL/psycopg AsyncSession transactions. The auth/ROE callbacks are
deliberately controlled TEST FIXTURES, not independently enrolled signatures.

Scope: new nonroot private Unix-socket-only PostgreSQL16 instance, minimal
session/Task/supervision-event predecessors, actual online 0040 Alembic upgrade.
No app DB, providers/targets, network listener, Docker or Git operations.
Opt in explicitly with OSOP_0040_SUBSCRIPTION_LIVE_PG=1.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_0040_SUBSCRIPTION_LIVE_PG"
STORE = ROOT / "src/ai_osop/memory/durable_supervision_subscriptions.py"
MIGRATION = ROOT / "migrations/versions/0040_supervision_durable_subscriptions.py"


def _linux_path(path: Path) -> str:
    raw = str(path.resolve())
    if os.name != "nt":
        return raw
    assert len(raw) > 3 and raw[1:3] == ":\\"
    return "/mnt/" + raw[0].lower() + raw[2:].replace("\\", "/")


def test_0040_live_qualification_requires_production_store_and_migration() -> None:
    """Lightweight default: no database, migration execution, or stubbed store."""
    source = STORE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    methods = {
        node.name
        for cls in tree.body if isinstance(cls, ast.ClassDef)
        and cls.name == "DurableSupervisionSubscriptions"
        for node in cls.body if isinstance(node, ast.AsyncFunctionDef)
    }
    assert {"acquire", "renew", "read_batch", "acknowledge", "release", "revoke"} <= methods
    assert "pg_advisory_xact_lock(hashtextextended(:engagement, 8044))" in source
    revision = MIGRATION.read_text(encoding="utf-8")
    assert "revision = \"0040\"" in revision
    assert "down_revision = \"0039\"" in revision


_LIVE_LINUX = r"""
import asyncio
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
import psycopg
from psycopg.rows import dict_row

assert os.name == "posix" and os.geteuid() != 0
PG = Path("/usr/lib/postgresql/16/bin")
assert all((PG / x).is_file() for x in ("initdb", "pg_ctl", "psql"))

def module_from_file(name, filename):
    path = ROOT / filename
    assert path.is_file(), path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    instance = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = instance
    spec.loader.exec_module(instance)
    return instance

migration = module_from_file(
    "_isolated_subscription_migration_0040",
    "migrations/versions/0040_supervision_durable_subscriptions.py",
)
revocation_migration = module_from_file(
    "_isolated_subscription_migration_0014",
    "migrations/versions/0014_operator_revocation.py",
)
source = module_from_file(
    "_isolated_subscription_store_0040",
    "src/ai_osop/memory/durable_supervision_subscriptions.py",
)
assert migration.revision == "0040" and migration.down_revision == "0039"
assert revocation_migration.revision == "0014"
Store = source.DurableSupervisionSubscriptions
Principal = source.SubscriberPrincipal
Denied = source.SubscriptionDenied

def process(*cmd):
    return subprocess.run(cmd, check=False, text=True, capture_output=True, timeout=40)

TENANT_A = "eng-durable-live-a"
TENANT_B = "eng-durable-live-b"
TASK_A = "task-durable-a"
TASK_OTHER = "task-durable-other"
AUTH_SHA = "a" * 64
TOKEN_DIGEST = "c" * 64  # Fixture token ID only. No enrolled/real bearer.

def identity(tenant=TENANT_A, task=TASK_A, subscriber=None, subject=None):
    return Principal(
        engagement_id=tenant,
        subscriber_id=subscriber or "subscr-" + uuid.uuid4().hex,
        issuer="fixture-test-issuer",
        subject=subject or ("owner-a" if tenant == TENANT_A else "owner-b"),
        role="operator",
        expires_at=int(datetime.now(timezone.utc).timestamp()) + 3600,
        authorization_version=2,
        authorization_sha256=AUTH_SHA,
        task_id=task,
    )

class Memory:
    def __init__(self, factory):
        self._async_session = factory

PG_DIALECT = postgresql.dialect(paramstyle="pyformat")

class PsycopgResult:
    '''Only SQLAlchemy AsyncResult methods used by the unmodified store.'''
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows

    def one_or_none(self):
        assert len(self._rows) <= 1
        return self._rows[0] if self._rows else None

    def scalar_one_or_none(self):
        result = self.one_or_none()
        return next(iter(result.values())) if result is not None else None

    def scalar_one(self):
        assert len(self._rows) == 1, self._rows
        return next(iter(self._rows[0].values()))

class LivePsycopgSession:
    '''Independent genuine PG backend; adapt only I/O, never store semantics.'''
    def __init__(self, socket, port, bind):
        self._socket = socket
        self._port = port
        self._conn = None
        self.bind = bind  # Actual SQLAlchemy PostgreSQL Engine, not a fake dialect.

    async def __aenter__(self):
        self._conn = await psycopg.AsyncConnection.connect(
            "dbname=postgres user=osop_0040_live",
            host=str(self._socket), port=self._port, connect_timeout=4,
            autocommit=True, row_factory=dict_row,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._conn is not None:
            await self._conn.close()

    @asynccontextmanager
    async def begin(self):
        assert self._conn is not None
        async with self._conn.transaction():
            yield self

    async def execute(self, statement, params=None):
        assert self._conn is not None
        # SQLAlchemy text(...) is compiled via its real PostgreSQL pyformat
        # compiler. Parameter substitution belongs to psycopg/libpq; the
        # original worker42 SQL source is not rewritten or interpreted.
        if isinstance(statement, sa.sql.elements.TextClause):
            sql = str(statement.compile(dialect=PG_DIALECT))
        else:
            raise AssertionError("Unrecognized worker42 SQL source")
        cursor = await self._conn.execute(sql, params or {})
        return PsycopgResult(await cursor.fetchall() if cursor.description else [])

async def run_cases(socket, port):
    # The Linux host has pure Python SQLAlchemy/Alembic/psycopg but not a
    # Linux greenlet extension, so SQLAlchemy AsyncSession is not available.
    # Each controlled adapter session instead owns an actual async psycopg
    # PostgreSQL connection and explicit transaction. Every worker42 text()
    # query is compiled with the real SQLAlchemy PostgreSQL pyformat dialect.
    sync_engine = sa.create_engine(
        "postgresql+psycopg://osop_0040_live@/postgres",
        connect_args={"host": str(socket), "port": port, "connect_timeout": 4},
        pool_size=2, max_overflow=2, pool_timeout=8,
    )
    def factory():
        return LivePsycopgSession(socket, port, sync_engine)
    credentials_revoked = set()
    roe_revoked = set()
    check_counts = {"credentials": 0, "roe": 0}

    async def live_fixture_credential_guard(db, principal):
        check_counts["credentials"] += 1
        # A test callback, intentionally NOT a verified signed bearer. Unlike
        # a mock, its revocation/disable lookups run against the real 0014
        # PostgreSQL tables in the exact active store transaction.
        revoked_token = (await db.execute(text(
            "SELECT EXISTS(SELECT 1 FROM operator_token_revocations "
            "WHERE digest=:digest)"
        ), {"digest": TOKEN_DIGEST})).scalar_one()
        disabled = (await db.execute(text(
            "SELECT COALESCE((SELECT disabled FROM operator_subject_controls "
            "WHERE actor_id=:subject),false)"
        ), {"subject": principal.subject})).scalar_one()
        return (not revoked_token and not disabled
                and principal.subject not in credentials_revoked
                and principal.issuer == "fixture-test-issuer")

    async def fixture_roe_guard(db, engagement, *, expected_version, expected_digest):
        check_counts["roe"] += 1
        # No real signed ROE or enrollment in this isolated test.
        if (engagement in roe_revoked or expected_version != 2
                or expected_digest != AUTH_SHA):
            return None
        return object()

    memory = Memory(factory)
    def store():
        return Store(memory, credential_guard=live_fixture_credential_guard,
                     roe_guard=fixture_roe_guard)

    async def db_scalar(sql, p=None):
        async with factory() as db:
            return (await db.execute(text(sql), p or {})).scalar_one()

    async def event(tenant=TENANT_A, task=TASK_A, kind="message", *, rollback=False,
                    started=None, gate=None):
        # Producer uses the SAME per-tenant transaction-scoped advisory lock as
        # actual supervision_store._append_event. It is fixture event creation,
        # NOT the full original producer's control plane or idempotency flow.
        async with factory() as db:
            try:
                async with db.begin():
                    await db.execute(text(
                        "SELECT pg_advisory_xact_lock(hashtextextended(:eng, 8044))"
                    ), {"eng": tenant})
                    seq = (await db.execute(text(
                        "INSERT INTO supervision_events "
                        "(id,engagement_id,task_id,kind,actor_id,payload) "
                        "VALUES (:id,:eng,:task,:kind,'fixture-producer',"
                        "CAST(:payload AS jsonb)) RETURNING sequence"
                    ), {"id": "evt-" + uuid.uuid4().hex, "eng": tenant,
                        "task": task, "kind": kind,
                        "payload": json.dumps({"fixture": True, "kind": kind})}
                    )).scalar_one()
                    if started is not None:
                        started.set()
                    if gate is not None:
                        await asyncio.wait_for(gate.wait(), timeout=8)
                    if rollback:
                        raise RuntimeError("fixture-producer-transaction-rollback")
                return seq
            except RuntimeError as exc:
                if rollback and str(exc) == "fixture-producer-transaction-rollback":
                    return seq
                raise

    async def fetch(engagement_id, subscriber_id):
        async with factory() as db:
            result = await db.execute(text(
                "SELECT cursor_sequence, lease_generation, lease_owner, "
                "lease_id, lease_until, revoked_at FROM "
                "supervision_durable_subscriptions "
                "WHERE engagement_id=:e AND subscriber_id=:s"
            ), {"e": engagement_id, "s": subscriber_id})
            return result.mappings().one_or_none()

    async def denied(awaitable, label):
        try:
            await awaitable
        except Denied:
            return
        raise AssertionError(label + " unexpectedly succeeded")

    try:
        # Independently connected async sessions, not a single mock connection.
        async with factory() as one, factory() as two:
            async with one.begin(), two.begin():
                pid1 = (await one.execute(text("SELECT pg_backend_pid()"))).scalar_one()
                pid2 = (await two.execute(text("SELECT pg_backend_pid()"))).scalar_one()
                assert pid1 != pid2, (pid1, pid2)

        # Genuine migration DDL in this independently disposable DB.
        with sync_engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE session_states "
                "(session_id varchar(64) PRIMARY KEY, created_by varchar(64) NOT NULL)"
            ))
            conn.execute(text(
                "CREATE TABLE tasks (id varchar(64) PRIMARY KEY, "
                "engagement_id varchar(64) NOT NULL)"
            ))
            conn.execute(text(
                "CREATE TABLE supervision_events ("
                "sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "
                "id varchar(64) NOT NULL UNIQUE, "
                "engagement_id varchar(64) NOT NULL, task_id varchar(64), "
                "kind varchar(64) NOT NULL, actor_id varchar(64) NOT NULL, "
                "payload jsonb NOT NULL, created_at timestamp "
                "NOT NULL DEFAULT now())"
            ))
            for tenant, owner in ((TENANT_A, "owner-a"), (TENANT_B, "owner-b")):
                conn.execute(text(
                    "INSERT INTO session_states (session_id,created_by) "
                    "VALUES (:t,:o)"
                ), {"t": tenant, "o": owner})
            for task, tenant in ((TASK_A, TENANT_A), (TASK_OTHER, TENANT_A),
                                 ("task-foreign", TENANT_B)):
                conn.execute(text(
                    "INSERT INTO tasks (id,engagement_id) VALUES (:t,:eng)"
                ), {"t": task, "eng": tenant})
            ctx = MigrationContext.configure(
                conn, opts={"transactional_ddl": True}
            )
            assert ctx.impl.transactional_ddl and not ctx.as_sql
            with Operations.context(ctx):
                # Real 0014 DDL with no 0013 predecessor side-effects;
                # minimal predecessor schema, not full app migration history.
                revocation_migration.upgrade()
                migration.upgrade()

        # Two actually independent 0040 store calls race inserting/claiming
        # the SAME tenant+subscriber. Must be one winner and one denial.
        who = identity()
        first, second = store(), store()
        acquired = await asyncio.gather(
            first.acquire(who, "replica-first"),
            second.acquire(who, "replica-second"),
            return_exceptions=True,
        )
        leases = [result for result in acquired
                  if isinstance(result, source.SubscriberLease)]
        failures = [result for result in acquired if isinstance(result, Denied)]
        assert len(leases) == len(failures) == 1, acquired
        active = leases[0]
        assert active.generation == 1 and active.cursor == 0
        assert (await fetch(TENANT_A, who.subscriber_id))["lease_owner"] == active.replica_id
        await denied(
            second.acquire(who, "replica-forbidden"), "second active claim"
        )

        # Same subscriber ID under distinct tenant must not alias cursor/lease.
        other = identity(tenant=TENANT_B, task=None, subscriber=who.subscriber_id)
        other_lease = await store().acquire(other, "replica-foreign")
        assert other_lease.cursor == 0
        await denied(
            store().acquire(identity(tenant=TENANT_A, task="task-foreign",
                                     subscriber="subscr-" + uuid.uuid4().hex),
                            "replica-cross-task"),
            "cross-tenant task owner",
        )
        await denied(
            store().acquire(identity(tenant=TENANT_A, subject="owner-b",
                                     subscriber="subscr-" + uuid.uuid4().hex),
                            "replica-wrong-owner"),
            "wrong tenant owner",
        )

        # Real committed event rows and sorted tenant+task filters.
        e1 = await event(kind="first")
        _ = await event(tenant=TENANT_B, task=None, kind="foreign-tenant")
        _ = await event(task=TASK_OTHER, kind="foreign-task")
        e2 = await event(kind="second")
        assert [row["sequence"] for row in await first.read_batch(who, active)] == [
            e1, e2
        ]
        await denied(
            first.acknowledge(who, active, expected_cursor=0, next_sequence=e2),
            "skipped first eligible event",
        )
        await denied(
            first.acknowledge(who, active, expected_cursor=0, next_sequence=e2 + 100),
            "forged sequence",
        )
        assert (await fetch(TENANT_A, who.subscriber_id))["cursor_sequence"] == 0
        ack1 = await first.acknowledge(
            who, active, expected_cursor=0, next_sequence=e1
        )
        assert ack1.cursor == e1
        await denied(
            first.acknowledge(who, active, expected_cursor=0, next_sequence=e1),
            "lost-ACK duplicate cursor replay",
        )
        ack2 = await first.acknowledge(
            who, ack1, expected_cursor=e1, next_sequence=e2
        )
        assert ack2.cursor == e2
        assert (await fetch(TENANT_B, who.subscriber_id))["cursor_sequence"] == 0

        # Concurrent producer holds the genuine transaction advisory lock:
        # ACK must block until producer commits, then observe the real row.
        producer_ready, allow_commit = asyncio.Event(), asyncio.Event()
        pending_producer = asyncio.create_task(event(
            kind="withheld-commit", started=producer_ready, gate=allow_commit,
        ))
        await asyncio.wait_for(producer_ready.wait(), timeout=6)
        # Sequence read from test-controlled producer's outstanding transaction
        # after its ready flag, before commit. No other subscriber can see it.
        seq_pending = await db_scalar(
            "SELECT last_value FROM supervision_events_sequence_seq"
        )
        pending_ack = asyncio.create_task(first.acknowledge(
            who, ack2, expected_cursor=e2, next_sequence=seq_pending,
        ))
        try:
            await asyncio.wait_for(asyncio.shield(pending_ack), timeout=0.20)
        except asyncio.TimeoutError:
            pass
        else:
            raise AssertionError("ACK advanced over uncommitted event")
        assert (await fetch(TENANT_A, who.subscriber_id))["cursor_sequence"] == e2
        allow_commit.set()
        assert await asyncio.wait_for(pending_producer, timeout=8) == seq_pending
        after_commit = await asyncio.wait_for(pending_ack, timeout=8)
        assert after_commit.cursor == seq_pending

        # Producer transaction rollback must NOT publish a committed event
        # or allow the worker42 ACK CAS to advance.
        aborted = await event(kind="uncommitted-abort", rollback=True)
        await denied(
            first.acknowledge(
                who, after_commit, expected_cursor=seq_pending,
                next_sequence=aborted,
            ), "ACK of uncommitted producer event"
        )
        assert (await fetch(TENANT_A, who.subscriber_id))["cursor_sequence"] == seq_pending

        # Fixture live-identity callback denies on the second transaction
        # authorization guard, AFTER 0040 cursor UPDATE, forcing real PG ROLLBACK.
        next_valid = await event(kind="after-rollback")
        guards = {"calls": 0}
        async def revoke_during_commit(db, principal):
            guards["calls"] += 1
            return guards["calls"] == 1
        ephemeral = Store(memory, credential_guard=revoke_during_commit,
                          roe_guard=fixture_roe_guard)
        await denied(
            ephemeral.acknowledge(
                who, after_commit, expected_cursor=seq_pending,
                next_sequence=next_valid,
            ), "mid-transaction revoked identity"
        )
        assert guards["calls"] >= 2
        assert (await fetch(TENANT_A, who.subscriber_id))["cursor_sequence"] == seq_pending
        after_rollback = await first.acknowledge(
            who, after_commit, expected_cursor=seq_pending,
            next_sequence=next_valid,
        )
        assert after_rollback.cursor == next_valid

        # Real release increments the durable generation, then a different
        # store instance (simulating restarted replica) acquires, retaining
        # cursor and denying former generation's ACK/renew/release.
        await first.release(who, after_rollback)
        recovered = await store().acquire(who, "replica-after-restart")
        assert recovered.cursor == next_valid
        assert recovered.generation >= after_rollback.generation + 2
        await denied(first.renew(who, after_rollback), "old release owner renew")
        await denied(first.read_batch(who, after_rollback), "old release owner read")
        await denied(first.release(who, after_rollback), "old release owner release")
        assert await store().read_batch(who, recovered) == []

        # Crash/lease expiry emulation: abandon lease (no release), then
        # backdate its deadline by test-only SQL. No actual process/host failover
        # is claimed. Old generation remains cryptographically inert.
        async with factory() as db:
            async with db.begin():
                await db.execute(text(
                    "UPDATE supervision_durable_subscriptions SET "
                    "lease_until=clock_timestamp()-interval '1 second' "
                    "WHERE engagement_id=:e AND subscriber_id=:s"
                ), {"e": TENANT_A, "s": who.subscriber_id})
        takeover = await store().acquire(who, "replica-after-crash")
        assert takeover.cursor == next_valid
        assert takeover.generation == recovered.generation + 1
        await denied(first.renew(who, recovered), "stale crash lease renew")
        await denied(first.read_batch(who, recovered), "stale crash lease read")

        # Competing revoke/renew/acquire are serialized by the exact row lock.
        # After a permanent revocation, even the previous lease and a fresh
        # store object cannot renew/recover/re-acquire.
        revoke_subject = identity(task=None)
        rev_store = store()
        rev_lease = await rev_store.acquire(revoke_subject, "replica-before-revoke")
        async def attempt_revoke():
            await store().revoke(revoke_subject)
            return "revoked"
        async def attempt_renew():
            try:
                await store().renew(revoke_subject, rev_lease)
                return "renewed-prior-to-revoke"
            except Denied:
                return "renew-refused"
        outcome = await asyncio.gather(attempt_revoke(), attempt_renew())
        assert "revoked" in outcome and outcome[1] in {
            "renewed-prior-to-revoke", "renew-refused"
        }
        tomb = await fetch(TENANT_A, revoke_subject.subscriber_id)
        assert tomb["revoked_at"] is not None and tomb["lease_owner"] is None
        await denied(
            rev_store.acquire(revoke_subject, "replica-post-revoke"),
            "revoked replica acquisition",
        )
        await denied(
            rev_store.renew(revoke_subject, rev_lease), "revoked replica renewal"
        )
        await denied(
            rev_store.revoke(revoke_subject), "duplicate revocation"
        )

        # Actual concurrent ON CONFLICT insert/acquire versus revoke on an
        # existing unleased principal row: final durable tombstone must win
        # irrespective of which PostgreSQL transaction serialized first.
        race_subject = identity(task=None)
        race_seed = await store().acquire(race_subject, "replica-race-seed")
        await store().release(race_subject, race_seed)
        async def race_subscribe():
            try:
                return await store().acquire(
                    race_subject, "replica-race-acquisition"
                )
            except Denied:
                return "acquire-denied"
        acquired_during_revoke, revoked_result = await asyncio.gather(
            race_subscribe(), store().revoke(race_subject),
        )
        assert revoked_result is None
        raced_row = await fetch(TENANT_A, race_subject.subscriber_id)
        assert raced_row["revoked_at"] is not None
        assert raced_row["lease_owner"] is None and raced_row["lease_id"] is None
        if isinstance(acquired_during_revoke, source.SubscriberLease):
            await denied(
                store().read_batch(race_subject, acquired_during_revoke),
                "acquire-before-revoke cannot keep lease alive",
            )
        else:
            assert acquired_during_revoke == "acquire-denied"
        await denied(
            store().acquire(race_subject, "replica-after-race-tombstone"),
            "ON CONFLICT must never reinstate revoked subscriber",
        )

        # Independent ROE/credential fixture revocation must reject the exact
        # principal before mutation and leave durable state unchanged.
        roe_revoked.add(TENANT_A)
        await denied(store().renew(who, takeover), "fixture ROE revocation")
        roe_revoked.remove(TENANT_A)
        credentials_revoked.add(who.subject)
        await denied(store().renew(who, takeover), "fixture credential revocation")
        credentials_revoked.remove(who.subject)
        assert (await fetch(TENANT_A, who.subscriber_id))["cursor_sequence"] == next_valid
        assert check_counts["credentials"] >= 30
        assert check_counts["roe"] >= 20

        # New production 0014 race fence: the principal's token/subject may
        # have NO revocation row at first authorization. An uncommitted INSERT
        # in either ledger holds ROW EXCLUSIVE; the real worker42
        # _fence_revocation_insert() must fail closed with SHARE NOWAIT, before
        # ACK/renew transaction commits. This is not a mocked lock.
        lock_principal = identity(task=None)
        lock_lease = await store().acquire(
            lock_principal, "replica-0014-real-lock",
        )
        async with factory() as writer:
            async with writer.begin():
                await writer.execute(text(
                    "INSERT INTO operator_subject_controls "
                    "(actor_id,disabled,updated_at,updated_by) "
                    "VALUES (:actor,true,clock_timestamp(),'fixture-writer')"
                ), {"actor": lock_principal.subject})
                await denied(
                    store().renew(lock_principal, lock_lease),
                    "uncommitted subject disable writer must be NOWAIT-fenced",
                )
        await denied(
            store().renew(lock_principal, lock_lease),
            "committed 0014 subject disable must fail credential callback",
        )
        # A principal with a DIFFERENT, correctly owned subject still reaches
        # the same 0014 table lock even with no matching ledger row.
        # Re-enable solely inside this isolated fixture to permit the next
        # positive lock trial; production re-enable requires senior approval.
        async with factory() as writer:
            async with writer.begin():
                await writer.execute(text(
                    "UPDATE operator_subject_controls SET disabled=false "
                    "WHERE actor_id=:actor"
                ), {"actor": lock_principal.subject})
        renewed_lock_lease = await store().renew(lock_principal, lock_lease)
        assert renewed_lock_lease.generation == lock_lease.generation

        # After worker42's SHARE NOWAIT fence is acquired, even an INSERT
        # for a formerly ABSENT subject row must block in another genuine PG
        # backend. A 400ms timeout proves lock contention, not cooperation
        # with the test credential callback or pre-existing row lock.
        hold_ready, hold_gate = asyncio.Event(), asyncio.Event()
        hold_counter = {"n": 0}
        async def hold_after_lock(db, principal):
            hold_counter["n"] += 1
            accepted = await live_fixture_credential_guard(db, principal)
            if hold_counter["n"] == 2:
                hold_ready.set()
                await asyncio.wait_for(hold_gate.wait(), timeout=6)
            return accepted
        holding = Store(memory, credential_guard=hold_after_lock,
                        roe_guard=fixture_roe_guard)
        pending_renew = asyncio.create_task(holding.renew(
            who, takeover, lease_seconds=30,
        ))
        await asyncio.wait_for(hold_ready.wait(), timeout=6)
        for sql, values in (
            (
                "INSERT INTO operator_token_revocations "
                "(digest,actor_id,expires_at,revoked_at) VALUES "
                "(:digest,:actor,clock_timestamp()+interval '1 hour',"
                "clock_timestamp())",
                {"digest": TOKEN_DIGEST, "actor": who.subject},
            ),
            (
                "INSERT INTO operator_subject_controls "
                "(actor_id,disabled,updated_at,updated_by) VALUES "
                "(:actor,true,clock_timestamp(),'fixture-writer') "
                "ON CONFLICT (actor_id) DO UPDATE SET disabled=true,"
                "updated_at=clock_timestamp()",
                {"actor": "never-present-fixture-subject"},
            ),
        ):
            try:
                async with factory() as writer:
                    async with writer.begin():
                        await writer.execute(text(
                            "SET LOCAL lock_timeout='400ms'"
                        ))
                        await writer.execute(text(sql), values)
            except psycopg.errors.LockNotAvailable as exc:
                assert exc.sqlstate == "55P03"
            else:
                raise AssertionError(
                    "0014 revocation writer incorrectly bypassed SHARE lock"
                )
        hold_gate.set()
        renewed_after_lock = await asyncio.wait_for(pending_renew, timeout=6)
        assert renewed_after_lock.generation == takeover.generation

        # A competing token INSERT was not visible at the initial no-row
        # credential check: an uncommitted writer locks the whole table and
        # makes the real store's final NOWAIT check reject rather than commit
        # against a phantom. After writer commit, the fixture bearer check
        # rejects it before mutation.
        async with factory() as writer:
            async with writer.begin():
                await writer.execute(text(
                    "INSERT INTO operator_token_revocations "
                    "(digest,actor_id,expires_at,revoked_at) VALUES "
                    "(:digest,:actor,clock_timestamp()+interval '1 hour',"
                    "clock_timestamp())"
                ), {"digest": TOKEN_DIGEST, "actor": who.subject})
                await denied(
                    store().renew(who, renewed_after_lock),
                    "uncommitted token revocation NOWAIT-fenced",
                )
        await denied(
            store().renew(who, renewed_after_lock),
            "committed token revocation must be observed",
        )
        assert (await fetch(TENANT_A, who.subscriber_id))["cursor_sequence"] == next_valid
        return {
            "pg_version": 16,
            "socket_only": True,
            "independent_backend_pids": [pid1, pid2],
            "actual_store_operations": [
                "acquire", "renew", "read_batch", "acknowledge",
                "release", "revoke"
            ],
            "one_winner_duplicate_acquire": True,
            "event_filter_and_next_ack": [e1, e2],
            "advisory_lock_blocks_uncommitted_ack": True,
            "rolled_back_producer_not_acknowledged": True,
            "revoke_at_commit_rolls_back_cursor": True,
            "release_and_expiry_fence_old_lease": True,
            "interleaved_revoke_renew": outcome,
            "interleaved_insert_acquire_revoke_tombstone": True,
            "real_0014_revocation_writer_nowait_fence": True,
            "actual_share_lock_blocks_absent_row_insert": True,
            "committed_0014_revocation_denied": True,
            "tombstone_and_credential_roe_fixture_denial": True,
            "credential_callback_calls": check_counts["credentials"],
            "roe_callback_calls": check_counts["roe"],
            "identity_is_test_callback_not_signed_bearer": True,
        }
    finally:
        sync_engine.dispose()

with tempfile.TemporaryDirectory(prefix="osop-0040-store-live-", dir="/tmp") as root_text:
    root = Path(root_text)
    root.chmod(0o700)
    data = root / "data"
    logfile = root / "pg.log"
    port = 55400 + secrets.randbelow(1200)
    initialized = process(
        str(PG / "initdb"), "-D", str(data), "-A", "trust",
        "-U", "osop_0040_live", "--no-instructions",
    )
    assert initialized.returncode == 0, initialized.stderr[-1000:]
    started = False
    try:
        boot = process(
            str(PG / "pg_ctl"), "-D", str(data), "-l", str(logfile),
            "-o", "-c listen_addresses='' -c unix_socket_directories="
            + str(root) + " -c unix_socket_permissions=0700 -c port="
            + str(port) + " -c fsync=on -c synchronous_commit=on",
            "-w", "-t", "20", "start",
        )
        assert boot.returncode == 0, boot.stderr[-1000:]
        started = True
        assert (root / (".s.PGSQL." + str(port))).is_socket()
        result = asyncio.run(run_cases(root, port))
        print("RESULT_LIVE_SUBSCRIPTIONS:" + json.dumps(result, sort_keys=True))
    finally:
        if started:
            stop = process(
                str(PG / "pg_ctl"), "-D", str(data), "-w", "-m", "fast", "stop"
            )
            assert stop.returncode == 0, stop.stderr[-1200:]
"""


def test_actual_store_0040_live_postgres_sessions_and_cas() -> None:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 for genuine isolated worker42 SQL transactions")
    if os.name == "nt":
        repo = _linux_path(ROOT)
        lib = _linux_path(Path(sys.prefix) / "Lib" / "site-packages")
        command = ["wsl.exe", "-d", "Ubuntu", "--", "env",
                   "PYTHONPATH=" + lib, "python3", "-"]
    elif sys.platform == "linux":
        repo = _linux_path(ROOT)
        command = [sys.executable, "-"]
    else:
        pytest.skip("Linux or WSL Ubuntu nonroot PostgreSQL16 required")
    script = "ROOT = __import__('pathlib').Path(" + repr(repo) + ")\n" + _LIVE_LINUX
    try:
        finished = subprocess.run(
            command, input=script, text=True, encoding="utf-8",
            errors="replace", capture_output=True, timeout=190,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.fail("Disposable PostgreSQL16 unavailable: " + str(exc))
    assert finished.returncode == 0, (
        "Real worker42 PostgreSQL transaction failure:\n"
        + finished.stderr[-5500:] + "\n" + finished.stdout[-1200:]
    )
    payload = [line.removeprefix("RESULT_LIVE_SUBSCRIPTIONS:")
               for line in finished.stdout.splitlines()
               if line.startswith("RESULT_LIVE_SUBSCRIPTIONS:")]
    assert len(payload) == 1, finished.stdout[-1000:]
    proof = json.loads(payload[0])
    assert proof["pg_version"] == 16
    assert proof["socket_only"] is True
    assert proof["independent_backend_pids"][0] != proof["independent_backend_pids"][1]
    assert proof["one_winner_duplicate_acquire"] is True
    assert proof["rolled_back_producer_not_acknowledged"] is True
    assert proof["revoke_at_commit_rolls_back_cursor"] is True
    assert proof["interleaved_insert_acquire_revoke_tombstone"] is True
    assert proof["real_0014_revocation_writer_nowait_fence"] is True
    assert proof["actual_share_lock_blocks_absent_row_insert"] is True
    assert proof["tombstone_and_credential_roe_fixture_denial"] is True
    assert proof["identity_is_test_callback_not_signed_bearer"] is True
