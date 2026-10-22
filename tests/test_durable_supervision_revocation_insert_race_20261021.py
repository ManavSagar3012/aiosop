"""Deterministic missing-revocation-row admission races (NO actual PostgreSQL).

0014 operator_token_revocations and operator_subject_controls admit INSERT.
Selecting a nonexistent digest/subject FOR SHARE locks no row. These fake
transactions model PostgreSQL SHARE table-lock vs writer ROW EXCLUSIVE conflict,
read-committed visibility, lease CAS rollback and irreversible 0040 tombstones.
Actual PostgreSQL isolation/lock behavior still needs a separate PG qualification.
"""

from __future__ import annotations

import asyncio
import copy
from contextlib import asynccontextmanager
from datetime import timedelta
from functools import wraps
from types import SimpleNamespace
from typing import Any, Optional

import pytest

from tests.test_durable_supervision_subscriptions_20261021 import (
    DurableSupervisionSubscriptions,
    Memory,
    Result,
    Session,
    SimulatedPostgres,
    SubscriptionDenied,
    principal,
)


def run_async(fn):
    @wraps(fn)
    def runner(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))
    return runner


class AdmissionPG(SimulatedPostgres):
    """Synthetic two-replica DB; one txn owns table SHARE until commit."""

    def __init__(self) -> None:
        super().__init__()
        self.isolation = "read committed"
        self.revoked_digests: set[str] = set()
        self.disabled_subjects: set[str] = set()
        self.writer_active = False
        self.writer_pending_commit = False
        self.table_share_held = False
        self.commit_order: list[str] = []
        self.revocation_before_fence = False
        self.writer_prepared_before_fence = False
        self.table_exists = True
        self.fail_table_lock = False
        self.admission_operations = 0

    def session(self) -> "AdmissionSession":
        return AdmissionSession(self)

    def execute(self, sql: str, params: dict[str, Any]) -> Result:
        self.statements.append(sql)
        if sql.startswith("SELECT current_setting('transaction_isolation')"):
            return Result(self.isolation)
        if sql.startswith("LOCK TABLE operator_token_revocations, operator_subject_controls"):
            if not sql.endswith("IN SHARE MODE NOWAIT"):
                raise AssertionError("Missing PostgreSQL writer exclusion")
            if not self.table_exists:
                raise RuntimeError("relation operator_token_revocations does not exist")
            if self.writer_active or self.fail_table_lock:
                raise RuntimeError("could not obtain SHARE lock NOWAIT")
            self.table_share_held = True
            return Result()
        if sql.startswith("SELECT digest FROM operator_token_revocations"):
            return Result("revoked" if "token" in self.revoked_digests else None)
        if sql.startswith("SELECT disabled FROM operator_subject_controls"):
            return Result(params["actor"] in self.disabled_subjects)
        if (self.revocation_before_fence and
            sql.startswith("UPDATE supervision_durable_subscriptions SET cursor_sequence=")):
            # Competing writer commits while admission holds no revocation
            # table lock. Existing missing-row FOR SHARE checks do not block it.
            self.revoked_digests.add("token")
            self.revocation_before_fence = False
        if (self.writer_prepared_before_fence and
            sql.startswith("UPDATE supervision_durable_subscriptions SET cursor_sequence=")):
            self.writer_active = True
            self.writer_prepared_before_fence = False
        return super().execute(sql, params)


class AdmissionSession(Session):
    def __init__(self, pg: AdmissionPG) -> None:
        super().__init__(pg)
        # Real AsyncSession exposes bind.dialect; this fake deliberately
        # advertises PostgreSQL to exercise production-only lock SQL.
        self.bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    @asynccontextmanager
    async def begin(self):
        async with self.pg.lock:
            snapshot = copy.deepcopy(self.pg.rows)
            self.pg.table_share_held = False
            try:
                yield
                # Deterministic writer INSERT at the final instant before
                # subscriber transaction COMMIT. Without SHARE, it wins.
                if self.pg.writer_pending_commit and not self.pg.table_share_held:
                    self.pg.revoked_digests.add("token")
                    self.pg.commit_order.append("revocation")
                    self.pg.writer_pending_commit = False
                self.pg.commit_order.append("admission")
            except BaseException:
                self.pg.rows = snapshot
                raise
            finally:
                held = self.pg.table_share_held
                self.pg.table_share_held = False
                if held and self.pg.writer_pending_commit:
                    # Writer ROW EXCLUSIVE must wait for SHARE to be released.
                    self.pg.revoked_digests.add("token")
                    self.pg.commit_order.append("revocation")
                    self.pg.writer_pending_commit = False


class RejectBadBindingPG(AdmissionPG):
    """Simulate adapters that fail to prove a PostgreSQL dialect at commit."""

    def __init__(self) -> None:
        super().__init__()
        self.bad_binding: Optional[str] = None

    def session(self) -> "AdmissionSession":
        db = AdmissionSession(self)
        if self.bad_binding == "missing":
            del db.bind
        elif self.bad_binding == "null":
            db.bind = None
        elif self.bad_binding == "sqlite":
            db.bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))
        elif self.bad_binding == "no-dialect":
            db.bind = SimpleNamespace()
        return db


def make_store(pg: AdmissionPG) -> DurableSupervisionSubscriptions:
    async def credential_guard(db: Any, checked: Any) -> bool:
        # Shape mirrors mounted _context.live_credential_guard: both absent
        # rows are SELECT FOR SHARE and can be inserted concurrently.
        revoked = (await db.execute(
            "SELECT digest FROM operator_token_revocations WHERE digest=:digest FOR SHARE",
            {"digest": "token"},
        )).scalar_one_or_none()
        disabled = (await db.execute(
            "SELECT disabled FROM operator_subject_controls WHERE actor_id=:actor FOR SHARE",
            {"actor": checked.subject},
        )).scalar_one_or_none()
        return revoked is None and disabled is not True

    async def signed_guard(
        db: Any, engagement: str, *,
        expected_version: int, expected_digest: str,
    ) -> Any:
        if engagement != "eng-a" or expected_version != 4 or expected_digest != "a" * 64:
            return None
        return object()

    return DurableSupervisionSubscriptions(
        Memory(pg), credential_guard=credential_guard, roe_guard=signed_guard,
    )


@run_async
async def test_missing_token_row_insert_just_before_final_fence_rolls_back_ack():
    pg = AdmissionPG()
    identity = principal()
    store = make_store(pg)
    lease = await store.acquire(identity, "replica-first")
    pg.revocation_before_fence = True
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.acknowledge(identity, lease, expected_cursor=0, next_sequence=12)
    assert pg.revoked_digests == {"token"}
    assert pg.rows[(identity.engagement_id, identity.subscriber_id)]["cursor_sequence"] == 0
    assert "LOCK TABLE operator_token_revocations, operator_subject_controls IN SHARE MODE NOWAIT" in pg.statements


@run_async
async def test_inflight_revocation_writer_makes_admission_fail_closed_on_nowait():
    pg = AdmissionPG()
    identity = principal()
    store = make_store(pg)
    lease = await store.acquire(identity, "replica-first")
    pg.writer_prepared_before_fence = True
    with pytest.raises(SubscriptionDenied, match="unavailable"):
        await store.acknowledge(identity, lease, expected_cursor=0, next_sequence=12)
    assert pg.rows[(identity.engagement_id, identity.subscriber_id)]["cursor_sequence"] == 0
    pg.writer_active = False


@run_async
async def test_share_mode_serializes_absent_row_writer_commit_after_ack():
    pg = AdmissionPG()
    identity = principal()
    store = make_store(pg)
    lease = await store.acquire(identity, "replica-first")
    pg.commit_order.clear()
    pg.writer_pending_commit = True
    ack = await store.acknowledge(identity, lease, expected_cursor=0, next_sequence=12)
    assert ack.cursor == 12
    assert pg.commit_order == ["admission", "revocation"]
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.renew(identity, ack)


@run_async
async def test_unprotected_for_share_lets_revocation_commit_before_ack():
    pg = AdmissionPG()
    identity = principal()
    unprotected = make_store(pg)
    lease = await unprotected.acquire(identity, "replica-first")
    pg.commit_order.clear()
    pg.writer_pending_commit = True

    # Deliberately simulate the PRE-FIX behavior to prove the original race.
    async def no_table_lock(_db: Any) -> None:
        return None

    unprotected._fence_revocation_insert = no_table_lock
    ack = await unprotected.acknowledge(
        identity, lease, expected_cursor=0, next_sequence=12,
    )
    assert ack.cursor == 12
    assert pg.commit_order == ["revocation", "admission"]
    assert pg.revoked_digests == {"token"}


@pytest.mark.parametrize("isolation", ["repeatable read", "serializable", "read uncommitted"])
@run_async
async def test_non_read_committed_snapshot_denies_racy_cursor_mutation(isolation):
    pg = AdmissionPG()
    identity = principal()
    store = make_store(pg)
    lease = await store.acquire(identity, "replica-first")
    pg.isolation = isolation
    with pytest.raises(SubscriptionDenied, match="snapshot isolation"):
        await store.acknowledge(identity, lease, expected_cursor=0, next_sequence=12)
    assert pg.rows[(identity.engagement_id, identity.subscriber_id)]["cursor_sequence"] == 0


@pytest.mark.parametrize("failure", ["missing_table", "lock_conflict"])
@run_async
async def test_missing_0014_table_or_locked_writer_denies_and_rolls_back(failure):
    pg = AdmissionPG()
    identity = principal()
    store = make_store(pg)
    lease = await store.acquire(identity, "replica-first")
    if failure == "missing_table":
        pg.table_exists = False
    else:
        pg.fail_table_lock = True
    with pytest.raises(SubscriptionDenied, match="unavailable"):
        await store.acknowledge(identity, lease, expected_cursor=0, next_sequence=12)
    assert pg.rows[(identity.engagement_id, identity.subscriber_id)]["cursor_sequence"] == 0


@run_async
async def test_token_revocation_blocks_new_lease_renew_and_release():
    pg = AdmissionPG()
    identity = principal()
    store = make_store(pg)
    lease = await store.acquire(identity, "replica-first")
    pg.revoked_digests.add("token")
    for operation in (
        store.renew(identity, lease),
        store.release(identity, lease),
        store.acquire(identity, "replica-second"),
    ):
        with pytest.raises(SubscriptionDenied, match="revoked"):
            await operation
    assert pg.rows[(identity.engagement_id, identity.subscriber_id)]["lease_id"] == lease.lease_id


@pytest.mark.parametrize("binding", ["missing", "null", "sqlite", "no-dialect"])
@run_async
async def test_unbound_or_non_postgres_adapter_denies_subscription_creation(binding):
    pg = RejectBadBindingPG()
    pg.bad_binding = binding
    identity = principal()
    with pytest.raises(SubscriptionDenied, match="PostgreSQL"):
        await make_store(pg).acquire(identity, "replica-first")
    assert pg.rows == {}  # Insertion in same transaction MUST roll back.
    assert not pg.table_share_held


@pytest.mark.parametrize("binding", ["missing", "sqlite"])
@run_async
async def test_losing_pg_bind_mid_lifecycle_rolls_back_cursor_and_lease(binding):
    pg = RejectBadBindingPG()
    identity = principal()
    store = make_store(pg)
    lease = await store.acquire(identity, "replica-first")
    key = (identity.engagement_id, identity.subscriber_id)
    before = copy.deepcopy(pg.rows[key])
    pg.bad_binding = binding
    for operation in (
        store.read_batch(identity, lease),
        store.acknowledge(identity, lease, expected_cursor=0, next_sequence=12),
        store.renew(identity, lease),
        store.release(identity, lease),
        store.revoke(identity),
    ):
        with pytest.raises(SubscriptionDenied, match="PostgreSQL"):
            await operation
        assert pg.rows[key] == before
    assert not pg.table_share_held


@run_async
async def test_disabled_subject_insert_blocks_cursor_and_current_lease():
    pg = AdmissionPG()
    identity = principal()
    store = make_store(pg)
    lease = await store.acquire(identity, "replica-first")
    pg.disabled_subjects.add(identity.subject)  # Synthetic subject-control INSERT.
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.acknowledge(identity, lease, expected_cursor=0, next_sequence=12)
    assert pg.rows[(identity.engagement_id, identity.subscriber_id)]["cursor_sequence"] == 0


@run_async
async def test_ack_then_subscription_tombstone_fences_recovery_even_with_new_token():
    pg = AdmissionPG()
    identity = principal()
    store = make_store(pg)
    lease = await store.acquire(identity, "replica-first")
    advanced = await store.acknowledge(identity, lease, expected_cursor=0, next_sequence=12)
    assert advanced.cursor == 12
    await store.revoke(identity)
    row = pg.rows[(identity.engagement_id, identity.subscriber_id)]
    assert row["revoked_at"] is not None and row["cursor_sequence"] == 12
    assert row["lease_generation"] > lease.generation
    pg.now += timedelta(seconds=300)
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.acquire(identity, "replica-new")
    with pytest.raises(SubscriptionDenied, match="revoked"):
        await store.acknowledge(identity, advanced, expected_cursor=12, next_sequence=18)


def test_writer_lock_contract_and_0040_trigger_never_claim_token_insert_fencing():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    source = (root / "src/ai_osop/memory/durable_supervision_subscriptions.py").read_text()
    migration = (root / "migrations/versions/0040_supervision_durable_subscriptions.py").read_text()
    assert "LOCK TABLE operator_token_revocations, operator_subject_controls" in source
    assert "IN SHARE MODE NOWAIT" in source
    assert "transaction_isolation" in source
    assert "lease_generation=:generation AND revoked_at IS NULL" in source
    assert "lease_until>clock_timestamp()" in source
    assert "NEW.cursor_sequence < OLD.cursor_sequence" in migration
    assert "OLD.revoked_at IS NOT NULL" in migration
    assert "operator_token_revocations" not in migration
