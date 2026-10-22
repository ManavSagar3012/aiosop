"""Actual 0040 store replica continuity and lost ACK under private PG16.

This NEW opt-in qualification reuses only the helper *definitions* (not test
cases or test state) from the previous direct-PG qualification. Each execution
creates its own fresh nonroot Unix-socket-only PG16 and runs the checked-in
0014/0040 Alembic upgrade() functions on minimal synthetic parents.

No application database, Docker, Git, paid provider, external network, target,
signed production bearer or real deployed replica is contacted. Credential
and ROE callbacks in this fixture are NOT independently enrolled signers.
Opt in with OSOP_0040_REPLICA_CONTINUITY_PG=1.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.qualification import test_0040_subscription_live_transactions_20261021 as prior

ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_0040_REPLICA_CONTINUITY_PG"
SOURCE = ROOT / "src/ai_osop/memory/durable_supervision_subscriptions.py"
MIGRATION = ROOT / "migrations/versions/0040_supervision_durable_subscriptions.py"


def test_replica_continuity_contract_present_without_pg() -> None:
    """Only inspect checked-in source; never imply the DB ran by default."""
    store = SOURCE.read_text(encoding="utf-8")
    migration = MIGRATION.read_text(encoding="utf-8")
    tree = ast.parse(store)
    methods = {
        node.name
        for cls in tree.body
        if isinstance(cls, ast.ClassDef)
        and cls.name == "DurableSupervisionSubscriptions"
        for node in cls.body
        if isinstance(node, ast.AsyncFunctionDef)
    }
    assert {"acquire", "read_batch", "acknowledge", "release", "renew"} <= methods
    for boundary in (
        "lease_generation=lease_generation+1",
        "AND lease_until>clock_timestamp()",
        "AND cursor_sequence=:cursor",
        "pg_advisory_xact_lock(hashtextextended(:engagement, 8044))",
        "precommit_disconnect",
    ):
        assert boundary in store, boundary
    assert 'revision = "0040"' in migration
    assert 'down_revision = "0039"' in migration


# Import only stable helpers for actual migration execution and SQL session
# adaptation. Never execute previous run_cases(), which would repeat old tests.
_PRELUDE = prior._LIVE_LINUX.split("async def run_cases(", 1)[0]
assert _PRELUDE.endswith("\n")

_NEW_SCENARIOS = r"""
async def continuity_cases(socket, port):
    # All workers are test-scoped store instances over separate actual
    # psycopg.AsyncConnection backends. No ASGI/stdin serialized test bridge.
    sync_engine = sa.create_engine(
        "postgresql+psycopg://osop_0040_live@/postgres",
        connect_args={"host": str(socket), "port": port, "connect_timeout": 4},
    )

    class DeadlineSession(LivePsycopgSession):
        async def __aenter__(self):
            await super().__aenter__()
            # Each transaction on its own actual server-side PostgreSQL backend
            # has bounded idle/statement/lock wait, even on a test failure.
            await self.execute(text("SET idle_in_transaction_session_timeout='7s'"))
            await self.execute(text("SET statement_timeout='4s'"))
            await self.execute(text("SET lock_timeout='2s'"))
            return self

    controls = {"gate": None, "updated": None, "blocked_pid": None}
    class PausedSession(DeadlineSession):
        async def execute(self, statement, params=None):
            result = await super().execute(statement, params)
            if (str(statement).startswith(
                    "UPDATE supervision_durable_subscriptions SET "
                    "cursor_sequence=:next,updated_at=clock_timestamp()")
                and controls["gate"] is not None):
                controls["blocked_pid"] = (
                    await super().execute(text("SELECT pg_backend_pid()"))
                ).scalar_one()
                controls["updated"].set()
                await controls["gate"].wait()
            return result

    def factory(pause=False):
        return PausedSession(socket, port, sync_engine) if pause else DeadlineSession(
            socket, port, sync_engine
        )

    async def fixture_identity_guard(db, principal):
        # A controlled, unsiged synthetic credential callback. Real PG
        # transaction checks still query durable 0014 revocation tables.
        blocked = (await db.execute(text(
            "SELECT EXISTS(SELECT 1 FROM operator_subject_controls "
            "WHERE actor_id=:subject AND disabled)"
        ), {"subject": principal.subject})).scalar_one()
        return principal.issuer == "fixture-test-issuer" and not blocked

    async def fixture_roe_guard(db, engagement, *, expected_version, expected_digest):
        return object() if (engagement == TENANT_A and expected_version == 2
                           and expected_digest == AUTH_SHA) else None

    class Memory:
        def __init__(self, use_pause=False):
            self._async_session = lambda: factory(use_pause)

    replica_a = Store(Memory(), credential_guard=fixture_identity_guard,
                      roe_guard=fixture_roe_guard)
    replica_b = Store(Memory(), credential_guard=fixture_identity_guard,
                      roe_guard=fixture_roe_guard)
    pausing_replica = Store(Memory(True), credential_guard=fixture_identity_guard,
                           roe_guard=fixture_roe_guard)

    async def get_row(principal):
        async with factory() as db:
            return (await db.execute(text(
                "SELECT cursor_sequence,lease_generation,lease_owner,lease_id,"
                "revoked_at FROM supervision_durable_subscriptions "
                "WHERE engagement_id=:eng AND subscriber_id=:sub"
            ), {"eng": principal.engagement_id,
                "sub": principal.subscriber_id})).mappings().one_or_none()

    async def reject(coroutine, reason):
        try:
            await asyncio.wait_for(coroutine, 6)
        except Denied:
            return
        raise AssertionError("Unexpected admission " + reason)

    try:
        # Real online 0014/0040 operations on disposable PG16, minimal
        # predecessor only; no claim of entire 0001..0040 upgrade chain.
        with sync_engine.begin() as db:
            db.exec_driver_sql(
                "CREATE TABLE session_states "
                "(session_id varchar(64) PRIMARY KEY,created_by varchar(64) NOT NULL)"
            )
            db.exec_driver_sql(
                "CREATE TABLE tasks "
                "(id varchar(64) PRIMARY KEY,engagement_id varchar(64) NOT NULL)"
            )
            db.exec_driver_sql(
                "CREATE TABLE supervision_events("
                "sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
                "id varchar(64) NOT NULL UNIQUE,engagement_id varchar(64) NOT NULL,"
                "task_id varchar(64),kind varchar(64) NOT NULL,"
                "actor_id varchar(64) NOT NULL,payload jsonb NOT NULL,"
                "created_at timestamp NOT NULL DEFAULT now())"
            )
            db.execute(text(
                "INSERT INTO session_states VALUES (:eng,:owner)"
            ), {"eng": TENANT_A, "owner": "owner-a"})
            db.execute(text(
                "INSERT INTO tasks VALUES (:task,:eng)"
            ), {"task": TASK_A, "eng": TENANT_A})
            ctx = MigrationContext.configure(db, opts={"transactional_ddl": True})
            with Operations.context(ctx):
                revocation_migration.upgrade()
                migration.upgrade()
            assert db.scalar(text("SHOW listen_addresses")) == ""
            assert db.scalar(text("SHOW server_version_num")).startswith("16")

        # Proven separately connected real PG sessions (different backends).
        async with factory() as session1, factory() as session2:
            pid_a = (await session1.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            pid_b = (await session2.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            assert pid_a != pid_b, (pid_a, pid_b)

        who = identity()
        # Human subscriber identity remains stable across two logical replica
        # store instances and their independently opened PostgreSQL backends.
        initial = await asyncio.wait_for(
            replica_a.acquire(who, "replica-continuity-a", lease_seconds=5), 8
        )
        await reject(
            replica_b.acquire(who, "replica-continuity-b", lease_seconds=5),
            "competing unexpired replica",
        )
        # Fixture event inserts are committed on a distinct real DB session,
        # serialized by the same per-tenant producer advisory lock as runtime.
        async def add_event(kind):
            async with factory() as db:
                async with db.begin():
                    await db.execute(text(
                        "SELECT pg_advisory_xact_lock(hashtextextended(:eng, 8044))"
                    ), {"eng": TENANT_A})
                    return (await db.execute(text(
                        "INSERT INTO supervision_events "
                        "(id,engagement_id,task_id,kind,actor_id,payload) "
                        "VALUES (:id,:eng,:task,:kind,'fixture-producer',"
                        "CAST(:payload AS jsonb)) RETURNING sequence"
                    ), {"id": "evt-" + uuid.uuid4().hex, "eng": TENANT_A,
                        "task": TASK_A, "kind": kind,
                        "payload": json.dumps({"source": "test-fixture"})}
                    )).scalar_one()

        first_seq = await add_event("lost-reply-ack")
        delivered = await replica_a.read_batch(who, initial)
        assert [event["sequence"] for event in delivered] == [first_seq]

        # Simulate LOST HTTP ACK response: commit actual store ACK and
        # deliberately drop/never use its return. Next replica must observe
        # committed cursor independently; replaying the old cursor is denied.
        _lost_response = await asyncio.wait_for(
            replica_a.acknowledge(
                who, initial, expected_cursor=0, next_sequence=first_seq
            ), 8
        )
        assert _lost_response.cursor == first_seq
        del _lost_response
        assert (await get_row(who))["cursor_sequence"] == first_seq
        await reject(
            replica_a.acknowledge(
                who, initial, expected_cursor=0, next_sequence=first_seq
            ), "blind duplicate ACK after lost response",
        )
        assert await replica_b.read_batch(who, initial) == []
        assert (await get_row(who))["cursor_sequence"] == first_seq

        # Expiration is REAL wall-clock PG lease_until, not artificially
        # backdated SQL. Fresh replica acquires after actual >=5s timeout.
        deadline = initial.lease_until.timestamp()
        await asyncio.sleep(max(0.0, deadline - datetime.now(timezone.utc).timestamp()) + 0.20)
        recovered_lease = await asyncio.wait_for(
            replica_b.acquire(who, "replica-continuity-b", lease_seconds=30), 8
        )
        assert recovered_lease.cursor == first_seq
        assert recovered_lease.generation == initial.generation + 1
        assert recovered_lease.lease_id != initial.lease_id
        await reject(replica_a.read_batch(who, initial), "stale owner read")
        await reject(replica_a.renew(who, initial), "stale owner renew")

        # Reconnect with a completely fresh store instance, same named
        # subscriber and current replica handle, no memory replay.
        reconnect = Store(Memory(), credential_guard=fixture_identity_guard,
                          roe_guard=fixture_roe_guard)
        assert await reconnect.read_batch(who, recovered_lease) == []
        second_seq = await add_event("held-row-cancellation")

        # Genuine PG UPDATE has executed but the transaction has not committed:
        # its separate backend holds an actual row lock; NOWAIT must return
        # 55P03. Cancel the server-side task while holding that lock and
        # require rollback + independent readback before any replay.
        controls["gate"] = asyncio.Event()
        controls["updated"] = asyncio.Event()
        holder = asyncio.create_task(pausing_replica.acknowledge(
            who, recovered_lease, expected_cursor=first_seq,
            next_sequence=second_seq,
        ))
        try:
            await asyncio.wait_for(controls["updated"].wait(), 8)
            assert controls["blocked_pid"] is not None
            async with factory() as independent:
                other_pid = (await independent.execute(
                    text("SELECT pg_backend_pid()")
                )).scalar_one()
                assert other_pid != controls["blocked_pid"]
                try:
                    await independent.execute(text(
                        "SELECT cursor_sequence FROM supervision_durable_subscriptions "
                        "WHERE engagement_id=:e AND subscriber_id=:sub "
                        "FOR UPDATE NOWAIT"
                    ), {"e": TENANT_A, "sub": who.subscriber_id})
                except psycopg.errors.LockNotAvailable as exc:
                    assert exc.sqlstate == "55P03"
                else:
                    raise AssertionError("Expected actual row lock contention")
            holder.cancel()
            try:
                await asyncio.wait_for(holder, 5)
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("Cancelled in-progress ACK unexpectedly returned")
        finally:
            controls["gate"].set()
            if not holder.done():
                holder.cancel()
                try:
                    await asyncio.wait_for(holder, 3)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass
            controls["gate"] = None
            controls["updated"] = None

        # New real connection sees the original cursor and can acquire the
        # exclusive row lock NOWAIT. This confirms test rollback, not merely
        # the holder task's cancellation acknowledgment.
        assert (await get_row(who))["cursor_sequence"] == first_seq
        async with factory() as after:
            async with after.begin():
                row = (await after.execute(text(
                    "SELECT cursor_sequence FROM supervision_durable_subscriptions "
                    "WHERE engagement_id=:e AND subscriber_id=:sub "
                    "FOR UPDATE NOWAIT"
                ), {"e": TENANT_A, "sub": who.subscriber_id})).scalar_one()
                assert row == first_seq
        # Fresh resumed replica may safely ACK after independent readback.
        read_after = await reconnect.read_batch(who, recovered_lease)
        assert [event["sequence"] for event in read_after] == [second_seq]
        final = await reconnect.acknowledge(
            who, recovered_lease, expected_cursor=first_seq, next_sequence=second_seq
        )
        assert final.cursor == second_seq
        await reject(
            pausing_replica.acknowledge(
                who, recovered_lease, expected_cursor=first_seq,
                next_sequence=second_seq,
            ), "second ACK on committed sequence",
        )
        return {
            "pg_major": 16,
            "private_unix_only": True,
            "distinct_backend_pids": [pid_a, pid_b],
            "actual_expiration_seconds": 5,
            "lost_ack_committed_cursor": first_seq,
            "new_replica_generation": recovered_lease.generation,
            "stale_old_replica_denied": True,
            "reconnect_readback": True,
            "pg_nowait_while_cancelled_holder": "55P03",
            "rollback_cursor_after_cancel": first_seq,
            "final_ack_cursor": second_seq,
            "fixture_callbacks_not_production_signers": True,
            "full_application_schema_or_real_host_crash": False,
        }
    finally:
        sync_engine.dispose()

with tempfile.TemporaryDirectory(prefix="osop-0040-replica-continuity-", dir="/tmp") as temp:
    root = Path(temp)
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
        result = asyncio.run(asyncio.wait_for(continuity_cases(root, port), 85))
        print("RESULT_0040_CONTINUITY:" + json.dumps(result, sort_keys=True))
    finally:
        if started:
            stopped = process(
                str(PG / "pg_ctl"), "-D", str(data), "-w", "-m", "fast", "stop"
            )
            assert stopped.returncode == 0, stopped.stderr[-1500:]
"""


def test_0040_real_pg16_replica_continuity() -> None:
    if os.getenv(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 for owned nonroot Unix-only PostgreSQL16")
    if os.name == "nt":
        root = prior._linux_path(ROOT)
        library = prior._linux_path(Path(sys.prefix) / "Lib" / "site-packages")
        argv = ["wsl.exe", "-d", "Ubuntu", "--", "env",
                "PYTHONPATH=" + library, "python3", "-"]
    elif sys.platform == "linux":
        root = prior._linux_path(ROOT)
        argv = [sys.executable, "-"]
    else:
        pytest.skip("Only nonroot Linux or WSL Ubuntu PostgreSQL16 supported")
    script = "ROOT = __import__('pathlib').Path(" + repr(root) + ")\n" + _PRELUDE + _NEW_SCENARIOS
    try:
        finished = subprocess.run(
            argv, input=script, text=True, encoding="utf-8",
            errors="replace", capture_output=True, timeout=145,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.fail("Private PostgreSQL16 continuity unavailable: " + str(exc))
    assert finished.returncode == 0, (
        "Actual 0040 replica continuity failed:\n"
        + finished.stderr[-5500:] + "\n" + finished.stdout[-1500:]
    )
    proof_lines = [
        row.removeprefix("RESULT_0040_CONTINUITY:")
        for row in finished.stdout.splitlines()
        if row.startswith("RESULT_0040_CONTINUITY:")
    ]
    assert len(proof_lines) == 1, finished.stdout[-1800:]
    proof = json.loads(proof_lines[0])
    assert proof["pg_major"] == 16 and proof["private_unix_only"] is True
    assert proof["distinct_backend_pids"][0] != proof["distinct_backend_pids"][1]
    assert proof["new_replica_generation"] == 2
    assert proof["pg_nowait_while_cancelled_holder"] == "55P03"
    assert proof["rollback_cursor_after_cancel"] == proof["lost_ack_committed_cursor"]
    assert proof["final_ack_cursor"] > proof["rollback_cursor_after_cancel"]
    assert proof["fixture_callbacks_not_production_signers"] is True
