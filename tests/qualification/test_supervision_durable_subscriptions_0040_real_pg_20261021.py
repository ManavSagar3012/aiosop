"""Real disposable PostgreSQL16/Alembic qualification for 0040 only.

The opt-in test starts an OWNED nonroot PostgreSQL 16 cluster bound to a 0700
private Unix socket, with no TCP listener. It uses the exact 0040 upgrade and
downgrade functions in live Alembic Operations. Only the session_states PK
predecessor is modeled: this is not the full application migration chain.

No app DB, Docker, dependency installation, provider/target, Git or production
SSE stream. The fixtures are synthetic tenant/subscriber metadata only.

Opt in with OSOP_DISPOSABLE_SUPERVISION_0040_PG=1.
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
MIGRATION = ROOT / "migrations/versions/0040_supervision_durable_subscriptions.py"
OPT_IN = "OSOP_DISPOSABLE_SUPERVISION_0040_PG"


def _linux_path(path: Path) -> str:
    path = path.resolve()
    raw = str(path)
    if os.name != "nt":
        return raw
    assert len(raw) > 3 and raw[1:3] == ":\\"
    return "/mnt/" + raw[0].lower() + raw[2:].replace("\\", "/")


def test_0040_head_and_schema_declared_without_database() -> None:
    """Cheap default test, does not contact any Postgres or invoke migration."""
    source = MIGRATION.read_text(encoding="utf-8")
    syntax = ast.parse(source)
    assignments = {
        item.targets[0].id: item.value.value
        for item in syntax.body
        if isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Name)
        and isinstance(item.value, ast.Constant)
    }
    assert assignments["revision"] == "0040"
    assert assignments["down_revision"] == "0039"
    assert (ROOT / "migrations/versions/0039_operator_global_library.py").is_file()
    for required in (
        "supervision_durable_subscriptions", "engagement_id", "subscriber_id",
        "principal_issuer", "principal_subject", "authorization_version",
        "authorization_sha256", "cursor_sequence", "lease_owner", "lease_id",
        "lease_generation", "lease_until", "revoked_at", "created_at", "updated_at",
        "ck_supervision_subscriber_lease_triad",
        "trg_supervision_durable_subscriptions_guard",
    ):
        assert required in source, required


_LINUX_SCRIPT = r"""
import importlib.util
import json
import os
import secrets
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.exc import DBAPIError, IntegrityError
import psycopg

assert os.name == "posix" and os.geteuid() != 0
PG = Path("/usr/lib/postgresql/16/bin")
assert all((PG / p).is_file() for p in ("initdb", "pg_ctl", "psql"))
path = ROOT / "migrations/versions/0040_supervision_durable_subscriptions.py"
spec = importlib.util.spec_from_file_location("isolated_0040", path)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert mod.revision == "0040" and mod.down_revision == "0039"

def invoke(connection, name):
    assert connection.in_transaction()
    ctx = MigrationContext.configure(connection, opts={"transactional_ddl": True})
    assert not ctx.as_sql and ctx.impl.transactional_ddl is True
    with Operations.context(ctx):
        getattr(mod, name)()

def process(*args):
    return subprocess.run(args, check=False, capture_output=True, text=True, timeout=45)

T = "supervision_durable_subscriptions"
CREATE = sa.text(
    "INSERT INTO supervision_durable_subscriptions "
    "(engagement_id, subscriber_id, principal_issuer, principal_subject, "
    "task_id, authorization_version, authorization_sha256) "
    "VALUES (:eng, :sub, :issuer, :subject, :task, :version, :sha)"
)
TENANT_A = "eng-supervision-tenant-a"
TENANT_B = "eng-supervision-tenant-b"
AUTH = "a" * 64

def props(eng=TENANT_A, sub="subscriber-1", **overrides):
    value = {
        "eng": eng, "sub": sub, "issuer": "idp-federation",
        "subject": "operator-principal", "task": None,
        "version": 1, "sha": AUTH,
    }
    value.update(overrides)
    return value

def expect_insert_denied(engine, row, state):
    try:
        with engine.begin() as conn:
            conn.execute(CREATE, row)
    except IntegrityError as exc:
        assert exc.orig.sqlstate == state, (exc.orig.sqlstate, str(exc))
    else:
        raise AssertionError("Invalid 0040 row accepted: " + repr(row))

def expect_update_denied(engine, sql, params=None, state="23514"):
    try:
        with engine.begin() as conn:
            conn.execute(sa.text(sql), params or {})
    except DBAPIError as exc:
        assert exc.orig.sqlstate == state, (exc.orig.sqlstate, str(exc))
    else:
        raise AssertionError("Forbidden 0040 mutation committed: " + sql)

with tempfile.TemporaryDirectory(prefix="osop-disposable-supervision-0040-", dir="/tmp") as tmp:
    root = Path(tmp)
    root.chmod(0o700)
    data = root / "data"
    log = root / "postgres.log"
    port = 54500 + secrets.randbelow(2000)
    init = process(str(PG/"initdb"), "-D", str(data), "-A", "trust",
                   "-U", "osop_subscription_disposable", "--no-instructions")
    assert init.returncode == 0, init.stderr[-1400:]
    started = False
    engine = None
    try:
        boot = process(
            str(PG/"pg_ctl"), "-D", str(data), "-l", str(log),
            "-o", "-c listen_addresses='' -c unix_socket_directories="
            + str(root) + " -c unix_socket_permissions=0700 -c port="
            + str(port) + " -c fsync=on -c synchronous_commit=on",
            "-w", "-t", "20", "start",
        )
        assert boot.returncode == 0, boot.stderr[-1400:]
        started = True
        assert (root / (".s.PGSQL." + str(port))).is_socket()
        engine = sa.create_engine(
            "postgresql+psycopg://osop_subscription_disposable@/postgres",
            connect_args={"host": str(root), "port": port, "connect_timeout": 3},
            pool_size=3, max_overflow=2, pool_timeout=6,
        )
        with engine.begin() as conn:
            assert conn.scalar(sa.text("SHOW listen_addresses")) == ""
            assert conn.scalar(sa.text("SHOW server_version_num")).startswith("16")
            assert conn.scalar(sa.text("SELECT current_database()")) == "postgres"
            conn.exec_driver_sql(
                "CREATE TABLE session_states (session_id varchar(64) PRIMARY KEY)"
            )
            conn.execute(
                sa.text("INSERT INTO session_states (session_id) VALUES (:a),(:b)"),
                {"a": TENANT_A, "b": TENANT_B},
            )
            invoke(conn, "upgrade")  # The ACTUAL 0040 Alembic function.
            assert conn.scalar(sa.text(
                "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE "
                "tgrelid='supervision_durable_subscriptions'::regclass "
                "AND tgname='trg_supervision_durable_subscriptions_guard' "
                "AND NOT tgisinternal)"
            ))
            constraints = {
                x for x in conn.execute(sa.text(
                    "SELECT conname FROM pg_constraint WHERE "
                    "conrelid='supervision_durable_subscriptions'::regclass"
                )).scalars()
            }
            for name in (
                "supervision_durable_subscriptions_pkey",
                "ck_supervision_subscriber_identity",
                "ck_supervision_subscriber_authorization",
                "ck_supervision_subscriber_counters",
                "ck_supervision_subscriber_lease_triad",
            ):
                assert name in constraints, name
            assert conn.scalar(sa.text("SELECT COUNT(*) FROM " + T)) == 0
        # The actual empty-state downgrade MUST succeed with no tombstones.
        with engine.begin() as conn:
            invoke(conn, "downgrade")
            assert conn.scalar(sa.text(
                "SELECT to_regclass('supervision_durable_subscriptions')"
            )) is None
        with engine.begin() as conn:
            invoke(conn, "upgrade")
            assert conn.scalar(sa.text(
                "SELECT to_regclass('supervision_durable_subscriptions')"
            )) == T

        expect_insert_denied(engine, props(eng="eng-unrecognized"), "23503")
        expect_insert_denied(engine, props(version=0), "23514")
        expect_insert_denied(engine, props(sha="f" * 63), "23514")
        expect_insert_denied(engine, props(issuer=""), "23514")
        with engine.begin() as conn:
            conn.execute(CREATE, props())
            conn.execute(CREATE, props(eng=TENANT_B))  # Same subscriber, distinct tenant.
            conn.execute(CREATE, props(sub="nullable-task", task=None))
            conn.execute(CREATE, props(sub="scoped-task", task="task-test-0040"))
            assert conn.scalar(sa.text(
                "SELECT COUNT(*) FROM supervision_durable_subscriptions"
            )) == 4
            assert conn.scalar(sa.text(
                "SELECT cursor_sequence FROM supervision_durable_subscriptions "
                "WHERE engagement_id=:eng AND subscriber_id=:sub"
            ), {"eng": TENANT_A, "sub": "subscriber-1"}) == 0
        expect_insert_denied(engine, props(), "23505")

        # Lease triad is exact all-null OR all-present.
        for sql in (
            "UPDATE " + T + " SET lease_owner='replica-a' WHERE "
            "engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET lease_owner='replica-a',lease_id='lease-a' "
            "WHERE engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET lease_owner='',lease_id='lease-a',"
            "lease_until=clock_timestamp()+interval '1 minute' WHERE "
            "engagement_id=:eng AND subscriber_id=:sub",
        ):
            expect_update_denied(
                engine, sql, {"eng": TENANT_A, "sub": "subscriber-1"}
            )

        # Two genuine independent DB clients race the initially unleased row.
        # Exactly one may acquire with generation=0 CAS; a stale candidate
        # cannot manufacture two simultaneous owners.
        def acquire_other(replica):
            with engine.begin() as conn:
                return conn.execute(sa.text(
                    "UPDATE " + T + " SET lease_owner=:replica,"
                    "lease_id=:lease,lease_generation=lease_generation+1,"
                    "lease_until=clock_timestamp()+interval '1 minute' "
                    "WHERE engagement_id=:eng AND subscriber_id=:sub "
                    "AND lease_generation=0 AND lease_owner IS NULL "
                    "AND revoked_at IS NULL"
                ), {"replica": replica, "lease": "lease-"+replica,
                    "eng": TENANT_A, "sub": "nullable-task"}).rowcount
        with ThreadPoolExecutor(max_workers=2) as pool:
            lease_winners = list(pool.map(
                acquire_other, ("replica-first", "replica-second")
            ))
        assert sorted(lease_winners) == [0, 1], lease_winners
        with engine.begin() as conn:
            row = conn.execute(sa.text(
                "SELECT lease_owner,lease_id,lease_generation,lease_until "
                "FROM " + T + " WHERE engagement_id=:eng AND subscriber_id=:sub"
            ), {"eng": TENANT_A, "sub": "nullable-task"}).mappings().one()
            assert row["lease_owner"] in ("replica-first", "replica-second")
            assert row["lease_id"] == "lease-" + row["lease_owner"]
            assert row["lease_generation"] == 1 and row["lease_until"] is not None

        # Independent replica A leases via atomic CAS. B races stale CAS; exact
        # statement predicates (not CHECKs) provide the runtime serialization.
        with engine.begin() as conn:
            lease = conn.execute(sa.text(
                "UPDATE " + T + " SET lease_owner='replica-a',lease_id='lease-a',"
                "lease_generation=1,lease_until=clock_timestamp()+interval '5 minutes',"
                "updated_at=clock_timestamp() "
                "WHERE engagement_id=:eng AND subscriber_id=:sub "
                "AND lease_generation=0 AND lease_owner IS NULL RETURNING lease_generation"
            ), {"eng": TENANT_A, "sub": "subscriber-1"}).scalar_one()
            assert lease == 1
        def advance_sequence(sequence):
            with engine.begin() as conn:
                # Distinct connections race to advance the same cursor;
                # exactly one expected-cursor CAS may succeed.
                return conn.execute(sa.text(
                    "UPDATE " + T + " SET cursor_sequence=:next,"
                    "updated_at=clock_timestamp() "
                    "WHERE engagement_id=:eng AND subscriber_id=:sub "
                    "AND cursor_sequence=0 AND lease_generation=1 "
                    "AND lease_owner='replica-a' AND lease_id='lease-a' "
                    "AND revoked_at IS NULL AND lease_until>clock_timestamp()"
                ), {"eng": TENANT_A, "sub": "subscriber-1",
                    "next": sequence}).rowcount
        with ThreadPoolExecutor(max_workers=2) as pool:
            winners = list(pool.map(advance_sequence, (1, 2)))
        assert sorted(winners) == [0, 1], winners
        with engine.begin() as conn:
            cursor = conn.scalar(sa.text(
                "SELECT cursor_sequence FROM " + T + " WHERE "
                "engagement_id=:eng AND subscriber_id=:sub"
            ), {"eng": TENANT_A, "sub": "subscriber-1"})
            assert cursor in (1, 2)
            assert conn.scalar(sa.text(
                "SELECT cursor_sequence FROM " + T + " WHERE "
                "engagement_id=:eng AND subscriber_id=:sub"
            ), {"eng": TENANT_B, "sub": "subscriber-1"}) == 0
        for sql in (
            "UPDATE " + T + " SET cursor_sequence=0 WHERE "
            "engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET lease_generation=0 WHERE "
            "engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET authorization_version=2 WHERE "
            "engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET authorization_sha256='" + ("b" * 64) + "' "
            "WHERE engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET principal_issuer='different-issuer' "
            "WHERE engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET principal_subject='other' WHERE "
            "engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET subscriber_id='subscriber-rebound' "
            "WHERE engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET task_id='task-foreign' WHERE "
            "engagement_id=:eng AND subscriber_id=:sub",
            "UPDATE " + T + " SET created_at=clock_timestamp() "
            "WHERE engagement_id=:eng AND subscriber_id=:sub",
        ):
            expect_update_denied(
                engine, sql, {"eng": TENANT_A, "sub": "subscriber-1"}
            )
        with engine.begin() as conn:
            assert conn.execute(sa.text(
                "UPDATE " + T + " SET lease_owner='replica-b',"
                "lease_id='lease-b',lease_generation=2,"
                "lease_until=clock_timestamp()+interval '3 minutes' "
                "WHERE engagement_id=:eng AND subscriber_id=:sub "
                "AND lease_owner='replica-a' AND lease_generation=1 "
                "AND revoked_at IS NULL"
            ), {"eng": TENANT_A, "sub": "subscriber-1"}).rowcount == 1
            assert conn.execute(sa.text(
                "UPDATE " + T + " SET cursor_sequence=:next "
                "WHERE engagement_id=:eng AND subscriber_id=:sub "
                "AND lease_owner='replica-a' AND lease_generation=1 "
                "AND revoked_at IS NULL"
            ), {"eng": TENANT_A, "sub": "subscriber-1",
                "next": cursor + 1}).rowcount == 0
            # Permanent revocation: revoke and clear the whole lease triad.
            assert conn.execute(sa.text(
                "UPDATE " + T + " SET revoked_at=clock_timestamp(),"
                "lease_owner=NULL,lease_id=NULL,lease_until=NULL,"
                "lease_generation=3 "
                "WHERE engagement_id=:eng AND subscriber_id=:sub "
                "AND lease_generation=2 AND revoked_at IS NULL"
            ), {"eng": TENANT_A, "sub": "subscriber-1"}).rowcount == 1
        expect_update_denied(
            engine,
            "UPDATE " + T + " SET revoked_at=NULL "
            "WHERE engagement_id=:eng AND subscriber_id=:sub",
            {"eng": TENANT_A, "sub": "subscriber-1"},
        )
        with engine.begin() as conn:
            assert conn.execute(sa.text(
                "UPDATE " + T + " SET lease_owner='replica-b',"
                "lease_id='lease-b',lease_until=clock_timestamp() "
                "WHERE engagement_id=:eng AND subscriber_id=:sub "
                "AND revoked_at IS NULL"
            ), {"eng": TENANT_A, "sub": "subscriber-1"}).rowcount == 0
            assert conn.scalar(sa.text(
                "SELECT lease_generation FROM " + T + " WHERE "
                "engagement_id=:eng AND subscriber_id=:sub"
            ), {"eng": TENANT_A, "sub": "subscriber-1"}) == 3
        expect_update_denied(
            engine, "DELETE FROM " + T + " WHERE engagement_id=:eng",
            {"eng": TENANT_A},
        )
        # Empty downgrade is possible, populated one is deliberately denied,
        # including revoked rows; test must not bypass immutable tombstones.
        try:
            with engine.begin() as conn:
                invoke(conn, "downgrade")
        except RuntimeError as exc:
            assert "including revoked subscribers" in str(exc), exc
        else:
            raise AssertionError("0040 dropped a nonempty durable subscriber ledger")
        with engine.begin() as conn:
            assert conn.scalar(sa.text("SELECT COUNT(*) FROM " + T)) == 4
            assert conn.scalar(sa.text(
                "SELECT COUNT(*) FROM " + T + " WHERE revoked_at IS NOT NULL"
            )) == 1
            assert conn.scalar(sa.text("SELECT to_regclass('" + T + "')")) == T
        print("RESULT_0040_PG:" + json.dumps({
            "postgres_major": 16, "unix_socket_only": True,
            "actual_alembic_upgrade_downgrade_empty": True,
            "triad_authority_identity_guard": True,
            "two_client_lease_cas_one_winner": lease_winners,
            "two_client_cursor_cas_one_winner": winners,
            "stale_lease_generation_denied": True,
            "permanent_revocation": True,
            "nonempty_downgrade_denied": True,
            "remaining_rows": 4,
            "minimal_predecessor_only": True,
        }, sort_keys=True))
    finally:
        if engine is not None:
            engine.dispose()
        if started:
            stopped = process(
                str(PG/"pg_ctl"), "-D", str(data), "-w", "-m", "fast", "stop"
            )
            assert stopped.returncode == 0, stopped.stderr[-1100:]
"""


def test_0040_real_nonroot_postgresql16_alembic_ops() -> None:
    if os.getenv(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 for an owned Unix-socket-only PG16")
    if os.name == "nt":
        repo = _linux_path(ROOT)
        python_libs = _linux_path(Path(sys.prefix) / "Lib" / "site-packages")
        argv = ["wsl.exe", "-d", "Ubuntu", "--", "env",
                "PYTHONPATH=" + python_libs, "python3", "-"]
    elif sys.platform == "linux":
        repo = _linux_path(ROOT)
        argv = [sys.executable, "-"]
    else:
        pytest.skip("Linux or WSL Ubuntu nonroot PostgreSQL16 required")
    script = "ROOT = __import__('pathlib').Path(" + repr(repo) + ")\n" + _LINUX_SCRIPT
    try:
        finished = subprocess.run(
            argv, input=script, text=True, encoding="utf-8", errors="replace",
            capture_output=True, timeout=190,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.fail("Disposable 0040 PostgreSQL16 unavailable: " + str(exc))
    assert finished.returncode == 0, (
        "Real 0040 PostgreSQL/Alembic Ops failed:\n"
        + finished.stderr[-3800:] + "\n" + finished.stdout[-800:]
    )
    results = [line.removeprefix("RESULT_0040_PG:")
               for line in finished.stdout.splitlines()
               if line.startswith("RESULT_0040_PG:")]
    assert len(results) == 1, finished.stdout[-1000:]
    proof = json.loads(results[0])
    assert proof["postgres_major"] == 16
    assert proof["unix_socket_only"] is True
    assert sorted(proof["two_client_lease_cas_one_winner"]) == [0, 1]
    assert sorted(proof["two_client_cursor_cas_one_winner"]) == [0, 1]
    assert proof["remaining_rows"] == 4
