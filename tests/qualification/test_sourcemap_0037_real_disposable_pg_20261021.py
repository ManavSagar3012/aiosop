"""Opt-in real PostgreSQL 16 + real Alembic Operations qualification of 0037.

Creates an owned, fresh nonroot Unix-socket-only PG16 cluster. SQLAlchemy,
Alembic and psycopg run INSIDE Linux, using the repository's existing Windows
virtualenv pure-Python libraries when invoked from Windows/WSL Ubuntu.

Actual online upgrades: 0013, 0027, 0029, 0035, 0036 and 0037 against minimal
FK predecessor tables; actual 0037 downgrade is tested empty and nonempty.
All Action/source/grant rows are explicitly SYNTHETIC SQL fixtures, not a
claim of executed 0027/0029 admission, signed source grants or worker effects.
No app DB, Docker, network listener, install or target. No shared file edits.

Opt in explicitly with OSOP_DISPOSABLE_SOURCEMAP_0037_PG=1.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_DISPOSABLE_SOURCEMAP_0037_PG"
MIGRATION = ROOT / "migrations/versions/0037_sourcemap_grant_binding.py"
_EXACT_PARENT_REVISIONS = {
    "0013": "0013_flow_artifacts.py",
    "0027": "0027_flow_mcp_action_dispatch.py",
    "0029": "0029_native_mcp_execution_grants.py",
    "0035": "0035_native_sourcemap_source_authority.py",
    "0036": "0036_sourcemap_native_grant_pair.py",
    "0037": "0037_sourcemap_grant_binding.py",
}


def _linux_path(path: Path) -> str:
    """Only convert a known local Windows path into WSL's /mnt/<drive> path."""
    path = path.resolve()
    raw = str(path)
    if os.name != "nt":
        return raw
    assert len(raw) > 3 and raw[1:3] == ":\\"
    drive = raw[0].lower()
    assert "a" <= drive <= "z"
    return "/mnt/" + drive + raw[2:].replace("\\", "/")


# Executed by Linux Python in an isolated subprocess. It uses ACTUAL migration
# upgrade()/downgrade() functions and Alembic Operations connected to psycopg's
# real Unix socket DBAPI, not fake op.get_bind, reconstructed DDL or an ASGI fake.
_LIVE_LINUX_TEST = r"""
import importlib.util
import json
import os
import random
import stat
import subprocess
import tempfile
import uuid
import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.exc import IntegrityError, DBAPIError
import psycopg

assert os.name == "posix" and os.geteuid() != 0, "Must start disposable PG as nonroot"
pg_bin = Path("/usr/lib/postgresql/16/bin")
assert all((pg_bin / x).is_file() for x in ("initdb", "pg_ctl", "psql"))

files = {
    "0013": "0013_flow_artifacts.py",
    "0027": "0027_flow_mcp_action_dispatch.py",
    "0029": "0029_native_mcp_execution_grants.py",
    "0035": "0035_native_sourcemap_source_authority.py",
    "0036": "0036_sourcemap_native_grant_pair.py",
    "0037": "0037_sourcemap_grant_binding.py",
}
def load(revision, filename):
    path = ROOT / "migrations" / "versions" / filename
    assert path.is_file(), path
    spec = importlib.util.spec_from_file_location("sourcemap_0037_live_" + revision, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == revision, module.revision
    return module

mod = {k: load(k, v) for k, v in files.items()}
assert mod["0037"].down_revision == "0036"
assert mod["0036"].down_revision == "0035"

def run(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=45)

def upgrade(connection, revision):
    context = MigrationContext.configure(connection, opts={"transactional_ddl": True})
    assert context.impl.transactional_ddl is True and not context.as_sql
    with Operations.context(context):
        mod[revision].upgrade()

def downgrade_0037(connection):
    context = MigrationContext.configure(connection, opts={"transactional_ddl": True})
    assert context.impl.transactional_ddl is True and not context.as_sql
    with Operations.context(context):
        mod["0037"].downgrade()

def digest(message):
    return hashlib.sha256(message.encode("ascii")).hexdigest()

def new_case(label):
    uid = uuid.uuid4().hex
    v = {
        "binding_id": "snb-" + uuid.uuid4().hex,
        "action_id": "action-" + uuid.uuid4().hex,
        "request_id": "req-" + uuid.uuid4().hex + uuid.uuid4().hex[:16],
        "preflight_id": "nsp-" + uuid.uuid4().hex,
        "grant_id": "ngr-" + uuid.uuid4().hex,
        "artifact_id": "artifact-" + uuid.uuid4().hex,
        "engagement_id": "eng-37-" + uid[:16],
        "flow_id": "flow-37-" + uid[:16],
        "task_id": "task-37-" + uid[:16],
        "subtask_id": "subtask-37-" + uid[:16],
        "owner_id": "source-original-owner",
        "reviewer_id": "independent-senior",
        "approval_id": "apr-37-" + uid[:16],
        "lease_id": "lease-37-" + uid[:16],
        "lease_owner_id": "worker-37-local",
        "flow_revision": 0,
        "authorization_id": "auth-37-" + uid[:16],
        "authorization_version": 1,
        "authorization_sha256": digest("auth-" + uid),
        "artifact_sha256": digest("artifact-" + uid),
        "resource_manifest_sha256": digest("manifest-" + uid),
        "declaration_sha256": digest("declaration-" + uid),
        "parameters_sha256": digest("parameters-" + uid),
        "preflight_claims_sha256": digest("source-claim-" + uid),
        "preflight_signature_sha256": digest("source-sig-" + uid),
        "grant_claims_sha256": digest("native-claim-" + uid),
        "grant_signature_sha256": digest("native-sig-" + uid),
        "join_sha256": digest("bound-join-" + uid),
        "status": "bound_only",
    }
    return v

COLS = (
    "binding_id", "action_id", "request_id", "preflight_id", "grant_id",
    "artifact_id", "engagement_id", "flow_id", "task_id", "subtask_id",
    "owner_id", "reviewer_id", "approval_id", "lease_id", "lease_owner_id",
    "flow_revision", "authorization_id", "authorization_version",
    "authorization_sha256", "artifact_sha256", "resource_manifest_sha256",
    "declaration_sha256", "parameters_sha256", "preflight_claims_sha256",
    "preflight_signature_sha256", "grant_claims_sha256",
    "grant_signature_sha256", "join_sha256", "status",
)
INSERT_BIND = sa.text(
    "INSERT INTO native_sourcemap_grant_bindings ("
    + ",".join(COLS) + ") VALUES (" + ",".join(":" + x for x in COLS) + ")"
)

def insert_case_parents(connection, v, label):
    # Synthetic FK rows: all predecessor TABLES use their real migration DDL.
    connection.execute(sa.text(
        "INSERT INTO session_states (session_id) VALUES (:id)"
    ), {"id": v["engagement_id"]})
    connection.execute(sa.text(
        "INSERT INTO execution_flows (id) VALUES (:id)"
    ), {"id": v["flow_id"]})
    connection.execute(sa.text("INSERT INTO tasks (id) VALUES (:id)"), {"id": v["task_id"]})
    connection.execute(sa.text("INSERT INTO execution_subtasks (id) VALUES (:id)"),
                       {"id": v["subtask_id"]})

    body = ('{"local_only":true,"case":"' + label + '"}\\n').encode("utf-8")
    actual = hashlib.sha256(body).hexdigest()
    connection.execute(sa.text(
        "INSERT INTO flow_artifacts "
        "(id,flow_id,engagement_id,owner_id,name,size_bytes,sha256,"
        "authorization_version,authorization_sha256,flow_revision,content) "
        "VALUES (:artifact_id,:flow_id,:engagement_id,:owner_id,:name,:size,:sha,"
        ":authorization_version,:authorization_sha256,:flow_revision,:body)"
    ), {**v, "name": label + ".json", "size": len(body), "sha": actual, "body": body})
    connection.execute(sa.text(
        "INSERT INTO flow_mcp_action_dispatches "
        "(action_id,engagement_id,flow_id,task_id,subtask_id,owner_id,"
        "flow_revision,authorization_id,authorization_version,"
        "authorization_sha256,approval_id,lease_id,lease_owner_id,"
        "server_id,tool_name,side_effect_class,declaration_sha256,"
        "parameters_sha256,safe_parameters,intent_sha256,request_id,"
        "reservation_token_sha256,status,revision,cancel_requested) "
        "VALUES (:action_id,:engagement_id,:flow_id,:task_id,:subtask_id,"
        ":owner_id,:flow_revision,:authorization_id,:authorization_version,"
        ":authorization_sha256,:approval_id,:lease_id,:lease_owner_id,"
        "'source-map-mcp','inspect_local_original_sourcemap','READ_ONLY',"
        ":declaration_sha256,:parameters_sha256,CAST('{}' AS json),:intent,"
        ":request_id,:reserved,'unknown',3,false)"
    ), {**v, "intent": digest("synthetic-intent-" + label), "reserved": "0"*64})
    connection.execute(sa.text(
        "INSERT INTO native_sourcemap_source_preflights "
        "(preflight_id,request_id,action_id,version,engagement_id,flow_id,"
        "task_id,subtask_id,owner_id,server_id,tool_name,artifact_sha256,"
        "manifest_sha256,approval_id,lease_id,authorization_version,"
        "authorization_sha256,issued_at,expires_at,kid,claims_sha256,signature_sha256) "
        "VALUES (:preflight_id,:request_id,:action_id,1,:engagement_id,:flow_id,"
        ":task_id,:subtask_id,:owner_id,'source-map-mcp',"
        "'inspect_local_original_sourcemap',:artifact_sha256,"
        ":resource_manifest_sha256,:approval_id,:lease_id,"
        ":authorization_version,:authorization_sha256,10000,10010,"
        "'synthetic-source-key',:preflight_claims_sha256,"
        ":preflight_signature_sha256)"
    ), v)
    # 0036 live Alembic changed the real 0029 CHECK to permit this exact pair.
    connection.execute(sa.text(
        "INSERT INTO native_mcp_execution_grants "
        "(grant_id,action_id,request_id,engagement_id,flow_id,task_id,subtask_id,"
        "owner_id,flow_revision,authorization_id,authorization_version,"
        "authorization_sha256,approval_id,lease_id,lease_owner_id,server_id,"
        "tool_name,side_effect_class,parameters_sha256,manifest_sha256,"
        "resource_sha256,intent_sha256,kid,claims_sha256,signature_sha256,"
        "issued_at,expires_at,status,revision) "
        "VALUES (:grant_id,:action_id,:request_id,:engagement_id,:flow_id,"
        ":task_id,:subtask_id,:owner_id,:flow_revision,:authorization_id,"
        ":authorization_version,:authorization_sha256,:approval_id,:lease_id,"
        ":lease_owner_id,'source-map-mcp','inspect_local_original_sourcemap',"
        "'READ_ONLY',:parameters_sha256,:declaration_sha256,:artifact_sha256,"
        ":intent,'synthetic-native-key',:grant_claims_sha256,"
        ":grant_signature_sha256,10000,10030,'issued',1)"
    ), {**v, "intent": digest("synthetic-grant-intent-" + label)})


def expect_integrity(engine, v, sqlstate):
    try:
        with engine.begin() as connection:
            connection.execute(INSERT_BIND, {key: v[key] for key in COLS})
    except IntegrityError as error:
        assert error.orig.sqlstate == sqlstate, error
        return
    raise AssertionError("Database accepted a row that should violate " + sqlstate)

with tempfile.TemporaryDirectory(prefix="osop-0037-native-binding-", dir="/tmp") as directory:
    root = Path(directory)
    root.chmod(0o700)
    data = root / "data"
    log = root / "pg.log"
    port = random.SystemRandom().randrange(54350, 56350)
    created = run([str(pg_bin/"initdb"), "-D", str(data), "-A", "trust",
                   "-U", "osop_0037_disposable", "--no-instructions"])
    assert created.returncode == 0, created.stderr[-1400:]
    started = False
    engine = None
    try:
        started_result = run([
            str(pg_bin/"pg_ctl"), "-D", str(data), "-l", str(log), "-o",
            "-c listen_addresses='' -c unix_socket_directories=" + str(root)
            + " -c unix_socket_permissions=0700 -c port=" + str(port)
            + " -c fsync=on -c synchronous_commit=on",
            "-w", "-t", "20", "start",
        ])
        assert started_result.returncode == 0, started_result.stderr[-1400:]
        started = True
        assert (root / (".s.PGSQL." + str(port))).is_socket()
        engine = sa.create_engine(
            "postgresql+psycopg://osop_0037_disposable@/postgres",
            connect_args={"host": str(root), "port": port, "connect_timeout": 5},
            pool_size=3, max_overflow=2, pool_timeout=6,
        )
        with engine.begin() as connection:
            assert connection.scalar(sa.text("SHOW listen_addresses")) == ""
            assert connection.scalar(sa.text("SHOW server_version_num")).startswith("16")
            assert connection.scalar(sa.text("SELECT current_database()")) == "postgres"
            # Minimal FK parents; these are NOT the application tables/migrations.
            for ddl in (
                "CREATE TABLE session_states (session_id varchar(64) PRIMARY KEY)",
                "CREATE TABLE execution_flows (id varchar(64) PRIMARY KEY)",
                "CREATE TABLE tasks (id varchar(64) PRIMARY KEY)",
                "CREATE TABLE execution_subtasks (id varchar(64) PRIMARY KEY)",
                "CREATE FUNCTION reject_target_authority_nonce_mutation() RETURNS trigger "
                "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
                "'Target authority replay receipts are immutable'; END; $$",
            ):
                connection.exec_driver_sql(ddl)
            for revision in ("0013", "0027", "0029", "0035", "0036"):
                upgrade(connection, revision)

        with engine.begin() as connection:
            upgrade(connection, "0037")  # ACTUAL online op.create_table/index/trigger.
            trigger = connection.scalar(sa.text(
                "SELECT EXISTS(SELECT 1 FROM pg_trigger "
                "WHERE tgrelid='native_sourcemap_grant_bindings'::regclass "
                "AND tgname='trg_sourcemap_grant_binding_immutable' AND NOT tgisinternal)"
            ))
            assert trigger is True
            constraints = dict(connection.execute(sa.text(
                "SELECT conname,contype FROM pg_constraint "
                "WHERE conrelid='native_sourcemap_grant_bindings'::regclass"
            )).all())
            assert constraints["ck_sourcemap_grant_binding_ids"] == "c"
            assert constraints["ck_sourcemap_grant_binding_inert"] == "c"
            assert constraints["ck_sourcemap_grant_binding_hashes"] == "c"
            assert sum(kind == "f" for kind in constraints.values()) == 4
            assert sum(kind == "u" for kind in constraints.values()) == 4
            idx = connection.scalar(sa.text(
                "SELECT EXISTS(SELECT 1 FROM pg_indexes "
                "WHERE tablename='native_sourcemap_grant_bindings' "
                "AND indexname='ix_sourcemap_grant_binding_tenant_flow')"
            ))
            assert idx is True

        # ACTUAL downgrade succeeds with an empty bound ledger.
        with engine.begin() as connection:
            downgrade_0037(connection)
            assert connection.scalar(sa.text(
                "SELECT to_regclass('native_sourcemap_grant_bindings')"
            )) is None
        with engine.begin() as connection:
            upgrade(connection, "0037")

        a, b = new_case("first"), new_case("second")
        with engine.begin() as connection:
            insert_case_parents(connection, a, "first")
            insert_case_parents(connection, b, "second")

        # FK protection for all four referenced original records.
        for key, prefix in (
            ("action_id", "action-"),
            ("preflight_id", "nsp-"),
            ("grant_id", "ngr-"),
            ("artifact_id", "artifact-"),
        ):
            invalid = {**a, "binding_id": "snb-" + uuid.uuid4().hex,
                       key: prefix + uuid.uuid4().hex}
            expect_integrity(engine, invalid, "23503")
        # CHECK predicates are actual PostgreSQL constraints from 0037.upgrade.
        for key, bad in (
            ("status", "issued"),
            ("reviewer_id", a["owner_id"]),
            ("join_sha256", "g" * 64),
            ("binding_id", "snb-wrong-format"),
        ):
            invalid = {**a, "binding_id": "snb-" + uuid.uuid4().hex, key: bad}
            expect_integrity(engine, invalid, "23514")

        # Two ACTUAL independent SQLAlchemy/psycopg connections race to bind
        # the exact same post-commit tuple. Both are valid synthetic references.
        def attempt():
            try:
                with engine.begin() as connection:
                    row = {**a, "binding_id": "snb-" + uuid.uuid4().hex}
                    connection.execute(INSERT_BIND, {k: row[k] for k in COLS})
                return "committed"
            except IntegrityError as error:
                assert error.orig.sqlstate == "23505", error
                return "unique_conflict"
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: attempt(), (0, 1)))
        assert sorted(outcomes) == ["committed", "unique_conflict"], outcomes

        with engine.begin() as connection:
            assert connection.scalar(sa.text(
                "SELECT COUNT(*) FROM native_sourcemap_grant_bindings"
            )) == 1
            row = connection.execute(sa.text(
                "SELECT action_id,request_id,preflight_id,grant_id,artifact_id,"
                "status FROM native_sourcemap_grant_bindings"
            )).mappings().one()
            assert all(row[key] == a[key] for key in row.keys())
            assert connection.scalar(sa.text(
                "SELECT status FROM flow_mcp_action_dispatches "
                "WHERE action_id=:id"
            ), {"id": a["action_id"]}) == "unknown"
            assert connection.scalar(sa.text(
                "SELECT status FROM native_mcp_execution_grants "
                "WHERE grant_id=:id"
            ), {"id": a["grant_id"]}) == "issued"
        # Single-axis UNIQUE constraints, all other unique FKs point to B.
        for field in ("action_id", "request_id", "preflight_id", "grant_id"):
            candidate = {**b, "binding_id": "snb-" + uuid.uuid4().hex,
                         field: a[field]}
            expect_integrity(engine, candidate, "23505")

        for sql in (
            "UPDATE native_sourcemap_grant_bindings SET status=status",
            "DELETE FROM native_sourcemap_grant_bindings",
        ):
            try:
                with engine.begin() as connection:
                    connection.exec_driver_sql(sql)
            except DBAPIError as exc:
                assert exc.orig.sqlstate == "P0001", exc
            else:
                raise AssertionError("0037 immutable trigger failed: " + sql)

        # Actual downgrade checks nonempty table with transactional lock and
        # rejects without dropping data. No fixture bypass for immutable rows.
        try:
            with engine.begin() as connection:
                downgrade_0037(connection)
        except RuntimeError as exc:
            assert "immutable SourceMap grant bindings exist" in str(exc), exc
        else:
            raise AssertionError("0037 downgrade removed populated bound ledger")
        with engine.begin() as connection:
            assert connection.scalar(sa.text(
                "SELECT COUNT(*) FROM native_sourcemap_grant_bindings"
            )) == 1
            assert connection.scalar(sa.text(
                "SELECT to_regclass('native_sourcemap_grant_bindings')"
            )) == "native_sourcemap_grant_bindings"
            assert connection.scalar(sa.text(
                "SELECT COUNT(*) FROM native_mcp_execution_grants"
            )) == 2  # Only synthetic FK parents; no real grant issuance.
        print("RESULT_JSON:" + json.dumps({
            "postgres_major": 16,
            "listen_addresses": "",
            "actual_upgrade_0037": True,
            "actual_empty_downgrade_0037": True,
            "actual_reupgrade_0037": True,
            "four_foreign_keys": True,
            "four_unique_constraints": True,
            "three_check_constraints": True,
            "race": outcomes,
            "immutable_update_delete": True,
            "nonempty_downgrade_denied": True,
            "binding_rows": 1,
            "original_action_unknown": True,
            "native_parent_rows_synthetic": 2,
        }, sort_keys=True))
    finally:
        if engine is not None:
            engine.dispose()
        if started:
            stopped = run([str(pg_bin/"pg_ctl"), "-D", str(data), "-w",
                           "-m", "fast", "stop"])
            assert stopped.returncode == 0, stopped.stderr[-1400:]
"""


def test_0037_migration_declares_explicit_bound_only_schema() -> None:
    """Cheap default check; no PostgreSQL, subprocess or migration execution."""
    import ast

    tree = ast.parse(MIGRATION.read_text(encoding="utf-8"))
    assert any(
        isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "revision"
                for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and node.value.value == "0037"
        for node in tree.body
    )
    assert all((ROOT / "migrations" / "versions" / x).is_file()
               for x in _EXACT_PARENT_REVISIONS.values())
    funcs = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert {"upgrade", "downgrade"} <= funcs


def test_real_0037_alembic_operations_unix_socket_pg16() -> None:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 for owned nonroot Unix-socket PostgreSQL16")
    if os.name == "nt":
        wsl_root = _linux_path(ROOT)
        packages = _linux_path(Path(sys.prefix) / "Lib" / "site-packages")
        command = ["wsl.exe", "-d", "Ubuntu", "--", "env",
                   "PYTHONPATH=" + packages, "python3", "-"]
    elif sys.platform == "linux":
        wsl_root = _linux_path(ROOT)
        command = [sys.executable, "-"]
    else:
        pytest.skip("Requires Linux or Ubuntu WSL with local PG16")
    script = "ROOT = __import__('pathlib').Path(" + repr(wsl_root) + ")\n" + _LIVE_LINUX_TEST
    try:
        result = subprocess.run(
            command, input=script, text=True, capture_output=True, timeout=190
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.fail("Isolated real PostgreSQL16 qualification unavailable: " + str(exc))
    assert result.returncode == 0, (
        "Isolated PostgreSQL/Alembic Ops failure:\n"
        + result.stderr[-3200:] + "\n" + result.stdout[-700:]
    )
    output = [line.removeprefix("RESULT_JSON:") for line in result.stdout.splitlines()
              if line.startswith("RESULT_JSON:")]
    assert len(output) == 1, result.stdout[-1000:]
    import json
    proof = json.loads(output[0])
    assert proof["postgres_major"] == 16
    assert proof["listen_addresses"] == ""
    assert proof["binding_rows"] == 1
    assert sorted(proof["race"]) == ["committed", "unique_conflict"]
    assert proof["nonempty_downgrade_denied"] is True
