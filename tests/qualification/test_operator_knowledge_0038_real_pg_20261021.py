"""Opt-in real PostgreSQL16 validation of operator-knowledge 0038 integrity.

Creates its own nonroot, Unix-socket-only PostgreSQL16 instance. Invokes actual
0019 and, once committed, 0038 upgrade/downgrade through live Alembic Ops
against minimal session_states/execution_flows parent schema. NOT the full
application migrations and never touches an app DB, Docker or a provider.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_DISPOSABLE_OPERATOR_KNOWLEDGE_0038_PG"
ORIGINAL_0019 = ROOT / "migrations/versions/0019_operator_knowledge_documents.py"
NEW_0038 = ROOT / "migrations/versions/0038_operator_knowledge_integrity.py"


def _linux_path(path: Path) -> str:
    """Return unchanged POSIX or exact WSL mount path for an owned local file."""
    absolute = str(path.resolve())
    if os.name != "nt":
        return absolute
    assert len(absolute) > 3 and absolute[1:3] == ":\\"
    return "/mnt/" + absolute[0].lower() + absolute[2:].replace("\\", "/")


def test_original_0019_has_the_exact_unbound_column_contract() -> None:
    """Runs safely before 0038 is ready; does not import its in-progress code."""
    tree = ast.parse(ORIGINAL_0019.read_text(encoding="utf-8"))
    attrs = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    assert "operator_knowledge_documents" in attrs
    assert "engagement_id" in attrs and "flow_id" in attrs
    assert "sha256" in attrs and "content" in attrs
    assert "ck_operator_knowledge_sha" in attrs


# The opt-in Linux subprocess imports migration 0038 only after the prime
# finalizes it. This body intentionally uses actual online Alembic Operations
# and a fresh owned PostgreSQL cluster, not fake SQL or a live application DB.
_LIVE_PG_BODY = r"""
import hashlib
import importlib.util
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.exc import IntegrityError
import psycopg

assert os.name == "posix" and os.geteuid() != 0
BIN = Path("/usr/lib/postgresql/16/bin")
assert all((BIN / executable).is_file() for executable in ("initdb", "pg_ctl", "psql"))

def load(revision, filename):
    file = ROOT / "migrations" / "versions" / filename
    assert file.is_file()
    spec = importlib.util.spec_from_file_location("operator_pg_" + revision, file)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == revision
    return module

old = load("0019", "0019_operator_knowledge_documents.py")
new = load("0038", "0038_operator_knowledge_integrity.py")
assert new.down_revision == "0037"

def migration(connection, method, name):
    context = MigrationContext.configure(connection, opts={"transactional_ddl": True})
    assert not context.as_sql and context.impl.transactional_ddl is True
    with Operations.context(context):
        getattr(method, name)()

def execute(args):
    return subprocess.run(args, check=False, capture_output=True, text=True, timeout=45)

def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

TENANT_A, TENANT_B = "eng-knowledge-tenant-a", "eng-knowledge-tenant-b"
FLOW_A, FLOW_B = "flow-knowledge-tenant-a", "flow-knowledge-tenant-b"
DOC_INSERT = sa.text(
    "INSERT INTO operator_knowledge_documents "
    "(id,engagement_id,flow_id,owner_id,title,doc_type,content,content_bytes,"
    "sha256,revision,source_flow_revision,authorization_version,authorization_sha256)"
    " VALUES (:id,:tenant,:flow,'operator-original','Inert knowledge','guide',"
    ":content,:nbytes,:sha,1,0,1,:auth)"
)

def insert_doc(connection, *, doc_id, tenant, flow, content, actual_sha=None):
    connection.execute(DOC_INSERT, {
        "id": doc_id, "tenant": tenant, "flow": flow, "content": content,
        "nbytes": len(content.encode("utf-8")),
        "sha": actual_sha if actual_sha is not None else sha(content),
        "auth": sha("fixture-authority"),
    })

def constraint_names(connection):
    return set(connection.execute(sa.text(
        "SELECT conname FROM pg_constraint WHERE "
        "conrelid IN ('operator_knowledge_documents'::regclass,"
        "'execution_flows'::regclass)"
    )).scalars())

ENFORCED = {
    "uq_execution_flows_id_engagement_knowledge",
    "fk_operator_knowledge_exact_flow_tenant",
    "ck_operator_knowledge_content_digest",
}

def expect_denied_precheck(engine, mismatch, marker):
    with engine.begin() as connection:
        insert_doc(connection, **mismatch)
    before = None
    with engine.begin() as connection:
        before = constraint_names(connection)
        assert not ENFORCED.intersection(before)
    try:
        with engine.begin() as connection:
            migration(connection, new, "upgrade")
    except RuntimeError as error:
        assert "existing knowledge tenant or content digest mismatch" in str(error), error
    else:
        raise AssertionError("0038 accepted bad " + marker + " preexisting row")
    with engine.begin() as connection:
        assert constraint_names(connection) == before, "Rejected upgrade changed DDL"
        assert connection.scalar(sa.text(
            "SELECT COUNT(*) FROM operator_knowledge_documents WHERE id=:id"
        ), {"id": mismatch["doc_id"]}) == 1, "Failed upgrade modified original data"
        connection.execute(sa.text(
            "DELETE FROM operator_knowledge_documents WHERE id=:id"
        ), {"id": mismatch["doc_id"]})

def expect_integrity(engine, *, code, sql):
    try:
        with engine.begin() as connection:
            connection.execute(sa.text(sql))
    except IntegrityError as error:
        assert error.orig.sqlstate == code, (error.orig.sqlstate, str(error))
    else:
        raise AssertionError("PostgreSQL accepted invalid constraint: " + sql)

with tempfile.TemporaryDirectory(prefix="osop-operator-0038-", dir="/tmp") as base:
    owned = Path(base)
    owned.chmod(0o700)
    directory = owned / "data"
    log = owned / "pg16.log"
    port = 55000 + secrets.randbelow(1200)
    initialized = execute([
        str(BIN/"initdb"), "-D", str(directory), "-A", "trust",
        "-U", "osop_operator_disposable", "--no-instructions",
    ])
    assert initialized.returncode == 0, initialized.stderr[-1100:]
    started = False
    engine = None
    try:
        boot = execute([
            str(BIN/"pg_ctl"), "-D", str(directory), "-l", str(log),
            "-o", "-c listen_addresses='' -c unix_socket_directories=" +
            str(owned) + " -c unix_socket_permissions=0700 -c port=" +
            str(port) + " -c fsync=on -c synchronous_commit=on",
            "-w", "-t", "20", "start",
        ])
        assert boot.returncode == 0, boot.stderr[-1500:]
        started = True
        assert (owned / (".s.PGSQL." + str(port))).is_socket()
        engine = sa.create_engine(
            "postgresql+psycopg://osop_operator_disposable@/postgres",
            connect_args={"host": str(owned), "port": port, "connect_timeout": 3},
            pool_size=2, max_overflow=2,
        )
        with engine.begin() as connection:
            assert connection.scalar(sa.text("SHOW listen_addresses")) == ""
            assert connection.scalar(sa.text("SHOW server_version_num")).startswith("16")
            assert connection.scalar(sa.text("SELECT current_database()")) == "postgres"
            connection.exec_driver_sql(
                "CREATE TABLE session_states (session_id varchar(64) PRIMARY KEY)"
            )
            connection.exec_driver_sql(
                "CREATE TABLE execution_flows "
                "(id varchar(64) PRIMARY KEY, engagement_id varchar(64) NOT NULL)"
            )
            connection.execute(sa.text(
                "INSERT INTO session_states (session_id) VALUES (:a),(:b)"
            ), {"a": TENANT_A, "b": TENANT_B})
            connection.execute(sa.text(
                "INSERT INTO execution_flows (id,engagement_id) "
                "VALUES (:a,:tenant_a),(:b,:tenant_b)"
            ), {"a": FLOW_A, "b": FLOW_B, "tenant_a": TENANT_A,
                "tenant_b": TENANT_B})
            migration(connection, old, "upgrade")
            assert not ENFORCED.intersection(constraint_names(connection))

        expect_denied_precheck(engine, {
            "doc_id": "doc-mismatched-tenant", "tenant": TENANT_A,
            "flow": FLOW_B, "content": "correct sha / foreign flow",
        }, "cross-tenant Flow")
        expect_denied_precheck(engine, {
            "doc_id": "doc-mismatched-sha", "tenant": TENANT_A,
            "flow": FLOW_A, "content": "same tenant / wrong SHA",
            "actual_sha": "f" * 64,
        }, "content SHA")

        # Existing legitimate rows are preserved by upgrade and indexed exactly.
        with engine.begin() as connection:
            insert_doc(connection, doc_id="doc-matching-a", tenant=TENANT_A,
                       flow=FLOW_A, content="approved legitimate notes")
            insert_doc(connection, doc_id="doc-matching-b", tenant=TENANT_B,
                       flow=FLOW_B, content="valid UTF8 👩‍💻 reference")
        with engine.begin() as connection:
            migration(connection, new, "upgrade")
            assert ENFORCED <= constraint_names(connection)
            assert connection.scalar(sa.text(
                "SELECT COUNT(*) FROM operator_knowledge_documents"
            )) == 2
            assert connection.scalar(sa.text(
                "SELECT content_bytes FROM operator_knowledge_documents "
                "WHERE id='doc-matching-b'"
            )) == len("valid UTF8 👩‍💻 reference".encode("utf-8"))
            assert connection.scalar(sa.text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname='fk_operator_knowledge_exact_flow_tenant'"
            )).find("FOREIGN KEY") >= 0

        # DB itself rejects wrong-tenant/wrong-hash inserts and updates.
        # Valid source Flow tenant and literal content digest may still mutate
        # when both are updated consistently (0019 is an editable document).
        with engine.begin() as connection:
            insert_doc(connection, doc_id="doc-valid-new", tenant=TENANT_A,
                       flow=FLOW_A, content="another approved document")
        for sql, code in (
            (
                "UPDATE operator_knowledge_documents "
                "SET flow_id='flow-knowledge-tenant-b' "
                "WHERE id='doc-valid-new'", "23503"
            ),
            (
                "UPDATE operator_knowledge_documents "
                "SET sha256='" + "0"*64 + "' WHERE id='doc-valid-new'",
                "23514"
            ),
            (
                "UPDATE operator_knowledge_documents "
                "SET content='altered source text' WHERE id='doc-valid-new'",
                "23514"
            ),
        ):
            expect_integrity(engine, code=code, sql=sql)
        with engine.begin() as connection:
            assert connection.scalar(sa.text(
                "SELECT COUNT(*) FROM operator_knowledge_documents"
            )) == 3
            connection.execute(sa.text(
                "UPDATE operator_knowledge_documents SET deleted_at=clock_timestamp() "
                "WHERE id='doc-valid-new'"
            ))

        # Even a tombstoned entry is protected from downgrade. Nonempty
        # migrations preserve content and leave DDL unchanged on denial.
        with engine.begin() as connection:
            old_constraints = constraint_names(connection)
        try:
            with engine.begin() as connection:
                migration(connection, new, "downgrade")
        except RuntimeError as error:
            assert "operator knowledge rows remain" in str(error), error
        else:
            raise AssertionError("0038 downgrade discarded nonempty documents")
        with engine.begin() as connection:
            assert constraint_names(connection) == old_constraints
            assert connection.scalar(sa.text(
                "SELECT COUNT(*) FROM operator_knowledge_documents"
            )) == 3
            assert connection.scalar(sa.text(
                "SELECT COUNT(*) FROM operator_knowledge_documents "
                "WHERE deleted_at IS NOT NULL"
            )) == 1
            # Deliberate disposable-fixture cleanup, never production deletion.
            connection.execute(sa.text("DELETE FROM operator_knowledge_documents"))
        with engine.begin() as connection:
            migration(connection, new, "downgrade")
            assert ENFORCED.isdisjoint(constraint_names(connection))
            assert "ck_operator_knowledge_content_length" in constraint_names(connection)
            assert connection.scalar(sa.text(
                "SELECT to_regclass('operator_knowledge_documents')"
            )) == "operator_knowledge_documents"
        print("RESULT_0038_PG_OK " + json.dumps({
            "postgres_major": 16, "unix_socket_only": True,
            "actual_0019_upgrade": True, "actual_0038_upgrade_downgrade": True,
            "preexisting_cross_tenant_denied": True,
            "preexisting_wrong_sha_denied": True,
            "matching_original_rows_preserved": True,
            "post_upgrade_fk_sha_checks_enforced": True,
            "nonempty_downgrade_denied": True,
            "empty_downgrade_succeeded": True,
            "app_database_touched": False,
        }, sort_keys=True))
    finally:
        if engine is not None:
            engine.dispose()
        if started:
            stop = execute([
                str(BIN/"pg_ctl"), "-D", str(directory), "-w", "-m", "fast",
                "stop",
            ])
            assert stop.returncode == 0, stop.stderr[-1100:]
"""


def test_actual_0038_alembic_upgrade_downgrade_isolated_pg16() -> None:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 to create an independent Unix-socket PostgreSQL16")
    if not NEW_0038.is_file():
        pytest.skip("0038 migration not yet available; fail closed")
    if os.name == "nt":
        repo = _linux_path(ROOT)
        packages = _linux_path(Path(sys.prefix) / "Lib" / "site-packages")
        command = [
            "wsl.exe", "-d", "Ubuntu", "--", "env",
            "PYTHONPATH=" + packages, "python3", "-",
        ]
    elif sys.platform == "linux":
        repo = _linux_path(ROOT)
        command = [sys.executable, "-"]
    else:
        pytest.skip("Linux or WSL Ubuntu required for isolated PostgreSQL16")
    script = "ROOT = __import__('pathlib').Path(" + repr(repo) + ")\n" + _LIVE_PG_BODY
    try:
        result = subprocess.run(
            command, input=script, text=True, encoding="utf-8",
            errors="replace", capture_output=True, timeout=190,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.fail("Disposable PostgreSQL16 unavailable: " + str(exc))
    assert result.returncode == 0, (
        "Live 0038 migration qualification failed:\n"
        + result.stderr[-3400:] + "\n" + result.stdout[-1000:]
    )
    assert "RESULT_0038_PG_OK" in result.stdout
