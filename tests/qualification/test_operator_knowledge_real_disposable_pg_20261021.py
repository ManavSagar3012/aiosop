"""PostgreSQL 16 qualification for the actual 0019 operator-knowledge schema.

Opt in on Linux/WSL using::

    OSOP_DISPOSABLE_OPERATOR_KNOWLEDGE_PG=1 python3 -m pytest -q -o addopts= \
      --confcutdir=tests/qualification \
      tests/qualification/test_operator_knowledge_real_disposable_pg_20261021.py

This suite extracts table columns, CHECKs and indexes from migration 0019's
source AST and executes their corresponding DDL on a newly initialized, private
Unix-socket-only PostgreSQL 16 cluster. It tests real PostgreSQL constraints,
transactional CAS and two independent psql connections. The parent tables are
minimal foreign-key fixtures. This does NOT run Alembic Operations, the full
application schema, OperatorKnowledgeStore, FastAPI, signed policy validation,
or production revocation. In particular, the scoped UPDATE below is a SQL
qualification probe, not a replacement for FlowArtifactStore._fence/guard_sql.

No application database, TCP listener, Docker or external service is used.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest


_ROOT = Path(__file__).resolve().parents[2]
_MIGRATION = _ROOT / "migrations/versions/0019_operator_knowledge_documents.py"
_BIN = Path("/usr/lib/postgresql/16/bin")
_OPT_IN = "OSOP_DISPOSABLE_OPERATOR_KNOWLEDGE_PG"
_AUTH_SHA = "a" * 64
_OTHER_SHA = "b" * 64


def _literal(node: ast.AST) -> object:
    return ast.literal_eval(node)


def _keyword(call: ast.Call, name: str) -> ast.AST | None:
    values = [item.value for item in call.keywords if item.arg == name]
    assert len(values) <= 1
    return values[0] if values else None


def _migration_ddl() -> tuple[str, list[str]]:
    """Translate only the 0019's recognized, explicit SQLAlchemy AST contract.

    Unknown column types, defaults, constraints or indexes must fail the test;
    no guessed schema may silently replace an expanded migration.
    """
    tree = ast.parse(_MIGRATION.read_text(encoding="utf-8"))
    assert (
        _literal(
            next(
                n.value
                for n in tree.body
                if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "revision" for t in n.targets)
            )
        )
        == "0019"
    )
    upgrade = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "upgrade")
    calls = [
        n.value for n in upgrade.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
    ]
    table_calls = [c for c in calls if ast.unparse(c.func) == "op.create_table"]
    index_calls = [c for c in calls if ast.unparse(c.func) == "op.create_index"]
    assert len(table_calls) == 1 and len(index_calls) == 2
    table = table_calls[0]
    assert _literal(table.args[0]) == "operator_knowledge_documents"

    columns: list[str] = []
    checks: dict[str, str] = {}
    names: list[str] = []
    for argument in table.args[1:]:
        assert isinstance(argument, ast.Call)
        kind = ast.unparse(argument.func)
        if kind == "sa.CheckConstraint":
            expression = _literal(argument.args[0])
            name_node = _keyword(argument, "name")
            assert isinstance(expression, str) and name_node is not None
            name = _literal(name_node)
            assert isinstance(name, str) and re.fullmatch(r"ck_operator_knowledge_[a-z_]+", name)
            assert name not in checks
            checks[name] = expression
            continue

        assert kind == "sa.Column" and len(argument.args) >= 2
        col = _literal(argument.args[0])
        assert isinstance(col, str) and re.fullmatch(r"[a-z][a-z0-9_]*", col)
        names.append(col)
        type_node = argument.args[1]
        assert isinstance(type_node, ast.Call)
        type_name = ast.unparse(type_node.func)
        if type_name == "sa.String":
            size = _literal(type_node.args[0])
            assert isinstance(size, int) and 1 <= size <= 128
            sql_type = f"VARCHAR({size})"
        else:
            sql_type = {
                "sa.Integer": "INTEGER",
                "sa.Text": "TEXT",
                "sa.DateTime": "TIMESTAMP WITHOUT TIME ZONE",
            }[type_name]
            assert not type_node.args

        rendered = f'"{col}" {sql_type}'
        for extra in argument.args[2:]:
            assert isinstance(extra, ast.Call) and ast.unparse(extra.func) == "sa.ForeignKey"
            target = _literal(extra.args[0])
            assert target in {"session_states.session_id", "execution_flows.id"}
            ondelete = _keyword(extra, "ondelete")
            assert ondelete is not None and _literal(ondelete) == "RESTRICT"
            parent, pk = target.split(".")
            rendered += f' REFERENCES "{parent}"("{pk}") ON DELETE RESTRICT'
        pk_node = _keyword(argument, "primary_key")
        nullable_node = _keyword(argument, "nullable")
        default_node = _keyword(argument, "server_default")
        if pk_node is not None:
            assert _literal(pk_node) is True
            rendered += " PRIMARY KEY"
        if nullable_node is not None:
            nullable = _literal(nullable_node)
            assert isinstance(nullable, bool)
            if not nullable:
                rendered += " NOT NULL"
        if default_node is not None:
            if isinstance(default_node, ast.Constant):
                assert _literal(default_node) == "1"
                rendered += " DEFAULT 1"
            else:
                assert ast.unparse(default_node) == "sa.func.now()"
                rendered += " DEFAULT now()"
        columns.append(rendered)

    assert names == [
        "id",
        "engagement_id",
        "flow_id",
        "owner_id",
        "title",
        "doc_type",
        "content",
        "content_bytes",
        "sha256",
        "revision",
        "source_flow_revision",
        "authorization_version",
        "authorization_sha256",
        "created_at",
        "updated_at",
        "deleted_at",
    ]
    assert set(checks) == {
        "ck_operator_knowledge_type",
        "ck_operator_knowledge_bytes",
        "ck_operator_knowledge_content_length",
        "ck_operator_knowledge_sha",
        "ck_operator_knowledge_revisions",
        "ck_operator_knowledge_authorization_sha",
    }
    ddl = (
        'CREATE TABLE "operator_knowledge_documents" ('
        + ", ".join(columns)
        + ", "
        + ", ".join(
            f'CONSTRAINT "{name}" CHECK ({condition})' for name, condition in checks.items()
        )
        + ")"
    )
    indexes: list[str] = []
    for index in index_calls:
        index_name, table_name, col_names = map(_literal, index.args)
        assert index_name in {
            "ix_operator_knowledge_owner_flow",
            "ix_operator_knowledge_active_kind",
        }
        assert table_name == "operator_knowledge_documents"
        assert isinstance(col_names, list) and all(name in names for name in col_names)
        where_node = _keyword(index, "postgresql_where")
        where = ""
        if where_node is not None:
            assert isinstance(where_node, ast.Call) and ast.unparse(where_node.func) == "sa.text"
            predicate = _literal(where_node.args[0])
            assert predicate == "deleted_at IS NULL"
            where = f" WHERE {predicate}"
        indexes.append(
            f'CREATE INDEX "{index_name}" ON "{table_name}" ('
            + ", ".join(f'"{name}"' for name in col_names)
            + ")"
            + where
        )
    assert len({s.split('"')[1] for s in indexes}) == 2
    return ddl, indexes


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=40, check=False)


@dataclass(frozen=True)
class PG:
    root: Path
    port: int

    def command(self, sql: str) -> subprocess.CompletedProcess[str]:
        return _run(
            [
                str(_BIN / "psql"),
                "-X",
                "-q",
                "-A",
                "-t",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                str(self.root),
                "-p",
                str(self.port),
                "-U",
                "osop_knowledge_qual",
                "-d",
                "postgres",
                "-c",
                sql,
            ]
        )

    def sql(self, statement: str, *, fails: str | None = None) -> str:
        outcome = self.command(statement)
        if fails is None:
            assert outcome.returncode == 0, outcome.stderr[-900:]
        else:
            assert outcome.returncode != 0, "Unexpected SQL success: " + statement[:160]
            assert fails in outcome.stderr, outcome.stderr[-900:]
        return outcome.stdout.strip()


@pytest.fixture(scope="module")
def server() -> Iterator[PG]:
    if sys.platform != "linux" or os.name != "posix":
        pytest.skip("Socket-only disposable PostgreSQL requires Linux/WSL")
    if os.environ.get(_OPT_IN) != "1":
        pytest.skip("Explicit opt-in OSOP_DISPOSABLE_OPERATOR_KNOWLEDGE_PG=1 required")
    if os.geteuid() == 0:
        pytest.skip("Refusing initdb as root")
    if any(not (_BIN / binary).is_file() for binary in ("initdb", "pg_ctl", "psql")):
        pytest.skip("Local PostgreSQL 16 binaries are missing")

    ddl, indexes = _migration_ddl()
    with tempfile.TemporaryDirectory(prefix="osop-operator-knowledge-", dir="/tmp") as folder:
        root = Path(folder)
        root.chmod(stat.S_IRWXU)
        data = root / "data"
        log = root / "postgres.log"
        port = 54000 + secrets.randbelow(1000)
        initialized = _run(
            [
                str(_BIN / "initdb"),
                "-D",
                str(data),
                "-A",
                "trust",
                "-U",
                "osop_knowledge_qual",
                "--no-instructions",
            ]
        )
        assert initialized.returncode == 0, initialized.stderr[-900:]
        started = False
        try:
            boot = _run(
                [
                    str(_BIN / "pg_ctl"),
                    "-D",
                    str(data),
                    "-l",
                    str(log),
                    "-o",
                    f"-c listen_addresses='' -c unix_socket_directories={root} "
                    f"-c unix_socket_permissions=0700 -c port={port}",
                    "-w",
                    "-t",
                    "20",
                    "start",
                ]
            )
            assert boot.returncode == 0, boot.stderr[-900:] + log.read_text()[-900:]
            started = True
            assert (root / f".s.PGSQL.{port}").is_socket()
            pg = PG(root, port)
            assert pg.sql("SHOW listen_addresses") == ""
            pg.sql(
                "CREATE TABLE session_states (session_id VARCHAR(64) PRIMARY KEY, "
                "created_by VARCHAR(64) NOT NULL, phase TEXT NOT NULL)"
            )
            pg.sql(
                "CREATE TABLE execution_flows (id VARCHAR(64) PRIMARY KEY, "
                "engagement_id VARCHAR(64) NOT NULL REFERENCES session_states(session_id), "
                "revision INTEGER NOT NULL, status TEXT NOT NULL)"
            )
            pg.sql(ddl)
            for statement in indexes:
                pg.sql(statement)
            yield pg
        finally:
            if started:
                stop = _run([str(_BIN / "pg_ctl"), "-D", str(data), "-w", "-m", "fast", "stop"])
                assert stop.returncode == 0, stop.stderr[-900:]


@pytest.fixture
def pg(server: PG) -> Iterator[PG]:
    server.sql("TRUNCATE operator_knowledge_documents, execution_flows, session_states")
    yield server


def _quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _doc(
    identifier: str,
    *,
    sid: str = "eng-owner-a",
    flow: str = "flow-owner-a",
    owner: str = "owner-a",
    content: str = "safe text",
    title: str = "Guide",
    kind: str = "guide",
    byte_size: int | None = None,
    sha: str | None = None,
    rev: int = 1,
    auth_version: int = 7,
    auth_sha: str = _AUTH_SHA,
) -> str:
    encoded = content.encode("utf-8")
    fields = [identifier, sid, flow, owner, title, kind, content]
    return (
        "INSERT INTO operator_knowledge_documents "
        "(id,engagement_id,flow_id,owner_id,title,doc_type,content,"
        "content_bytes,sha256,revision,source_flow_revision,authorization_version,"
        "authorization_sha256) VALUES ("
        + ",".join(_quoted(field) for field in fields)
        + f",{len(encoded) if byte_size is None else byte_size},"
        + _quoted(hashlib.sha256(encoded).hexdigest() if sha is None else sha)
        + f",{rev},2,{auth_version},{_quoted(auth_sha)})"
    )


def _owners(pg: PG) -> None:
    pg.sql(
        "INSERT INTO session_states VALUES "
        "('eng-owner-a','owner-a','reconnaissance'),"
        "('eng-owner-b','owner-b','reconnaissance')"
    )
    pg.sql(
        "INSERT INTO execution_flows VALUES "
        "('flow-owner-a','eng-owner-a',2,'running'),"
        "('flow-owner-b','eng-owner-b',9,'running')"
    )


def _fenced_cas(
    identifier: str,
    *,
    owner: str = "owner-a",
    flow: str = "flow-owner-a",
    revision: int = 2,
    auth_version: int = 7,
    auth_sha: str = _AUTH_SHA,
    expected_document: int = 1,
    content: str = "revised text",
) -> str:
    """Probe owner/Flow/CAS SQL only; no signed guard_sql implementation here."""
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return (
        "UPDATE operator_knowledge_documents d SET content="
        + _quoted(content)
        + f",content_bytes={len(content.encode('utf-8'))},sha256={_quoted(digest)},"
        "revision=d.revision+1,updated_at=now() "
        "WHERE d.id="
        + _quoted(identifier)
        + " AND d.owner_id="
        + _quoted(owner)
        + " AND d.flow_id="
        + _quoted(flow)
        + " AND d.authorization_sha256="
        + _quoted(auth_sha)
        + f" AND d.authorization_version={auth_version} "
        + f"AND d.revision={expected_document} AND d.deleted_at IS NULL "
        + "AND EXISTS (SELECT 1 FROM execution_flows f JOIN session_states s "
        "ON s.session_id=f.engagement_id WHERE f.id=d.flow_id "
        "AND f.engagement_id=d.engagement_id AND s.created_by=d.owner_id "
        "AND s.created_by=" + _quoted(owner) + f" AND f.revision={revision} "
        "AND f.status IN ('pending','running') "
        "AND s.phase NOT IN ('halted','completed')) RETURNING d.revision"
    )


def test_0019_real_constraint_and_foreign_key_enforcement(pg: PG) -> None:
    """The CHECKs and FKs extracted from 0019 actually run in PostgreSQL."""
    _owners(pg)
    constraints = pg.sql(
        "SELECT conname FROM pg_constraint WHERE conrelid="
        "'operator_knowledge_documents'::regclass ORDER BY conname"
    )
    for name in (
        "ck_operator_knowledge_type",
        "ck_operator_knowledge_bytes",
        "ck_operator_knowledge_content_length",
        "ck_operator_knowledge_sha",
        "ck_operator_knowledge_revisions",
        "ck_operator_knowledge_authorization_sha",
    ):
        assert name in constraints.splitlines()
    indexes = pg.sql(
        "SELECT indexname FROM pg_indexes WHERE tablename=" "'operator_knowledge_documents'"
    )
    assert "ix_operator_knowledge_owner_flow" in indexes
    assert "ix_operator_knowledge_active_kind" in indexes

    identifier = "knowledge-" + "1" * 32
    pg.sql(_doc(identifier, content="é" * 4096))  # exactly 8192 UTF-8 bytes
    assert (
        pg.sql(
            "SELECT content_bytes FROM operator_knowledge_documents "
            f"WHERE id={_quoted(identifier)}"
        )
        == "8192"
    )
    invalid = [
        (_doc("knowledge-" + "2" * 32, kind="prompt"), "ck_operator_knowledge_type"),
        (_doc("knowledge-" + "3" * 32, byte_size=8193), "ck_operator_knowledge_bytes"),
        (_doc("knowledge-" + "4" * 32, byte_size=3), "ck_operator_knowledge_content_length"),
        (_doc("knowledge-" + "5" * 32, sha="F" * 64), "ck_operator_knowledge_sha"),
        (_doc("knowledge-" + "6" * 32, rev=0), "ck_operator_knowledge_revisions"),
        (
            _doc("knowledge-" + "7" * 32, auth_sha="invalid"),
            "ck_operator_knowledge_authorization_sha",
        ),
        (
            _doc("knowledge-" + "8" * 32, sid="eng-missing"),
            "operator_knowledge_documents_engagement_id_fkey",
        ),
        (
            _doc("knowledge-" + "9" * 32, flow="flow-missing"),
            "operator_knowledge_documents_flow_id_fkey",
        ),
    ]
    for statement, constraint in invalid:
        pg.sql(statement, fails=constraint)

    # FK constraints reference the session and Flow independently. They do
    # not enforce that the referenced Flow belongs to this engagement: only
    # the application transaction's _fence establishes that relationship.
    mismatched = "knowledge-" + "a" * 32
    pg.sql(_doc(mismatched, flow="flow-owner-b"))
    assert (
        pg.sql(
            "SELECT count(*) FROM operator_knowledge_documents WHERE " "id=" + _quoted(mismatched)
        )
        == "1"
    )
    assert pg.sql(_fenced_cas(mismatched)) == ""


def test_two_real_clients_owner_flow_cas_lineage_tombstone_and_replay(pg: PG) -> None:
    """Real competing client transactions test scoped SQL behavior and gaps."""
    _owners(pg)
    identifier = "knowledge-" + "b" * 32
    pg.sql(_doc(identifier))
    pg.sql(_doc("knowledge-" + "c" * 32, sid="eng-owner-b", flow="flow-owner-b", owner="owner-b"))

    for kwargs in (
        {"owner": "owner-b"},
        {"flow": "flow-owner-b"},
        {"revision": 9},
        {"auth_version": 8},
        {"auth_sha": _OTHER_SHA},
        {"expected_document": 2},
    ):
        assert pg.sql(_fenced_cas(identifier, **kwargs)) == ""
    assert (
        pg.sql("SELECT revision FROM operator_knowledge_documents WHERE id=" + _quoted(identifier))
        == "1"
    )

    # Separate real psql processes acquire conflicting row locks. Exactly one
    # may advance revision 1 to 2; a stale second UPDATE returns no row.
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(
            executor.map(
                pg.command,
                (
                    _fenced_cas(identifier, content="client one"),
                    _fenced_cas(identifier, content="client two"),
                ),
            )
        )
    assert all(result.returncode == 0 for result in outcomes)
    assert sum(bool(result.stdout.strip()) for result in outcomes) == 1
    assert (
        pg.sql("SELECT revision FROM operator_knowledge_documents WHERE id=" + _quoted(identifier))
        == "2"
    )
    assert pg.sql(_fenced_cas(identifier, expected_document=1)) == ""

    # A changed Flow revision denies this scoped probe until the caller uses
    # the current revision. Real store/API revocation and signatures are NOT
    # exercised by this manually constructed SQL probe.
    pg.sql("UPDATE execution_flows SET revision=3 WHERE id='flow-owner-a'")
    assert pg.sql(_fenced_cas(identifier, expected_document=2)) == ""
    assert pg.sql(_fenced_cas(identifier, expected_document=2, revision=3)) == "3"
    tombstone = (
        "UPDATE operator_knowledge_documents SET deleted_at=now(),revision=revision+1 "
        f"WHERE id={_quoted(identifier)} AND owner_id='owner-a' "
        "AND revision=3 AND deleted_at IS NULL RETURNING revision"
    )
    assert pg.sql(tombstone) == "4"
    assert pg.sql(tombstone) == ""  # repeat delete cannot increment twice
    assert pg.sql(_fenced_cas(identifier, revision=3, expected_document=4)) == ""
    assert (
        pg.sql(
            "SELECT count(*) FROM operator_knowledge_documents WHERE "
            f"id={_quoted(identifier)} AND deleted_at IS NULL"
        )
        == "0"
    )
    pg.sql(_doc(identifier), fails="operator_knowledge_documents_pkey")
    assert (
        pg.sql(
            "SELECT revision FROM operator_knowledge_documents " f"WHERE id={_quoted(identifier)}"
        )
        == "4"
    )

    # Same contents with a *new* generated id are not deduplicated by 0019;
    # create() has no caller-supplied idempotency token or content UNIQUE.
    pg.sql(_doc("knowledge-" + "d" * 32, content="same body"))
    pg.sql(_doc("knowledge-" + "e" * 32, content="same body"))
    assert (
        pg.sql("SELECT count(*) FROM operator_knowledge_documents " "WHERE content='same body'")
        == "2"
    )


def test_digest_integrity_requires_store_and_signatures_remain_unqualified(pg: PG) -> None:
    """Document exactly where SQL constraints stop enforcing provenance."""
    _owners(pg)
    identifier = "knowledge-" + "f" * 32
    pg.sql(_doc(identifier, content="before"))
    original_sha = pg.sql(
        "SELECT sha256 FROM operator_knowledge_documents " f"WHERE id={_quoted(identifier)}"
    )
    # Migration 0019 validates digest syntax, not hash(content) equality.
    # Actual OperatorKnowledgeStore._verified_content rejects this on GET.
    pg.sql(
        "UPDATE operator_knowledge_documents SET content='AFTER!' "
        f"WHERE id={_quoted(identifier)}"
    )
    assert (
        pg.sql("SELECT sha256 FROM operator_knowledge_documents " f"WHERE id={_quoted(identifier)}")
        == original_sha
    )
    assert original_sha != hashlib.sha256(b"AFTER!").hexdigest()
