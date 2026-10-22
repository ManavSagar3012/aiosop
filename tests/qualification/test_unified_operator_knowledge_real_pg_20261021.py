"""Unified operator knowledge qualification, strictly scoped and evidence-labelled.

Default: mounted FastAPI router + ACTUAL 0039 and 0019 store search methods
over a deliberately synthetic SQL session and signed-Flow fence. Neither
signature verification nor PostgreSQL is claimed by the default tests.

Opt-in: on Linux or WSL, creates its own nonroot PostgreSQL16 data directory,
Unix socket only, applies actual Alembic 0019/0038/0039 migrations to minimal
FK parents, probes real digest/tenant/tombstone/current-version behavior.
It NEVER connects to any application DB, Docker or target.
"""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.api.routers import unified_knowledge_search as unified
from ai_osop.memory import flow_artifacts as artifacts
from ai_osop.memory import operator_knowledge as flow_store
from ai_osop.memory.operator_knowledge import KnowledgeDenied


ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_DISPOSABLE_UNIFIED_KNOWLEDGE_PG"
ISSUER = "https://identity.example.test"
ALICE = "operator-unified-a"
BOB = "operator-unified-b"
FLOW = "flow-unified-private"
ENG = "eng-unified-private"
AUTH_SHA = "a" * 64
FLOW_CONTENT = "unified readme Flow note 🔒"
GLOBAL_CONTENT = "unified readme global note 📘"
NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _owner(subject: str) -> str:
    return _hash(ISSUER + "\x00" + subject)


def _operator_claims(subject: str) -> dict[str, Any]:
    # A synthetic dependency override, NOT a verified JWT/OIDC or signed ROE.
    return {
        "sub": subject,
        "role": "operator",
        "claims": {"iss": ISSUER, "exp": 2147483647},
    }


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def mappings(self) -> "_Result":
        return self

    def all(self) -> list[dict[str, Any]]:
        return self.rows

    def one_or_none(self) -> Any:
        assert len(self.rows) <= 1
        return self.rows[0] if self.rows else None


class _FakeSession:
    """Synthetic database queries, NO claims of PostgreSQL behavior."""

    def __init__(self) -> None:
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self.global_docs: list[dict[str, Any]] = []
        self.flow_docs: list[dict[str, Any]] = []

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    @asynccontextmanager
    async def begin(self) -> Any:
        yield self

    async def execute(self, statement: Any, params: Any = None) -> _Result:
        sql = str(statement)
        args = dict(params or {})
        self.queries.append((sql, args))
        assert sql.lstrip().upper().startswith("SELECT "), sql
        if "FROM operator_global_library_documents" in sql:
            assert "d.principal_issuer=:issuer" in sql
            assert "d.principal_subject=:owner" in sql
            assert "d.deleted_at IS NULL" in sql
            assert "v.revision=d.current_revision" in sql
            assert "strpos(lower(v.content),lower(:query))>0" in sql
            rows = [
                row
                for row in self.global_docs
                if row["_issuer"] == args["issuer"]
                and row["_owner"] == args["owner"]
                and row["_deleted"] is False
                and args["query"].lower() in (row["title"] + row["content"]).lower()
            ]
            return _Result(
                [
                    {key: value for key, value in row.items() if not key.startswith("_")}
                    for row in rows[args["offset"] : args["offset"] + args["limit"]]
                ]
            )
        if "FROM operator_knowledge_documents" in sql:
            assert "engagement_id=:sid" in sql
            assert "flow_id=:fid" in sql
            assert "owner_id=:owner" in sql
            assert "authorization_version=:version" in sql
            assert "authorization_sha256=:auth_sha" in sql
            assert "deleted_at IS NULL" in sql
            rows = [
                row
                for row in self.flow_docs
                if row["engagement_id"] == args["sid"]
                and row["flow_id"] == args["fid"]
                and row["owner_id"] == args["owner"]
                and row["authorization_version"] == args["version"]
                and row["authorization_sha256"] == args["auth_sha"]
                and row["deleted_at"] is None
                and args["needle"].lower() in (row["title"] + row["content"]).lower()
            ]
            return _Result(rows[args["offset"] : args["offset"] + args["limit"]])
        raise AssertionError("Unexpected SQL source: " + sql)


@pytest.fixture
def mounted(monkeypatch: pytest.MonkeyPatch) -> tuple[FastAPI, _FakeSession]:
    db = _FakeSession()
    db.global_docs = [
        {
            "_issuer": ISSUER,
            "_owner": _owner(ALICE),
            "_deleted": False,
            "id": "lib-" + "1" * 32,
            "current_revision": 2,
            "title": "Readme global",
            "doc_type": "answer",
            "content": GLOBAL_CONTENT,
            "content_bytes": len(GLOBAL_CONTENT.encode()),
            "sha256": _hash(GLOBAL_CONTENT),
            "created_at": NOW,
            "version_created_at": NOW,
        },
        {
            "_issuer": ISSUER,
            "_owner": _owner(ALICE),
            "_deleted": True,
            "id": "lib-" + "2" * 32,
            "current_revision": 1,
            "title": "Readme deleted",
            "doc_type": "guide",
            "content": "deleted",
            "content_bytes": 7,
            "sha256": _hash("deleted"),
            "created_at": NOW,
            "version_created_at": NOW,
        },
        {
            "_issuer": ISSUER,
            "_owner": _owner(BOB),
            "_deleted": False,
            "id": "lib-" + "3" * 32,
            "current_revision": 1,
            "title": "Readme other principal",
            "doc_type": "guide",
            "content": "private Bob",
            "content_bytes": len(b"private Bob"),
            "sha256": _hash("private Bob"),
            "created_at": NOW,
            "version_created_at": NOW,
        },
    ]
    db.flow_docs = [
        {
            "id": "knowledge-" + "4" * 32,
            "engagement_id": ENG,
            "flow_id": FLOW,
            "owner_id": ALICE,
            "title": "Readme Flow",
            "doc_type": "guide",
            "content": FLOW_CONTENT,
            "content_bytes": len(FLOW_CONTENT.encode()),
            "sha256": _hash(FLOW_CONTENT),
            "revision": 1,
            "source_flow_revision": 4,
            "authorization_version": 7,
            "authorization_sha256": AUTH_SHA,
            "created_at": NOW,
            "updated_at": NOW,
            "deleted_at": None,
        },
    ]
    memory = SimpleNamespace(_async_session=lambda: db)
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(session_memory=memory))

    # Actual Flow store/list/search continues to run, but this mocked Flow
    # fence is NOT signed ROE/DB enforcement. Cross-owner denial is synthetic.
    async def simulated_signed_fence(
        _db: Any,
        flow_id: str,
        owner: str,
        revision: int,
        authorization_version: int,
        *,
        writing: bool = False,
    ) -> tuple[str, str]:
        if (flow_id, owner, revision, authorization_version) != (FLOW, ALICE, 4, 7):
            raise KnowledgeDenied(403, "Synthetic signed Flow authority unavailable")
        return ENG, AUTH_SHA

    monkeypatch.setattr(
        flow_store.OperatorKnowledgeStore,
        "_fence",
        staticmethod(simulated_signed_fence),
    )
    app = FastAPI()
    app.include_router(unified.router)
    app.dependency_overrides[_operator] = lambda: _operator_claims(ALICE)
    return app, db


def test_real_store_sql_routing_metadata_and_tombstone_synthetic(
    mounted: tuple[FastAPI, _FakeSession],
) -> None:
    app, db = mounted
    with TestClient(app) as client:
        response = client.get(
            "/operator/search/knowledge",
            params={
                "query": "READMe",
                "limit_per_source": 5,
                "flow_id": FLOW,
                "expected_flow_revision": 4,
                "expected_authorization_version": 7,
            },
        )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["atomic_cross_source_snapshot"] is False
    assert data["synthesis_performed"] is False
    assert data["independent_target_effect_verified"] is False
    assert response.headers["cache-control"] == "private, no-store"
    global_rows = data["sources"]["user_global_0039"]["items"]
    flow_rows = data["sources"]["flow_local_0019_0038"]["items"]
    assert len(global_rows) == len(flow_rows) == 1
    assert global_rows[0]["sha256"] == _hash(GLOBAL_CONTENT)
    assert global_rows[0]["revision"] == 2
    assert flow_rows[0]["sha256"] == _hash(FLOW_CONTENT)
    assert flow_rows[0]["source_flow_revision"] == 4
    for item in global_rows + flow_rows:
        assert item["approved_for_agent_context"] is False
        assert item["verified_target_evidence"] is False
        assert item["safe_for_execution"] is False
        assert item["reportable"] is False
        assert not any(
            k in item for k in ("content", "untrusted_content", "owner_id", "engagement_id")
        )
    assert len(db.queries) == 2
    assert db.queries[0][1]["owner"] == _owner(ALICE)
    assert db.queries[1][1]["owner"] == ALICE


def test_global_only_works_without_flow_and_foreign_flow_denied_synthetic(
    mounted: tuple[FastAPI, _FakeSession],
) -> None:
    app, db = mounted
    with TestClient(app) as client:
        global_only = client.get("/operator/search/knowledge?query=readme")
        assert global_only.status_code == 200
        assert set(global_only.json()["sources"]) == {"user_global_0039"}
        assert len(db.queries) == 1
        # Same signed principal namespace can own global notes without the
        # distinct signed Flow principal. No partial global fallback on denial.
        app.dependency_overrides[_operator] = lambda: _operator_claims(BOB)
        denied = client.get(
            "/operator/search/knowledge?query=readme"
            f"&flow_id={FLOW}&expected_flow_revision=4&expected_authorization_version=7"
        )
        assert denied.status_code == 403
        assert "Synthetic signed Flow" not in denied.text
        assert "sources" not in denied.json()
        bob_only = client.get("/operator/search/knowledge?query=readme")
        assert bob_only.status_code == 200
        rows = bob_only.json()["sources"]["user_global_0039"]["items"]
        assert len(rows) == 1 and rows[0]["id"] == "lib-" + "3" * 32


def test_corrupt_current_global_digest_denied_no_flow_fallback_synthetic(
    mounted: tuple[FastAPI, _FakeSession],
) -> None:
    app, db = mounted
    db.global_docs[0]["sha256"] = "f" * 64
    with TestClient(app) as client:
        response = client.get(
            "/operator/search/knowledge?query=readme"
            f"&flow_id={FLOW}&expected_flow_revision=4&expected_authorization_version=7"
        )
    assert response.status_code == 503
    assert len(db.queries) == 1
    assert "sources" not in response.json()


def test_migration_revisions_and_parent_foreign_keys_are_grounded() -> None:
    for revision, name, expected_table, predecessor in (
        ("0019", "0019_operator_knowledge_documents.py", "operator_knowledge_documents", "0018"),
        ("0038", "0038_operator_knowledge_integrity.py", "operator_knowledge_documents", "0037"),
        ("0039", "0039_operator_global_library.py", "operator_global_library_versions", "0038"),
    ):
        source = (ROOT / "migrations" / "versions" / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        values = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        assert revision in values and predecessor in values
        assert expected_table in source
    assert "fk_operator_knowledge_exact_flow_tenant" in (
        ROOT / "migrations/versions/0038_operator_knowledge_integrity.py"
    ).read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_real_flow_owner_fence_before_stubbed_signed_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Actual FlowArtifactStore._fence; SQL rows and signed guard are FAKE."""

    class _FenceDB:
        def __init__(self, revision: int = 4) -> None:
            self.revision = revision
            self.calls: list[str] = []

        async def execute(self, statement: Any, params: Any = None) -> _Result:
            sql = str(statement)
            self.calls.append(sql)
            if "SELECT engagement_id FROM execution_flows" in sql:
                assert params == {"fid": FLOW}
                return _Result([{"engagement_id": ENG}])
            if "FROM session_states" in sql:
                assert params == {"sid": ENG}
                assert "FOR SHARE" in sql
                return _Result([{"created_by": ALICE, "phase": "reconnaissance"}])
            if "SELECT id, engagement_id, revision, status FROM execution_flows" in sql:
                assert params == {"fid": FLOW, "sid": ENG}
                assert "FOR SHARE" in sql
                return _Result(
                    [
                        {
                            "id": FLOW,
                            "engagement_id": ENG,
                            "revision": self.revision,
                            "status": "running",
                        }
                    ]
                )
            raise AssertionError("Unexpected fenced SQL: " + sql)

    guard = AsyncMock(return_value=SimpleNamespace(policy_sha256=AUTH_SHA))
    monkeypatch.setattr(artifacts, "guard_sql", guard)
    foreign_db = _FenceDB()
    with pytest.raises(artifacts.ArtifactDenied) as denial:
        await artifacts.FlowArtifactStore._fence(foreign_db, FLOW, BOB, 4, 7)
    assert denial.value.status == 403
    guard.assert_not_awaited()
    assert len(foreign_db.calls) == 2

    owned_db = _FenceDB()
    assert await artifacts.FlowArtifactStore._fence(owned_db, FLOW, ALICE, 4, 7) == (
        ENG,
        AUTH_SHA,
    )
    guard.assert_awaited_once_with(owned_db, ENG, expected_version=7)
    assert len(owned_db.calls) == 3

    stale_db = _FenceDB(revision=5)
    with pytest.raises(artifacts.ArtifactDenied) as stale:
        await artifacts.FlowArtifactStore._fence(stale_db, FLOW, ALICE, 4, 7)
    assert stale.value.status == 409


_LIVE_PG = r"""
import hashlib
import importlib.util
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.exc import IntegrityError

assert os.name == "posix" and os.geteuid() != 0, "Never run private DB as root"
BIN = Path("/usr/lib/postgresql/16/bin")
assert all((BIN / name).is_file() for name in ("initdb", "pg_ctl"))
def run(parts):
    return subprocess.run(parts, capture_output=True, text=True, timeout=45)
def load(revision, name):
    spec = importlib.util.spec_from_file_location(
        "osop_unified_" + revision, ROOT / "migrations/versions" / name)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == revision
    return module
old=load("0019","0019_operator_knowledge_documents.py")
integrity=load("0038","0038_operator_knowledge_integrity.py")
global_library=load("0039","0039_operator_global_library.py")
assert old.down_revision == "0018" and integrity.down_revision == "0037"
assert global_library.down_revision == "0038"
def migrate(connection, mod):
    context = MigrationContext.configure(connection,opts={"transactional_ddl":True})
    with Operations.context(context):
        mod.upgrade()
def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
def deny(engine, sql, state):
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(sql)
    except IntegrityError as exc:
        assert exc.orig.sqlstate == state, (state,exc.orig.sqlstate,str(exc))
    else:
        raise AssertionError("PostgreSQL failed to deny " + sql[:130])
with tempfile.TemporaryDirectory(prefix="osop-unified-knowledge-",dir="/tmp") as directory:
    parent=Path(directory)
    parent.chmod(0o700)
    data=parent/"data"
    assert run([str(BIN/"initdb"),"-D",str(data),"-A","trust",
                "-U","osop_unified_qual","--no-instructions"]).returncode == 0
    port=57000+secrets.randbelow(1000)
    started=False
    engine=None
    try:
        boot=run([str(BIN/"pg_ctl"),"-D",str(data),"-l",str(parent/"postgres.log"),
            "-o","-c listen_addresses='' -c unix_socket_directories="+str(parent)+
            " -c unix_socket_permissions=0700 -c port="+str(port)+
            " -c fsync=on -c synchronous_commit=on","-w","-t","20","start"])
        assert boot.returncode == 0, boot.stderr[-1200:]
        started=True
        assert (parent/(".s.PGSQL."+str(port))).is_socket()
        engine=sa.create_engine("postgresql+psycopg://osop_unified_qual@/postgres",
            connect_args={"host":str(parent),"port":port,"connect_timeout":3})
        with engine.begin() as conn:
            assert conn.scalar(sa.text("SHOW listen_addresses")) == ""
            assert conn.scalar(sa.text("SHOW server_version_num")).startswith("16")
            conn.exec_driver_sql("CREATE TABLE session_states (session_id varchar(64) PRIMARY KEY)")
            conn.exec_driver_sql("CREATE TABLE execution_flows "
                "(id varchar(64) PRIMARY KEY,engagement_id varchar(64) NOT NULL "
                "REFERENCES session_states(session_id))")
            conn.execute(sa.text("INSERT INTO session_states VALUES ('eng-uni-a'),('eng-uni-b')"))
            conn.execute(sa.text("INSERT INTO execution_flows VALUES "
                "('flow-uni-a','eng-uni-a'),('flow-uni-b','eng-uni-b')"))
            migrate(conn,old)
        with engine.begin() as conn:
            migrate(conn,integrity)
        with engine.begin() as conn:
            migrate(conn,global_library)
        text_a="private Flow guide 🔒"
        text_g="private Global guide 📘"
        with engine.begin() as conn:
            conn.execute(sa.text(
                "INSERT INTO operator_knowledge_documents "
                "(id,engagement_id,flow_id,owner_id,title,doc_type,content,content_bytes,"
                "sha256,revision,source_flow_revision,authorization_version,authorization_sha256) "
                "VALUES ('knowledge-'||repeat('1',32),'eng-uni-a','flow-uni-a','owner-a',"
                "'Search Flow','guide',:content,:size,:sha,1,2,7,:auth)"),
                {"content":text_a,"size":len(text_a.encode()),"sha":sha(text_a),"auth":"a"*64})
            conn.execute(sa.text(
                "INSERT INTO operator_global_library_documents "
                "(id,principal_issuer,principal_subject,current_revision) "
                "VALUES ('lib-'||repeat('1',32),'issuer-signed','principal-a',1)"))
            conn.execute(sa.text(
                "INSERT INTO operator_global_library_versions "
                "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                "VALUES ('lib-'||repeat('1',32),1,'Search Global','answer',:content,:size,:sha)"),
                {"content":text_g,"size":len(text_g.encode()),"sha":sha(text_g)})
        with engine.begin() as conn:
            matching=conn.execute(sa.text(
                "SELECT sha256,content_bytes FROM operator_knowledge_documents "
                "WHERE owner_id='owner-a' AND flow_id='flow-uni-a' AND "
                "deleted_at IS NULL AND strpos(lower(content),lower('Guide'))>0"
            )).mappings().all()
            assert len(matching)==1 and matching[0]["sha256"]==sha(text_a)
            global_rows=conn.execute(sa.text(
                "SELECT v.sha256,v.content_bytes FROM operator_global_library_documents d "
                "JOIN operator_global_library_versions v "
                "ON v.document_id=d.id AND v.revision=d.current_revision "
                "WHERE d.principal_issuer='issuer-signed' AND "
                "d.principal_subject='principal-a' AND d.deleted_at IS NULL"
            )).mappings().all()
            assert len(global_rows)==1 and global_rows[0]["sha256"]==sha(text_g)
            assert conn.scalar(sa.text("SELECT COUNT(*) FROM operator_knowledge_documents "
                "WHERE owner_id='owner-b' AND flow_id='flow-uni-a'"))==0
            assert conn.scalar(sa.text("SELECT COUNT(*) FROM operator_global_library_documents "
                "WHERE principal_subject='principal-b'"))==0
        deny(engine,"UPDATE operator_knowledge_documents SET sha256='"+'f'*64+
            "' WHERE id='knowledge-"+'1'*32+"'",'23514')
        deny(engine,"UPDATE operator_knowledge_documents SET engagement_id='eng-uni-b' "
            "WHERE id='knowledge-"+'1'*32+"'",'23503')
        deny(engine,"UPDATE operator_global_library_versions SET sha256='"+'f'*64+
            "' WHERE document_id='lib-"+'1'*32+"'",'23514')
        revised="current version only 🔐"
        with engine.begin() as conn:
            conn.execute(sa.text(
                "INSERT INTO operator_global_library_versions "
                "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                "VALUES ('lib-'||repeat('1',32),2,'Search Global updated','guide',:body,:size,:sha)"),
                {"body":revised,"size":len(revised.encode()),"sha":sha(revised)})
            conn.execute(sa.text(
                "UPDATE operator_global_library_documents SET current_revision=2 "
                "WHERE id='lib-'||repeat('1',32)"))
            assert conn.scalar(sa.text(
                "SELECT v.sha256 FROM operator_global_library_documents d "
                "JOIN operator_global_library_versions v ON "
                "v.document_id=d.id AND v.revision=d.current_revision "
                "WHERE d.id='lib-'||repeat('1',32)"))==sha(revised)
            conn.execute(sa.text(
                "UPDATE operator_global_library_documents SET deleted_at=now() "
                "WHERE id='lib-'||repeat('1',32)"))
            assert conn.scalar(sa.text(
                "SELECT COUNT(*) FROM operator_global_library_documents "
                "WHERE principal_subject='principal-a' AND deleted_at IS NULL"))==0
            assert conn.scalar(sa.text(
                "SELECT COUNT(*) FROM operator_global_library_versions "
                "WHERE document_id='lib-'||repeat('1',32)"))==2
        print("RESULT_UNIFIED_PG16_OK migrations=0019_0038_0039 "
              "private_nonroot_unix_only=true real_fk_sha_tombstone_current_version=true "
              "signed_flow_guard_tested=false unified_asgi_real_pg=false")
    finally:
        if engine is not None:
            engine.dispose()
        if started:
            stopped=run([str(BIN/"pg_ctl"),"-D",str(data),"-w","-m","fast","stop"])
            assert stopped.returncode == 0, stopped.stderr[-1200:]
"""


def test_opt_in_real_private_nonroot_pg16_actual_0019_0038_0039() -> None:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 for independent PostgreSQL16 cluster")
    if os.name == "nt":

        def wsl_path(path: Path) -> str:
            absolute = str(path.resolve())
            assert len(absolute) > 3 and absolute[1:3] == ":\\"
            return "/mnt/" + absolute[0].lower() + absolute[2:].replace("\\", "/")

        linux_root = wsl_path(ROOT)
        linux_packages = wsl_path(Path(sys.prefix) / "Lib" / "site-packages")
        command = [
            "wsl.exe",
            "-d",
            "Ubuntu",
            "--",
            "env",
            "PYTHONPATH=" + linux_packages,
            "python3",
            "-",
        ]
    elif sys.platform == "linux":
        linux_root = str(ROOT.resolve())
        command = [sys.executable, "-"]
    else:
        pytest.skip("Linux/Ubuntu WSL required; never use application DB")
    result = subprocess.run(
        command,
        input="ROOT=__import__('pathlib').Path(" + repr(linux_root) + ")\n" + _LIVE_PG,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=190,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-3000:] + "\n" + result.stdout[-1200:]
    assert "RESULT_UNIFIED_PG16_OK" in result.stdout
