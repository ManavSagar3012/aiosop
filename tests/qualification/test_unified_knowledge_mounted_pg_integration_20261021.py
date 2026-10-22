"""Opt-in mounted unified search against a genuinely isolated PostgreSQL16.

The Windows HTTP application is the real mounted FastAPI route. A private WSL
subprocess holds a single Unix-domain-socket-only PostgreSQL16 connection and
transports parameterized SQL requests over local stdio. This is NOT an app DB,
Docker, native runtime, multi-replica or remotely accessible network service.

Explicit opt-in: OSOP_PRIVATE_UNIFIED_MOUNTED_PG16=1. No implicit fallback to
an existing DB. The Linux helper loads only migrations/psycopg/SQLAlchemy;
FastAPI/Pydantic's Windows-compiled wheel cannot run under WSL Python.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy.dialects import postgresql

from ai_osop.api.deps import state
from ai_osop.api.main import app as mounted_main_app
from ai_osop.core.config import settings
from ai_osop.safety.signed_roe import canonical_json_bytes, verify_signed_roe


ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_PRIVATE_UNIFIED_MOUNTED_PG16"
URI = "/operator/search/knowledge"
ISSUER = "unified-fixture-issuer"
ALICE = "operator-unified-a"
BOB = "operator-unified-b"
SESSION = "eng-unified-private"
FLOW = "flow-unified-private"
FLOW_REVISION = 4
AUTH_VERSION = 7
AUTH_ID = "auth-unified-actual"
KID = "unified-ephemeral-test"
GLOBAL_TEXT = "needle global immutable original 📘"
FLOW_TEXT = "needle Flow signed original 🔒"
GLOBAL_ID = "lib-" + "1" * 32
FLOW_ID = "knowledge-" + "2" * 32


def _sha(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _owner(subject: str) -> str:
    return _sha(ISSUER + "\x00" + subject)


def _stamp(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


_PG_WORKER = r"""
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

assert os.name == 'posix' and os.geteuid() != 0
BIN=Path('/usr/lib/postgresql/16/bin')
assert all((BIN/name).is_file() for name in ('initdb','pg_ctl'))
def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=45)
def load(revision, filename):
    spec=importlib.util.spec_from_file_location(
        'unified_qualified_'+revision, ROOT/'migrations/versions'/filename)
    assert spec and spec.loader
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision==revision
    return module
mods=[
    load('0009','0009_signed_authorization.py'),
    load('0014','0014_operator_revocation.py'),
    load('0019','0019_operator_knowledge_documents.py'),
    load('0038','0038_operator_knowledge_integrity.py'),
    load('0039','0039_operator_global_library.py'),
]
def upgrade(connection, module):
    ctx=MigrationContext.configure(connection,opts={'transactional_ddl':True})
    with Operations.context(ctx):
        module.upgrade()
def encode(value):
    if isinstance(value,datetime):
        return {'__datetime_utc__':value.isoformat()}
    if isinstance(value,(bytes,bytearray,memoryview)):
        raise ValueError('Unexpected binary result')
    if isinstance(value,list):
        return [encode(v) for v in value]
    if isinstance(value,dict):
        return {k:encode(v) for k,v in value.items()}
    return value
with tempfile.TemporaryDirectory(prefix='osop-private-unified-mounted-',dir='/tmp') as tmp:
    parent=Path(tmp)
    parent.chmod(0o700)
    data=parent/'pgdata'
    init=run([str(BIN/'initdb'),'-D',str(data),'-A','trust',
              '-U','osop_unified_qualified','--no-instructions'])
    assert init.returncode==0, init.stderr[-800:]
    port=58000+secrets.randbelow(1000)
    booted=False
    engine=None
    connection=None
    try:
        boot=run([str(BIN/'pg_ctl'),'-D',str(data),'-l',str(parent/'postgres.log'),
            '-o',"-c listen_addresses='' -c unix_socket_directories="+str(parent)+
                 ' -c unix_socket_permissions=0700 -c port='+str(port)+
                 ' -c fsync=on -c synchronous_commit=on',
            '-w','-t','20','start'])
        assert boot.returncode==0,boot.stderr[-1000:]
        booted=True
        assert (parent/('.s.PGSQL.'+str(port))).is_socket()
        engine=sa.create_engine('postgresql+psycopg://osop_unified_qualified@/postgres',
            connect_args={'host':str(parent),'port':port,'connect_timeout':3})
        with engine.begin() as db:
            assert db.scalar(sa.text('SHOW listen_addresses'))==''
            assert db.scalar(sa.text('SHOW server_version_num')).startswith('16')
            db.exec_driver_sql('CREATE TABLE session_states ('
                'session_id varchar(64) PRIMARY KEY,created_by varchar(64) NOT NULL,'
                'phase varchar(32) NOT NULL,scope JSONB NOT NULL,roe JSONB NOT NULL)')
            db.exec_driver_sql('CREATE TABLE execution_flows ('
                'id varchar(64) PRIMARY KEY,'
                'engagement_id varchar(64) NOT NULL REFERENCES session_states(session_id),'
                'revision integer NOT NULL,status varchar(32) NOT NULL)')
            for module in mods[:3]:
                upgrade(db,module)
        with engine.begin() as db:
            upgrade(db,mods[3])
        with engine.begin() as db:
            upgrade(db,mods[4])
            for table in ('signed_authorizations','operator_token_revocations',
                          'operator_subject_controls','operator_knowledge_documents',
                          'operator_global_library_documents','operator_global_library_versions'):
                assert db.scalar(sa.text('SELECT to_regclass(:name)'),{'name':table})==table
        connection=psycopg.connect(dbname='postgres',user='osop_unified_qualified',
            host=str(parent),port=port,connect_timeout=3,row_factory=dict_row,autocommit=True)
        print(json.dumps({'ready':True,'pg':'16','unix_only':True}),flush=True)
        for line in sys.stdin:
            message=json.loads(line)
            cmd=message['op']
            if cmd=='shutdown':
                print(json.dumps({'ok':True}),flush=True)
                break
            try:
                if cmd=='begin':
                    connection.execute('BEGIN')
                    out={'ok':True}
                elif cmd=='end':
                    connection.execute('COMMIT' if message.get('commit') else 'ROLLBACK')
                    out={'ok':True}
                elif cmd=='execute':
                    cursor=connection.execute(message['sql'],message.get('params') or {})
                    rows=cursor.fetchall() if cursor.description else []
                    out={'ok':True,'rows':encode(rows)}
                else:
                    raise RuntimeError('Unsupported DB operation')
            except Exception as exc:
                # A failed PG statement aborts its transaction; caller must rollback.
                out={'ok':False,'error':type(exc).__name__,
                     'sqlstate':getattr(exc,'sqlstate',None),
                     'message':str(exc)[:220]}
            print(json.dumps(out,sort_keys=True,ensure_ascii=False),flush=True)
    finally:
        if connection is not None:
            connection.close()
        if engine is not None:
            engine.dispose()
        if booted:
            stopped=run([str(BIN/'pg_ctl'),'-D',str(data),'-w','-m','fast','stop'])
            assert stopped.returncode==0,stopped.stderr[-600:]
"""


class PrivatePgError(RuntimeError):
    def __init__(self, message: str, code: Optional[str]) -> None:
        super().__init__(message)
        self.code = code


class _PgBridge:
    """Read/write ONLY the one newly created, private WSL subprocess."""

    def __init__(self) -> None:
        if os.name == "nt":
            site = str(Path(sys.prefix) / "Lib" / "site-packages")
            root = str(ROOT.resolve())
            assert site[1:3] == ":\\" and root[1:3] == ":\\"

            def linux_path(value: str) -> str:
                return "/mnt/" + value[0].lower() + value[2:].replace("\\", "/")

            command = [
                "wsl.exe",
                "-d",
                "Ubuntu",
                "--",
                "env",
                "PYTHONPATH=" + linux_path(site),
                "python3",
                "-u",
                "-c",
                "ROOT=__import__('pathlib').Path(" + repr(linux_path(root)) + ")\n" + _PG_WORKER,
            ]
        elif sys.platform == "linux":
            command = [
                sys.executable,
                "-u",
                "-c",
                "ROOT=__import__('pathlib').Path(" + repr(str(ROOT.resolve())) + ")\n" + _PG_WORKER,
            ]
        else:
            raise RuntimeError("Only Linux/WSL isolated nonroot PG16 is supported")
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
            text=True,
            bufsize=1,
        )
        self.lock = threading.RLock()
        # If startup fails before READY, cap the wait and report the error.
        ready: list[str] = []
        reader = threading.Thread(
            target=lambda: ready.append(self.process.stdout.readline()), daemon=True
        )
        reader.start()
        reader.join(100)
        if reader.is_alive():
            self.process.kill()
            raise RuntimeError("Private PG16 bootstrap exceeded 100 seconds")
        if not ready or not ready[0]:
            error = self.process.stderr.read()[-1800:] if self.process.poll() is not None else ""
            self.process.kill()
            raise RuntimeError("Private PG16 bootstrap failed: " + error)
        status = json.loads(ready[0])
        if status != {"ready": True, "pg": "16", "unix_only": True}:
            self.process.kill()
            raise RuntimeError("Unexpected PostgreSQL16 bootstrap status: " + str(status))

    def command(self, op: str, **params: Any) -> dict[str, Any]:
        with self.lock:
            assert self.process.poll() is None, "Private PG16 subprocess has terminated"
            assert self.process.stdin and self.process.stdout
            self.process.stdin.write(json.dumps({"op": op, **params}, allow_nan=False) + "\n")
            self.process.stdin.flush()
            reply = self.process.stdout.readline()
            if not reply:
                raise RuntimeError("Private PG16 subprocess response missing")
            response = json.loads(reply)
            if response.get("ok") is not True:
                raise PrivatePgError(
                    "Private PG16 SQL failed: " + str(response.get("message")),
                    response.get("sqlstate"),
                )
            return response

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                self.command("shutdown")
            finally:
                self.process.wait(timeout=40)
        assert self.process.returncode == 0, (
            self.process.stderr.read()[-1000:] if self.process.stderr else "Unexpected helper exit"
        )


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = [
            {
                key: (
                    datetime.fromisoformat(value["__datetime_utc__"])
                    if isinstance(value, dict) and set(value) == {"__datetime_utc__"}
                    else value
                )
                for key, value in row.items()
            }
            for row in rows
        ]

    def mappings(self) -> "_Result":
        return self

    def all(self) -> list[dict[str, Any]]:
        return self.rows

    def one_or_none(self) -> Optional[dict[str, Any]]:
        assert len(self.rows) <= 1
        return self.rows[0] if self.rows else None

    def one(self) -> dict[str, Any]:
        assert len(self.rows) == 1
        return self.rows[0]

    def scalar_one_or_none(self) -> Any:
        row = self.one_or_none()
        return next(iter(row.values())) if row is not None else None

    def scalar_one(self) -> Any:
        return next(iter(self.one().values()))


class _PgSession:
    def __init__(self, bridge: _PgBridge) -> None:
        self.bridge = bridge

    async def __aenter__(self) -> "_PgSession":
        self.bridge.command("begin")
        return self

    async def __aexit__(self, error: Any, _value: Any, _tb: Any) -> None:
        self.bridge.command("end", commit=error is None)

    @asynccontextmanager
    async def begin(self) -> Any:
        # One transaction is held from __aenter__ to __aexit__ for both
        # guard_sql's lock and the subsequent real document query.
        yield self

    async def execute(self, statement: Any, params: Optional[dict[str, Any]] = None) -> _Result:
        compiled = statement.compile(dialect=postgresql.dialect(paramstyle="pyformat"))
        bindings = dict(compiled.params)
        bindings.update(params or {})
        return _Result(self.bridge.command("execute", sql=str(compiled), params=bindings)["rows"])


def _jwt(subject: str, secret: str) -> str:
    return jwt.encode(
        {
            "sub": subject,
            "iss": ISSUER,
            "role": "operator",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        },
        secret,
        algorithm="HS256",
    )


def _policy(private: Ed25519PrivateKey) -> tuple[dict[str, Any], str, str]:
    now = datetime.now(timezone.utc)
    scope = {
        "domains": ["example.test"],
        "ips": [],
        "exclusions": [],
        "allowed_techniques": ["recon"],
        "restrictions": ["no-write"],
        "approval_required_for": [],
        "testing_window_start": _stamp(now - timedelta(minutes=30)),
        "testing_window_end": _stamp(now + timedelta(minutes=30)),
    }
    policy = {
        **scope,
        "engagement_id": SESSION,
        "created_by": ALICE,
        "roe": {"allow_automated_exploitation": False},
        "issued_at": _stamp(now - timedelta(minutes=25)),
        "not_before": _stamp(now - timedelta(minutes=20)),
        "expires_at": _stamp(now + timedelta(minutes=20)),
        "version": AUTH_VERSION,
        "authorization_id": AUTH_ID,
        "key_id": KID,
    }
    signed_bytes = canonical_json_bytes(policy)
    signature = base64.urlsafe_b64encode(private.sign(signed_bytes)).rstrip(b"=").decode("ascii")
    verified = verify_signed_roe(
        {"version": AUTH_VERSION, "policy": policy, "signature": signature},
        expected_engagement_id=SESSION,
        expected_owner=ALICE,
        expected_scope={"engagement_id": SESSION, "authorization_ref": AUTH_ID, **scope},
        expected_roe=policy["roe"],
        now=now,
    )
    return policy, signature, verified.policy_digest


@pytest.fixture(scope="module")
def private_pg() -> Any:
    if os.getenv(OPT_IN) != "1":
        pytest.skip("Explicit opt-in " + OPT_IN + "=1 needed for isolated nonroot PG16")
    bridge = _PgBridge()
    try:
        yield bridge
    finally:
        bridge.close()


def _seed(bridge: _PgBridge, *, policy: dict[str, Any], signature: str, digest: str) -> None:
    def sql(statement: str, **params: Any) -> Any:
        from sqlalchemy import text

        session = _PgSession(bridge)
        # No running event loop here (synchronous pytest fixture).
        import asyncio

        async def run() -> Any:
            async with session:
                result = await session.execute(text(statement), params)
                return result.rows

        return asyncio.run(run())

    scope = {
        "engagement_id": SESSION,
        **{
            name: policy[name]
            for name in (
                "domains",
                "ips",
                "exclusions",
                "allowed_techniques",
                "restrictions",
                "approval_required_for",
                "testing_window_start",
                "testing_window_end",
            )
        },
        "authorization_ref": AUTH_ID,
    }
    sql(
        "INSERT INTO session_states(session_id,created_by,phase,scope,roe) "
        "VALUES (:sid,:owner,'reconnaissance',CAST(:scope AS JSONB),CAST(:roe AS JSONB))",
        sid=SESSION,
        owner=ALICE,
        scope=json.dumps(scope),
        roe=json.dumps(policy["roe"]),
    )
    # Existing tenant with a DIFFERENT Flow binding, so the 0038 composite
    # FK (rather than merely the old session FK) must reject cross-tenant
    # reassignment even when both independent parent IDs exist.
    sql(
        "INSERT INTO session_states(session_id,created_by,phase,scope,roe) "
        "VALUES ('eng-other',:owner,'reconnaissance',CAST('{}' AS JSONB),CAST('{}' AS JSONB))",
        owner=BOB,
    )
    sql(
        "INSERT INTO execution_flows(id,engagement_id,revision,status) "
        "VALUES (:flow,:sid,:revision,'running')",
        flow=FLOW,
        sid=SESSION,
        revision=FLOW_REVISION,
    )
    sql(
        "INSERT INTO signed_authorizations "
        "(authorization_id,session_id,version,kid,policy_sha256,canonical_policy,"
        "signature,status,actor_id,verified_at) VALUES "
        "(:aid,:sid,:version,:kid,:sha,CAST(:policy AS JSONB),:sig,'active',:owner,now())",
        aid=AUTH_ID,
        sid=SESSION,
        version=AUTH_VERSION,
        kid=KID,
        sha=digest,
        policy=json.dumps(policy),
        sig=signature,
        owner=ALICE,
    )
    sql(
        "INSERT INTO operator_knowledge_documents "
        "(id,engagement_id,flow_id,owner_id,title,doc_type,content,content_bytes,"
        "sha256,revision,source_flow_revision,authorization_version,authorization_sha256) "
        "VALUES (:id,:sid,:flow,:owner,'needle Flow guide','guide',:body,:size,"
        ":sha,1,:flowrev,:authver,:authsha)",
        id=FLOW_ID,
        sid=SESSION,
        flow=FLOW,
        owner=ALICE,
        body=FLOW_TEXT,
        size=len(FLOW_TEXT.encode()),
        sha=_sha(FLOW_TEXT),
        flowrev=FLOW_REVISION,
        authver=AUTH_VERSION,
        authsha=digest,
    )
    # 0039 intentionally has a deferrable current-version FK. The newly
    # inserted document and initial immutable revision MUST commit together.
    import asyncio
    from sqlalchemy import text

    async def create_initial_global_version() -> None:
        async with _PgSession(bridge) as db:
            await db.execute(
                text(
                    "INSERT INTO operator_global_library_documents "
                    "(id,principal_issuer,principal_subject,current_revision) "
                    "VALUES (:id,:issuer,:owner,1)"
                ),
                {"id": GLOBAL_ID, "issuer": ISSUER, "owner": _owner(ALICE)},
            )
            await db.execute(
                text(
                    "INSERT INTO operator_global_library_versions "
                    "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                    "VALUES (:id,1,'needle Global guide','answer',:body,:size,:sha)"
                ),
                {
                    "id": GLOBAL_ID,
                    "body": GLOBAL_TEXT,
                    "size": len(GLOBAL_TEXT.encode()),
                    "sha": _sha(GLOBAL_TEXT),
                },
            )

    asyncio.run(create_initial_global_version())


def test_actual_main_mount_rejects_missing_bearer_without_database() -> None:
    assert (
        sum(
            route.path == URI and "GET" in (getattr(route, "methods", ()) or ())
            for route in mounted_main_app.routes
        )
        == 1
    )
    # Do not enter the lifespan (which starts application dependencies).
    client = TestClient(mounted_main_app)
    try:
        response = client.get(URI, params={"query": "needle"})
    finally:
        client.close()
    assert response.status_code == 401
    assert "sources" not in response.json()


def test_actual_mounted_both_stores_with_signed_jwt_roe_revocation_and_pg16(
    private_pg: _PgBridge, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All stores, JWT and signed ROE are REAL; DB is disposable only."""

    private = Ed25519PrivateKey.generate()
    key = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_ROE_TRUSTED_KEYS_JSON",
        json.dumps({KID: base64.b64encode(key).decode("ascii")}),
    )
    policy, signature, digest = _policy(private)
    _seed(private_pg, policy=policy, signature=signature, digest=digest)

    secret = "isolated-unified-" + "q" * 48
    for field, value in (
        ("environment", "production"),
        ("jwt_secret", secret),
        ("jwt_algorithm", "HS256"),
        ("jwt_issuer", None),
        ("jwt_audience", None),
        ("operator_revocation_required", True),
    ):
        monkeypatch.setattr(settings, field, value)
    memory = SimpleNamespace(_async_session=lambda: _PgSession(private_pg))
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(session_memory=memory))
    monkeypatch.setitem(state, "session_store", SimpleNamespace(sm=memory))

    alice = _jwt(ALICE, secret)
    bob = _jwt(BOB, secret)
    route = URI + "?query=needle"
    scoped = route + f"&flow_id={FLOW}&expected_flow_revision=4&expected_authorization_version=7"

    def request(client: TestClient, path: str, token: str) -> Any:
        return client.get(path, headers={"Authorization": "Bearer " + token})

    def sql(statement: str, **params: Any) -> list[dict[str, Any]]:
        from sqlalchemy import text
        import asyncio

        async def run() -> list[dict[str, Any]]:
            async with _PgSession(private_pg) as db:
                return (await db.execute(text(statement), params)).all()

        return asyncio.run(run())

    # TestClient without lifespan: real route/middleware/dependencies run,
    # but no application Redis/Neo4j/agents/Docker startup is attempted.
    client = TestClient(mounted_main_app)
    try:
        both = request(client, scoped, alice)
        assert both.status_code == 200, both.text
        payload = both.json()
        assert payload["atomic_cross_source_snapshot"] is False
        assert payload["synthesis_performed"] is False
        assert payload["approved_for_agent_context"] is False
        assert both.headers["cache-control"] == "private, no-store"
        assert set(payload["sources"]) == {"user_global_0039", "flow_local_0019_0038"}
        global_rows = payload["sources"]["user_global_0039"]["items"]
        flow_rows = payload["sources"]["flow_local_0019_0038"]["items"]
        assert len(global_rows) == len(flow_rows) == 1
        assert global_rows[0]["id"] == GLOBAL_ID and global_rows[0]["sha256"] == _sha(GLOBAL_TEXT)
        assert flow_rows[0]["id"] == FLOW_ID and flow_rows[0]["sha256"] == _sha(FLOW_TEXT)
        assert flow_rows[0]["authorization_version"] == AUTH_VERSION
        for item in global_rows + flow_rows:
            assert item["approved_for_agent_context"] is False
            assert item["verified_target_evidence"] is False
            assert item["reportable"] is False
            assert item["safe_for_execution"] is False
            assert not {"content", "untrusted_content", "engagement_id", "owner_id"} & item.keys()

        # The caller has a genuine signed JWT but is not this Flow's owner.
        foreign = request(client, scoped, bob)
        assert foreign.status_code == 403, foreign.text
        assert "sources" not in foreign.json()
        owner_global = request(client, route, alice)
        assert owner_global.status_code == 200
        assert set(owner_global.json()["sources"]) == {"user_global_0039"}
        assert request(client, route, bob).json()["sources"]["user_global_0039"]["items"] == []

        assert (
            request(
                client,
                route
                + f"&flow_id={FLOW}&expected_flow_revision=5&expected_authorization_version=7",
                alice,
            ).status_code
            == 409
        )
        assert (
            request(
                client,
                route
                + f"&flow_id={FLOW}&expected_flow_revision=4&expected_authorization_version=8",
                alice,
            ).status_code
            == 403
        )

        invalid = jwt.encode(
            {
                "sub": ALICE,
                "role": "operator",
                "iss": ISSUER,
                "exp": int(time.time()) + 3600,
            },
            "wrong-issuer-symmetric-signing-key",
            algorithm="HS256",
        )
        assert request(client, scoped, invalid).status_code == 401
        assert request(client, scoped, alice).status_code == 200

        # Missing independently configured ROE trust root must deny Flow,
        # although the owner-global library remains independently available.
        monkeypatch.delenv("OSOP_ROE_TRUSTED_KEYS_JSON")
        assert request(client, scoped, alice).status_code == 403
        assert request(client, route, alice).status_code == 200
        monkeypatch.setenv(
            "OSOP_ROE_TRUSTED_KEYS_JSON",
            json.dumps({KID: base64.b64encode(key).decode("ascii")}),
        )
        assert request(client, scoped, alice).status_code == 200

        # Actual 0038 database constraint, not merely _verified_content.
        with pytest.raises(PrivatePgError) as wrong_sha:
            sql(
                "UPDATE operator_knowledge_documents SET sha256=:sha WHERE id=:id",
                id=FLOW_ID,
                sha="f" * 64,
            )
        assert wrong_sha.value.code == "23514"
        with pytest.raises(PrivatePgError) as cross_tenant:
            sql(
                "UPDATE operator_knowledge_documents SET engagement_id=:eng WHERE id=:id",
                id=FLOW_ID,
                eng="eng-other",
            )
        assert cross_tenant.value.code == "23503"

        # True 0039 current-version and tombstone changes in this PG cluster.
        next_text = "needle globally revised"
        sql(
            "INSERT INTO operator_global_library_versions "
            "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
            "VALUES (:id,2,'needle Current','answer',:body,:size,:sha)",
            id=GLOBAL_ID,
            body=next_text,
            size=len(next_text.encode()),
            sha=_sha(next_text),
        )
        sql(
            "UPDATE operator_global_library_documents SET current_revision=2 WHERE id=:id",
            id=GLOBAL_ID,
        )
        latest = request(client, route, alice)
        assert latest.status_code == 200
        rows = latest.json()["sources"]["user_global_0039"]["items"]
        assert len(rows) == 1 and rows[0]["revision"] == 2
        assert rows[0]["sha256"] == _sha(next_text)
        sql(
            "UPDATE operator_global_library_documents SET deleted_at=now() WHERE id=:id",
            id=GLOBAL_ID,
        )
        tombstone = request(client, scoped, alice)
        assert tombstone.status_code == 200
        assert tombstone.json()["sources"]["user_global_0039"]["items"] == []
        assert len(tombstone.json()["sources"]["flow_local_0019_0038"]["items"]) == 1

        # Actual local-JWT token digest revocation in the SAME private DB.
        sql(
            "INSERT INTO operator_token_revocations(digest,actor_id,expires_at,revoked_at) "
            "VALUES (:digest,:owner,now()+interval '1 hour',now())",
            digest=hashlib.sha256(alice.encode()).hexdigest(),
            owner=ALICE,
        )
        assert request(client, scoped, alice).status_code == 401
        # A different valid JWT token belonging to this same owner is still
        # denied once the durable subject is disabled.
        fresh_alice = jwt.encode(
            {
                "sub": ALICE,
                "role": "operator",
                "iss": ISSUER,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "jti": "not-the-revoked-credential-2",
            },
            secret,
            algorithm="HS256",
        )
        assert fresh_alice != alice
        assert request(client, scoped, fresh_alice).status_code == 200
        sql(
            "INSERT INTO operator_subject_controls(actor_id,disabled,updated_at,updated_by) "
            "VALUES (:owner,true,now(),'test-senior')",
            owner=ALICE,
        )
        assert request(client, scoped, fresh_alice).status_code == 401
        sql(
            "UPDATE operator_subject_controls SET disabled=false WHERE actor_id=:owner", owner=ALICE
        )
        assert request(client, scoped, fresh_alice).status_code == 200
        # Distinct token avoids exact digest revocation; _fence must still
        # independently reject latest ROE status revoked.
        fresh_alice = jwt.encode(
            {
                "sub": ALICE,
                "role": "operator",
                "iss": ISSUER,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3700,
                "jti": "after-unblocked-before-roe-revocation",
            },
            secret,
            algorithm="HS256",
        )
        sql(
            "UPDATE signed_authorizations SET status='revoked',revoked_at=now() "
            "WHERE authorization_id=:auth",
            auth=AUTH_ID,
        )
        assert request(client, scoped, fresh_alice).status_code == 403
        independent_global = request(client, route, fresh_alice)
        assert independent_global.status_code == 200
        assert independent_global.json()["sources"]["user_global_0039"]["items"] == []
    finally:
        client.close()
