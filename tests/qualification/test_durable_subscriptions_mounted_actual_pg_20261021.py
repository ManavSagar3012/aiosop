"""Opt-in mounted main.app plus ACTUAL private nonroot PostgreSQL16 SQL.

Windows FastAPI/SQLAlchemy/Ed25519 run in the user's Poetry virtualenv. An
independently bootstrapped Linux WSL PostgreSQL16 communicates exclusively over
local stdio; the database listens only on a private 0700 Unix socket. This
test NEVER opens an application database, TCP PostgreSQL, Docker, scanner,
network target or provider, and never starts the main app lifespan.

The 0009, 0014, and 0040 Alembic upgrade() code genuinely executes against
real PG16. Only minimal parent tables exist; the existing supervision ORM
parent checker is replaced by SQL on those minimal tables (NOT a complete
application-ORM qualification). The REAL, unmodified auth verify_token,
signed_roe.verify_signed_roe, authorization_store.guard_sql, mounted router,
and worker42 subscription store execute without authorization mocks.

Opt-in OSOP_DURABLE_MOUNTED_ACTUAL_PG16=1; disabled runs do no WSL/PG work.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jose import jwt
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

from ai_osop.api import deps, main
from ai_osop.api.routers import supervision
from ai_osop.core import config as core_config
from ai_osop.memory.supervision_store import SupervisionConflict
from ai_osop.safety.signed_roe import canonical_json_bytes, verify_signed_roe


ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_DURABLE_MOUNTED_ACTUAL_PG16"
ENG_A = "eng-mounted-real-pg-a"
ENG_B = "eng-mounted-real-pg-b"
OWNER_A = "operator-pg-a"
OWNER_B = "operator-pg-b"
TASK_A = "task-mounted-pg-a"
TASK_B = "task-mounted-pg-b"
SUB = "subscr-" + "a" * 32
SUB_B = "subscr-" + "b" * 32
KID = "private-mounted-pg16-ed25519"
AUTH_ID = "auth-mounted-pg16"
AUTH_VERSION = 4
JWT_SECRET = "private-mounted-actual-pg-hs256-key-not-production"


def _stamp(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


_WORKER = r"""
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tempfile
from datetime import date, datetime
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

assert os.name=='posix' and os.geteuid()!=0
BIN=Path('/usr/lib/postgresql/16/bin')
assert all((BIN/name).is_file() for name in ('initdb','pg_ctl'))
def run(argv):
    return subprocess.run(argv,capture_output=True,text=True,timeout=45)
def load(revision,file):
    spec=importlib.util.spec_from_file_location(
        'durable_actual_'+revision, ROOT/'migrations/versions'/file)
    assert spec is not None and spec.loader is not None
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision==revision
    return mod
def upgrade(connection,mod):
    ctx=MigrationContext.configure(connection,opts={'transactional_ddl':True})
    with Operations.context(ctx):
        mod.upgrade()
def encode(v):
    if isinstance(v,(datetime,date)):
        return {'__utc_datetime__':v.isoformat()}
    if isinstance(v,dict):
        return {k:encode(x) for k,x in v.items()}
    if isinstance(v,(list,tuple)):
        return [encode(x) for x in v]
    return v
with tempfile.TemporaryDirectory(prefix='osop-durable-mounted-private-',dir='/tmp') as tmp:
    root=Path(tmp)
    root.chmod(0o700)
    data=root/'pgdata'
    init=run([str(BIN/'initdb'),'-D',str(data),'-A','trust','-U',
              'osop_durable_private','--no-instructions'])
    assert init.returncode==0, init.stderr[-700:]
    port=59000+secrets.randbelow(1000)
    booted=False
    engine=None
    connections={}
    try:
        boot=run([str(BIN/'pg_ctl'),'-D',str(data),'-l',str(root/'postgres.log'),
            '-o', "-c listen_addresses='' -c unix_socket_directories="+str(root)+
                 ' -c unix_socket_permissions=0700 -c port='+str(port)+
                 ' -c fsync=on -c synchronous_commit=on',
            '-w','-t','20','start'])
        assert boot.returncode==0,boot.stderr[-700:]
        booted=True
        assert (root/('.s.PGSQL.'+str(port))).is_socket()
        engine=sa.create_engine(
            'postgresql+psycopg://osop_durable_private@/postgres',
            connect_args={'host':str(root),'port':port,'connect_timeout':3})
        with engine.begin() as db:
            assert db.scalar(sa.text('SHOW listen_addresses'))==''
            assert db.scalar(sa.text('SHOW server_version_num')).startswith('16')
            db.exec_driver_sql('CREATE TABLE session_states ('
                'session_id VARCHAR(64) PRIMARY KEY, created_by VARCHAR(64) NOT NULL,'
                'phase VARCHAR(32) NOT NULL, scope JSONB NOT NULL, roe JSONB NOT NULL)')
            db.exec_driver_sql('CREATE TABLE tasks ('
                'id VARCHAR(64) PRIMARY KEY, engagement_id VARCHAR(64) NOT NULL '
                'REFERENCES session_states(session_id), payload JSONB NOT NULL)')
            db.exec_driver_sql('CREATE TABLE supervision_events ('
                'sequence BIGINT PRIMARY KEY, id VARCHAR(64) NOT NULL,'
                'engagement_id VARCHAR(64) NOT NULL REFERENCES session_states(session_id),'
                'task_id VARCHAR(64), kind VARCHAR(64) NOT NULL,'
                'actor_id VARCHAR(64) NOT NULL, payload JSONB NOT NULL,'
                'created_at TIMESTAMPTZ NOT NULL DEFAULT now())')
            upgrade(db,load('0009','0009_signed_authorization.py'))
            upgrade(db,load('0014','0014_operator_revocation.py'))
            upgrade(db,load('0040','0040_supervision_durable_subscriptions.py'))
            assert db.scalar(sa.text(
                "SELECT to_regclass('supervision_durable_subscriptions')"))==(
                'supervision_durable_subscriptions')
        print(json.dumps({'ready':True,'pg':'16','unix_only':True,
                          'real_ddl':['0009','0014','0040']}),flush=True)
        for line in sys.stdin:
            message=json.loads(line)
            cmd=message['op']
            ident=str(message.get('client','host'))
            try:
                if cmd=='shutdown':
                    print(json.dumps({'ok':True}),flush=True)
                    break
                if cmd=='connect':
                    assert ident not in connections
                    connections[ident]=psycopg.connect(
                        dbname='postgres',user='osop_durable_private',
                        host=str(root),port=port,connect_timeout=3,
                        row_factory=dict_row,autocommit=True)
                    out={'ok':True}
                elif cmd=='disconnect':
                    conn=connections.pop(ident,None)
                    if conn is not None:
                        conn.close()
                    out={'ok':True}
                elif cmd=='begin':
                    connections[ident].execute('BEGIN')
                    out={'ok':True}
                elif cmd=='end':
                    connections[ident].execute('COMMIT' if message.get('commit') else 'ROLLBACK')
                    out={'ok':True}
                elif cmd=='execute':
                    cursor=connections[ident].execute(
                        message['sql'],message.get('params') or {})
                    rows=cursor.fetchall() if cursor.description else []
                    out={'ok':True,'rows':encode(rows)}
                else:
                    raise RuntimeError('unsupported private SQL bridge operation')
            except Exception as exc:
                out={'ok':False,'sqlstate':getattr(exc,'sqlstate',None),
                     'error':type(exc).__name__,'detail':str(exc)[:220]}
            print(json.dumps(out,sort_keys=True),flush=True)
    finally:
        for conn in connections.values():
            conn.close()
        if engine is not None:
            engine.dispose()
        if booted:
            stopped=run([str(BIN/'pg_ctl'),'-D',str(data),'-w','-m','fast','stop'])
            assert stopped.returncode==0,stopped.stderr[-800:]
"""


class PrivateSqlError(RuntimeError):
    def __init__(self, message: str, sqlstate: Optional[str] = None) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


class PgBridge:
    """Strict stdio to our own WSL child only; no app DB URL or host/port."""

    def __init__(self) -> None:
        if os.name == "nt":
            root = str(ROOT.resolve())
            site = str(Path(sys.prefix) / "Lib" / "site-packages")
            assert root[1:3] == ":\\" and site[1:3] == ":\\"

            def linux_path(path: str) -> str:
                return "/mnt/" + path[0].lower() + path[2:].replace("\\", "/")

            cmd = [
                "wsl.exe",
                "-d",
                "Ubuntu",
                "--",
                "env",
                "PYTHONPATH=" + linux_path(site),
                "python3",
                "-u",
                "-c",
                "ROOT=__import__('pathlib').Path(" + repr(linux_path(root)) + ")\n" + _WORKER,
            ]
        elif sys.platform == "linux":
            cmd = [
                sys.executable,
                "-u",
                "-c",
                "ROOT=__import__('pathlib').Path(" + repr(str(ROOT.resolve())) + ")\n" + _WORKER,
            ]
        else:
            raise RuntimeError("Private nonroot PG16 supported only in Linux or WSL")
        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.lock = threading.RLock()
        self.statements: list[str] = []
        ready: list[str] = []
        reader = threading.Thread(
            target=lambda: ready.append(self.process.stdout.readline()), daemon=True
        )
        reader.start()
        reader.join(100)
        if reader.is_alive():
            self.process.kill()
            raise RuntimeError("Private PG16 start exceeded 100 seconds")
        if not ready or not ready[0]:
            error = self.process.stderr.read()[-1500:] if self.process.poll() is not None else ""
            self.process.kill()
            raise RuntimeError("Private PG16 unavailable " + error)
        self.startup = json.loads(ready[0])
        assert self.startup == {
            "ready": True,
            "pg": "16",
            "unix_only": True,
            "real_ddl": ["0009", "0014", "0040"],
        }, self.startup

    def command(self, op: str, *, client: str = "host", **args: Any) -> dict[str, Any]:
        with self.lock:
            if self.process.poll() is not None:
                raise PrivateSqlError("Private PG16 child not running")
            assert self.process.stdin is not None and self.process.stdout is not None
            if op == "execute":
                self.statements.append(str(args.get("sql", "")))
            self.process.stdin.write(
                json.dumps({"op": op, "client": client, **args}, allow_nan=False) + "\n"
            )
            self.process.stdin.flush()
            response_line = self.process.stdout.readline()
            if not response_line:
                raise PrivateSqlError("Private PG16 stdio EOF")
            response = json.loads(response_line)
            if response.get("ok") is not True:
                raise PrivateSqlError(
                    str(response.get("error")) + ": " + str(response.get("detail")),
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
            self.process.stderr.read()[-1200:] if self.process.stderr else "Private PG16 exit"
        )


class QueryResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = [
            {
                key: (
                    datetime.fromisoformat(value["__utc_datetime__"])
                    if isinstance(value, dict) and set(value) == {"__utc_datetime__"}
                    else value
                )
                for key, value in row.items()
            }
            for row in rows
        ]

    def mappings(self) -> "QueryResult":
        return self

    def one_or_none(self) -> Optional[dict[str, Any]]:
        assert len(self.rows) <= 1
        return self.rows[0] if self.rows else None

    def all(self) -> list[dict[str, Any]]:
        return self.rows

    def scalar_one_or_none(self) -> Any:
        row = self.one_or_none()
        return next(iter(row.values())) if row is not None else None

    def scalar_one(self) -> Any:
        row = self.one_or_none()
        assert row is not None
        return next(iter(row.values()))


class PgSession:
    def __init__(self, bridge: PgBridge, client: str) -> None:
        self.bridge = bridge
        self.client = client
        # Mirror AsyncSession.bind to enable worker42's *real* PostgreSQL
        # transaction-isolation and SHARE NOWAIT revocation insert fence.
        self.bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    async def __aenter__(self) -> "PgSession":
        await asyncio.to_thread(self.bridge.command, "connect", client=self.client)
        await asyncio.to_thread(self.bridge.command, "begin", client=self.client)
        return self

    async def __aexit__(self, error: Any, _value: Any, _tb: Any) -> None:
        try:
            await asyncio.to_thread(
                self.bridge.command, "end", client=self.client, commit=error is None
            )
        finally:
            await asyncio.to_thread(self.bridge.command, "disconnect", client=self.client)

    @asynccontextmanager
    async def begin(self) -> Any:
        yield self

    async def execute(self, stmt: Any, params: Optional[dict[str, Any]] = None) -> QueryResult:
        compiled = stmt.compile(dialect=postgresql.dialect(paramstyle="pyformat"))
        bindings = dict(compiled.params)
        bindings.update(params or {})
        result = await asyncio.to_thread(
            self.bridge.command,
            "execute",
            client=self.client,
            sql=str(compiled),
            params=bindings,
        )
        return QueryResult(result["rows"])


class PgMemory:
    def __init__(self, bridge: PgBridge) -> None:
        self.bridge = bridge
        self._next = 0

    def _async_session(self) -> PgSession:
        self._next += 1
        return PgSession(self.bridge, "session-" + str(self._next))

    async def load_session_state(self, session_id: str) -> Any:
        async with self._async_session() as db:
            found = (
                (
                    await db.execute(
                        text(
                            "SELECT session_id,created_by FROM session_states WHERE session_id=:sid"
                        ),
                        {"sid": session_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
        return SimpleNamespace(created_by=found["created_by"]) if found else None


def signed_policy(key: Ed25519PrivateKey) -> tuple[dict[str, Any], str, str]:
    now = datetime.now(timezone.utc)
    scope = {
        "domains": ["example.test"],
        "ips": [],
        "exclusions": [],
        "allowed_techniques": ["recon"],
        "restrictions": ["no-write"],
        "approval_required_for": [],
        "testing_window_start": _stamp(now - timedelta(minutes=25)),
        "testing_window_end": _stamp(now + timedelta(minutes=25)),
    }
    policy = {
        **scope,
        "engagement_id": ENG_A,
        "created_by": OWNER_A,
        "roe": {"allow_automated_exploitation": False},
        "issued_at": _stamp(now - timedelta(minutes=22)),
        "not_before": _stamp(now - timedelta(minutes=20)),
        "expires_at": _stamp(now + timedelta(minutes=20)),
        "version": AUTH_VERSION,
        "authorization_id": AUTH_ID,
        "key_id": KID,
    }
    signature = (
        base64.urlsafe_b64encode(key.sign(canonical_json_bytes(policy)))
        .rstrip(b"=")
        .decode("ascii")
    )
    verified = verify_signed_roe(
        {"version": AUTH_VERSION, "policy": policy, "signature": signature},
        expected_engagement_id=ENG_A,
        expected_owner=OWNER_A,
        expected_scope={"engagement_id": ENG_A, "authorization_ref": AUTH_ID, **scope},
        expected_roe=policy["roe"],
        now=now,
    )
    return policy, signature, verified.policy_digest


async def sql(memory: PgMemory, query: str, **params: Any) -> list[dict[str, Any]]:
    async with memory._async_session() as db:
        return (await db.execute(text(query), params)).rows


def token(subject: str, *, role: str = "operator", exp_secs: int = 3600) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": subject,
            "role": role,
            "iss": "local-jwt",
            "exp": now + exp_secs,
            "iat": now,
        },
        JWT_SECRET,
        algorithm="HS256",
    )


def lease_body(result: dict[str, Any], *, task: Optional[str] = TASK_A) -> dict[str, Any]:
    lease = result["lease"]
    return {
        "replica_id": lease["replica_id"],
        "lease_id": lease["lease_id"],
        "generation": lease["generation"],
        "cursor": lease["cursor"],
        "task_id": task,
    }


@pytest.fixture
def private_pg() -> Any:
    if os.getenv(OPT_IN) != "1":
        pytest.skip("Explicit private PostgreSQL16 opt-in " + OPT_IN + "=1 required")
    bridge = PgBridge()
    try:
        yield bridge
    finally:
        bridge.close()


@pytest.fixture
async def mounted_real(private_pg: PgBridge, monkeypatch: pytest.MonkeyPatch) -> Any:
    memory = PgMemory(private_pg)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_ROE_TRUSTED_KEYS_JSON", json.dumps({KID: base64.b64encode(public).decode("ascii")})
    )
    monkeypatch.setattr(
        deps,
        "settings",
        SimpleNamespace(
            environment="testing",
            jwt_secret=JWT_SECRET,
            jwt_algorithm="HS256",
            jwt_issuer="",
            jwt_audience="",
            api_token="",
            operator_revocation_required=True,
            oidc_issuer=None,
            oidc_audience=None,
            oidc_jwks_url=None,
        ),
    )
    monkeypatch.setattr(core_config.settings, "operator_revocation_required", True)
    state_old = deps.state.copy()
    deps.state["session_store"] = None
    deps.state["orchestrator"] = SimpleNamespace(_sessions={}, session_memory=memory)

    # Minimal predecessor lacks the full SessionStateORM schema. Preserve the
    # actual supervision._access and deps.assert_engagement_access, substituting
    # ONLY SupervisionStore's ORM-dependent durable lookup with real PG SQL.
    class MinimalSupervisor:
        async def assert_access(
            self, engagement_id: str, actor_id: str, role: str, task_id: Optional[str]
        ) -> None:
            async with memory._async_session() as db:
                owner = (
                    (
                        await db.execute(
                            text("SELECT created_by FROM session_states WHERE session_id=:sid"),
                            {"sid": engagement_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if owner is None or (role != "senior_operator" and owner["created_by"] != actor_id):
                    raise SupervisionConflict("Persisted engagement owner mismatched")
                if task_id is not None:
                    found = (
                        await db.execute(
                            text("SELECT id FROM tasks WHERE id=:task AND engagement_id=:sid"),
                            {"task": task_id, "sid": engagement_id},
                        )
                    ).scalar_one_or_none()
                    if found != task_id:
                        raise SupervisionConflict("Persisted Task not in engagement")

    monkeypatch.setattr(supervision, "_supervision", lambda: MinimalSupervisor())
    policy, signature, digest = signed_policy(private)
    scope = {
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
    }
    scope.update({"engagement_id": ENG_A, "authorization_ref": AUTH_ID})
    try:
        # Seed each row with actual private PG transactions, no app DB. Entire
        # migration 0009/0014/0040 ran at bootstrap, not mocked.
        await sql(
            memory,
            "INSERT INTO session_states(session_id,created_by,phase,scope,roe) "
            "VALUES (:sid,:owner,'reconnaissance',CAST(:scope AS JSONB),CAST(:roe AS JSONB))",
            sid=ENG_A,
            owner=OWNER_A,
            scope=json.dumps(scope),
            roe=json.dumps(policy["roe"]),
        )
        await sql(
            memory,
            "INSERT INTO session_states(session_id,created_by,phase,scope,roe) "
            "VALUES (:sid,:owner,'reconnaissance',CAST('{}' AS JSONB),CAST('{}' AS JSONB))",
            sid=ENG_B,
            owner=OWNER_B,
        )
        await sql(
            memory,
            "INSERT INTO tasks(id,engagement_id,payload) "
            "VALUES (:task,:sid,CAST(:payload AS JSONB))",
            task=TASK_A,
            sid=ENG_A,
            payload=json.dumps(
                {"_authorization_version": AUTH_VERSION, "_authorization_sha256": digest}
            ),
        )
        await sql(
            memory,
            "INSERT INTO tasks(id,engagement_id,payload) "
            "VALUES (:task,:sid,CAST(:payload AS JSONB))",
            task=TASK_B,
            sid=ENG_B,
            payload=json.dumps({"_authorization_version": AUTH_VERSION}),
        )
        await sql(
            memory,
            "INSERT INTO signed_authorizations "
            "(authorization_id,session_id,version,kid,policy_sha256,canonical_policy,"
            "signature,status,actor_id,verified_at) VALUES "
            "(:aid,:sid,:version,:kid,:sha,CAST(:policy AS JSONB),:sig,'active',:owner,now())",
            aid=AUTH_ID,
            sid=ENG_A,
            version=AUTH_VERSION,
            kid=KID,
            sha=digest,
            policy=json.dumps(policy),
            sig=signature,
            owner=OWNER_A,
        )
        for sequence, tenant, task, owner in (
            (11, ENG_A, TASK_A, OWNER_A),
            (12, ENG_B, TASK_B, OWNER_B),
            (19, ENG_A, TASK_A, OWNER_A),
        ):
            await sql(
                memory,
                "INSERT INTO supervision_events "
                "(sequence,id,engagement_id,task_id,kind,actor_id,payload) "
                "VALUES (:seq,:id,:sid,:task,'agent.message',:actor,CAST(:payload AS JSONB))",
                seq=sequence,
                id="evt-" + str(sequence),
                sid=tenant,
                task=task,
                actor=owner,
                payload=json.dumps({"message": "private PG committed"}),
            )
        # Validate genuine signer/guard_sql; THIS routine remains unpatched.
        from ai_osop.memory.authorization_store import guard_sql

        async with memory._async_session() as db:
            attested = await guard_sql(
                db, ENG_A, expected_version=AUTH_VERSION, expected_digest=digest
            )
        assert attested.policy_sha256 == digest and attested.version == AUTH_VERSION
        yield {
            "bridge": private_pg,
            "memory": memory,
            "digest": digest,
            "alice": token(OWNER_A),
            "bob": token(OWNER_B),
            "senior": token(OWNER_B, role="senior_operator"),
        }
    finally:
        deps.state.clear()
        deps.state.update(state_old)
        # The child process is independently shut down in private_pg teardown.


async def post(
    world: dict[str, Any],
    action: str,
    body: dict[str, Any],
    *,
    subject: str = "alice",
    subscriber: str = SUB,
    engagement: str = ENG_A,
) -> httpx.Response:
    assert action in {"acquire", "renew", "read", "ack", "cursor-readback", "release", "revoke"}
    address = (
        "/supervision/engagements/" + engagement + "/subscriptions/" + subscriber + "/" + action
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app, raise_app_exceptions=False),
        base_url="http://mounted-private.invalid",
        timeout=12,
    ) as client:
        return await client.post(
            address,
            json=body,
            headers={"Authorization": "Bearer " + world[subject]},
        )


def test_real_main_route_registration_no_pg() -> None:
    targets = [
        route
        for route in main.app.routes
        if "/subscriptions/" in route.path and route.path.startswith("/supervision/engagements/")
    ]
    assert len(targets) == 7
    assert {route.path.rsplit("/", 1)[-1] for route in targets} == {
        "acquire",
        "renew",
        "read",
        "ack",
        "cursor-readback",
        "release",
        "revoke",
    }


@pytest.mark.asyncio
async def test_mounted_real_pg16_signed_roe_lease_ack_and_revocation(
    mounted_real: dict[str, Any]
) -> None:
    world = mounted_real
    # External bearer/engagement and Task checks must deny before SQL admission.
    denied = await post(
        world,
        "acquire",
        {"replica_id": "replica-foreign", "task_id": TASK_A},
        subject="bob",
    )
    assert denied.status_code == 403, denied.text[:250]
    foreign_task = await post(
        world, "acquire", {"replica_id": "replica-foreign", "task_id": TASK_B}
    )
    assert foreign_task.status_code == 403, foreign_task.text[:250]

    first = await post(world, "acquire", {"replica_id": "replica-one", "task_id": TASK_A})
    assert first.status_code == 200, first.text[:500]
    proof = first.json()
    assert proof["lease"]["generation"] == 1
    assert proof["lease"]["cursor"] == 0
    assert proof["lease"]["delivery_semantics"] == "at_least_once"

    lease = lease_body(proof)
    other_replica = await post(world, "acquire", {"replica_id": "replica-two", "task_id": TASK_A})
    assert other_replica.status_code == 409
    viewed = await post(world, "read", lease)
    assert viewed.status_code == 200, viewed.text[:300]
    assert [row["sequence"] for row in viewed.json()["events"]] == [11, 19]
    assert viewed.json()["acknowledged"] is False
    skipped = await post(world, "ack", {**lease, "expected_cursor": 0, "next_sequence": 19})
    assert skipped.status_code == 409
    assert (
        await sql(
            world["memory"],
            "SELECT cursor_sequence FROM "
            "supervision_durable_subscriptions WHERE subscriber_id=:sub",
            sub=SUB,
        )
    )[0]["cursor_sequence"] == 0

    acknowledged = await post(world, "ack", {**lease, "expected_cursor": 0, "next_sequence": 11})
    assert acknowledged.status_code == 200, acknowledged.text[:500]
    advanced = lease_body(acknowledged.json())
    assert advanced["cursor"] == 11
    # The HTTP response can be lost; committed ACK is NOT replayable.
    unknown_ack = await post(world, "ack", {**lease, "expected_cursor": 0, "next_sequence": 11})
    assert unknown_ack.status_code == 409
    assert (
        await sql(
            world["memory"],
            "SELECT cursor_sequence FROM "
            "supervision_durable_subscriptions WHERE subscriber_id=:sub",
            sub=SUB,
        )
    )[0]["cursor_sequence"] == 11

    renewed = await post(world, "renew", {**advanced, "lease_seconds": 30})
    assert renewed.status_code == 200, renewed.text[:300]
    stale = await post(world, "read", {**advanced, "replica_id": "replica-two"})
    assert stale.status_code == 409
    before_release = lease_body(renewed.json())
    released = await post(world, "release", before_release)
    assert released.status_code == 200, released.text[:300]
    recovered = await post(
        world, "acquire", {"replica_id": "replica-after-crash", "task_id": TASK_A}
    )
    assert recovered.status_code == 200, recovered.text[:500]
    after = recovered.json()["lease"]
    assert after["cursor"] == 11
    assert after["generation"] > proof["lease"]["generation"]
    assert after["lease_id"] != proof["lease"]["lease_id"]
    # Signed ROE revocation in real PG must invalidate current read without
    # changing the cursor; only the issuer ledger changes.
    await sql(
        world["memory"],
        "UPDATE signed_authorizations SET status='revoked',"
        "revoked_at=clock_timestamp() WHERE session_id=:sid",
        sid=ENG_A,
    )
    revoked = await post(world, "read", lease_body(recovered.json()))
    assert revoked.status_code == 409, revoked.text[:300]
    assert (
        await sql(
            world["memory"],
            "SELECT cursor_sequence FROM "
            "supervision_durable_subscriptions WHERE subscriber_id=:sub",
            sub=SUB,
        )
    )[0]["cursor_sequence"] == 11


@pytest.mark.asyncio
async def test_mounted_actual_pg16_revoked_bearer_and_subscription(
    mounted_real: dict[str, Any]
) -> None:
    world = mounted_real
    first = await post(
        world, "acquire", {"replica_id": "replica-b", "task_id": TASK_A}, subscriber=SUB_B
    )
    assert first.status_code == 200, first.text[:450]
    original = lease_body(first.json())
    # Durable subscriber tombstone: actual PostgreSQL 0040 trigger prevents
    # deletion/rebinding; store revocation causes old and new replicas to fail.
    killed = await post(world, "revoke", {"task_id": TASK_A}, subscriber=SUB_B)
    assert killed.status_code == 200, killed.text[:350]
    stale = await post(
        world, "ack", {**original, "expected_cursor": 0, "next_sequence": 11}, subscriber=SUB_B
    )
    assert stale.status_code == 409
    restart = await post(
        world,
        "acquire",
        {"replica_id": "replica-new", "task_id": TASK_A},
        subscriber=SUB_B,
    )
    assert restart.status_code == 409
    found = await sql(
        world["memory"],
        "SELECT revoked_at,lease_generation,cursor_sequence "
        "FROM supervision_durable_subscriptions WHERE subscriber_id=:sub",
        sub=SUB_B,
    )
    assert found[0]["revoked_at"] is not None and found[0]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_real_pg16_token_revocation_blocks_mounted_read(mounted_real: dict[str, Any]) -> None:
    world = mounted_real
    fresh = "subscr-" + uuid.uuid4().hex
    acquired = await post(
        world,
        "acquire",
        {"replica_id": "replica-token", "task_id": TASK_A},
        subscriber=fresh,
    )
    assert acquired.status_code == 200
    digest = hashlib.sha256(world["alice"].encode("utf-8")).hexdigest()
    lease = lease_body(acquired.json())

    class _RollbackIntent(RuntimeError):
        pass

    # An uncommitted revocation INSERT holds ROW EXCLUSIVE on the real 0014
    # table. Worker42's genuine SHARE NOWAIT must deny this concurrent ACK
    # instead of allowing an absent digest to pass a stale snapshot.
    try:
        async with world["memory"]._async_session() as writer:
            await writer.execute(
                text(
                    "INSERT INTO operator_token_revocations "
                    "(digest,actor_id,expires_at,revoked_at) "
                    "VALUES (:digest,:actor,now()+interval '2 hours',clock_timestamp())"
                ),
                {"digest": digest, "actor": OWNER_A},
            )
            raced = await post(
                world,
                "ack",
                {**lease, "expected_cursor": 0, "next_sequence": 11},
                subscriber=fresh,
            )
            assert raced.status_code == 409, raced.text[:350]
            # Emulates crash/cancel of the revocation writer, *not* a commit.
            raise _RollbackIntent()
    except _RollbackIntent:
        pass
    assert (
        await sql(
            world["memory"],
            "SELECT cursor_sequence FROM "
            "supervision_durable_subscriptions WHERE subscriber_id=:sub",
            sub=fresh,
        )
    )[0]["cursor_sequence"] == 0

    # Inject a transport/process failure AFTER real PG cursor UPDATE but
    # BEFORE COMMIT. The app store must roll back the SQL transaction, and
    # preserve the old cursor for an entirely new client connection.
    real_factory = world["memory"]._async_session
    updated = {"observed": 0}

    class FailingSession(PgSession):
        async def execute(
            self, statement: Any, params: Optional[dict[str, Any]] = None
        ) -> QueryResult:
            result = await super().execute(statement, params)
            if str(statement).startswith(
                "UPDATE supervision_durable_subscriptions SET cursor_sequence=:next"
            ):
                updated["observed"] += 1
                raise RuntimeError("Injected crash after actual PG UPDATE before COMMIT")
            return result

    world["memory"]._async_session = lambda: FailingSession(
        world["bridge"], "crash-" + uuid.uuid4().hex
    )
    try:
        aborted = await post(
            world,
            "ack",
            {**lease, "expected_cursor": 0, "next_sequence": 11},
            subscriber=fresh,
        )
        assert aborted.status_code == 409, aborted.text[:300]
    finally:
        world["memory"]._async_session = real_factory
    assert updated["observed"] == 1
    assert (
        await sql(
            world["memory"],
            "SELECT cursor_sequence FROM "
            "supervision_durable_subscriptions WHERE subscriber_id=:sub",
            sub=fresh,
        )
    )[0]["cursor_sequence"] == 0

    committed = await post(
        world,
        "ack",
        {**lease, "expected_cursor": 0, "next_sequence": 11},
        subscriber=fresh,
    )
    assert committed.status_code == 200, committed.text[:300]
    assert committed.json()["lease"]["cursor"] == 11
    await sql(
        world["memory"],
        "INSERT INTO operator_token_revocations "
        "(digest,actor_id,expires_at,revoked_at) "
        "VALUES (:digest,:actor,now()+interval '2 hours',clock_timestamp())",
        digest=digest,
        actor=OWNER_A,
    )
    denied = await post(world, "read", lease_body(committed.json()), subscriber=fresh)
    assert denied.status_code in {401, 409}, denied.text[:300]
    stored = await sql(
        world["memory"],
        "SELECT cursor_sequence FROM " "supervision_durable_subscriptions WHERE subscriber_id=:sub",
        sub=fresh,
    )
    assert stored[0]["cursor_sequence"] == 11
    assert any(
        "LOCK TABLE operator_token_revocations, operator_subject_controls "
        "IN SHARE MODE NOWAIT" in statement
        for statement in world["bridge"].statements
    )
    assert any(
        "current_setting('transaction_isolation')" in statement
        for statement in world["bridge"].statements
    )
