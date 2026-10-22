"""Opt-in actual 0039 Alembic on isolated nonroot Unix-socket PostgreSQL16.

Runs NO app migrations/database, Docker, network listeners, or user providers.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/versions/0039_operator_global_library.py"
OPT_IN = "OSOP_DISPOSABLE_OPERATOR_GLOBAL_LIBRARY_0039_PG"


def test_library_migration_is_separate_from_flow_knowledge() -> None:
    tree = ast.parse(MIGRATION.read_text(encoding="utf-8"))
    strings = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    assert "0039" in strings and "0038" in strings
    assert "operator_global_library_documents" in strings
    assert "operator_global_library_versions" in strings


_LIVE = r"""
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

assert os.name == 'posix' and os.geteuid() != 0
BIN = Path('/usr/lib/postgresql/16/bin')
assert all((BIN/x).is_file() for x in ('initdb','pg_ctl'))
spec = importlib.util.spec_from_file_location(
    'osop_0039_disposable', ROOT/'migrations/versions/0039_operator_global_library.py')
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.revision == '0039' and module.down_revision == '0038'

def cmd(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=40)

def migrate(connection, action):
    context = MigrationContext.configure(connection, opts={'transactional_ddl': True})
    with Operations.context(context):
        getattr(module, action)()

def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def must_deny(engine, statement, *, state='23514'):
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(statement)
    except IntegrityError as error:
        assert error.orig.sqlstate == state, (error.orig.sqlstate,str(error))
    else:
        raise AssertionError('Original PostgreSQL mutation was accepted: '+statement)

with tempfile.TemporaryDirectory(prefix='osop-global-library-0039-',dir='/tmp') as base:
    parent = Path(base)
    parent.chmod(0o700)
    data = parent/'pgdata'
    initialized=cmd([str(BIN/'initdb'),'-D',str(data),'-A','trust',
                     '-U','osop_disposable_0039','--no-instructions'])
    assert initialized.returncode == 0, initialized.stderr[-1200:]
    port=57000+secrets.randbelow(1000)
    boot=cmd([str(BIN/'pg_ctl'),'-D',str(data),'-l',str(parent/'pg.log'),
              '-o',("-c listen_addresses='' -c unix_socket_directories="+str(parent)+
                    ' -c unix_socket_permissions=0700 -c port='+str(port)+
                    ' -c fsync=on -c synchronous_commit=on'),'-w','-t','20','start'])
    assert boot.returncode == 0, boot.stderr[-1500:]
    engine=None
    try:
        assert (parent/('.s.PGSQL.'+str(port))).is_socket()
        engine=sa.create_engine('postgresql+psycopg://osop_disposable_0039@/postgres',
             connect_args={'host':str(parent),'port':port,'connect_timeout':3})
        with engine.begin() as conn:
            assert conn.scalar(sa.text('SHOW listen_addresses')) == ''
            assert conn.scalar(sa.text('SHOW server_version_num')).startswith('16')
            migrate(conn,'upgrade')
            assert conn.scalar(sa.text("SELECT to_regclass('operator_global_library_versions')"))
        # Empty downgrade really works before any data is accepted.
        with engine.begin() as conn:
            migrate(conn,'downgrade')
            assert conn.scalar(sa.text("SELECT to_regclass('operator_global_library_versions')")) is None
        with engine.begin() as conn:
            migrate(conn,'upgrade')
        text='user-owned UTF8 reference 📘'
        with engine.begin() as conn:
            conn.execute(sa.text("INSERT INTO operator_global_library_documents "
                 "(id,principal_issuer,principal_subject,current_revision) "
                 "VALUES (:id,'signed-local','alice',1)"),{'id':'lib-'+'1'*32})
            conn.execute(sa.text("INSERT INTO operator_global_library_versions "
                 "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                 "VALUES (:id,1,'Original','guide',:content,:size,:sha)"),
                 {'id':'lib-'+'1'*32,'content':text,
                  'size':len(text.encode('utf-8')),'sha':digest(text)})
            assert conn.scalar(sa.text('SELECT count(*) FROM operator_global_library_versions')) == 1
        must_deny(engine,"UPDATE operator_global_library_documents "
                  "SET principal_subject='bob' WHERE id='lib-"+'1'*32+"'")
        must_deny(engine,"UPDATE operator_global_library_versions "
                  "SET content='corrupted' WHERE document_id='lib-"+'1'*32+"'")
        must_deny(engine,"DELETE FROM operator_global_library_versions "
                  "WHERE document_id='lib-"+'1'*32+"'")
        must_deny(engine,"UPDATE operator_global_library_documents "
                  "SET current_revision=2 WHERE id='lib-"+'1'*32+"'",state='23503')
        must_deny(engine,"INSERT INTO operator_global_library_versions "
                  "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                  "VALUES ('lib-"+'1'*32+"',2,'Tamper','guide','wrong',5,'"+'0'*64+"')")
        newer='second immutable version 🔒'
        with engine.begin() as conn:
            conn.execute(sa.text("INSERT INTO operator_global_library_versions "
                "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                "VALUES (:id,2,'Revised','answer',:content,:size,:sha)"),
                {'id':'lib-'+'1'*32,'content':newer,'size':len(newer.encode('utf-8')),
                 'sha':digest(newer)})
            conn.execute(sa.text("UPDATE operator_global_library_documents "
                "SET current_revision=2 WHERE id=:id"),{'id':'lib-'+'1'*32})
            assert conn.scalar(sa.text("SELECT count(*) FROM operator_global_library_versions")) == 2
        must_deny(engine,"UPDATE operator_global_library_documents "
                  "SET current_revision=1 WHERE id='lib-"+'1'*32+"'")
        with engine.begin() as conn:
            conn.execute(sa.text("UPDATE operator_global_library_documents "
                "SET deleted_at=clock_timestamp() WHERE id=:id"),{'id':'lib-'+'1'*32})
        must_deny(engine,"UPDATE operator_global_library_documents "
                  "SET deleted_at=NULL WHERE id='lib-"+'1'*32+"'")
        try:
            with engine.begin() as conn:
                migrate(conn,'downgrade')
        except RuntimeError as error:
            assert 'rows (including tombstones) remain' in str(error)
        else:
            raise AssertionError('0039 dropped nonempty immutable user library')
        with engine.begin() as conn:
            assert conn.scalar(sa.text('SELECT count(*) FROM operator_global_library_versions')) == 2
            assert conn.scalar(sa.text('SELECT count(*) FROM operator_global_library_documents WHERE deleted_at IS NOT NULL')) == 1
        # Execute the production store's actual bound SQL against the SAME
        # real PostgreSQL16 server with an independent async psycopg adapter.
        # The Windows virtualenv has no Linux greenlet wheel, so this is a
        # real DB/SQL qualification, NOT a deployed SQLAlchemy runtime test.
        import asyncio
        import re
        import psycopg
        from psycopg.rows import dict_row
        from types import SimpleNamespace

        source = ROOT/'src/ai_osop/memory/operator_global_library.py'
        store_spec=importlib.util.spec_from_file_location('osop_0039_live_store',source)
        assert store_spec and store_spec.loader
        store_module=importlib.util.module_from_spec(store_spec)
        store_spec.loader.exec_module(store_module)

        class RealPGResult:
            def __init__(self, rows):
                self.rows=rows
            def mappings(self):
                return self
            def one_or_none(self):
                assert len(self.rows)<=1
                return self.rows[0] if self.rows else None
            def scalar_one_or_none(self):
                row=self.one_or_none()
                return next(iter(row.values())) if row is not None else None
            def scalar_one(self):
                assert len(self.rows)==1
                return next(iter(self.rows[0].values()))
            def all(self):
                return self.rows

        class RealPGSession:
            async def __aenter__(self):
                self.connection=await psycopg.AsyncConnection.connect(
                    dbname='postgres',user='osop_disposable_0039',
                    host=str(parent),port=port,connect_timeout=3, row_factory=dict_row)
                return self
            async def __aexit__(self, kind, value, trace):
                await self.connection.close()
            def begin(self):
                return self.connection.transaction()
            async def execute(self, statement, params=None):
                assert isinstance(statement,sa.sql.elements.TextClause)
                bound=re.sub(r':([A-Za-z_][A-Za-z_0-9]*)',r'%(\1)s',statement.text)
                cursor=await self.connection.execute(bound,params or {})
                rows=await cursor.fetchall() if cursor.description else []
                return RealPGResult(rows)

        async def exercise_real_store():
            store=store_module.OperatorGlobalLibrary(
                SimpleNamespace(_async_session=lambda:RealPGSession()))
            if True:
                current=await store.create('signed-local','principal-a',
                    title='Owned reference',doc_type='guide',content='Owner 📗 text')
                assert current['revision']==1 and current['sha256']==digest('Owner 📗 text')
                doc_id=current['id']
                assert (await store.get('signed-local','principal-a',doc_id))['content']=='Owner 📗 text'
                try:
                    await store.get('signed-local','principal-b',doc_id)
                except store_module.KnowledgeDenied as error:
                    assert error.status==404
                else:
                    raise AssertionError('Foreign user read original library bytes')
                search=await store.search('signed-local','principal-a',query='REfERENCE')
                assert len(search['items'])==1 and search['items'][0]['id']==doc_id
                assert (await store.search('other-issuer','principal-a'))['items']==[]
                revision=await store.update('signed-local','principal-a',doc_id,1,
                    title='New reference',doc_type='answer',content='revision two 🔒')
                assert revision['revision']==2 and revision['sha256']==digest('revision two 🔒')
                try:
                    await store.update('signed-local','principal-a',doc_id,1,
                        title='Bad',doc_type='code',content='stale')
                except store_module.KnowledgeDenied as error:
                    assert error.status==409
                else:
                    raise AssertionError('Stale user update was admitted')
                # Two actual independent PostgreSQL connections race one
                # immutable CAS version: exactly one may append revision 2.
                competing=await store.create('signed-local','principal-a',
                    title='Race seed',doc_type='guide',content='before race')
                async def racing_writer(label):
                    try:
                        return await store.update('signed-local','principal-a',
                            competing['id'],1,title=label,doc_type='answer',
                            content='new data '+label)
                    except store_module.KnowledgeDenied as error:
                        return error.status
                race=await asyncio.gather(
                    racing_writer('writer-a'),racing_writer('writer-b'))
                assert sum(isinstance(value,dict) for value in race)==1, race
                assert sum(value==409 for value in race if isinstance(value,int))==1, race
                assert (await store.get('signed-local','principal-a',
                        competing['id']))['revision']==2
                assert (await store.delete('signed-local','principal-a',
                        competing['id'],2))['status']=='tombstoned'
                try:
                    await store.delete('signed-local','principal-b',doc_id,2)
                except store_module.KnowledgeDenied as error:
                    assert error.status==404
                else:
                    raise AssertionError('Foreign owner tombstoned document')
                deleted=await store.delete('signed-local','principal-a',doc_id,2)
                assert deleted['status']=='tombstoned'
                try:
                    await store.get('signed-local','principal-a',doc_id)
                except store_module.KnowledgeDenied as error:
                    assert error.status==404
                else:
                    raise AssertionError('Tombstoned original remained visible')
                assert (await store.search('signed-local','principal-a'))['items']==[]

        asyncio.run(exercise_real_store())
        print('RESULT_0039_PG_OK actual_online_alembic disposable_unix_only '
              'immutable_sha_cas_owner_tombstone nonempty_downgrade_denied '
              'actual_async_store_crud_isolated_owners')
    finally:
        if engine is not None:
            engine.dispose()
        stopped=cmd([str(BIN/'pg_ctl'),'-D',str(data),'-w','-m','fast','stop'])
        assert stopped.returncode == 0, stopped.stderr[-1200:]
"""


def test_actual_0039_isolated_postgresql16() -> None:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 to run a private nonroot PostgreSQL16 cluster")
    if os.name == "nt":
        absolute = str(ROOT.resolve())
        linux_root = "/mnt/" + absolute[0].lower() + absolute[2:].replace("\\", "/")
        packages = str(Path(sys.prefix) / "Lib" / "site-packages")
        linux_packages = "/mnt/" + packages[0].lower() + packages[2:].replace("\\", "/")
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
        pytest.skip("Local Linux or WSL Ubuntu required")
    try:
        result = subprocess.run(
            command,
            input=f"ROOT=__import__('pathlib').Path({linux_root!r})\n" + _LIVE,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=190,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        pytest.fail("Disposable PostgreSQL16 qualification unavailable: " + str(error))
    assert result.returncode == 0, result.stderr[-4300:] + "\n" + result.stdout[-1500:]
    assert "RESULT_0039_PG_OK" in result.stdout
