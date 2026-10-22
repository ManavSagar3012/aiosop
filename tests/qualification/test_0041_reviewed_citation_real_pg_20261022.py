"""Opt-in genuine nonroot disposable PG16 0041 immutable citation DDL.

The parent tables are *minimal* synthetic predecessors; neither production
signer roots nor the application database/cluster are accessed. Tests operate
through local 0700 Unix socket only, no TCP listener and no Docker.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_0041_REVIEWED_CITATION_PRIVATE_PG"

_LINUX = r"""
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

def migration(number):
    paths = sorted((ROOT/'migrations/versions').glob(number+'_*'))
    assert len(paths)==1
    spec=importlib.util.spec_from_file_location('osop_private_'+number, paths[0])
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

m0039, m0041 = migration('0039'), migration('0041')
assert (m0041.revision,m0041.down_revision)==('0041','0040')

def command(args):
    return subprocess.run(args,text=True,capture_output=True,timeout=40)

def run_migration(connection, module, method):
    ctx=MigrationContext.configure(connection,opts={'transactional_ddl':True})
    with Operations.context(ctx):
        getattr(module,method)()

def rejected(engine, statement, params, sqlstate):
    try:
        with engine.begin() as db:
            db.execute(sa.text(statement), params)
    except IntegrityError as exc:
        assert exc.orig.sqlstate==sqlstate, (exc.orig.sqlstate,str(exc))
    else:
        raise AssertionError('Unsafe PostgreSQL citation operation admitted')

with tempfile.TemporaryDirectory(prefix='osop-0041-citation-',dir='/tmp') as work:
    directory=Path(work)
    directory.chmod(0o700)
    data=directory/'pgdata'
    built=command([str(BIN/'initdb'),'-D',str(data),'-A','trust',
                   '-U','osop_private_0041','--no-instructions'])
    assert built.returncode==0,built.stderr[-1200:]
    port=57000+secrets.randbelow(1000)
    started=command([str(BIN/'pg_ctl'),'-D',str(data),'-l',str(directory/'pg.log'),
         '-o',("-c listen_addresses='' -c unix_socket_directories="+str(directory)+
                ' -c unix_socket_permissions=0700 -c port='+str(port)+
                ' -c fsync=on -c synchronous_commit=on'),'-w','-t','20','start'])
    assert started.returncode==0,started.stderr[-1200:]
    engine=None
    try:
        assert (directory/('.s.PGSQL.'+str(port))).is_socket()
        engine=sa.create_engine('postgresql+psycopg://osop_private_0041@/postgres',
            connect_args={'host':str(directory),'port':port,'connect_timeout':3})
        with engine.begin() as db:
            assert db.scalar(sa.text('SHOW listen_addresses')) == ''
            db.exec_driver_sql('CREATE TABLE session_states (session_id varchar(64) PRIMARY KEY)')
            db.exec_driver_sql('CREATE TABLE execution_flows (id varchar(64) PRIMARY KEY, '
                               'engagement_id varchar(64) NOT NULL)')
            # Exact predecessor 0038 established this composite key.
            db.exec_driver_sql('ALTER TABLE execution_flows ADD CONSTRAINT '
                               'uq_execution_flows_id_engagement_knowledge UNIQUE(id,engagement_id)')
            run_migration(db,m0039,'upgrade')
            run_migration(db,m0041,'upgrade')
            assert db.scalar(sa.text("SELECT to_regclass('operator_reviewed_global_flow_citations')"))
        with engine.begin() as db:
            run_migration(db,m0041,'downgrade')
            run_migration(db,m0041,'upgrade')
            db.execute(sa.text("INSERT INTO session_states VALUES ('eng-a'),('eng-b')"))
            db.execute(sa.text("INSERT INTO execution_flows VALUES ('flow-a','eng-a')"))
            value='Untrusted user text, not instructions 📘'
            digest=hashlib.sha256(value.encode('utf8')).hexdigest()
            db.execute(sa.text("INSERT INTO operator_global_library_documents "
                    "(id,principal_issuer,principal_subject,current_revision) "
                    "VALUES (:id,'issuer-a','principal-a',1)"),{'id':'lib-'+'1'*32})
            db.execute(sa.text("INSERT INTO operator_global_library_versions "
                    "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                    "VALUES (:id,1,'Guide','guide',:original,:size,:digest)"),
                    {'id':'lib-'+'1'*32,'original':value,'size':len(value.encode('utf8')),'digest':digest})
        row={'id':'citation-'+'2'*32,'issuer':'issuer-a','owner':'a'*64,
             'source':'lib-'+'1'*32,'revision':1,'digest':digest,'kind':'guide',
             'eng':'eng-a','flow':'flow-a','flow_owner':'principal-a',
             'flow_rev':1,'task':'task-1','auth_ver':1,'auth_sha':'b'*64,'review':'c'*64}
        sql=("INSERT INTO operator_reviewed_global_flow_citations "
             "(id,principal_issuer,principal_owner_sha256,global_document_id,global_revision,"
             "global_sha256,source_kind,engagement_id,flow_id,flow_owner,flow_revision,task_id,"
             "authorization_version,authorization_sha256,reviewed_identity_sha256) "
             "VALUES (:id,:issuer,:owner,:source,:revision,:digest,:kind,:eng,:flow,:flow_owner,"
             ":flow_rev,:task,:auth_ver,:auth_sha,:review)")
        with engine.begin() as db:
            db.execute(sa.text(sql),row)
            assert db.scalar(sa.text('SELECT count(*) FROM operator_reviewed_global_flow_citations'))==1
            assert db.scalar(sa.text('SELECT count(*) FROM operator_reviewed_global_flow_citations '
                      'WHERE global_sha256=:sha'),{'sha':digest})==1
        rejected(engine,sql,row,'23505')
        rejected(engine,sql,{**row,'id':'citation-'+'3'*32,'revision':2,'review':'d'*64},'23503')
        rejected(engine,sql,{**row,'id':'citation-'+'3'*32,'eng':'eng-b','review':'d'*64},'23503')
        rejected(engine,sql,{**row,'id':'citation-'+'3'*32,'review':'bad'},'23514')
        rejected(engine,'UPDATE operator_reviewed_global_flow_citations '
                 'SET global_sha256=:sha WHERE id=:id',
                 {'sha':'d'*64,'id':row['id']},'23514')
        rejected(engine,'DELETE FROM operator_reviewed_global_flow_citations WHERE id=:id',
                 {'id':row['id']},'23514')
        try:
            with engine.begin() as db:
                run_migration(db,m0041,'downgrade')
        except RuntimeError as exc:
            assert 'history exists' in str(exc)
        else:
            raise AssertionError('Nonempty history was destructively downgraded')
        print('RESULT_0041_PG_OK unix_only nonroot immutable_original_citation '
              'schema_fk_tenant_sha_unique_trigger_nonempty_downgrade_denied')
    finally:
        if engine is not None:
            engine.dispose()
        stopped=command([str(BIN/'pg_ctl'),'-D',str(data),'-w','-m','fast','stop'])
        assert stopped.returncode==0,stopped.stderr[-1200:]
"""


def test_private_nonroot_pg16_0041_immutable_citation() -> None:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 for an independent private nonroot PG16 database")
    if os.name == "nt":
        absolute = str(ROOT.resolve())
        linux_root = "/mnt/" + absolute[0].lower() + absolute[2:].replace("\\", "/")
        packages = str(Path(sys.prefix) / "Lib" / "site-packages")
        linux_packages = "/mnt/" + packages[0].lower() + packages[2:].replace("\\", "/")
        command = ["wsl.exe", "-d", "Ubuntu", "--", "env", "PYTHONPATH=" + linux_packages, "python3", "-"]
    elif sys.platform == "linux":
        linux_root = str(ROOT.resolve())
        command = [sys.executable, "-"]
    else:
        pytest.skip("WSL Ubuntu or Linux required")
    result = subprocess.run(
        command,
        input=f"ROOT=__import__('pathlib').Path({linux_root!r})\n" + _LINUX,
        encoding="utf-8",
        errors="replace",
        text=True,
        capture_output=True,
        timeout=160,
    )
    assert result.returncode == 0, result.stderr[-4500:] + "\n" + result.stdout[-800:]
    assert "RESULT_0041_PG_OK" in result.stdout
