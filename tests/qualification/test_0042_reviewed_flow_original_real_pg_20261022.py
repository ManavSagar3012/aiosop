"""Opt-in real nonroot private PG16 for atomic 0041+0042 original materialization.

The parent `execution_flows` and `session_states` are minimal disposable test
tables. No application DB, Docker, TCP listening, provider or target touched.
Synthetic source rows/authority identifiers do NOT certify host signers.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.qualification import test_0041_reviewed_citation_real_pg_20261022 as prior

ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_0042_REVIEWED_FLOW_ORIGINAL_PRIVATE_PG"
_PRELUDE = prior._LINUX.split("with tempfile.TemporaryDirectory", 1)[0]

_SCENARIOS = r"""
m0042 = migration('0042')
assert (m0042.revision,m0042.down_revision) == ('0042','0041')

with tempfile.TemporaryDirectory(prefix='osop-reviewed-flow-0042-', dir='/tmp') as work:
    directory=Path(work)
    directory.chmod(0o700)
    data=directory/'pgdata'
    started_init=command([str(BIN/'initdb'),'-D',str(data),'-A','trust',
                          '-U','osop_private_0042','--no-instructions'])
    assert started_init.returncode==0, started_init.stderr[-1200:]
    port=57000+secrets.randbelow(1000)
    started=command([str(BIN/'pg_ctl'),'-D',str(data),'-l',str(directory/'pg.log'),
         '-o',("-c listen_addresses='' -c unix_socket_directories="+str(directory)+
                ' -c unix_socket_permissions=0700 -c port='+str(port)+
                ' -c fsync=on -c synchronous_commit=on'),'-w','-t','20','start'])
    assert started.returncode==0, started.stderr[-1200:]
    engine=None
    try:
        assert (directory/('.s.PGSQL.'+str(port))).is_socket()
        engine=sa.create_engine('postgresql+psycopg://osop_private_0042@/postgres',
             connect_args={'host':str(directory),'port':port,'connect_timeout':3})
        with engine.begin() as db:
            assert db.scalar(sa.text('SHOW listen_addresses'))==''
            assert db.scalar(sa.text('SHOW server_version_num')).startswith('16')
            db.exec_driver_sql('CREATE TABLE session_states (session_id varchar(64) PRIMARY KEY)')
            db.exec_driver_sql('CREATE TABLE execution_flows (id varchar(64) PRIMARY KEY, engagement_id varchar(64) NOT NULL)')
            db.exec_driver_sql('ALTER TABLE execution_flows ADD CONSTRAINT '
                               'uq_execution_flows_id_engagement_knowledge UNIQUE(id,engagement_id)')
            for rev in (m0039,m0041,m0042):
                run_migration(db,rev,'upgrade')
            assert db.scalar(sa.text("SELECT to_regclass('operator_reviewed_flow_originals')"))
        with engine.begin() as db:
            run_migration(db,m0042,'downgrade')
            run_migration(db,m0042,'upgrade')
            db.execute(sa.text("INSERT INTO session_states VALUES ('eng-a'),('eng-b')"))
            db.execute(sa.text("INSERT INTO execution_flows VALUES ('flow-a','eng-a')"))
            original='reviewed but untrusted original 📘 no tool execution'
            digest=hashlib.sha256(original.encode('utf8')).hexdigest()
            db.execute(sa.text("INSERT INTO operator_global_library_documents "
                 "(id,principal_issuer,principal_subject,current_revision) "
                 "VALUES (:id,'issuer-a','principal-a',1)"),{'id':'lib-'+'1'*32})
            db.execute(sa.text("INSERT INTO operator_global_library_versions "
                "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                "VALUES (:id,1,'Reviewed original','guide',:text,:size,:sha)"),
                {'id':'lib-'+'1'*32,'text':original,'size':len(original.encode('utf8')),'sha':digest})

        metadata={'id':'citation-'+'2'*32,'issuer':'issuer-a','owner':'a'*64,
             'source':'lib-'+'1'*32,'revision':1,'digest':digest,'kind':'guide',
             'eng':'eng-a','flow':'flow-a','flow_owner':'principal-a',
             'flow_rev':2,'task':'task-a','auth_ver':1,'auth_sha':'b'*64,'review':'c'*64}
        metadata_sql=("INSERT INTO operator_reviewed_global_flow_citations "
             "(id,principal_issuer,principal_owner_sha256,global_document_id,global_revision,"
             "global_sha256,source_kind,engagement_id,flow_id,flow_owner,flow_revision,task_id,"
             "authorization_version,authorization_sha256,reviewed_identity_sha256) "
             "VALUES (:id,:issuer,:owner,:source,:revision,:digest,:kind,:eng,:flow,:flow_owner,"
             ":flow_rev,:task,:auth_ver,:auth_sha,:review)")
        inert={'id':metadata['id'],'eng':metadata['eng'],'flow':metadata['flow'],
               'flow_owner':metadata['flow_owner'],'sha':digest,'kind':'guide',
               'original':original,'bytes':len(original.encode('utf8'))}
        inert_sql=("INSERT INTO operator_reviewed_flow_originals "
                   "(citation_id,engagement_id,flow_id,flow_owner,sha256,source_kind,content,content_bytes) "
                   "VALUES (:id,:eng,:flow,:flow_owner,:sha,:kind,:original,:bytes)")

        # ONE COMMIT atomically creates the reviewed metadata and exact source
        # material. PostgreSQL rejects false trust flags at the schema level.
        with engine.begin() as db:
            db.execute(sa.text(metadata_sql),metadata)
            db.execute(sa.text(inert_sql),inert)
            assert db.scalar(sa.text('SELECT count(*) FROM operator_reviewed_flow_originals'))==1
        with engine.begin() as db:
            row=db.execute(sa.text('SELECT content,content_bytes,sha256,approved_for_agent_context,'
                     'verified_target_evidence FROM operator_reviewed_flow_originals')).one()
            assert row[0]==original and row[1]==len(original.encode('utf8')) and row[2]==digest
            assert row[3] is False and row[4] is False
        rejected(engine,'UPDATE operator_reviewed_flow_originals SET content=:x WHERE citation_id=:id',
                 {'id':inert['id'],'x':'forged'},'23514')
        rejected(engine,'UPDATE operator_reviewed_flow_originals '
                 'SET approved_for_agent_context=true WHERE citation_id=:id',
                 {'id':inert['id']},'23514')
        rejected(engine,'DELETE FROM operator_reviewed_flow_originals WHERE citation_id=:id',
                 {'id':inert['id']},'23514')

        # Synthetic second reviewer transaction: citation INSERT succeeds, but
        # invalid original content digest causes failure and MUST roll back
        # the citation as well. Never allow partial metadata-only promotion.
        other={**metadata,'id':'citation-'+'3'*32,'review':'d'*64}
        false_content={**inert,'id':other['id'],'original':'forged other text',
                       'bytes':len('forged other text'.encode('utf8'))}
        try:
            with engine.begin() as db:
                db.execute(sa.text(metadata_sql),other)
                db.execute(sa.text(inert_sql),false_content)
        except IntegrityError as exc:
            assert exc.orig.sqlstate=='23514', str(exc)
        else:
            raise AssertionError('Untrusted content digest was accepted')
        with engine.begin() as db:
            assert db.scalar(sa.text('SELECT count(*) FROM operator_reviewed_global_flow_citations'))==1
            assert db.scalar(sa.text('SELECT count(*) FROM operator_reviewed_flow_originals'))==1

        wrong_flow={**metadata,'id':'citation-'+'4'*32,'review':'e'*64}
        try:
            with engine.begin() as db:
                db.execute(sa.text(metadata_sql),wrong_flow)
                db.execute(sa.text(inert_sql),{**inert,'id':wrong_flow['id'],'flow_owner':'forged-owner'})
        except IntegrityError as exc:
            assert exc.orig.sqlstate=='23503', str(exc)
        else:
            raise AssertionError('Cross-owner original was accepted')
        with engine.begin() as db:
            assert db.scalar(sa.text('SELECT count(*) FROM operator_reviewed_global_flow_citations'))==1

        try:
            with engine.begin() as db:
                run_migration(db,m0042,'downgrade')
        except RuntimeError as exc:
            assert 'immutable Flow original remains' in str(exc)
        else:
            raise AssertionError('Nonempty 0042 downgrade unexpectedly destroyed original')
        print('RESULT_0042_PG_OK private_unix_nonroot online_0039_0041_0042 '
              'joint_atom_rollback_content_SHA_flow_FK_no_agent_promotion immutable_downgrade_denied')
    finally:
        if engine is not None:
            engine.dispose()
        stopped=command([str(BIN/'pg_ctl'),'-D',str(data),'-w','-m','fast','stop'])
        assert stopped.returncode==0,stopped.stderr[-1200:]
"""


def test_private_nonroot_pg16_0042_flow_original_atomic_rollback() -> None:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 to use private nonroot PostgreSQL16")
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
    script = f"ROOT=__import__('pathlib').Path({linux_root!r})\n" + _PRELUDE + _SCENARIOS
    result = subprocess.run(command, input=script, encoding="utf-8", errors="replace",
                            text=True, capture_output=True, timeout=160)
    assert result.returncode == 0, result.stderr[-5000:] + "\n" + result.stdout[-1200:]
    assert "RESULT_0042_PG_OK" in result.stdout
