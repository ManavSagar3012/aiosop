"""Disposable NONROOT PG16 current SourceMap original-byte chain; no execution.

Run OSOP_SOURCEMAP_ORIGINAL_CURRENT_PG=1 explicitly. This uses the real 0013,
0015,0026,0027,0029,0030,0031,0033,0035,0036,0037 migration upgrades on a
fresh owned Linux Unix-socket-only PostgreSQL16 cluster. The rows are LOCAL SQL
fixtures, NOT genuine 0027 approvals/0035 issuance/0029 grant redemption.

Earlier qualification's fixture builders are read-only imports; their synthetic
data is *not* recycled as live signed external authority. No PID, container,
host mount, app database, Docker, target or native MCP server is created.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPGrantDenied, _require_operational_pair,
)
from ai_osop.memory.sourcemap_source_authority import canonical
from ai_osop.memory.sourcemap_status_authority import (
    STATUS_DOMAIN, STATUS_FIELDS, SourceMapStatusAuthorityStore,
)
from ai_osop.orchestrator.sourcemap_0033_current_witness import (
    SourceMap0033CurrentWitness, SourceMap0033CurrentWitnessDenied,
)


ROOT = Path(__file__).resolve().parents[2]
OPT_IN = "OSOP_SOURCEMAP_ORIGINAL_CURRENT_PG"
UPGRADES_OFFLINE = (
    ("0013", "0013_flow_artifacts.py"),
    ("0015", "0015_flow_artifact_reviews.py"),
    ("0026", "0026_flow_resource_folders.py"),
    ("0027", "0027_flow_mcp_action_dispatch.py"),
    ("0029", "0029_native_mcp_execution_grants.py"),
    ("0030", "0030_native_mcp_resource_delivery.py"),
    ("0031", "0031_pinned_native_folder_stage.py"),
    ("0033", "0033_native_worker_supervision.py"),
    ("0035", "0035_native_sourcemap_source_authority.py"),
)
UPGRADES_ONLINE = (
    ("0036", "0036_sourcemap_native_grant_pair.py"),
    ("0037", "0037_sourcemap_grant_binding.py"),
)


def _load_migration(revision: str, name: str):
    path = ROOT / "migrations" / "versions" / name
    spec = importlib.util.spec_from_file_location("original_current_pg_" + revision, path)
    assert spec and spec.loader, path
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == revision
    return mod


def _previous_fixture_source():
    """Reuse *data builders*, not earlier tests or asserted outcomes."""
    path = ROOT / "tests/qualification/test_sourcemap_real_pg_status_join_20261021.py"
    spec = importlib.util.spec_from_file_location("original_pg_fixture_reader_only", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _actual_migration_sql() -> str:
    buf = io.StringIO()
    context = MigrationContext.configure(dialect_name="postgresql", opts={
        "as_sql": True, "output_buffer": buf, "transactional_ddl": True,
    })
    with Operations.context(context):
        for rev, filename in UPGRADES_OFFLINE:
            _load_migration(rev, filename).upgrade()
    sql = buf.getvalue()
    for needle in (
        "CREATE TABLE flow_artifacts", "CREATE TABLE flow_artifact_reviews",
        "flow_resource_folder_catalogs", "flow_mcp_action_dispatches",
        "native_mcp_execution_grants", "native_mcp_resource_offers",
        "folder_staging_sha256", "native_mcp_worker_supervisions",
        "native_sourcemap_source_preflights", "trg_native_sourcemap_source_immutable",
    ):
        assert needle in sql, needle
    return sql


def _single_quote(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


def _additional_original_grant_and_binding(c: dict) -> dict[str, str]:
    """SQL-only existing-parent fixtures; NEVER call the grant issuer."""
    row = c["intent"]
    claim = c["claims"]
    uid = uuid.uuid4().hex
    grant = "ngr-" + uid
    joining = "snb-" + uuid.uuid4().hex
    original_sha = hashlib.sha256(c["claims"]["artifact_sha256"].encode()).hexdigest()
    known = {
        "grant_id": grant,
        "binding_id": joining,
        "preflight_id": claim["preflight_id"],
        "action_id": c["action"],
        "request_id": c["request"],
        "artifact_id": c["artifact"],
        "engagement_id": c["eng"],
        "flow_id": c["flow"],
        "task_id": c["task"],
        "subtask_id": c["subtask"],
        "owner_id": row["owner_id"],
        "reviewer_id": "operator-pg-status-senior",
        "approval_id": row["approval_id"],
        "lease_id": row["lease_id"],
        "lease_owner_id": row["lease_owner_id"],
        "flow_revision": 0,
        "authorization_id": row["authorization_id"],
        "authorization_version": 1,
        "authorization_sha256": row["authorization_sha256"],
        "artifact_sha256": claim["artifact_sha256"],
        "resource_manifest_sha256": claim["manifest_sha256"],
        "declaration_sha256": row["declaration_sha256"],
        "parameters_sha256": row["parameters_sha256"],
        "preflight_claims_sha256": c["saved"]["claims_sha256"],
        "preflight_signature_sha256": c["saved"]["signature_sha256"],
        "grant_claims_sha256": hashlib.sha256((uid + "grant-claims").encode()).hexdigest(),
        "grant_signature_sha256": hashlib.sha256((uid + "grant-sig").encode()).hexdigest(),
        "join_sha256": original_sha,
        "status": "bound_only",
    }
    def value(k: str) -> str:
        return str(known[k]) if type(known[k]) is int else _single_quote(str(known[k]))

    # 0036 expands DB row CHECK; production _require_operational_pair still DENIES.
    grant_sql = """INSERT INTO native_mcp_execution_grants
       (grant_id,action_id,request_id,engagement_id,flow_id,task_id,subtask_id,
        owner_id,flow_revision,authorization_id,authorization_version,
        authorization_sha256,approval_id,lease_id,lease_owner_id,server_id,
        tool_name,side_effect_class,parameters_sha256,manifest_sha256,
        resource_sha256,intent_sha256,kid,claims_sha256,signature_sha256,
        issued_at,expires_at,status,revision)
       VALUES (""" + ",".join([
        value(k) for k in (
            "grant_id", "action_id", "request_id", "engagement_id", "flow_id",
            "task_id", "subtask_id", "owner_id", "flow_revision",
            "authorization_id", "authorization_version", "authorization_sha256",
            "approval_id", "lease_id", "lease_owner_id",
        )
    ] + [
        "'source-map-mcp'", "'inspect_local_original_sourcemap'", "'READ_ONLY'",
        value("parameters_sha256"), value("declaration_sha256"), value("artifact_sha256"),
        _single_quote(hashlib.sha256((uid + "grant-intent").encode()).hexdigest()),
        "'local-fixture-only-kid'", value("grant_claims_sha256"),
        value("grant_signature_sha256"), "10000", "10030", "'issued'", "1",
    ]) + ");"
    cols = (
        "binding_id", "action_id", "request_id", "preflight_id", "grant_id",
        "artifact_id", "engagement_id", "flow_id", "task_id", "subtask_id",
        "owner_id", "reviewer_id", "approval_id", "lease_id", "lease_owner_id",
        "flow_revision", "authorization_id", "authorization_version",
        "authorization_sha256", "artifact_sha256", "resource_manifest_sha256",
        "declaration_sha256", "parameters_sha256", "preflight_claims_sha256",
        "preflight_signature_sha256", "grant_claims_sha256",
        "grant_signature_sha256", "join_sha256", "status",
    )
    def binding(insert: dict) -> str:
        return (
            "INSERT INTO native_sourcemap_grant_bindings (" + ",".join(cols) + ") VALUES ("
            + ",".join(
                str(insert[k]) if type(insert[k]) is int else _single_quote(str(insert[k]))
                for k in cols
            ) + ");"
        )
    forged_fk = {**known, "binding_id": "snb-" + uuid.uuid4().hex,
                 "action_id": "action-" + uuid.uuid4().hex,
                 "request_id": "req-" + uuid.uuid4().hex}
    return {
        "grant": grant_sql,
        "binding": binding(known),
        "missing_fk": binding(forged_fk),
        "wrong_sha": "f" * 64,
        "known": json.dumps(known),
    }


def _join_query(c: dict[str, str]) -> str:
    """Explicit verification query only: not production store.admit()."""
    return """
SELECT count(*) FROM native_sourcemap_grant_bindings b
 JOIN native_sourcemap_source_preflights p
   ON p.preflight_id=b.preflight_id AND p.action_id=b.action_id
    AND p.request_id=b.request_id AND p.artifact_sha256=b.artifact_sha256
    AND p.manifest_sha256=b.resource_manifest_sha256
 JOIN native_mcp_execution_grants g ON g.grant_id=b.grant_id
    AND g.action_id=b.action_id AND g.request_id=b.request_id
    AND g.resource_sha256=b.artifact_sha256
 JOIN flow_mcp_action_dispatches a ON a.action_id=b.action_id
    AND a.request_id=b.request_id AND a.task_id=b.task_id
    AND a.status='unknown' AND a.cancel_requested=false AND a.receipt_sha256 IS NULL
 JOIN session_states s ON s.session_id=b.engagement_id AND s.created_by=b.owner_id
    AND s.phase NOT IN ('completed','halted')
 JOIN supervision_execution_leases l ON l.task_id=b.task_id
    AND l.engagement_id=b.engagement_id AND l.lease_id=b.lease_id
    AND l.state='dispatched' AND l.expires_at > clock_timestamp()
 JOIN flow_artifacts art ON art.id=b.artifact_id
    AND art.engagement_id=b.engagement_id AND art.flow_id=b.flow_id
    AND art.owner_id=b.owner_id AND art.sha256=b.artifact_sha256
    AND octet_length(art.content)=art.size_bytes
    AND encode(sha256(art.content),'hex')=art.sha256
 JOIN flow_artifact_reviews rev ON rev.artifact_id=b.artifact_id
    AND rev.reviewer_sub=b.reviewer_id AND rev.uploader_sub=b.owner_id
    AND rev.decision='approve' AND rev.reviewer_role='senior_operator'
    AND rev.artifact_sha256=b.artifact_sha256
 JOIN operator_subject_controls ctr ON ctr.actor_id=b.reviewer_id AND ctr.disabled=false
 JOIN tasks t ON t.id=b.task_id AND t.engagement_id=b.engagement_id
    AND t.payload->>'resource_artifact_id'=art.id
    AND t.payload->>'resource_artifact_sha256'=b.artifact_sha256
    AND t.payload->>'resource_manifest_sha256'=b.resource_manifest_sha256
 WHERE b.action_id=""" + _single_quote(c["action"]) + """
    AND b.request_id=""" + _single_quote(c["request"]) + """
    AND b.artifact_sha256=""" + _single_quote(c["original_sha"]) + """
    AND (s.roe->>'allow_read_only')::boolean=true
    AND (s.roe->>'allow_source_map_inspection')::boolean=true;
"""


# This script is supplied directly to Ubuntu's own non-root python3. Its ONLY
# server is new, private Unix-socket PostgreSQL16, never a TCP listener/app DB.
_LINUX_PG = r'''
import importlib.util, json, os, random, socket, subprocess, tempfile
from pathlib import Path
import sqlalchemy as sa
import psycopg
from alembic.migration import MigrationContext
from alembic.operations import Operations

assert os.name == 'posix' and os.geteuid() != 0
binroot = Path('/usr/lib/postgresql/16/bin')
assert all((binroot/x).is_file() for x in ('initdb','pg_ctl','psql'))
def run(cmd, input=None):
    return subprocess.run(cmd, input=input, text=True, capture_output=True, timeout=65)
def load(revision, filename):
    path = Path(PAYLOAD['root'])/'migrations'/'versions'/filename
    spec=importlib.util.spec_from_file_location('original_current_live_'+revision, path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision==revision
    return mod
with tempfile.TemporaryDirectory(prefix='osop-original-current-chain-',dir='/tmp') as folder:
    root=Path(folder);root.chmod(0o700)
    data=root/'data'; logfile=root/'pg.log'
    port=random.SystemRandom().randrange(56001,59000)
    out=run([str(binroot/'initdb'),'-D',str(data),'-A','trust','-U','osop_readonly_fixture','--no-instructions'])
    assert out.returncode==0,out.stderr[-1200:]
    started=False; engine=None
    try:
        out=run([str(binroot/'pg_ctl'),'-D',str(data),'-l',str(logfile),'-o',
           "-c listen_addresses='' -c unix_socket_directories="+str(root)+
           ' -c unix_socket_permissions=0700 -c port='+str(port)+
           ' -c fsync=on -c synchronous_commit=on','-w','-t','20','start'])
        assert out.returncode==0,out.stderr[-1200:]
        started=True
        assert (root/('.s.PGSQL.'+str(port))).is_socket()
        assert not (root/('.s.PGSQL.'+str(port))).is_symlink()
        engine=sa.create_engine('postgresql+psycopg://osop_readonly_fixture@/postgres',
            connect_args={'host':str(root),'port':port,'connect_timeout':5})
        def psql(sql, success=True):
            out=run([str(binroot/'psql'),'-X','-q','-A','-t','-v','ON_ERROR_STOP=1',
                '-h',str(root),'-p',str(port),'-U','osop_readonly_fixture','-d','postgres'],sql)
            if success:assert out.returncode==0,out.stderr[-1600:]+sql[:300]
            else:assert out.returncode!=0,'Unexpected SQL acceptance: '+sql[:300]
            return out.stdout.strip(),out.stderr
        assert psql('SHOW listen_addresses;')[0]==''
        assert psql('SHOW server_version_num;')[0].startswith('16')
        assert psql('SELECT current_database();')[0]=='postgres'
        assert psql('SELECT pg_backend_pid();')[0]!=psql('SELECT pg_backend_pid();')[0]
        psql(PAYLOAD['predecessors'])
        psql(PAYLOAD['ddl'])
        with engine.begin() as conn:
            ctx=MigrationContext.configure(conn,opts={'transactional_ddl':True})
            with Operations.context(ctx):
                for rev,filename in PAYLOAD['online']:
                    load(rev,filename).upgrade()
        for name in ('flow_artifacts','flow_artifact_reviews','flow_resource_folder_catalogs',
          'flow_mcp_action_dispatches','native_mcp_execution_grants',
          'native_mcp_resource_offers','native_mcp_worker_supervisions',
          'native_sourcemap_source_preflights','native_sourcemap_grant_bindings'):
            assert psql("SELECT to_regclass('"+name+"');")[0]==name
        psql(PAYLOAD['original_rows'])
        assert psql(PAYLOAD['live_original_sha'])[0]==PAYLOAD['sha']
        assert psql('SELECT status FROM flow_mcp_action_dispatches;')[0]=='unknown'
        assert psql('SELECT count(*) FROM native_mcp_execution_grants;')[0]=='0'
        psql(PAYLOAD['preflight'])
        assert psql(PAYLOAD['preflight_conflict'])[0]==''
        assert psql('SELECT count(*) FROM native_sourcemap_source_preflights;')[0]=='1'
        _,duplicate=psql(PAYLOAD['preflight'],success=False)
        assert 'duplicate key value' in duplicate
        psql(PAYLOAD['grant']) # synthetic row ONLY, no operational source grant issuance
        assert psql('SELECT count(*) FROM native_mcp_resource_offers;')[0]=='0'
        assert psql('SELECT count(*) FROM native_mcp_worker_supervisions;')[0]=='0'
        assert psql('SELECT count(*) FROM native_mcp_worker_supervision_events;')[0]=='0'
        _, fk=psql(PAYLOAD['missing_fk'],success=False)
        assert 'foreign key constraint' in fk,fk
        psql(PAYLOAD['binding'])
        _, dupe=psql(PAYLOAD['binding'],success=False)
        assert 'duplicate key value' in dupe
        assert psql('SELECT count(*) FROM native_sourcemap_grant_bindings;')[0]=='1'
        assert psql(PAYLOAD['join'])[0]=='1','Wrong live original/current DB join'
        assert psql(PAYLOAD['join_wrong_sha'])[0]=='0'
        _,immutable=psql('UPDATE native_sourcemap_grant_bindings SET status=status;',success=False)
        assert 'immutable' in immutable
        _,immutable=psql('DELETE FROM native_sourcemap_source_preflights;',success=False)
        assert 'immutable' in immutable
        # Mutate only mutable AUTHORITATIVE CURRENT rows. Never mutate original bytes or review.
        psql("UPDATE operator_subject_controls SET disabled=true WHERE actor_id='operator-pg-status-senior';")
        assert psql(PAYLOAD['join'])[0]=='0'
        psql("UPDATE operator_subject_controls SET disabled=false WHERE actor_id='operator-pg-status-senior';")
        assert psql(PAYLOAD['join'])[0]=='1'
        psql("UPDATE supervision_execution_leases SET state='cancelled';")
        assert psql(PAYLOAD['join'])[0]=='0'
        psql("UPDATE supervision_execution_leases SET state='dispatched';")
        assert psql(PAYLOAD['join'])[0]=='1'
        psql("UPDATE session_states SET roe='{}'::jsonb;")
        assert psql(PAYLOAD['join'])[0]=='0'
        psql("""UPDATE session_states SET roe='{"allow_read_only":true,"allow_source_map_inspection":true}'::jsonb;""")
        assert psql(PAYLOAD['join'])[0]=='1'
        psql('UPDATE flow_mcp_action_dispatches SET cancel_requested=true;')
        assert psql(PAYLOAD['join'])[0]=='0'
        # Never restore cancellation: the original Action is consumed/UNKNOWN.
        assert psql('SELECT status FROM flow_mcp_action_dispatches;')[0]=='unknown'
        assert psql('SELECT count(*) FROM native_mcp_resource_offers;')[0]=='0'
        assert psql('SELECT count(*) FROM native_mcp_worker_supervisions;')[0]=='0'
        print('RESULT_JSON:'+json.dumps({
           'postgres':16,'private_unix_socket':True,'migrations':
            [x[0] for x in PAYLOAD['offline']]+[x[0] for x in PAYLOAD['online']],
           'original_sha':PAYLOAD['sha'],'action_status':'unknown',
           'preflight_count':1,'binding_count':1,'grant_fixture_count':1,
           'offer_count':0,'supervisor_count':0,'fk_denied':True,
           'lost_ack_one_use':True,'live_digest_join':True,
           'wrong_sha_denied':True,'revoked_senior_denied':True,
           'revoked_lease_denied':True,'revoked_roe_denied':True,
           'cancelled_denied':True,'no_real_pid_or_mount':True
        },sort_keys=True))
    finally:
        if engine is not None:engine.dispose()
        if started:
            out=run([str(binroot/'pg_ctl'),'-D',str(data),'-w','-m','fast','stop'])
            assert out.returncode==0,out.stderr[-1200:]
'''


def _linux_path(path: Path) -> str:
    raw = str(path.resolve())
    if os.name != "nt":
        return raw
    assert raw[1:3] == ":\\"
    return "/mnt/" + raw[0].lower() + raw[2:].replace("\\", "/")


def test_source_migrations_and_operational_gap_are_explicit() -> None:
    assert len(UPGRADES_OFFLINE) == 9 and len(UPGRADES_ONLINE) == 2
    ddl = _actual_migration_sql()
    assert "native_mcp_worker_supervisions" in ddl
    for rev, name in UPGRADES_ONLINE:
        mod = _load_migration(rev, name)
        assert callable(mod.upgrade)
    with pytest.raises(NativeMCPGrantDenied):
        _require_operational_pair(
            "source-map-mcp", "inspect_local_original_sourcemap", "READ_ONLY"
        )


def test_without_independently_enrolled_pid_mount_roots_current_witness_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No fake PID/process or mount is ever materialized."""
    for name in (
        "OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON",
    ):
        monkeypatch.delenv(name, raising=False)
    # Constructor refuses producer enrollment before DB or any resource/host work.
    with pytest.raises(SourceMap0033CurrentWitnessDenied):
        SourceMap0033CurrentWitness(FlowMCPActionStore.__new__(FlowMCPActionStore))


def test_independent_fixture_status_signature_is_not_operator_or_pid_authority() -> None:
    """Distinct test keys: validate cryptography, DO NOT call production admit."""
    original = _previous_fixture_source()._fixture()
    source_key = original["issuer_signer"]
    status_key = Ed25519PrivateKey.generate()
    assert source_key.public_key() != status_key.public_key()
    issued = SourceMapStatusAuthorityStore._verify_issued(
        {**original["saved"], "committed_at": object()},
        {**original["intent"], "request_id": original["request"],
         "authorization_version": 1},
        original["claims"]["manifest_sha256"],
        original["claims"]["artifact_sha256"],
        current_kid="sourcemap-pg-status-current",
        now=original["claims"]["issued_at"] + 1,
    )
    status_claim = {**issued, "status_id": "nss-" + uuid.uuid4().hex}
    status_claim["issued_at"] = int(time.time())
    status_claim["expires_at"] = status_claim["issued_at"] + 5
    assert set(status_claim) == STATUS_FIELDS
    sig = status_key.sign(STATUS_DOMAIN + canonical(status_claim))
    status_key.public_key().verify(sig, STATUS_DOMAIN + canonical(status_claim))
    with pytest.raises(InvalidSignature):
        source_key.public_key().verify(sig, STATUS_DOMAIN + canonical(status_claim))
    tampered = {**status_claim, "artifact_sha256": "0" * 64}
    with pytest.raises(InvalidSignature):
        status_key.public_key().verify(sig, STATUS_DOMAIN + canonical(tampered))
    # A *separately* signed fixture STATUS is not a real issuer response:
    # no DB insertion, no enrolled production root, no process or mount.


def test_real_pg16_migrations_source_original_current_chain_failclosed() -> None:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 to create isolated nonroot socket-only PG16")
    previous = _previous_fixture_source()
    c = previous._fixture()
    extra = _additional_original_grant_and_binding(c)
    query = _join_query({"action": c["action"], "request": c["request"],
                         "original_sha": c["original_sha"]})
    payload = {
        "root": _linux_path(ROOT),
        "predecessors": previous._minimum_predecessors(),
        "ddl": _actual_migration_sql(),
        "offline": UPGRADES_OFFLINE,
        "online": UPGRADES_ONLINE,
        "original_rows": previous._insert_fixture(c),
        "preflight": previous._source_insert(c),
        "preflight_conflict": previous._source_insert(c, on_conflict=True),
        "grant": extra["grant"],
        "binding": extra["binding"],
        "missing_fk": extra["missing_fk"],
        "sha": c["original_sha"],
        "live_original_sha": "SELECT encode(sha256(content),'hex') FROM flow_artifacts;",
        "join": query,
        "join_wrong_sha": _join_query({"action": c["action"], "request": c["request"],
                                        "original_sha": extra["wrong_sha"]}),
    }
    source = "import base64,json\nPAYLOAD=json.loads(base64.b64decode(" + repr(
        base64.b64encode(json.dumps(payload).encode()).decode()
    ) + "))\n" + _LINUX_PG
    if os.name == "nt":
        deps = _linux_path(Path(sys.prefix) / "Lib" / "site-packages")
        cmd = ["wsl.exe", "-d", "Ubuntu", "--", "env", "PYTHONPATH=" + deps,
               "python3", "-"]
    elif sys.platform == "linux":
        cmd = [sys.executable, "-"]
    else:
        pytest.skip("Requires nonroot Linux/Ubuntu WSL PostgreSQL16")
    try:
        result = subprocess.run(cmd, input=source, text=True, capture_output=True,
                                timeout=190, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.fail("Private nonroot PostgreSQL16 setup unavailable: " + str(exc))
    assert result.returncode == 0, (
        "Real private PostgreSQL test failed: " + result.stderr[-3500:] +
        "\n" + result.stdout[-850:]
    )
    found = [line[12:] for line in result.stdout.splitlines()
             if line.startswith("RESULT_JSON:")]
    assert len(found) == 1, result.stdout[-1200:]
    observed = json.loads(found[0])
    assert observed["migrations"] == [x[0] for x in (*UPGRADES_OFFLINE, *UPGRADES_ONLINE)]
    assert observed["postgres"] == 16 and observed["private_unix_socket"]
    assert observed["original_sha"] == c["original_sha"]
    assert observed["action_status"] == "unknown"
    assert observed["preflight_count"] == observed["binding_count"] == 1
    assert observed["grant_fixture_count"] == 1
    assert observed["offer_count"] == observed["supervisor_count"] == 0
    assert all(observed[key] is True for key in (
        "fk_denied", "lost_ack_one_use", "live_digest_join",
        "wrong_sha_denied", "revoked_senior_denied", "revoked_lease_denied",
        "revoked_roe_denied", "cancelled_denied", "no_real_pid_or_mount",
    ))
