"""SourceMap 0035 source->current STATUS SQL contract on fresh real PG16.

Scope is deliberately narrow: compile ACTUAL selected Alembic upgrade() ops,
apply them to a tiny dependency schema on an owned Unix-socket-only PostgreSQL
cluster, and exercise its real constraints with two independent psql clients.
The fixture rows are synthetic; this does not run real 0027 prepare/dispatch,
source/status store.admit, the full application migration chain, or 0036 grant
issuance. See docs/SOURCEMAP_CURRENT_PG_JOIN_20261021.md.

Windows runner: OSOP_SOURCEMAP_STATUS_UNIX_PG=1 with WSL Ubuntu + local PG16.
POSIX runner: same opt-in and local PG16 binaries in /usr/lib/postgresql/16/bin.
No Docker, app database, TCP listener, targets, downloads, or dependency install.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    _DIGEST_DOMAIN,
    _digest,
)
from ai_osop.memory.flow_resource_exports import make_manifest
from ai_osop.memory.sourcemap_source_authority import (
    CLAIM_FIELDS,
    DOMAIN,
    SourceMapSourceDenied,
    canonical,
)
from ai_osop.memory.sourcemap_status_authority import (
    STATUS_DOMAIN,
    STATUS_FIELDS,
    SourceMapStatusAuthorityStore,
)


ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = (
    ("0013", "0013_flow_artifacts.py"),
    ("0015", "0015_flow_artifact_reviews.py"),
    ("0027", "0027_flow_mcp_action_dispatch.py"),
    ("0029", "0029_native_mcp_execution_grants.py"),
    ("0033", "0033_native_worker_supervision.py"),
    ("0035", "0035_native_sourcemap_source_authority.py"),
)
OPT_IN = "OSOP_SOURCEMAP_STATUS_UNIX_PG"
ORIGINAL = (
    b'{"version":3,"sources":["src/offline.ts"],"names":[],"mappings":"AAAA",'
    b'"sourcesContent":["const fixture=1;"]}'
)
SHA = hashlib.sha256(ORIGINAL).hexdigest()
OWNER = "operator-pg-status-owner"
REVIEWER = "operator-pg-status-senior"
APPROVER = "operator-pg-status-approver"
KID = "sourcemap-pg-status-current"


def _migration_ddl() -> str:
    """Render literal Alembic upgrades, never reconstruct CHECKs by hand."""
    buffer = io.StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": buffer, "transactional_ddl": True},
    )
    with Operations.context(context):
        for revision, filename in MIGRATIONS:
            path = ROOT / "migrations" / "versions" / filename
            spec = importlib.util.spec_from_file_location(
                "_source_status_offline_" + revision, path
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            assert module.revision == revision
            module.upgrade()
    ddl = buffer.getvalue()
    for required in (
        "trg_flow_artifact_immutable",
        "trg_flow_artifact_review_immutable",
        "trg_flow_mcp_action_events_immutable",
        "trg_native_mcp_grant_events_immutable",
        "trg_native_worker_supervision_events_immutable",
        "trg_native_sourcemap_source_immutable",
        "ck_native_sourcemap_source_expiry",
    ):
        assert required in ddl, required
    return ddl


def _quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _fixture() -> dict[str, Any]:
    suffix = uuid.uuid4().hex[:12]
    eng = "eng-pg-status-" + suffix
    flow = "flow-pg-status-" + suffix
    task = "task-pg-status-" + suffix
    subtask = "subtask-pg-status-" + suffix
    action = "action-" + uuid.uuid4().hex
    art = "artifact-" + uuid.uuid4().hex
    params = {"artifact_sha256": SHA}
    sha_params = FlowMCPActionStore.parameters_sha256(params)
    auth_sha = hashlib.sha256(("independent-roe-" + suffix).encode()).hexdigest()
    declaration = hashlib.sha256(("native-declaration-" + suffix).encode()).hexdigest()
    manifest = make_manifest(
        flow,
        0,
        1,
        [
            (
                {
                    "id": art,
                    "flow_id": flow,
                    "name": "approved-original.map.json",
                    "size_bytes": len(ORIGINAL),
                    "sha256": SHA,
                    "flow_revision": 0,
                    "authorization_version": 1,
                },
                ORIGINAL,
            )
        ],
    )["manifest_sha256"]
    bind = {
        "engagement_id": eng,
        "flow_id": flow,
        "revision": 0,
        "version": 1,
        "authorization_id": "auth-pg-status-" + suffix,
        "authorization_sha256": auth_sha,
    }
    intent = {
        **bind,
        "task_id": task,
        "subtask_id": subtask,
        "action_id": action,
        "owner_id": OWNER,
        "approval_id": "apr-pg-status-" + suffix,
        "lease_id": "lease-pg-status-" + suffix,
        "lease_owner_id": "worker-pg-status",
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "side_effect_class": "READ_ONLY",
        "declaration_sha256": declaration,
        "parameters_sha256": sha_params,
    }
    intent_sha = _digest(_DIGEST_DOMAIN, intent, 4096)
    request = "req-" + intent_sha[:48]
    claims = {
        "version": 1,
        "preflight_id": "nsp-" + uuid.uuid4().hex,
        "request_id": request,
        "engagement_id": eng,
        "flow_id": flow,
        "task_id": task,
        "subtask_id": subtask,
        "action_id": action,
        "owner_id": OWNER,
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": SHA,
        "manifest_sha256": manifest,
        "approval_id": intent["approval_id"],
        "lease_id": intent["lease_id"],
        "authorization_version": 1,
        "authorization_sha256": auth_sha,
        "issued_at": int(time.time()) - 1,
        "expires_at": int(time.time()) + 9,
    }
    assert set(claims) == CLAIM_FIELDS
    issuer = Ed25519PrivateKey.generate()
    signature = issuer.sign(DOMAIN + canonical(claims))
    issuer.public_key().verify(signature, DOMAIN + canonical(claims))
    saved = {
        **claims,
        "kid": KID,
        "claims_sha256": hashlib.sha256(canonical(claims)).hexdigest(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }
    return {
        "eng": eng, "flow": flow, "task": task, "subtask": subtask,
        "action": action, "artifact": art, "intent": intent,
        "intent_sha": intent_sha, "params": params,
        "request": request, "claims": claims, "saved": saved,
        "original_sha": SHA, "original_hex": ORIGINAL.hex(),
        "signature": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        "issuer_public": base64.b64encode(issuer.public_key().public_bytes_raw()).decode(),
        "issuer_signer": issuer,
    }


def _minimum_predecessors() -> str:
    """Explicit FK parents and exact 0016 trigger function, not a full app DB."""
    return """
CREATE TABLE session_states (session_id varchar(64) PRIMARY KEY,
    created_by varchar(64) NOT NULL, phase text NOT NULL, roe jsonb NOT NULL);
CREATE TABLE execution_flows (id varchar(64) PRIMARY KEY,
    engagement_id varchar(64) NOT NULL, revision integer NOT NULL,
    status varchar(16) NOT NULL);
CREATE TABLE tasks (id varchar(64) PRIMARY KEY,
    engagement_id varchar(64) NOT NULL, payload jsonb NOT NULL);
CREATE TABLE execution_subtasks (id varchar(64) PRIMARY KEY);
CREATE TABLE operator_subject_controls (actor_id varchar(64) PRIMARY KEY,
    disabled boolean NOT NULL);
CREATE TABLE supervision_execution_leases (task_id varchar(64) PRIMARY KEY,
    engagement_id varchar(64) NOT NULL, lease_id varchar(64) NOT NULL,
    state varchar(20) NOT NULL, expires_at timestamp NOT NULL);
CREATE FUNCTION reject_target_authority_nonce_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Target authority replay receipts are immutable';
END;
$$;
"""


def _insert_fixture(c: dict[str, Any]) -> str:
    row = c["intent"]
    task_payload = {
        "resource_artifact_id": c["artifact"],
        "resource_artifact_sha256": SHA,
        "resource_authorization_sha256": row["authorization_sha256"],
        "resource_command_sha256": row["parameters_sha256"],
        "resource_manifest_sha256": c["claims"]["manifest_sha256"],
    }
    def q(key: str) -> str:
        return _quote(str(row[key]))

    return f"""
INSERT INTO session_states VALUES ({_quote(c["eng"])},{_quote(OWNER)},'reconnaissance',
    '{{"allow_read_only":true,"allow_source_map_inspection":true}}'::jsonb);
INSERT INTO execution_flows VALUES ({_quote(c["flow"])},{_quote(c["eng"])},0,'running');
INSERT INTO tasks VALUES ({_quote(c["task"])},{_quote(c["eng"])},
    {_quote(json.dumps(task_payload))}::jsonb);
INSERT INTO execution_subtasks VALUES ({_quote(c["subtask"])});
INSERT INTO operator_subject_controls VALUES ({_quote(REVIEWER)}, false),
    ({_quote(APPROVER)},false), ({_quote(OWNER)},false);
INSERT INTO supervision_execution_leases VALUES
    ({_quote(c["task"])},{_quote(c["eng"])},{q("lease_id")},'dispatched',
    clock_timestamp() + interval '5 minutes');
INSERT INTO flow_artifacts
 (id,flow_id,engagement_id,owner_id,name,size_bytes,sha256,authorization_version,
  authorization_sha256,flow_revision,content)
 VALUES ({_quote(c["artifact"])},{_quote(c["flow"])},{_quote(c["eng"])},{_quote(OWNER)},
 'approved-original.map.json',{len(ORIGINAL)},{_quote(SHA)},1,
 {q("authorization_sha256")},0,decode({_quote(c["original_hex"])},'hex'));
INSERT INTO flow_artifact_reviews
 (id,artifact_id,flow_id,engagement_id,uploader_sub,reviewer_sub,reviewer_role,
  decision,reason,artifact_sha256,flow_revision,authorization_id,
  authorization_version,authorization_sha256)
 VALUES ({_quote("review-" + uuid.uuid4().hex)},{_quote(c["artifact"])},
 {_quote(c["flow"])},{_quote(c["eng"])},{_quote(OWNER)},{_quote(REVIEWER)},
 'senior_operator','approve','Independent synthetic schema review', {_quote(SHA)},
 0,{q("authorization_id")},1,{q("authorization_sha256")});
INSERT INTO flow_mcp_action_dispatches
 (action_id,engagement_id,flow_id,task_id,subtask_id,owner_id,flow_revision,
 authorization_id,authorization_version,authorization_sha256,approval_id,lease_id,
 lease_owner_id,server_id,tool_name,side_effect_class,declaration_sha256,
 parameters_sha256,safe_parameters,intent_sha256,request_id,
 reservation_token_sha256,status,revision,cancel_requested)
 VALUES ({_quote(c["action"])},{_quote(c["eng"])},{_quote(c["flow"])},
 {_quote(c["task"])},{_quote(c["subtask"])},{_quote(OWNER)},0,
 {q("authorization_id")},1,{q("authorization_sha256")},
 {q("approval_id")},{q("lease_id")},{q("lease_owner_id")},
 {q("server_id")},{q("tool_name")},{q("side_effect_class")},
 {q("declaration_sha256")},{q("parameters_sha256")},
 {_quote(json.dumps(c["params"]))}::json, {_quote(c["intent_sha"])},
 {_quote(c["request"])},{_quote("0"*64)},'unknown',3,false);
INSERT INTO flow_mcp_action_dispatch_events
 (id,action_id,engagement_id,flow_id,task_id,revision,kind,status,intent_sha256)
 VALUES ({_quote("evt-" + uuid.uuid4().hex)},{_quote(c["action"])},
 {_quote(c["eng"])},{_quote(c["flow"])},{_quote(c["task"])},3,
 'dispatch_attempted','unknown',{_quote(c["intent_sha"])});
"""


def _source_insert(c: dict[str, Any], *, on_conflict: bool = False) -> str:
    values = c["saved"]
    columns = ", ".join(values)
    encoded = ", ".join(str(v) if type(v) is int else _quote(v) for v in values.values())
    suffix = " ON CONFLICT DO NOTHING RETURNING preflight_id" if on_conflict else ""
    return (
        "INSERT INTO native_sourcemap_source_preflights (" + columns +
        ") VALUES (" + encoded + ")" + suffix + ";"
    )


def _join(c: dict[str, Any], *, sha: str = SHA) -> str:
    # Test SQL recreates only a subset of production fences; see report.
    return f"""
SELECT row_to_json(found)::text FROM (
 SELECT p.*, a.status AS action_status, a.receipt_sha256 AS action_receipt,
    a.cancel_requested AS action_cancelled
 FROM native_sourcemap_source_preflights p
 JOIN flow_mcp_action_dispatches a
   ON a.action_id=p.action_id AND a.request_id=p.request_id
   AND a.engagement_id=p.engagement_id AND a.flow_id=p.flow_id
   AND a.task_id=p.task_id AND a.subtask_id=p.subtask_id
   AND a.owner_id=p.owner_id AND a.approval_id=p.approval_id
   AND a.lease_id=p.lease_id
   AND a.authorization_sha256=p.authorization_sha256
   AND a.authorization_version=p.authorization_version
   AND a.server_id=p.server_id AND a.tool_name=p.tool_name
 JOIN flow_mcp_action_dispatch_events e
   ON e.action_id=a.action_id AND e.intent_sha256=a.intent_sha256
   AND e.kind='dispatch_attempted' AND e.status='unknown'
 JOIN session_states s ON s.session_id=a.engagement_id AND s.created_by=a.owner_id
 JOIN execution_flows f ON f.id=a.flow_id AND f.engagement_id=a.engagement_id
 JOIN tasks t ON t.id=a.task_id AND t.engagement_id=a.engagement_id
 JOIN supervision_execution_leases l
   ON l.task_id=a.task_id AND l.engagement_id=a.engagement_id
   AND l.lease_id=a.lease_id
 JOIN flow_artifacts art ON art.engagement_id=a.engagement_id
   AND art.flow_id=a.flow_id AND art.owner_id=a.owner_id
   AND art.sha256=p.artifact_sha256
 JOIN flow_artifact_reviews review ON review.artifact_id=art.id
   AND review.engagement_id=a.engagement_id
   AND review.reviewer_sub<>a.owner_id
   AND review.reviewer_role='senior_operator'
   AND review.decision='approve'
   AND review.artifact_sha256=p.artifact_sha256
   AND review.authorization_sha256=a.authorization_sha256
   AND review.authorization_version=a.authorization_version
 JOIN operator_subject_controls ctrl ON ctrl.actor_id=review.reviewer_sub
 WHERE p.request_id={_quote(c["request"])}
   AND p.action_id={_quote(c["action"])}
   AND p.artifact_sha256={_quote(sha)}
   AND p.kid={_quote(KID)}
   AND p.claims_sha256={_quote(c["saved"]["claims_sha256"])}
   AND a.status='unknown' AND a.cancel_requested=false AND a.receipt_sha256 IS NULL
   AND s.phase NOT IN ('completed','halted') AND f.status='running'
   AND (s.roe->>'allow_read_only')::boolean IS TRUE
   AND (s.roe->>'allow_source_map_inspection')::boolean IS TRUE
   AND l.state='dispatched' AND l.expires_at>clock_timestamp()
   AND ctrl.disabled=false
   AND octet_length(art.content)=art.size_bytes
   AND encode(sha256(art.content),'hex')=art.sha256
   AND t.payload->>'resource_artifact_id'=art.id
   AND t.payload->>'resource_artifact_sha256'=p.artifact_sha256
   AND t.payload->>'resource_manifest_sha256'=p.manifest_sha256
   AND t.payload->>'resource_authorization_sha256'=a.authorization_sha256
   AND t.payload->>'resource_command_sha256'=a.parameters_sha256
) found;
"""


_LINUX_WORKER = r"""
import json, os, pathlib, random, shutil, stat, subprocess, tempfile
from concurrent.futures import ThreadPoolExecutor
p = PAYLOAD
bin_dir = pathlib.Path("/usr/lib/postgresql/16/bin")
assert os.name == "posix" and os.geteuid() != 0
assert all((bin_dir / tool).is_file() for tool in ("initdb","pg_ctl","psql"))
def run(argv, sql=None):
    return subprocess.run(argv, input=sql, capture_output=True, text=True, timeout=50)
with tempfile.TemporaryDirectory(prefix="osop-sourcemap-current-status-", dir="/tmp") as folder:
    root = pathlib.Path(folder)
    root.chmod(0o700)
    data = root / "data"
    log = root / "postgres.log"
    port = random.SystemRandom().randrange(54100, 56000)
    init = run([str(bin_dir/"initdb"), "-D", str(data), "-A", "trust", "-U",
                "osop_status_disposable", "--no-instructions"])
    assert init.returncode == 0, init.stderr[-1100:]
    started = False
    try:
        start = run([str(bin_dir/"pg_ctl"), "-D", str(data), "-l", str(log),
                     "-o", "-c listen_addresses='' -c unix_socket_directories=" +
                     str(root) + " -c unix_socket_permissions=0700 -c port=" + str(port) +
                     " -c fsync=on -c synchronous_commit=on",
                     "-w", "-t", "20", "start"])
        assert start.returncode == 0, start.stderr[-1100:]
        started = True
        assert (root / (".s.PGSQL." + str(port))).is_socket()
        def psql(sql, success=True):
            outcome = run([str(bin_dir/"psql"), "-X", "-q", "-A", "-t",
                           "-v", "ON_ERROR_STOP=1", "-h", str(root), "-p",
                           str(port), "-U", "osop_status_disposable", "-d", "postgres"], sql)
            if success:
                assert outcome.returncode == 0, outcome.stderr[-1100:] + sql[:180]
            else:
                assert outcome.returncode != 0, "Unexpected acceptance: " + sql[:140]
            return outcome.stdout.strip(), outcome.stderr
        assert psql("SHOW listen_addresses;")[0] == ""
        assert psql("SHOW server_version_num;")[0].startswith("16")
        pid_a = int(psql("SELECT pg_backend_pid();")[0])
        pid_b = int(psql("SELECT pg_backend_pid();")[0])
        assert pid_a != pid_b, (pid_a, pid_b)
        psql(p["predecessors"])
        psql(p["migration_sql"])
        names = psql("SELECT string_agg(conname, ',' ORDER BY conname) FROM pg_constraint "
                     "WHERE conrelid='native_sourcemap_source_preflights'::regclass;")[0]
        for name in ("ck_native_sourcemap_source_expiry",
                     "ck_native_sourcemap_source_identity",
                     "ck_native_sourcemap_source_hashes"):
            assert name in names
        grant_check = psql(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid='native_mcp_execution_grants'::regclass "
            "AND conname='ck_native_mcp_grant_inert_tool';")[0]
        assert "authority_status" in grant_check
        assert "inspect_local_original_sourcemap" not in grant_check
        psql(p["fixture_sql"])
        assert psql("SELECT count(*) FROM native_sourcemap_source_preflights;")[0]=="0"
        assert psql(p["join"])[0] == ""
        # Client A commits, deliberately discards returned ACK; independent
        # Client B observes the durable commit and cannot reissue an Action.
        psql(p["insert"])
        assert psql(p["insert_conflict"])[0] == ""
        assert psql("SELECT count(*) FROM native_sourcemap_source_preflights;")[0]=="1"
        original_join, _ = psql(p["join"])
        assert original_join, "Current original-STATUS row join did not match"
        record = json.loads(original_join)
        assert record["action_status"] == "unknown"
        assert record["action_receipt"] is None and record["action_cancelled"] is False
        # 0035 immutable row, FK and unique constraints are live PG enforcement.
        _, dupe_err = psql(p["insert"], success=False)
        assert "duplicate key value" in dupe_err
        _, immutable_update = psql(
            "UPDATE native_sourcemap_source_preflights SET kid=kid;", success=False)
        assert "immutable" in immutable_update
        _, immutable_delete = psql(
            "DELETE FROM native_sourcemap_source_preflights;", success=False)
        assert "immutable" in immutable_delete
        _, immutable_original = psql(
            "UPDATE flow_artifacts SET sha256=sha256;", success=False)
        assert "immutable" in immutable_original
        _, immutable_review = psql(
            "UPDATE flow_artifact_reviews SET decision=decision;", success=False)
        assert "immutable" in immutable_review
        # Both status readers may inspect the ORIGINAL immutable source once
        # while independent current authority remains live.
        second_join, _ = psql(p["join"])
        assert second_join == original_join
        # Real PG revocations/cancellations, not fake database objects.
        psql(p["revoke_senior"])
        assert psql(p["join"])[0] == ""
        psql(p["restore_senior"])
        psql(p["revoke_lease"])
        assert psql(p["join"])[0] == ""
        psql(p["restore_lease"])
        psql(p["revoke_roe"])
        assert psql(p["join"])[0] == ""
        psql(p["restore_roe"])
        psql(p["mutate_task_pin"])
        assert psql(p["join"])[0] == ""
        psql(p["restore_task_pin"])
        assert psql(p["wrong_sha_join"])[0] == ""
        assert psql(p["join"])[0] == original_join
        assert psql("SELECT status FROM flow_mcp_action_dispatches;")[0] == "unknown"
        assert psql("SELECT count(*) FROM native_mcp_execution_grants;")[0] == "0"
        print("RESULT_JSON:" + json.dumps({
            "pg_version": psql("SHOW server_version;")[0],
            "listen_addresses": psql("SHOW listen_addresses;")[0],
            "client_pids_distinct": pid_a != pid_b,
            "source_preflights": 1, "grant_rows": 0,
            "original_status": "unknown",
            "row": record,
            "steps": ["actual_offline_alembic_ddl","one_use_ack_loss",
                      "two_independent_socket_clients","current_join_read_twice",
                      "senior_revocation","lease_revocation","roe_revocation",
                      "manifest_pin_mutation","wrong_artifact_sha",
                      "immutable_source_artifact_review","source_grant_absent"]
        }, separators=(",", ":")))
    finally:
        if started:
            stopped = run([str(bin_dir/"pg_ctl"), "-D", str(data), "-w",
                           "-m", "fast", "stop"])
            assert stopped.returncode == 0, stopped.stderr[-700:]
"""


def _wsl_or_posix_run(payload: dict[str, str]) -> dict[str, Any]:
    script = (
        "import base64,json\nPAYLOAD=json.loads(base64.b64decode("
        + repr(base64.b64encode(json.dumps(payload).encode()).decode()) + "))\n"
        + _LINUX_WORKER
    )
    if os.name == "nt":
        args = ["wsl.exe", "-d", "Ubuntu", "--", "python3", "-"]
    elif sys.platform == "linux":
        args = [sys.executable, "-"]
    else:
        pytest.skip("Requires Linux or WSL Ubuntu, local PostgreSQL16")
    try:
        run = subprocess.run(
            args, input=script, text=True, capture_output=True, timeout=160
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.fail("Owned Unix-socket PG16 run unavailable: " + str(exc))
    assert run.returncode == 0, "Real PG16 fixture failed: " + run.stderr[-2200:]
    lines = [line[12:] for line in run.stdout.splitlines() if line.startswith("RESULT_JSON:")]
    assert len(lines) == 1, run.stdout[-700:]
    return json.loads(lines[0])


def test_offline_real_migration_ddl_and_contract() -> None:
    ddl = _migration_ddl()
    assert "CREATE TABLE native_sourcemap_source_preflights" in ddl
    assert "CREATE TABLE flow_mcp_action_dispatches" in ddl
    assert "CREATE TABLE native_mcp_execution_grants" in ddl
    assert "native_mcp_worker_supervisions" in ddl
    assert "CREATE TABLE flow_artifacts" in ddl
    assert "CREATE TABLE flow_artifact_reviews" in ddl
    assert "UNIQUE (request_id)" in ddl
    assert "UNIQUE (action_id)" in ddl
    assert "trg_native_sourcemap_source_immutable" in ddl


def test_real_0035_signed_source_current_status_join_unix_socket() -> None:
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Set {OPT_IN}=1 to initialize owned Unix-socket-only PG16")
    c = _fixture()
    payload = {
        "predecessors": _minimum_predecessors(),
        "migration_sql": _migration_ddl(),
        "fixture_sql": _insert_fixture(c),
        "insert": _source_insert(c),
        "insert_conflict": _source_insert(c, on_conflict=True),
        "join": _join(c),
        "wrong_sha_join": _join(c, sha="f"*64),
        "revoke_senior": "UPDATE operator_subject_controls SET disabled=true "
                         "WHERE actor_id=" + _quote(REVIEWER) + ";",
        "restore_senior": "UPDATE operator_subject_controls SET disabled=false "
                          "WHERE actor_id=" + _quote(REVIEWER) + ";",
        "revoke_lease": "UPDATE supervision_execution_leases SET state='cancelled';",
        "restore_lease": "UPDATE supervision_execution_leases SET state='dispatched';",
        "revoke_roe": "UPDATE session_states SET roe="
                      "'{\"allow_read_only\":false,\"allow_source_map_inspection\":true}'::jsonb;",
        "restore_roe": "UPDATE session_states SET roe="
                       "'{\"allow_read_only\":true,\"allow_source_map_inspection\":true}'::jsonb;",
        "mutate_task_pin": "UPDATE tasks SET payload=jsonb_set(payload,"
                           "'{resource_manifest_sha256}',to_jsonb(" + _quote("e"*64)
                           + "::text));",
        "restore_task_pin": "UPDATE tasks SET payload=jsonb_set(payload,"
                            "'{resource_manifest_sha256}',to_jsonb("
                            + _quote(c["claims"]["manifest_sha256"]) + "::text));",
    }
    observed = _wsl_or_posix_run(payload)
    assert observed["listen_addresses"] == ""
    assert observed["client_pids_distinct"] is True
    assert observed["source_preflights"] == 1
    assert observed["grant_rows"] == 0
    assert observed["original_status"] == "unknown"
    stored = observed["row"]
    row = c["intent"]
    expected_original = {
            "request_id": c["request"], "engagement_id": c["eng"],
            "flow_id": c["flow"], "task_id": c["task"],
            "subtask_id": c["subtask"], "action_id": c["action"],
            "owner_id": OWNER, "server_id": row["server_id"],
            "tool_name": row["tool_name"], "approval_id": row["approval_id"],
            "lease_id": row["lease_id"], "authorization_version": 1,
            "authorization_sha256": row["authorization_sha256"],
    }
    assert stored["signature_sha256"] == hashlib.sha256(
        base64.urlsafe_b64decode(c["signature"] + "==")
    ).hexdigest()
    c["issuer_signer"].public_key().verify(
        base64.urlsafe_b64decode(c["signature"] + "=="),
        DOMAIN + canonical(c["claims"]),
    )
    current_issuer = SourceMapStatusAuthorityStore._verify_issued(
        stored,
        expected_original,
        c["claims"]["manifest_sha256"],
        SHA,
        current_kid=KID,
        now=int(time.time()),
    )
    assert set(current_issuer) == CLAIM_FIELDS
    assert current_issuer == c["claims"]
    for tampered in (
        {**stored, "claims_sha256": "0" * 64},
        {**stored, "kid": "different-issuer-kid"},
        {**stored, "manifest_sha256": "f" * 64},
    ):
        with pytest.raises(SourceMapSourceDenied):
            SourceMapStatusAuthorityStore._verify_issued(
                tampered,
                expected_original,
                c["claims"]["manifest_sha256"],
                SHA,
                current_kid=KID,
                now=int(time.time()),
            )
    # Current production STATUS claim shape/domain, tested cryptographically,
    # not mistaken for production SourceMapStatusAuthorityStore.admit execution.
    source_key = c["issuer_signer"]  # Production STATUS uses the source issuer key.
    current_status = {
        **current_issuer, "status_id": "nss-" + secrets.token_hex(16),
    }
    current_status["issued_at"] = int(time.time())
    current_status["expires_at"] = current_status["issued_at"] + 5
    assert set(current_status) == STATUS_FIELDS
    signature = source_key.sign(STATUS_DOMAIN + canonical(current_status))
    source_key.public_key().verify(signature, STATUS_DOMAIN + canonical(current_status))
    assert current_status["expires_at"] - current_status["issued_at"] == 5
