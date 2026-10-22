"""Adversarial SOURCE_MAP current-DB witness checks over *fake* PostgreSQL.

These tests exercise signed proof matching and the read-only, current 0033
revision/event join without a DB, Docker, target or issuer private key. The
real PostgreSQL 0033 presently authorizes only ``authority_status`` grants,
so the successful fake-row case is a contract probe, NOT a live integration
or production SourceMap certification.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import stat
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.memory import sourcemap_supervisor_current_db_witness as db_mod
from ai_osop.memory.sourcemap_status_authority import SourceMapStatusAuthorityStore
from ai_osop.orchestrator import sourcemap_supervisor_source_issuer as issuer


ENG = "eng-sourcemap-db"
FLOW = "flow-sourcemap-db"
TASK = "task-sourcemap-db"
REQUEST = "req-" + "a" * 48
ACTION = "action-" + "b" * 32
GRANT = "ngr-" + "c" * 32
CONTAINER = "d" * 64
SHA = "e" * 64
AUTH = "f" * 64


def _signed(
    key: Ed25519PrivateKey, claims: dict[str, Any], domain: bytes, kid: str
) -> dict[str, Any]:
    return {
        "claims": copy.deepcopy(claims),
        "kid": kid,
        "signature": base64.urlsafe_b64encode(key.sign(domain + db_mod._canonical(claims)))
        .decode("ascii")
        .rstrip("="),
    }


class _Result:
    def __init__(self, value: Any) -> None:
        self.value = value

    def mappings(self) -> "_Result":
        return self

    def one_or_none(self) -> Any:
        return self.value

    def all(self) -> list[Any]:
        return self.value


class _Session:
    def __init__(self, source: "_FakePG") -> None:
        self.source = source

    async def __aenter__(self) -> "_Session":
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    def begin(self) -> "_Session":
        return self

    async def execute(self, statement: Any, params: dict[str, Any]) -> _Result:
        sql = str(statement)
        self.source.sql.append(sql)
        self.source.params.append(params)
        assert sql.startswith("SELECT "), "No writes, reissue or replay allowed"
        if "native_sourcemap_source_preflights" in sql:
            return _Result(self.source.preflight)
        if "native_mcp_execution_grants" in sql:
            return _Result(self.source.grant)
        if "native_mcp_resource_offers" in sql:
            return _Result(self.source.offer)
        if "native_mcp_worker_supervisions" in sql:
            return _Result(self.source.supervision)
        if "native_mcp_worker_supervision_events" in sql:
            return _Result(self.source.events)
        raise AssertionError("Unexpected SQL read: " + sql)


class _FakePG:
    def __init__(
        self, preflight: dict[str, Any], supervision: dict[str, Any], event: dict[str, Any]
    ):
        self.preflight = preflight
        self.supervision = supervision
        self.events = [event]
        self.sql: list[str] = []
        self.params: list[dict[str, Any]] = []

    def session(self) -> _Session:
        return _Session(self)


class _OriginalSource:
    def __init__(self, row: dict[str, Any], manifest: str, now: int):
        self.row = row
        self.manifest = manifest
        self.now = now
        self.called: list[dict[str, Any]] = []
        self.denied = False

    async def _source(self, _: _Session, request: dict[str, str]) -> tuple[dict[str, Any], str]:
        self.called.append(request)
        if self.denied:
            raise ValueError("Current signed ROE, reviewer or lease revoked")
        assert set(request) == {
            "request_id",
            "engagement_id",
            "task_id",
            "server_id",
            "tool_name",
            "artifact_sha256",
        }
        return self.row, self.manifest

    async def _now(self, _: _Session) -> int:
        return self.now


@pytest.fixture
def source() -> dict[str, Any]:
    now = int(time.time())
    ledger_signer, status_signer, current_signer = (Ed25519PrivateKey.generate() for _ in range(3))
    ledger = {
        "version": 1,
        "grant_id": GRANT,
        "request_id": REQUEST,
        "server_id": "source-map-mcp",
        "worker_id": "worker-sourcemap",
        "container_id": CONTAINER,
        "epoch": 31,
        "expected_revision": 4,
        "state": "running",
        "observed_at": now,
        "evidence_sha256": SHA,
        "resource_sha256": SHA,
        "folder_staging_sha256": "9" * 64,
        "readback_sha256": None,
    }
    status = {
        "version": 1,
        "preflight_id": "nsp-" + "2" * 32,
        "status_id": "nss-" + "3" * 32,
        "request_id": REQUEST,
        "engagement_id": ENG,
        "flow_id": FLOW,
        "task_id": TASK,
        "subtask_id": "subtask-sourcemap-db",
        "action_id": ACTION,
        "owner_id": "owner-sourcemap",
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": SHA,
        "manifest_sha256": SHA,
        "approval_id": "apr-sourcemap",
        "lease_id": "lease-sourcemap",
        "authorization_version": 4,
        "authorization_sha256": AUTH,
        "issued_at": now,
        "expires_at": now + 5,
    }
    original = {key: value for key, value in status.items() if key != "status_id"}
    original["issued_at"] = now - 1
    original["expires_at"] = now + 9
    preflight = {
        **original,
        "kid": "status-enrolled",
        "claims_sha256": hashlib.sha256(db_mod._canonical(original)).hexdigest(),
        "signature_sha256": SHA,
        "committed_at": object(),
    }
    original_row = {
        **{k: v for k, v in status.items() if k != "status_id"},
        "status": "unknown",
        "cancel_requested": False,
        "receipt_sha256": None,
        "flow_revision": 0,
        "authorization_id": "auth-sourcemap",
        "lease_owner_id": "worker-sourcemap",
    }
    supervision = {
        **{
            key: original_row[key]
            for key in (
                "request_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "server_id",
                "authorization_version",
                "authorization_sha256",
            )
        },
        "grant_id": GRANT,
        "resource_sha256": SHA,
        "worker_id": ledger["worker_id"],
        "container_id": CONTAINER,
        "epoch": ledger["epoch"],
        "revision": 5,
        "state": "running",
        "supervisor_kid": "ledger-enrolled",
        "supervisor_id": "independent-container-observer",
        "folder_staging_sha256": "9" * 64,
    }
    signed_ledger = _signed(ledger_signer, ledger, issuer.LEDGER_DOMAIN, "ledger-enrolled")
    signed_status = _signed(status_signer, status, issuer.SOURCE_STATUS_DOMAIN, "status-enrolled")
    event = {
        "grant_id": GRANT,
        "epoch": ledger["epoch"],
        "revision": 5,
        "state": "running",
        "kid": "ledger-enrolled",
        "supervisor_id": supervision["supervisor_id"],
        "observed_at": now,
        "evidence_sha256": SHA,
        "claims_sha256": hashlib.sha256(db_mod._canonical(ledger)).hexdigest(),
        "signature_sha256": hashlib.sha256(
            base64.urlsafe_b64decode(signed_ledger["signature"] + "==")
        ).hexdigest(),
    }
    pg = _FakePG(preflight, supervision, event)
    pg.grant = {
        **{
            key: original_row[key]
            for key in (
                "request_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "server_id",
                "approval_id",
                "lease_id",
                "lease_owner_id",
                "flow_revision",
                "authorization_id",
                "authorization_version",
                "authorization_sha256",
            )
        },
        "grant_id": GRANT,
        "tool_name": "inspect_local_original_sourcemap",
        "status": "redeemed",
        "resource_sha256": SHA,
        "expires_at": now + 7,
    }
    pg.offer = {
        **{
            key: pg.grant[key]
            for key in (
                "grant_id",
                "engagement_id",
                "flow_id",
                "action_id",
                "request_id",
                "server_id",
            )
        },
        "manifest_sha256": SHA,
        "folder_staging_sha256": "9" * 64,
        "status": "offered",
    }
    original_store = _OriginalSource(original_row, SHA, now)
    source_status = SimpleNamespace(
        sources=original_store, _verify_issued=SourceMapStatusAuthorityStore._verify_issued
    )
    witness = object.__new__(db_mod.SourceMapSupervisorCurrentDBWitness)
    witness._actions = SimpleNamespace(_sessions=lambda: pg.session)
    witness._status = source_status
    witness._private = current_signer
    witness._kid = "db-enrolled"
    witness._ledger_roots = {"ledger-enrolled": ledger_signer.public_key().public_bytes_raw()}
    witness._status_roots = {"status-enrolled": status_signer.public_key().public_bytes_raw()}
    witness._db_roots = {"db-enrolled": current_signer.public_key().public_bytes_raw()}

    async def approved_stage(_: Any, row: dict[str, Any]) -> str:
        assert row == pg.grant
        pg.stage_checks += 1
        return "9" * 64

    pg.stage_checks = 0
    witness._folder_plan = approved_stage
    return {
        "witness": witness,
        "pg": pg,
        "original": original_store,
        "ledger": signed_ledger,
        "status": signed_status,
        "ledger_signer": ledger_signer,
        "status_signer": status_signer,
        "current_signer": current_signer,
        "now": now,
    }


@pytest.mark.asyncio
async def test_fake_postgres_current_signed_sources_yield_exact_worker34_db_envelope(
    source: dict[str, Any],
) -> None:
    witness = source["witness"]
    result = await witness.issue(
        supervisor_observation=source["ledger"], source_status=source["status"]
    )
    verified, digest = issuer._verified(
        result, witness._db_roots, issuer.CURRENT_DB_DOMAIN, issuer._DB_FIELDS
    )
    assert len(digest) == 64
    assert set(verified) == issuer._DB_FIELDS
    assert verified["revision"] == 5
    assert verified["epoch"] == 31
    assert (
        verified["status_proof_sha256"]
        == issuer._verified(
            source["status"],
            witness._status_roots,
            issuer.SOURCE_STATUS_DOMAIN,
            issuer._STATUS_FIELDS,
        )[1]
    )
    assert verified["signed_roe_sha256"] == AUTH
    assert all(
        verified[k] is True
        for k in (
            "source_current",
            "lease_active",
            "approval_current",
            "reviewer_current",
            "roe_current",
        )
    )
    assert all(sql.startswith("SELECT ") and "FOR SHARE" in sql for sql in source["pg"].sql)
    assert len(source["pg"].sql) == 5
    assert source["pg"].params[-1]["revision"] == 5
    assert len(source["original"].called) == 1
    assert source["pg"].stage_checks == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "stale_epoch",
        "row_revision",
        "foreign_action",
        "foreign_owner",
        "foreign_worker",
        "stale_event",
        "event_claim_digest",
        "event_signature_digest",
        "missing_event",
        "missing_supervisor",
        "no_preflight",
        "revoked_reviewer",
        "changed_artifact",
        "grant_inert_tool",
        "grant_expired",
        "missing_offer",
        "wrong_folder",
    ],
)
async def test_fake_postgres_denies_mutated_currentness_and_identity(
    source: dict[str, Any], mutation: str
) -> None:
    pg = source["pg"]
    ledger = source["ledger"]
    status = source["status"]
    if mutation == "stale_epoch":
        pg.supervision["epoch"] += 1
    elif mutation == "row_revision":
        pg.supervision["revision"] += 1
    elif mutation == "foreign_action":
        pg.supervision["action_id"] = "action-" + "8" * 32
    elif mutation == "foreign_owner":
        pg.supervision["owner_id"] = "another-owner"
    elif mutation == "foreign_worker":
        pg.supervision["worker_id"] = "foreign-worker"
    elif mutation == "stale_event":
        pg.events[0]["revision"] -= 1
    elif mutation == "event_claim_digest":
        pg.events[0]["claims_sha256"] = "0" * 64
    elif mutation == "event_signature_digest":
        pg.events[0]["signature_sha256"] = "1" * 64
    elif mutation == "missing_event":
        pg.events = []
    elif mutation == "missing_supervisor":
        pg.supervision = None
    elif mutation == "no_preflight":
        pg.preflight = None
    elif mutation == "revoked_reviewer":
        source["original"].denied = True
    elif mutation == "changed_artifact":
        source["original"].manifest = "0" * 64
    elif mutation == "grant_inert_tool":
        pg.grant["tool_name"] = "authority_status"
    elif mutation == "grant_expired":
        pg.grant["expires_at"] = source["now"] - 1
    elif mutation == "missing_offer":
        pg.offer = None
    elif mutation == "wrong_folder":
        pg.offer["folder_staging_sha256"] = "0" * 64
    with pytest.raises(db_mod.SourceMapCurrentDBDenied):
        await source["witness"].issue(supervisor_observation=ledger, source_status=status)
    assert all(sql.startswith("SELECT ") for sql in pg.sql)


@pytest.mark.asyncio
async def test_signed_wrong_identity_and_wrong_domain_rejected_without_db(
    source: dict[str, Any]
) -> None:
    bad = copy.deepcopy(source["status"])
    bad["claims"]["request_id"] = "req-" + "7" * 48
    for proof, second in (
        (source["ledger"], bad),
        (source["status"], source["ledger"]),
        ({"claims": {}}, source["status"]),
    ):
        with pytest.raises(db_mod.SourceMapCurrentDBDenied):
            await source["witness"].issue(supervisor_observation=proof, source_status=second)
    assert source["pg"].sql == []


def test_host_private_signer_denies_unprotected_os_and_missing_enrollment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = Ed25519PrivateKey.generate()
    roots = {"host-db-key": signer.public_key().public_bytes_raw()}
    monkeypatch.setenv("OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_SIGNING_KID", "host-db-key")
    monkeypatch.delenv("OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_SIGNING_KEY_FILE", raising=False)
    with pytest.raises(db_mod.SourceMapCurrentDBDenied):
        db_mod._key_from_host_file(roots, ())
    if db_mod.sys.platform != "linux":
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_SIGNING_KEY_FILE", "/tmp/fake-host-signing.key"
        )
        with pytest.raises(db_mod.SourceMapCurrentDBDenied, match="Linux host-only"):
            db_mod._key_from_host_file(roots, ())


def test_live_0033_schema_is_signed_event_hash_only_and_original_go_only() -> None:
    root = Path(__file__).resolve().parents[1]
    migration = (root / "migrations/versions/0033_native_worker_supervision.py").read_text()
    observer = (root / "src/ai_osop/memory/native_mcp_worker_supervision.py").read_text()
    original_go = (root / "src/ai_osop/memory/native_mcp_execution_grants.py").read_text()
    grant_schema = (root / "migrations/versions/0029_native_mcp_execution_grants.py").read_text()
    pinned_stage = (root / "migrations/versions/0031_pinned_native_folder_stage.py").read_text()
    assert "claims_sha256" in migration and "signature_sha256" in migration
    assert 'sa.Column("signature"' not in migration
    assert 'sa.Column("claims"' not in migration
    assert "revision=revision+1,state=:state" in observer
    assert 'row["revision"] + 1' in observer
    assert 'row.get("tool_name") != "authority_status"' in original_go
    assert '"inspect_local_original_sourcemap"' not in original_go
    assert "tool_name='authority_status'" in grant_schema
    assert "folder_staging_sha256" in pinned_stage


def test_exact_contract_and_no_issuance_or_sql_write_in_source() -> None:
    assert db_mod.CURRENT_DB_DOMAIN == issuer.CURRENT_DB_DOMAIN
    assert db_mod._DB_FIELDS is issuer._DB_FIELDS
    code = Path(db_mod.__file__).read_text(encoding="utf-8")
    assert "INSERT INTO" not in code and "UPDATE native_mcp_" not in code
    assert "DELETE FROM" not in code
    assert "await self._status.sources._source(db, request)" in code
