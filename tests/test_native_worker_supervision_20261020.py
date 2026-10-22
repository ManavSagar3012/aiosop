"""Native 0033 independent supervisor attestation and lifecycle adversarial tests."""

from __future__ import annotations

import base64
import hashlib
import json
from contextlib import asynccontextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore, MCPActionDenied
from ai_osop.memory.native_mcp_worker_supervision import (
    DOMAIN,
    NativeMCPWorkerSupervisionStore,
    _canonical,
    _verify_observation,
)
from ai_osop.memory import native_mcp_worker_supervision as module

NOW = 1770000000
ENG = "eng-isolated"
FLOW = "flow-isolated"
GRANT = "ngr-" + "1" * 32
ACTION = "action-" + "2" * 32
REQUEST = "req-" + "3" * 48
SERVER = "recon-mcp"
WORKER = "worker-isolated"
CONTAINER = "c" * 64
SECRET = "independent-disposable-supervisor-secret"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class QueryResult:
    def __init__(self, value=None, *, rows=None):
        self.value = value
        self.rows = rows

    def mappings(self):
        return self

    def scalar_one(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value

    def one_or_none(self):
        return self.value

    def all(self):
        return self.rows


class FakePG:
    """Only model 0033's committed CAS SQL, not an application DB or target."""

    def __init__(self):
        self.epoch = 800
        self.worker = None
        self.events = []
        self.offer = None
        self.receipt = None
        self.recovery = []
        self.grant_source = None
        self.grant_events = []

    @asynccontextmanager
    async def begin(self):
        saved = (
            deepcopy(self.worker),
            deepcopy(self.events),
            self.epoch,
            deepcopy(self.recovery),
            deepcopy(self.grant_source),
            deepcopy(self.grant_events),
        )
        try:
            yield self
        except Exception:
            self.worker, self.events, self.epoch, self.recovery = saved[:4]
            if self.grant_source is not None and saved[4] is not None:
                self.grant_source.clear()
                self.grant_source.update(saved[4])
            self.grant_events = saved[5]
            raise

    async def execute(self, sql, params=None):
        source = str(sql)
        if "nextval('native_mcp_worker_epoch_seq')" in source:
            self.epoch += 1
            return QueryResult(self.epoch)
        if source.startswith("INSERT INTO native_mcp_worker_supervisions"):
            if self.worker is not None:
                return QueryResult(None)
            self.worker = dict(params)
            return QueryResult(params["grant_id"])
        if source.startswith("UPDATE native_mcp_worker_supervisions"):
            row = self.worker
            if row is None or any(
                row[k] != params[v]
                for k, v in (
                    ("grant_id", "grant"),
                    ("epoch", "epoch"),
                    ("revision", "prior"),
                    ("state", "old"),
                    ("supervisor_id", "supervisor"),
                    ("supervisor_kid", "kid"),
                )
            ):
                return QueryResult(None)
            row.update(
                revision=row["revision"] + 1,
                state=params["state"],
                container_id=params["container"],
                folder_staging_sha256=params["folder"],
            )
            return QueryResult(row["revision"])
        if source.startswith("INSERT INTO native_mcp_worker_supervision_events"):
            assert all(event["revision"] != params["revision"] for event in self.events)
            self.events.append(dict(params))
            return QueryResult()
        if source.startswith("INSERT INTO native_mcp_worker_recovery_intents"):
            if any(
                item["grant"] == params["grant"] and item["revision"] == params["revision"]
                for item in self.recovery
            ):
                return QueryResult(None)
            self.recovery.append(dict(params))
            return QueryResult(params["id"])
        if source.startswith("UPDATE native_mcp_execution_grants SET status='unknown'"):
            grant = self.grant_source
            if (
                grant is None
                or grant["status"] != "issued"
                or grant["revision"] != params["prior"]
                or any(
                    grant[k] != params[p]
                    for k, p in (
                        ("grant_id", "grant"),
                        ("engagement_id", "eng"),
                        ("request_id", "request"),
                        ("action_id", "action"),
                    )
                )
            ):
                return QueryResult(None)
            grant.update(status="unknown", revision=grant["revision"] + 1)
            return QueryResult(grant["revision"])
        if source.startswith("INSERT INTO native_mcp_execution_grant_events"):
            self.grant_events.append(dict(params))
            return QueryResult()
        if source.startswith("SELECT * FROM native_mcp_worker_supervisions"):
            return QueryResult(deepcopy(self.worker))
        if source.startswith("SELECT * FROM native_mcp_resource_offers"):
            return QueryResult(deepcopy(self.offer))
        if source.startswith("SELECT * FROM native_mcp_stage_receipts"):
            return QueryResult(deepcopy(self.receipt))
        if source.startswith("SELECT w.state,w.revision,EXISTS("):
            return QueryResult(
                rows=(
                    [
                        {
                            "state": self.worker["state"],
                            "revision": self.worker["revision"],
                            "recovery_intent_pending": any(
                                item["revision"] == self.worker["revision"]
                                for item in self.recovery
                            ),
                        }
                    ]
                    if self.worker
                    else []
                )
            )
        raise AssertionError("unexpected SQL: " + source)


@pytest.fixture
def supervisor(monkeypatch):
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    trust = {
        "external-supervisor": {
            "kid": "supervisorKey",
            "public_key": _b64(raw),
            "secret_sha256": hashlib.sha256(SECRET.encode()).hexdigest(),
        }
    }
    monkeypatch.setenv("OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON", json.dumps(trust))
    monkeypatch.delenv("OSOP_NATIVE_STAGE_RECEIPT_TRUST_JSON", raising=False)
    return SimpleNamespace(key=key, trust=trust)


def _signed(
    signer,
    state,
    *,
    epoch=0,
    prior=0,
    container=None,
    resource=None,
    folder=None,
    readback=None,
    observed_at=NOW,
):
    # Resource-bound 0033 provisioning now persists the *independently signed*
    # original container identity before redemption. Legacy no-resource
    # inert tests still exercise the historical nullable provision contract.
    if state == "provisioned" and resource is not None and container is None:
        container = CONTAINER
    claims = {
        "version": 1,
        "grant_id": GRANT,
        "request_id": REQUEST,
        "server_id": SERVER,
        "worker_id": WORKER,
        "container_id": container,
        "epoch": epoch,
        "expected_revision": prior,
        "state": state,
        "observed_at": observed_at,
        "evidence_sha256": "e" * 64,
        "resource_sha256": resource,
        "folder_staging_sha256": folder,
        "readback_sha256": readback,
    }
    return {
        "claims": claims,
        "kid": "supervisorKey",
        "signature": _b64(signer.key.sign(DOMAIN + _canonical(claims))),
    }


@pytest.fixture
def context(monkeypatch, supervisor):
    db = FakePG()
    actions = object.__new__(FlowMCPActionStore)
    actions._sessions = lambda: lambda: _context(db)
    actions._authority = AsyncMock(return_value={"scope": {}})
    store = NativeMCPWorkerSupervisionStore(actions)
    row = {
        "grant_id": GRANT,
        "request_id": REQUEST,
        "engagement_id": ENG,
        "flow_id": FLOW,
        "task_id": "task-1",
        "subtask_id": "subtask-1",
        "action_id": ACTION,
        "owner_id": "operator-1",
        "server_id": SERVER,
        "approval_id": "apr-1",
        "lease_id": "lease-1",
        "lease_owner_id": "operator-1",
        "flow_revision": 1,
        "authorization_id": "authorization-1",
        "authorization_version": 1,
        "authorization_sha256": "a" * 64,
        "resource_sha256": None,
        "manifest_sha256": "b" * 64,
        "status": "issued",
        "revision": 1,
        "kid": "grantKid",
        "claims_sha256": "7" * 64,
        "signature_sha256": "8" * 64,
        "issued_at": NOW - 10,
        "expires_at": NOW + 50,
        "tool_name": "authority_status",
        "side_effect_class": "READ_ONLY",
        "intent_sha256": "9" * 64,
        "parameters_sha256": "d" * 64,
    }
    original = dict(row, declaration_sha256=row["manifest_sha256"], status="unknown")
    db.grant_source = row
    token_claims = {
        key: row[key]
        for key in module.NativeMCPExecutionGrantStore._signed.__globals__["_CLAIMS"]
        if key in row
    }
    token_claims.update(version=1, issued_at=NOW - 10, expires_at=NOW + 50)
    # Actual Ed25519 supervisor proof is tested; existing tests separately
    # qualify the original issuer's signed 0029 token verification.
    monkeypatch.setattr(
        module, "_verify", lambda token: (token_claims, "grantKid", "7" * 64, "8" * 64)
    )
    store.grants._grant = AsyncMock(side_effect=lambda db, grant_id, lock: deepcopy(row))
    store.grants._source = AsyncMock(return_value=original)
    actions._row = AsyncMock(return_value=original)
    store.grants._now = AsyncMock(return_value=NOW)
    store.grants._resources = AsyncMock()
    store._current_folder = AsyncMock(return_value=None)
    return SimpleNamespace(
        store=store,
        db=db,
        row=row,
        signer=supervisor,
        token={"claims": token_claims},
        actions=actions,
    )


@asynccontextmanager
async def _context(db):
    yield db


async def _record(c, obs):
    return await c.store.record(
        c.token, obs, supervisor_id="external-supervisor", supervisor_secret=SECRET
    )


@pytest.mark.asyncio
async def test_provision_before_redeem_global_epoch_cas_and_cleanup(context):
    c = context
    first = await _record(c, _signed(c.signer, "provisioned"))
    assert first["epoch"] == 801 and first["state"] == "provisioned"
    assert len(c.db.events) == 1
    with pytest.raises(MCPActionDenied):
        await _record(c, _signed(c.signer, "provisioned"))
    with pytest.raises(MCPActionDenied):
        await _record(c, _signed(c.signer, "running", epoch=801, prior=1, container=CONTAINER))
    c.row["status"] = "redeemed"
    running = _signed(c.signer, "running", epoch=801, prior=1, container=CONTAINER)
    assert (await _record(c, running))["revision"] == 2
    with pytest.raises(MCPActionDenied):
        await _record(c, running)
    with pytest.raises(MCPActionDenied):
        await _record(c, _signed(c.signer, "terminating", epoch=802, prior=2, container=CONTAINER))
    assert (
        await _record(c, _signed(c.signer, "terminating", epoch=801, prior=2, container=CONTAINER))
    )["state"] == "terminating"
    assert (
        await _record(c, _signed(c.signer, "terminated", epoch=801, prior=3, container=CONTAINER))
    )["state"] == "terminated"
    assert (await _record(c, _signed(c.signer, "reaped", epoch=801, prior=4, container=CONTAINER)))[
        "state"
    ] == "reaped"
    assert [e["revision"] for e in c.db.events] == [1, 2, 3, 4, 5]
    with pytest.raises(MCPActionDenied):
        await _record(c, _signed(c.signer, "running", epoch=801, prior=5, container=CONTAINER))
    assert len(c.db.events) == 5


@pytest.mark.asyncio
async def test_resource_bound_provision_cannot_omit_daemon_observed_container(context):
    c = context
    c.row["resource_sha256"] = "a" * 64
    c.token["claims"]["resource_sha256"] = "a" * 64
    c.store.grants._source.return_value["resource_sha256"] = "a" * 64
    unsigned = _signed(c.signer, "provisioned", resource="a" * 64)
    unsigned["claims"]["container_id"] = None
    unsigned["signature"] = _b64(c.signer.key.sign(DOMAIN + _canonical(unsigned["claims"])))
    with pytest.raises(MCPActionDenied):
        await _record(c, unsigned)
    assert c.db.worker is None
    assert c.db.events == []
    approved = _signed(c.signer, "provisioned", resource="a" * 64)
    answer = await _record(c, approved)
    assert answer["state"] == "provisioned"
    assert c.db.worker["container_id"] == CONTAINER


@pytest.mark.asyncio
async def test_revoked_expired_grant_allows_only_supervised_cleanup(context):
    c = context
    first = await _record(c, _signed(c.signer, "provisioned"))
    c.row["status"] = "revoked"
    c.store.grants._now = AsyncMock(return_value=NOW + 100)
    c.store.grants._source = AsyncMock(side_effect=MCPActionDenied(409, "revoked"))
    signed = _signed(c.signer, "unknown", epoch=first["epoch"], prior=1, observed_at=NOW + 100)
    assert (await _record(c, signed))["state"] == "unknown"
    assert (
        await _record(
            c, _signed(c.signer, "reaped", epoch=first["epoch"], prior=2, observed_at=NOW + 100)
        )
    )["state"] == "reaped"
    with pytest.raises(MCPActionDenied):
        await _record(
            c,
            _signed(
                c.signer,
                "running",
                epoch=first["epoch"],
                prior=3,
                container=CONTAINER,
                observed_at=NOW + 100,
            ),
        )
    assert c.store.grants._source.await_count == 1
    assert c.actions._row.await_count == 2


@pytest.mark.asyncio
async def test_signed_supervisor_crash_closes_unredeemed_grant_without_action_replay(context):
    """0033 terminal signed evidence closes only an ISSUED 0029 capability.

    Original source may already be revoked: cleanup/closure must remain
    possible without reauthorizing the original UNKNOWN Action or scanner.
    """
    c = context
    first = await _record(c, _signed(c.signer, "provisioned"))
    assert first["revision"] == 1 and c.row["status"] == "issued"
    c.store.grants._source = AsyncMock(side_effect=MCPActionDenied(409, "revoked"))
    event = _signed(c.signer, "unknown", epoch=first["epoch"], prior=1)
    result = await _record(c, event)
    assert result["state"] == "unknown" and result["original_action_status"] == "unknown"
    assert c.row["status"] == "unknown" and c.row["revision"] == 2
    assert len(c.db.grant_events) == 1
    assert c.db.grant_events[0]["status"] == "unknown"
    assert c.db.grant_events[0]["revision"] == 2
    # Same signed observation can never trigger another closure or replay.
    with pytest.raises(MCPActionDenied):
        await _record(c, event)
    assert len(c.db.grant_events) == 1
    reaped = await _record(c, _signed(c.signer, "reaped", epoch=first["epoch"], prior=2))
    assert reaped["state"] == "reaped"
    assert len(c.db.grant_events) == 1
    assert c.row["status"] == "unknown"
    c.store.grants._source.assert_not_awaited()


@pytest.mark.asyncio
async def test_finished_original_action_cannot_be_misreported_as_unknown(context):
    c = context
    first = await _record(c, _signed(c.signer, "provisioned"))
    c.actions._row = AsyncMock(
        return_value=dict(c.row, status="finished", declaration_sha256=c.row["manifest_sha256"])
    )
    before = list(c.db.events)
    with pytest.raises(MCPActionDenied):
        await _record(c, _signed(c.signer, "unknown", epoch=first["epoch"], prior=1))
    assert c.db.events == before and c.db.worker["state"] == "provisioned"


@pytest.mark.asyncio
async def test_signed_operator_metadata_recovery_intent_dedupes_without_changing_observer(context):
    c = context
    await _record(c, _signed(c.signer, "provisioned"))
    assert (await _record(c, _signed(c.signer, "unknown", epoch=801, prior=1)))["revision"] == 2
    binding = {
        "engagement_id": ENG,
        "flow_id": FLOW,
        "revision": 1,
        "version": 1,
        "authorization_id": "authorization-1",
        "authorization_sha256": "a" * 64,
    }
    kwargs = {
        "binding": binding,
        "actor_id": "operator-1",
        "grant_id": GRANT,
        "expected_revision": 2,
        "explicit_human_confirmation": True,
    }
    with pytest.raises(MCPActionDenied):
        await c.store.request_recovery(**{**kwargs, "explicit_human_confirmation": False})
    with pytest.raises(MCPActionDenied):
        await c.store.request_recovery(**{**kwargs, "expected_revision": 1})
    ack = await c.store.request_recovery(**kwargs)
    assert ack == {
        "grant_id": GRANT,
        "supervisor_revision": 2,
        "recovery_intent_recorded": True,
        "worker_execution_replayed": False,
        "independent_target_effect_verified": False,
    }
    assert c.db.worker["state"] == "unknown" and c.db.worker["revision"] == 2
    assert len(c.db.events) == 2 and len(c.db.recovery) == 1
    with pytest.raises(MCPActionDenied):
        await c.store.request_recovery(**kwargs)
    result = await c.store.list_flow(binding, "operator-1")
    assert result["workers"][0]["recovery_intent_pending"] is True
    assert "worker-isolated" not in str(result)


@pytest.mark.asyncio
async def test_current_approved_folder_changed_denies_active_running(context):
    c = context
    c.row["resource_sha256"] = "a" * 64
    c.token["claims"]["resource_sha256"] = "a" * 64
    await _record(c, _signed(c.signer, "provisioned", resource="a" * 64))
    c.row["status"] = "redeemed"
    c.db.offer = {
        "grant_id": GRANT,
        "status": "offered",
        "engagement_id": ENG,
        "flow_id": FLOW,
        "action_id": ACTION,
        "request_id": REQUEST,
        "server_id": SERVER,
        "manifest_sha256": "a" * 64,
        "folder_staging_sha256": "f" * 64,
    }
    c.store._current_folder.return_value = "d" * 64
    with pytest.raises(MCPActionDenied):
        await _record(
            c,
            _signed(
                c.signer,
                "running",
                epoch=801,
                prior=1,
                container=CONTAINER,
                resource="a" * 64,
                folder="f" * 64,
            ),
        )
    assert c.db.worker["state"] == "provisioned"


@pytest.mark.asyncio
async def test_offer_and_worker_receipt_sha_checked_against_db_not_self_report(context):
    c = context
    c.row["resource_sha256"] = "a" * 64
    c.token["claims"]["resource_sha256"] = "a" * 64
    await _record(c, _signed(c.signer, "provisioned", resource="a" * 64))
    c.row["status"] = "redeemed"
    c.db.offer = {
        "grant_id": GRANT,
        "status": "offered",
        "engagement_id": ENG,
        "flow_id": FLOW,
        "action_id": ACTION,
        "request_id": REQUEST,
        "server_id": SERVER,
        "manifest_sha256": "a" * 64,
        "folder_staging_sha256": "f" * 64,
    }
    c.db.receipt = {
        "grant_id": GRANT,
        "status": "worker_reported",
        "engagement_id": ENG,
        "flow_id": FLOW,
        "action_id": ACTION,
        "request_id": REQUEST,
        "server_id": SERVER,
        "resource_sha256": "a" * 64,
        "folder_staging_sha256": "f" * 64,
        "readback_sha256": "b" * 64,
    }
    c.store._current_folder.return_value = "f" * 64
    with pytest.raises(MCPActionDenied):
        await _record(
            c,
            _signed(
                c.signer,
                "running",
                epoch=801,
                prior=1,
                container=CONTAINER,
                resource="a" * 64,
                folder="f" * 64,
                readback="c" * 64,
            ),
        )
    assert (
        await _record(
            c,
            _signed(
                c.signer,
                "running",
                epoch=801,
                prior=1,
                container=CONTAINER,
                resource="a" * 64,
                folder="f" * 64,
                readback="b" * 64,
            ),
        )
    )["state"] == "running"
    c.db.offer["folder_staging_sha256"] = "d" * 64
    with pytest.raises(MCPActionDenied):
        await _record(
            c,
            _signed(
                c.signer,
                "unknown",
                epoch=801,
                prior=2,
                container=CONTAINER,
                resource="a" * 64,
                folder="d" * 64,
            ),
        )


def test_signed_supervisor_denies_wrong_key_rotated_key_worker_collision_and_forgery(
    monkeypatch, supervisor
):
    good = _signed(supervisor, "provisioned")
    assert _verify_observation(good, "external-supervisor", SECRET)[0]["state"] == "provisioned"
    for changed in ("state", "server_id", "worker_id", "observed_at", "resource_sha256"):
        forged = deepcopy(good)
        forged["claims"][changed] = {
            "state": "running",
            "server_id": "payload-mcp",
            "worker_id": "worker-foreign",
            "observed_at": NOW + 1,
            "resource_sha256": "b" * 64,
        }[changed]
        with pytest.raises(MCPActionDenied):
            _verify_observation(forged, "external-supervisor", SECRET)
    with pytest.raises(MCPActionDenied):
        _verify_observation(good, "external-supervisor", "foreign-supervisor-secret-over-20")
    trust = deepcopy(supervisor.trust)
    trust["external-supervisor"]["kid"] = "rotatedKid"
    monkeypatch.setenv("OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON", json.dumps(trust))
    with pytest.raises(MCPActionDenied):
        _verify_observation(good, "external-supervisor", SECRET)
    monkeypatch.setenv("OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON", json.dumps(supervisor.trust))
    monkeypatch.setenv(
        "OSOP_NATIVE_STAGE_RECEIPT_TRUST_JSON",
        json.dumps(
            {
                SERVER: {
                    "kid": "workerKey",
                    "public_key": supervisor.trust["external-supervisor"]["public_key"],
                }
            }
        ),
    )
    with pytest.raises(MCPActionDenied):
        _verify_observation(good, "external-supervisor", SECRET)


@pytest.mark.asyncio
async def test_safe_flow_readback_has_no_worker_or_secret_identifiers(context):
    c = context
    await _record(c, _signed(c.signer, "provisioned"))
    binding = {
        "engagement_id": ENG,
        "flow_id": FLOW,
        "revision": 1,
        "version": 1,
        "authorization_id": "authorization-1",
        "authorization_sha256": "a" * 64,
    }
    result = await c.store.list_flow(binding, "operator-1")
    assert result["workers"] == [
        {
            "state": "provisioned",
            "revision": 1,
            "supervisor_observed": True,
            "cleanup_attested": False,
            "pending_recovery": False,
            "recovery_intent_pending": False,
        }
    ]
    for secret in (GRANT, ACTION, WORKER, CONTAINER, "external-supervisor", SECRET):
        assert secret not in str(result)
