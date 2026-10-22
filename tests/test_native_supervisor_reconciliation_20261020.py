"""Existing 0029/0033 orchestration: SUSPECT is never proof of destruction.

These tests reuse the real 0033 signed/CAS in-memory PostgreSQL fixture, with
only new select statements modeled here. No app DB, Docker, providers, target
or running worker is used.
"""

from __future__ import annotations

import copy
import base64
import json
from typing import Any
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied
from ai_osop.memory.native_mcp_execution_grants import NativeMCPGrantDenied
from ai_osop.memory.native_mcp_supervisor_reconciliation import (
    NativeMCPSupervisorReconciler,
)
from ai_osop.safety.native_mcp_worker_supervisor import (
    _DOMAIN as CLEAN_DOMAIN,
    _OWNERSHIP_DOMAIN,
    _sign,
)
from tests.test_native_worker_supervision_20261020 import (
    ACTION,
    CONTAINER,
    ENG,
    FLOW,
    GRANT,
    NOW,
    REQUEST,
    SECRET,
    SERVER,
    WORKER,
    QueryResult,
    _record,
    _signed,
    context,
    supervisor,
)

_NETWORK = "a" * 64
_OWNER = "osop-native-sup-" + "b" * 32


def _binding() -> dict[str, Any]:
    return {
        "engagement_id": ENG,
        "flow_id": FLOW,
        "revision": 1,
        "version": 1,
        "authorization_id": "authorization-1",
        "authorization_sha256": "a" * 64,
    }


@pytest.fixture
def case(context: Any, monkeypatch: Any) -> Any:
    """Apply only read-only SELECT modeling on top of original 0033 fake PG."""
    import ai_osop.memory.native_mcp_supervisor_reconciliation as module

    c = context
    issuer_seed = Ed25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    monkeypatch.setenv("OSOP_NATIVE_MCP_GRANT_ACTIVE_KID", "grantKid")
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON",
        json.dumps({"grantKid": base64.b64encode(issuer_seed).decode("ascii")}),
    )
    monkeypatch.setattr(
        module,
        "_verify",
        lambda token: (token["claims"], "grantKid", "7" * 64, "8" * 64),
    )
    c.store.grants._now = AsyncMock(return_value=NOW)
    old_execute = c.db.execute
    c.db.selects = []
    c.db.last_transition = NOW - 120
    c.db.injected_rows = None
    c.db.stale_event = False

    async def execute(sql: Any, params: Any = None) -> QueryResult:
        query = str(sql)
        if query.startswith("SELECT w.*, FLOOR(EXTRACT(EPOCH FROM w.updated_at))"):
            c.db.selects.append((query, params))
            if c.db.injected_rows is not None:
                return QueryResult(rows=copy.deepcopy(c.db.injected_rows))
            if c.db.worker is None or c.db.last_transition > params["before"]:
                return QueryResult(rows=[])
            return QueryResult(
                rows=[{**copy.deepcopy(c.db.worker), "transition_at": c.db.last_transition}]
            )
        if query.startswith("SELECT * FROM native_mcp_worker_supervision_events"):
            c.db.selects.append((query, params))
            if c.db.stale_event or not c.db.events:
                return QueryResult(None)
            latest = copy.deepcopy(c.db.events[-1])
            assert latest["grant_id"] == params["grant"]
            return QueryResult(latest)
        return await old_execute(sql, params)

    c.db.execute = execute
    c.reconcile = NativeMCPSupervisorReconciler(c.store)
    return c


async def _provision(c: Any) -> dict[str, Any]:
    return await _record(c, _signed(c.signer, "provisioned"))


def _cleanup_statements(c: Any, *, created: int = NOW - 8) -> tuple[dict, dict]:
    signer = c.signer.key
    binding = {
        "request_id": REQUEST,
        "engagement_id": ENG,
        "flow_id": FLOW,
        "task_id": "task-1",
        "subtask_id": "subtask-1",
        "action_id": ACTION,
        "lease_id": "lease-1",
        "authorization_sha256": "a" * 64,
        "server_id": SERVER,
        "tool_name": "authority_status",
    }
    ownership = _sign(
        signer,
        _OWNERSHIP_DOMAIN,
        {
            "version": 1,
            "owner": _OWNER,
            "container_id": CONTAINER,
            "network_id": _NETWORK,
            "created_at": created,
        },
        "supervisorKey",
    )
    cleanup = _sign(
        signer,
        CLEAN_DOMAIN,
        {
            "version": 1,
            "server_id": SERVER,
            "tool_name": "authority_status",
            "binding": binding,
            "observations": {
                "container_id": CONTAINER,
                "network_id": _NETWORK,
                "private_stage_mount_verified": True,
                "stage_empty": True,
                "no_host_mounts": True,
                "no_external_network": True,
            },
            "container_id": CONTAINER,
            "network_id": _NETWORK,
            "cleanup_verified": True,
            "observed_at": NOW,
            "target_contacted": False,
            "provider_contacted": False,
            "scanner_invoked": False,
        },
        "supervisorKey",
    )
    return ownership, cleanup


@pytest.mark.asyncio
async def test_old_transition_produces_only_suspect_and_no_durable_change(case: Any) -> None:
    c = case
    first = await _provision(c)
    original_worker = copy.deepcopy(c.db.worker)
    initial_events = len(c.db.events)
    result = await c.reconcile.suspects(_binding(), "operator-1", limit=2)
    assert result["source"] == "durable_0033_last_transition_not_heartbeat"
    assert result["automatic_reaping_enabled"] is False
    assert result["independent_process_liveness_verified"] is False
    assert result["candidates"] == [
        {
            "grant_id": GRANT,
            "request_id": REQUEST,
            "worker_id": WORKER,
            "epoch": first["epoch"],
            "revision": 1,
            "state": "provisioned",
            "grant_status": "issued",
            "age_since_last_signed_transition_seconds": 120,
            "classification": "suspected_orphan_unverified",
            "container_destroyed_verified": False,
            "execution_replay_authorized": False,
        }
    ]
    assert c.db.worker == original_worker
    assert len(c.db.events) == initial_events
    assert c.row["status"] == "issued"
    assert not c.db.grant_events
    assert len(c.db.selects) == 2


@pytest.mark.asyncio
async def test_fresh_transition_and_revoked_signed_owner_are_never_listed(case: Any) -> None:
    c = case
    await _provision(c)
    c.db.last_transition = NOW - 2
    assert (await c.reconcile.suspects(_binding(), "operator-1"))["candidates"] == []
    c.db.last_transition = NOW - 120
    c.actions._authority = AsyncMock(side_effect=MCPActionDenied(409, "revoked"))
    with pytest.raises(MCPActionDenied):
        await c.reconcile.suspects(_binding(), "operator-1")
    assert c.db.worker["state"] == "provisioned"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "wrong_tenant",
        "wrong_owner",
        "wrong_epoch",
        "wrong_revision",
        "missing_event",
        "bad_transition",
        "overflow",
        "missing_source",
    ],
)
async def test_suspect_read_fails_closed_on_cross_source_and_missing_event(
    case: Any, failure: str
) -> None:
    c = case
    await _provision(c)
    if failure in {"wrong_tenant", "wrong_owner", "wrong_epoch", "wrong_revision"}:
        row = {**c.db.worker, "transition_at": NOW - 150}
        if failure == "wrong_tenant":
            row["engagement_id"] = "eng-foreign"
        elif failure == "wrong_owner":
            row["owner_id"] = "untrusted"
        elif failure == "wrong_epoch":
            row["epoch"] = 900
        else:
            row["revision"] = 99
        c.db.injected_rows = [row]
    elif failure == "missing_event":
        c.db.stale_event = True
    elif failure == "bad_transition":
        c.db.last_transition = NOW + 300
        c.db.injected_rows = [{**c.db.worker, "transition_at": c.db.last_transition}]
    elif failure == "overflow":
        c.db.injected_rows = [{**c.db.worker, "transition_at": NOW - 120} for _ in range(3)]
    else:
        c.store.grants._grant = AsyncMock(return_value=None)
    with pytest.raises(NativeMCPGrantDenied):
        await c.reconcile.suspects(_binding(), "operator-1", limit=2)
    assert c.db.worker["state"] == "provisioned"


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [0, 59, 86401, True, 1.5, "60"])
async def test_reject_unbounded_or_ambiguous_stale_windows(case: Any, value: Any) -> None:
    c = case
    with pytest.raises(NativeMCPGrantDenied):
        await c.reconcile.suspects(_binding(), "operator-1", minimum_age_seconds=value)
    assert not c.db.selects


@pytest.mark.asyncio
async def test_signed_unknown_records_durably_and_closes_unused_0029(case: Any) -> None:
    c = case
    first = await _provision(c)
    observed = _signed(
        c.signer,
        "unknown",
        epoch=first["epoch"],
        prior=1,
        container=CONTAINER,
    )
    result = await c.reconcile.reconcile_signed(
        c.token,
        observed,
        supervisor_id="external-supervisor",
        supervisor_secret=SECRET,
    )
    assert result == {
        "grant_id": GRANT,
        "epoch": first["epoch"],
        "revision": 2,
        "state": "unknown",
        "durable_supervisor_observation_recorded": True,
        "container_destroyed_verified": False,
        "original_action_settled": False,
        "replay_authorized": False,
    }
    assert c.db.worker["state"] == "unknown"
    assert c.row["status"] == "unknown"
    assert [e["revision"] for e in c.db.events] == [1, 2]
    assert [e["status"] for e in c.db.grant_events] == ["unknown"]
    with pytest.raises(NativeMCPGrantDenied):
        await c.reconcile.reconcile_signed(
            c.token,
            observed,
            supervisor_id="external-supervisor",
            supervisor_secret=SECRET,
        )
    assert len(c.db.events) == 2


@pytest.mark.asyncio
async def test_reap_requires_two_signed_owned_cleanup_facts(case: Any) -> None:
    c = case
    first = await _provision(c)
    await c.reconcile.reconcile_signed(
        c.token,
        _signed(c.signer, "unknown", epoch=first["epoch"], prior=1, container=CONTAINER),
        supervisor_id="external-supervisor",
        supervisor_secret=SECRET,
    )
    reaped = _signed(
        c.signer,
        "reaped",
        epoch=first["epoch"],
        prior=2,
        container=CONTAINER,
    )
    with pytest.raises(NativeMCPGrantDenied):
        await c.reconcile.reconcile_signed(
            c.token,
            reaped,
            supervisor_id="external-supervisor",
            supervisor_secret=SECRET,
        )
    assert c.db.worker["state"] == "unknown"
    ownership, cleanup = _cleanup_statements(c)
    result = await c.reconcile.reconcile_signed(
        c.token,
        reaped,
        supervisor_id="external-supervisor",
        supervisor_secret=SECRET,
        ownership_statement=ownership,
        cleanup_statement=cleanup,
    )
    assert result["state"] == "reaped"
    assert result["container_destroyed_verified"] is True
    assert result["revision"] == 3
    assert c.db.worker["state"] == "reaped"
    assert c.row["status"] == "unknown"
    assert c.db.grant_events[0]["status"] == "unknown"
    with pytest.raises(NativeMCPGrantDenied):
        await c.reconcile.reconcile_signed(
            c.token,
            reaped,
            supervisor_id="external-supervisor",
            supervisor_secret=SECRET,
            ownership_statement=ownership,
            cleanup_statement=cleanup,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        "unsigned_bool",
        "changed_container",
        "changed_network",
        "foreign_task",
        "claim_replay",
        "stale_cleanup",
        "untrusted_key",
        "fake_stage",
        "stale_epoch",
        "expired_observation",
    ],
)
async def test_false_cleanup_and_stale_cas_can_never_mark_reaped(case: Any, bad: str) -> None:
    c = case
    first = await _provision(c)
    await c.reconcile.reconcile_signed(
        c.token,
        _signed(c.signer, "unknown", epoch=first["epoch"], prior=1, container=CONTAINER),
        supervisor_id="external-supervisor",
        supervisor_secret=SECRET,
    )
    ownership, cleanup = _cleanup_statements(c)
    observation = _signed(
        c.signer,
        "reaped",
        epoch=first["epoch"],
        prior=2,
        container=CONTAINER,
    )
    if bad == "unsigned_bool":
        cleanup["claims"]["cleanup_verified"] = True
        cleanup["signature"] = "A" * 86
    elif bad == "changed_container":
        cleanup["claims"]["container_id"] = "f" * 64
    elif bad == "changed_network":
        cleanup["claims"]["network_id"] = "f" * 64
    elif bad == "foreign_task":
        cleanup["claims"]["binding"]["task_id"] = "task-foreign"
    elif bad == "claim_replay":
        ownership["claims"]["owner"] = "osop-native-sup-" + "c" * 32
    elif bad == "stale_cleanup":
        ownership, cleanup = _cleanup_statements(c, created=NOW + 2)
    elif bad == "untrusted_key":
        c.signer.key = Ed25519PrivateKey.generate()
        ownership, cleanup = _cleanup_statements(c)
    elif bad == "fake_stage":
        cleanup["claims"]["observations"]["private_stage_mount_verified"] = False
    elif bad == "stale_epoch":
        observation = _signed(
            c.signer,
            "reaped",
            epoch=first["epoch"] + 1,
            prior=2,
            container=CONTAINER,
        )
    else:
        observation = _signed(
            c.signer,
            "reaped",
            epoch=first["epoch"],
            prior=2,
            container=CONTAINER,
            observed_at=NOW + 300,
        )
    with pytest.raises((MCPActionDenied, NativeMCPGrantDenied)):
        await c.reconcile.reconcile_signed(
            c.token,
            observation,
            supervisor_id="external-supervisor",
            supervisor_secret=SECRET,
            ownership_statement=ownership,
            cleanup_statement=cleanup,
        )
    assert c.db.worker["state"] == "unknown"
    assert c.row["status"] == "unknown"


@pytest.mark.asyncio
async def test_observer_failure_never_writes_and_cannot_infer_death_from_age(case: Any) -> None:
    c = case
    first = await _provision(c)
    c.db.last_transition = NOW - 10000
    assert len((await c.reconcile.suspects(_binding(), "operator-1"))["candidates"]) == 1
    assert c.db.worker["state"] == "provisioned"
    c.store.record = AsyncMock(side_effect=TimeoutError("owned worker unknown"))
    with pytest.raises(NativeMCPGrantDenied):
        await c.reconcile.reconcile_signed(
            c.token,
            _signed(c.signer, "unknown", epoch=first["epoch"], prior=1),
            supervisor_id="external-supervisor",
            supervisor_secret=SECRET,
        )
    assert c.db.worker["state"] == "provisioned"
    assert not c.db.grant_events
