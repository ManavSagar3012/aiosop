"""Adversarial qualification for independent, durable Flow MCP Action ledger."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.mcp.protocol import (
    MCPRegistry,
    MCPToolDefinition,
    MCPToolParameter,
    SideEffectClass,
)
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    MCPActionDenied,
    _binding,
    _safe_parameters,
)
from ai_osop.core.models import ScopeDefinition
from ai_osop.core.config import settings
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.safety.approval_binding import pinned_evidence
from ai_osop.safety.scope import ScopeEnforcer


def definition() -> MCPToolDefinition:
    return MCPToolDefinition(
        name="fetch_page",
        description="Explicit scoped read",
        parameters=[
            MCPToolParameter(name="url", type="string", description="Scope URL"),
            MCPToolParameter(name="depth", type="integer", description="Depth", required=False),
        ],
        returns={"type": "object"},
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        scope_check=True,
    )


def binding() -> dict:
    return {
        "engagement_id": "eng-durable",
        "flow_id": "flow-authorized",
        "revision": 6,
        "version": 3,
        "authorization_id": "signed-policy-3",
        "authorization_sha256": "a" * 64,
    }


def build_store() -> FlowMCPActionStore:
    registry = MCPRegistry()
    registry._servers["browser-mcp"] = SimpleNamespace(
        server_id="browser-mcp",
        _initialized=True,
        _tools={"fetch_page": definition()},
        get_circuit_state=lambda: "closed",
    )
    return FlowMCPActionStore(SessionMemory(), registry)


def test_declared_parameter_digest_matches_approved_request_builder() -> None:
    store = build_store()
    value = {"url": "https://owned.example/test", "depth": 2}
    declared = {
        "server_id": "browser-mcp",
        "declaration": definition().model_dump(mode="json"),
    }
    assert (
        store.declaration_sha256(definition(), "browser-mcp")
        == hashlib.sha256(
            json.dumps(declared, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
    )
    assert (
        store.parameters_sha256(value)
        == hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
    )
    assert store.declaration_sha256(definition(), "other-mcp") != store.declaration_sha256(
        definition(), "browser-mcp"
    )


@pytest.mark.parametrize(
    "parameters",
    [
        {"url": "https://owned.example/?token=key"},
        {"url": "https://alice:secret@owned.example/"},
        {"url": "https://owned.example/#fragment"},
        {"url": "https://owned.example/", "cookie": "value"},
        {"url": "https://owned.example/", "depth": True},
        {"url": "https://owned.example/", "depth": 100000000},
        {"url": "https://owned.example/", "depth": float("nan")},
        {"url": "https://owned.example/", "depth": {"headers": "secret"}},
        {"url": "https://owned.example/\r\nCookie: secret"},
        {"url": "https://owned.example/" * 150},
    ],
)
def test_secret_unbounded_or_undeclared_parameters_denied(parameters: dict) -> None:
    with pytest.raises(MCPActionDenied):
        _safe_parameters(parameters, definition())


@pytest.mark.parametrize(
    "mutation",
    [
        {"authorization_sha256": "b" * 65},
        {"authorization_id": "policy\nheader"},
        {"version": 0},
        {"version": True},
        {"revision": -1},
        {"engagement_id": "tenant/other"},
    ],
)
def test_invalid_signed_binding_fails_closed(mutation: dict) -> None:
    with pytest.raises(MCPActionDenied):
        _binding({**binding(), **mutation})


def test_registry_requires_initialized_healthy_scoped_declaration() -> None:
    store = build_store()
    assert store._declaration("browser-mcp", "fetch_page") == definition()
    connection = store.registry._servers["browser-mcp"]
    connection._initialized = False
    with pytest.raises(MCPActionDenied):
        store._declaration("browser-mcp", "fetch_page")
    connection._initialized = True
    connection.get_circuit_state = lambda: "open"
    with pytest.raises(MCPActionDenied):
        store._declaration("browser-mcp", "fetch_page")
    connection.get_circuit_state = lambda: "closed"
    connection._tools["fetch_page"] = definition().model_copy(update={"scope_check": False})
    with pytest.raises(MCPActionDenied):
        store._declaration("browser-mcp", "fetch_page")


class Result:
    def __init__(self, one=None, rows=None):
        self.one = one
        self.rows = [] if rows is None else rows

    def mappings(self):
        return self

    def one_or_none(self):
        return self.one

    def all(self):
        return self.rows

    def scalar_one_or_none(self):
        return self.one


class FakeDB:
    """Deterministic SQL transaction harness for critical state transitions."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.events: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    @asynccontextmanager
    async def begin(self):
        yield self

    async def execute(self, statement, params=None):
        sql = str(statement)
        params = params or {}
        if sql.startswith("SELECT scope FROM session_states"):
            return Result(
                one={
                    "scope": {
                        "engagement_id": "eng-durable",
                        "domains": ["owned.example"],
                        "ips": [],
                    }
                }
            )
        if sql.startswith("INSERT INTO flow_mcp_action_dispatch_events"):
            self.events.append(dict(params))
            return Result()
        if sql.startswith("INSERT INTO flow_mcp_action_dispatches"):
            action = params["action_id"]
            if action in self.rows:
                return Result(one=None)
            self.rows[action] = {
                **params,
                "safe_parameters": json.loads(params["safe_parameters"]),
                "status": "prepared",
                "revision": 1,
                "cancel_requested": False,
                "receipt_sha256": None,
            }
            return Result(one=action)
        if sql.startswith("SELECT * FROM flow_mcp_action_dispatches"):
            row = self.rows.get(params["action"])
            return Result(one=dict(row) if row else None)
        if sql.startswith("UPDATE flow_mcp_action_dispatches SET"):
            row = self.rows[params["action"]]
            if row["revision"] != params["prior"] or row["status"] != params["previous"]:
                return Result()
            row.update(
                {
                    k: v
                    for k, v in params.items()
                    if k
                    in {"status", "cancel_requested", "receipt_sha256", "reservation_token_sha256"}
                }
            )
            row["revision"] += 1
            return Result(one=row["revision"])
        raise AssertionError("Unexpected SQL: " + sql[:130])


def harness(monkeypatch):
    store = build_store()
    db = FakeDB()
    store._sessions = lambda: (lambda: db)

    async def authority(_db, _b, _actor, *, dispatch):
        return {
            "scope": {
                "engagement_id": "eng-durable",
                "domains": ["owned.example"],
                "ips": [],
                "exclusions": [],
                "approval_required_for": [],
                "restrictions": [],
                "allowed_techniques": [],
            }
        }

    store._authority = authority
    store._approved_task = AsyncMock(
        return_value={
            "action_id": "action-" + "1" * 32,
            "approval_id": "apr-current",
            "lease_id": "lease-current",
            "lease_owner_id": "worker-1",
        }
    )
    return store, db


@pytest.mark.asyncio
async def test_prepare_reserve_unknown_and_no_consequential_replay(monkeypatch) -> None:
    store, db = harness(monkeypatch)
    params = {"url": "https://owned.example/page", "depth": 2}
    digest = store.parameters_sha256(params)
    manifest = store.declaration_sha256(definition(), "browser-mcp")
    args = (
        binding(),
        "owner-1",
        "task-1",
        "step-1",
        "browser-mcp",
        "fetch_page",
        params,
        digest,
        manifest,
    )
    prepared = await store.prepare(*args)
    assert prepared["status"] == "prepared"
    assert "parameters" not in prepared
    assert len(db.events) == 1
    assert (await store.prepare(*args))["action_id"] == prepared["action_id"]
    assert len(db.events) == 1
    first = await store.reserve(binding(), "owner-1", prepared["action_id"])
    assert first["status"] == "reserved"
    assert first["admitted_for_dispatch"] is True
    assert first["parameters"] == params
    assert len(first["reservation_token"]) == 68
    duplicate = await store.reserve(binding(), "owner-1", prepared["action_id"])
    assert duplicate["admitted_for_dispatch"] is False
    assert "reservation_token" not in duplicate
    with pytest.raises(MCPActionDenied):
        await store.mark_dispatched(
            binding(), "owner-1", prepared["action_id"], first["request_id"], "res-" + "0" * 64
        )
    committed = await store.mark_dispatched(
        binding(),
        "owner-1",
        prepared["action_id"],
        first["request_id"],
        first["reservation_token"],
    )
    assert committed["status"] == "unknown"
    assert committed["dispatch_attempt_committed"] is True
    assert (await store.cancel(binding(), "owner-1", prepared["action_id"]))["status"] == "unknown"
    assert db.rows[prepared["action_id"]]["cancel_requested"] is True
    assert "safe_parameters" not in str(db.events)
    assert [event["kind"] for event in db.events] == [
        "prepared",
        "reserved",
        "dispatch_attempted",
        "cancel_requested_unknown",
    ]
    with pytest.raises(MCPActionDenied):
        await store.mark_dispatched(
            binding(),
            "owner-1",
            prepared["action_id"],
            first["request_id"],
            first["reservation_token"],
        )
    assert (await store.reserve(binding(), "owner-1", prepared["action_id"]))[
        "admitted_for_dispatch"
    ] is False
    assert (await store.get(binding(), "owner-1", prepared["action_id"]))["status"] == "unknown"


@pytest.mark.asyncio
async def test_unknown_cannot_be_promoted_by_unsigned_provider_claim(monkeypatch) -> None:
    store, db = harness(monkeypatch)
    params = {"url": "https://owned.example/"}
    prepared = await store.prepare(
        binding(),
        "owner-1",
        "task-1",
        "step-1",
        "browser-mcp",
        "fetch_page",
        params,
        store.parameters_sha256(params),
        store.declaration_sha256(definition(), "browser-mcp"),
    )
    reserved = await store.reserve(binding(), "owner-1", prepared["action_id"])
    await store.mark_dispatched(
        binding(),
        "owner-1",
        prepared["action_id"],
        reserved["request_id"],
        reserved["reservation_token"],
    )
    receipt = {
        "request_id": reserved["request_id"],
        "engagement_id": "eng-durable",
        "task_id": "task-1",
        "server_id": "browser-mcp",
        "status": "finished",
        "verified": True,
        "stopped": False,
        "issued_at": 0,
    }
    with pytest.raises(MCPActionDenied):
        await store.settle(
            binding(), "owner-1", prepared["action_id"], reserved["request_id"], "finished", receipt
        )
    assert db.rows[prepared["action_id"]]["status"] == "unknown"
    assert len(db.events) == 3
    assert (
        await store.settle(
            binding(), "owner-1", prepared["action_id"], reserved["request_id"], "unknown"
        )
    )["status"] == "unknown"
    assert len(db.events) == 3


@pytest.mark.asyncio
async def test_signed_reconciliation_requires_current_distinct_provider_trust(monkeypatch) -> None:
    store, db = harness(monkeypatch)
    params = {"url": "https://owned.example/"}
    prepared = await store.prepare(
        binding(),
        "owner-1",
        "task-1",
        "step-1",
        "browser-mcp",
        "fetch_page",
        params,
        store.parameters_sha256(params),
        store.declaration_sha256(definition(), "browser-mcp"),
    )
    reserved = await store.reserve(binding(), "owner-1", prepared["action_id"])
    await store.mark_dispatched(
        binding(),
        "owner-1",
        prepared["action_id"],
        reserved["request_id"],
        reserved["reservation_token"],
    )

    signer = Ed25519PrivateKey.generate()
    pubkey = base64.b64encode(
        signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    claims = {
        "server_id": "browser-mcp",
        "request_id": reserved["request_id"],
        "engagement_id": "eng-durable",
        "task_id": "task-1",
        "status": "finished",
        "verified": True,
        "stopped": False,
        "issued_at": int(time.time()),
    }
    signature = (
        base64.urlsafe_b64encode(
            signer.sign(
                json.dumps(
                    claims,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            )
        )
        .decode("ascii")
        .rstrip("=")
    )
    receipt = {**claims, "attestation": {"kid": "provider-key-1", "signature": signature}}

    # Invalid deployment trust leaves the permanently dispatched Action UNKNOWN.
    monkeypatch.delenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", raising=False)
    with pytest.raises(MCPActionDenied):
        await store.settle(
            binding(),
            "owner-1",
            prepared["action_id"],
            reserved["request_id"],
            "finished",
            receipt,
        )
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({"browser-mcp": {"provider-key-1": pubkey}}),
    )
    with pytest.raises(MCPActionDenied):
        await store.settle(
            binding(),
            "owner-1",
            prepared["action_id"],
            reserved["request_id"],
            "cancelled",
            receipt,
        )
    wrong_identity = {**receipt, "task_id": "task-foreign"}
    with pytest.raises(MCPActionDenied):
        await store.settle(
            binding(),
            "owner-1",
            prepared["action_id"],
            reserved["request_id"],
            "finished",
            wrong_identity,
        )
    assert db.rows[prepared["action_id"]]["status"] == "unknown"
    finished = await store.settle(
        binding(),
        "owner-1",
        prepared["action_id"],
        reserved["request_id"],
        "finished",
        receipt,
    )
    assert finished["status"] == "finished"
    assert len(finished["receipt_sha256"]) == 64
    assert "attestation" not in str(db.events)
    assert [event["kind"] for event in db.events] == [
        "prepared",
        "reserved",
        "dispatch_attempted",
        "reconciled",
    ]
    assert (await store.reserve(binding(), "owner-1", prepared["action_id"]))[
        "admitted_for_dispatch"
    ] is False


@pytest.mark.asyncio
async def test_cancel_before_dispatch_consumes_all_future_admission(monkeypatch) -> None:
    store, db = harness(monkeypatch)
    params = {"url": "https://owned.example/"}
    prepared = await store.prepare(
        binding(),
        "owner-1",
        "task-1",
        "step-1",
        "browser-mcp",
        "fetch_page",
        params,
        store.parameters_sha256(params),
        store.declaration_sha256(definition(), "browser-mcp"),
    )
    assert (await store.cancel(binding(), "owner-1", prepared["action_id"]))[
        "status"
    ] == "cancelled"
    assert (await store.reserve(binding(), "owner-1", prepared["action_id"]))[
        "admitted_for_dispatch"
    ] is False
    assert "cancelled_before_dispatch" in [event["kind"] for event in db.events]
    with pytest.raises(MCPActionDenied):
        await store.get({**binding(), "version": 4}, "owner-1", prepared["action_id"])


@pytest.mark.asyncio
async def test_real_approved_task_gate_rejects_pinned_digest_swap(monkeypatch) -> None:
    store = build_store()
    approved_payload = {
        "planner_flow_revision": 6,
        "mcp_flow_revision": 6,
        "_authorization_version": 3,
        "mcp_action_id": "action-" + "1" * 32,
        "mcp_server_id": "browser-mcp",
        "mcp_tool_name": "fetch_page",
        "mcp_declaration_sha256": store.declaration_sha256(definition(), "browser-mcp"),
        "mcp_parameters_sha256": "c" * 64,
        "operator_approved": True,
        "approval_id": "apr-current",
        "target": "https://owned.example/",
    }
    task = {
        "id": "task-1",
        "engagement_id": "eng-durable",
        "flow_id": "flow-authorized",
        "subtask_id": "step-1",
        "assigned_agent_id": "agent-1",
        "status": "running",
        "started_at": datetime.utcnow(),
        "completed_at": None,
        "scope_check": True,
        "approval_required": True,
        "type": "recon",
        "payload": approved_payload,
    }
    step = {
        "execution_task_id": "task-1",
        "status": "running",
        "approval_required": True,
        "task_type": "recon",
    }
    approval = {
        "status": "approved",
        "action_type": "recon",
        "operator_id": "human-2",
        "responded_at": datetime.utcnow(),
        "target": approved_payload["target"],
        "evidence": pinned_evidence([], approved_payload),
    }
    lease = {
        "state": "dispatched",
        "lease_id": "lease-current",
        "owner_id": "worker-1",
        "expires_at": datetime.utcnow() + timedelta(minutes=1),
    }
    reviewer_control = {"disabled": False}

    class ReadOnlyDB:
        async def execute(self, sql, args):
            query = str(sql)
            if "FROM tasks" in query:
                return Result(one=task)
            if "FROM execution_subtasks" in query:
                return Result(one=step)
            if "FROM approval_requests" in query:
                return Result(one=approval)
            if "FROM operator_subject_controls" in query:
                return Result(one=reviewer_control.copy() if reviewer_control else None)
            if "FROM supervision_execution_leases" in query:
                return Result(one=lease)
            raise AssertionError(query)

    scope = ScopeEnforcer(ScopeDefinition(engagement_id="eng-durable", domains=["owned.example"]))
    args = (
        ReadOnlyDB(),
        binding(),
        "owner-1",
        "task-1",
        "step-1",
        "browser-mcp",
        "fetch_page",
        approved_payload["mcp_declaration_sha256"],
        "c" * 64,
        SideEffectClass.READ_ONLY.value,
        scope,
    )
    assert (await store._approved_task(*args))["action_id"] == approved_payload["mcp_action_id"]
    # A signed MCP Task can pin only mcp_flow_revision. Its valid revision must
    # still be accepted, while a stale revision must fail even when an attacker
    # supplies a fresh human-evidence fingerprint for the altered payload.
    del approved_payload["planner_flow_revision"]
    approval["evidence"] = pinned_evidence([], approved_payload)
    assert (await store._approved_task(*args))["action_id"] == approved_payload["mcp_action_id"]
    approved_payload["mcp_flow_revision"] = 7
    approval["evidence"] = pinned_evidence([], approved_payload)
    with pytest.raises(MCPActionDenied):
        await store._approved_task(*args)
    approved_payload["mcp_flow_revision"] = 6
    approval["evidence"] = pinned_evidence([], approved_payload)
    with pytest.raises(MCPActionDenied):
        await store._approved_task(*args[:-3], "d" * 64, SideEffectClass.READ_ONLY.value, scope)
    approval["operator_id"] = "owner-1"
    with pytest.raises(MCPActionDenied):
        await store._approved_task(*args)
    approval["operator_id"] = "human-2"
    reviewer_control["disabled"] = True
    with pytest.raises(MCPActionDenied):
        await store._approved_task(*args)
    reviewer_control["disabled"] = False
    reviewer_control.clear()
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    with pytest.raises(MCPActionDenied):
        await store._approved_task(*args)
    reviewer_control["disabled"] = False
    assert (await store._approved_task(*args))["action_id"] == approved_payload["mcp_action_id"]
    lease["expires_at"] = datetime.utcnow() - timedelta(seconds=1)
    with pytest.raises(MCPActionDenied):
        await store._approved_task(*args)
