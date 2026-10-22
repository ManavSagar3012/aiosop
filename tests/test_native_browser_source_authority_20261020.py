"""Real issuer signatures + FastAPI + fake-PG atomic source checks (not live PG)."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from ai_osop.api.routers import native_browser_source_authority as api
from ai_osop.core.models import ScopeDefinition
from ai_osop.mcp.protocol import SideEffectClass
from ai_osop.memory.browser_source_authority import (
    DOMAIN,
    BrowserSourceAuthorityStore,
    BrowserSourceDenied,
    _canonical,
    exact_origin,
)
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    MCPActionDenied,
    _DIGEST_DOMAIN,
    _digest,
)
from ai_osop.safety.scope import ScopeEnforcer

URL = "https://example.org/account"
SHA = hashlib.sha256(URL.encode("utf-8")).hexdigest()
SERVICE = "independent-central-browser-source-service-token"
KID = "browser-central-issuer"


@dataclass
class Parameter:
    name: str
    type: str = "string"
    required: bool = True
    enum: object = None


def original_row() -> dict:
    parameters = {"url": URL, "action": "navigate", "user_label": "ownerA"}
    row = {
        "action_id": "action-" + "a" * 32,
        "engagement_id": "eng-source-fixture",
        "flow_id": "flow-source-fixture",
        "task_id": "task-source-fixture",
        "subtask_id": "subtask-source-fixture",
        "owner_id": "operator-owner",
        "flow_revision": 7,
        "authorization_id": "auth-original",
        "authorization_version": 4,
        "authorization_sha256": "4" * 64,
        "approval_id": "apr-independent",
        "lease_id": "lease-live-original",
        "lease_owner_id": "agent-alive",
        "server_id": "browser-mcp",
        "tool_name": "execute",
        "side_effect_class": "RECON_ACTIVE",
        "declaration_sha256": "5" * 64,
        "parameters_sha256": FlowMCPActionStore.parameters_sha256(parameters),
        "safe_parameters": parameters,
        "status": "unknown",
        "cancel_requested": False,
        "receipt_sha256": None,
    }
    binding = {
        "engagement_id": row["engagement_id"],
        "flow_id": row["flow_id"],
        "revision": row["flow_revision"],
        "version": row["authorization_version"],
        "authorization_id": row["authorization_id"],
        "authorization_sha256": row["authorization_sha256"],
    }
    pinned_intent = {
        **binding,
        **{
            key: row[key]
            for key in (
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "lease_owner_id",
                "server_id",
                "tool_name",
                "side_effect_class",
                "declaration_sha256",
                "parameters_sha256",
            )
        },
    }
    row["intent_sha256"] = _digest(_DIGEST_DOMAIN, pinned_intent, 4096)
    row["request_id"] = "req-" + row["intent_sha256"][:48]
    return row


def source_request(row: dict) -> dict:
    return {
        "request_id": row["request_id"],
        "engagement_id": row["engagement_id"],
        "task_id": row["task_id"],
        "server_id": "browser-mcp",
        "tool_name": "execute",
        "action": "navigate",
        "url_sha256": SHA,
        "origin": "https://example.org:443",
        "user_label": "ownerA",
        "evidence_mode": "none",
    }


class Result:
    def __init__(self, *, row=None, scalar=None):
        self.row = row
        self.scalar = scalar

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row

    def scalar_one_or_none(self):
        return self.scalar

    def scalar_one(self):
        return self.scalar


class Ledger:
    def __init__(self, row=None):
        self.row = copy.deepcopy(row if row is not None else original_row())
        self.lock = asyncio.Lock()
        self.committed = {}
        self.dispatch_event = True
        self.roe = {}
        self.clock = 1792494800
        self.commit_fails = False


class FakePG:
    """Serializes fake transactions and commits only on clean exit.

    This is a race model for deterministic unit tests; it does not prove
    PostgreSQL isolation levels, migrated schema, or network qualification.
    """

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.pending = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, typ, exc, tb):
        return None

    def begin(self):
        pg = self

        class Transaction:
            async def __aenter__(self):
                await pg.ledger.lock.acquire()
                return pg

            async def __aexit__(self, typ, exc, tb):
                try:
                    if typ is None and pg.pending is not None:
                        if pg.ledger.commit_fails:
                            raise RuntimeError("Simulated commit uncertainty")
                        pg.ledger.committed[pg.pending["request_id"]] = pg.pending
                finally:
                    pg.ledger.lock.release()

        return Transaction()

    async def execute(self, statement, parameters=None):
        query = str(statement)
        parameters = parameters or {}
        if "SELECT * FROM flow_mcp_action_dispatches WHERE request_id" in query:
            return Result(
                row=(
                    copy.deepcopy(self.ledger.row)
                    if parameters["request"] == self.ledger.row["request_id"]
                    else None
                )
            )
        if "SELECT * FROM flow_mcp_action_dispatches WHERE action_id" in query:
            return Result(
                row=(
                    copy.deepcopy(self.ledger.row)
                    if parameters["action"] == self.ledger.row["action_id"]
                    else None
                )
            )
        if "FROM flow_mcp_action_dispatch_events" in query:
            return Result(scalar=1 if self.ledger.dispatch_event else None)
        if "SELECT roe FROM session_states" in query:
            return Result(row={"roe": copy.deepcopy(self.ledger.roe)})
        if "EXTRACT(EPOCH FROM clock_timestamp())" in query:
            return Result(scalar=self.ledger.clock)
        if "INSERT INTO native_browser_source_preflights" in query:
            if parameters["request_id"] in self.ledger.committed or any(
                r["action_id"] == parameters["action_id"] for r in self.ledger.committed.values()
            ):
                return Result()
            self.pending = dict(parameters)
            return Result(scalar=parameters["preflight_id"])
        raise AssertionError("Unexpected fake PG source query: " + query[:130])


def make_authority(ledger: Ledger) -> tuple[BrowserSourceAuthorityStore, FlowMCPActionStore]:
    actions = object.__new__(FlowMCPActionStore)
    actions._sessions = lambda: lambda: FakePG(ledger)
    actions.memory = SimpleNamespace(
        _ensure_redis=AsyncMock(side_effect=RuntimeError("No Redis in fake-PG test"))
    )
    actions._authority = AsyncMock(
        return_value={
            "scope": {
                "engagement_id": ledger.row["engagement_id"],
                "domains": ["example.org"],
            }
        }
    )
    actions._approved_task = AsyncMock(
        return_value={
            k: ledger.row[k] for k in ("action_id", "approval_id", "lease_id", "lease_owner_id")
        }
    )
    declaration = SimpleNamespace(
        name="execute",
        side_effect_class=SideEffectClass.RECON_ACTIVE,
        requires_approval=True,
        scope_check=True,
        parameters=[
            Parameter("url", required=False),
            Parameter("action"),
            Parameter("user_label"),
            Parameter("evidence_mode", required=False),
        ],
    )
    actions._declaration = lambda *_: declaration
    actions.declaration_sha256 = lambda *_: ledger.row["declaration_sha256"]
    return BrowserSourceAuthorityStore(actions), actions


@pytest.fixture
def signer(monkeypatch):
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_SIGNING_KID", KID)
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_SIGNING_PRIVATE_KEY_B64", base64.b64encode(seed).decode("ascii")
    )
    return key


def verify_receipt(receipt: dict, signer) -> None:
    assert set(receipt) == {"claims", "kid", "signature"}
    assert receipt["kid"] == KID
    assert len(receipt["claims"]) == 22
    signature = base64.urlsafe_b64decode(receipt["signature"] + "==")
    signer.public_key().verify(signature, DOMAIN + _canonical(receipt["claims"]))


@pytest.mark.asyncio
async def test_original_unknown_receipt_signed_after_durable_one_shot(signer):
    ledger = Ledger()
    source, actions = make_authority(ledger)
    original = source_request(ledger.row)
    receipt = await source.admit(original)
    verify_receipt(receipt, signer)
    claims = receipt["claims"]
    assert claims["url_sha256"] == SHA and claims["action"] == "navigate"
    assert claims["user_label"] == "ownerA"
    assert claims["authorization_sha256"] == ledger.row["authorization_sha256"]
    assert claims["lease_id"] == ledger.row["lease_id"]
    assert claims["expires_at"] - claims["issued_at"] == 10
    assert claims["request_id"] in ledger.committed
    assert (
        ledger.committed[claims["request_id"]]["claims_sha256"]
        == hashlib.sha256(_canonical(claims)).hexdigest()
    )
    assert "url" not in receipt["claims"]
    assert actions._authority.await_args.kwargs == {"dispatch": True}
    with pytest.raises(BrowserSourceDenied):
        await source.admit(original)
    assert len(ledger.committed) == 1


@pytest.mark.asyncio
async def test_explicit_original_capture_consent_is_independently_signed_and_one_shot(signer):
    """A different mode is a different reviewed Action, not caller preference."""
    row = original_row()
    approved_parameters = {
        **row["safe_parameters"],
        "evidence_mode": "screenshot_dom_har",
    }
    row["safe_parameters"] = approved_parameters
    row["parameters_sha256"] = FlowMCPActionStore.parameters_sha256(approved_parameters)
    original_binding = {
        "engagement_id": row["engagement_id"],
        "flow_id": row["flow_id"],
        "revision": row["flow_revision"],
        "version": row["authorization_version"],
        "authorization_id": row["authorization_id"],
        "authorization_sha256": row["authorization_sha256"],
    }
    intent = {
        **original_binding,
        **{
            name: row[name]
            for name in (
                "task_id",
                "subtask_id",
                "action_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "lease_owner_id",
                "server_id",
                "tool_name",
                "side_effect_class",
                "declaration_sha256",
                "parameters_sha256",
            )
        },
    }
    row["intent_sha256"] = _digest(_DIGEST_DOMAIN, intent, 4096)
    row["request_id"] = "req-" + row["intent_sha256"][:48]
    ledger = Ledger(row)
    source, _ = make_authority(ledger)
    no_capture = source_request(row)
    with pytest.raises(BrowserSourceDenied):
        await source.admit(no_capture)
    assert ledger.committed == {}
    full_capture = {**no_capture, "evidence_mode": "screenshot_dom_har"}
    signed = await source.admit(full_capture)
    verify_receipt(signed, signer)
    assert signed["claims"]["evidence_mode"] == "screenshot_dom_har"
    assert ledger.committed[row["request_id"]]["evidence_mode"] == "screenshot_dom_har"
    with pytest.raises(BrowserSourceDenied):
        await source.admit(full_capture)
    assert len(ledger.committed) == 1


@pytest.mark.asyncio
async def test_parallel_requests_use_one_global_action_and_request(signer):
    ledger = Ledger()
    source, _ = make_authority(ledger)
    outcomes = await asyncio.gather(
        *(source.admit(source_request(ledger.row)) for _ in range(8)),
        return_exceptions=True,
    )
    assert sum(isinstance(result, dict) for result in outcomes) == 1
    assert sum(isinstance(result, BrowserSourceDenied) for result in outcomes) == 7
    assert len(ledger.committed) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        {"engagement_id": "eng-other"},
        {"task_id": "task-other"},
        {"url_sha256": "f" * 64},
        {"origin": "https://wrong.example.org:443"},
        {"user_label": "another-identity"},
        {"action": "click"},
        {"server_id": "recon-mcp"},
        {"tool_name": "authority_status"},
    ],
)
async def test_claimed_url_tenant_task_or_tool_cannot_mint_authority(signer, mutation):
    ledger = Ledger()
    source, actions = make_authority(ledger)
    requested = {**source_request(ledger.row), **mutation}
    with pytest.raises(BrowserSourceDenied):
        await source.admit(requested)
    assert not ledger.committed
    if mutation.get("action") == "click":
        actions._authority.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source_change",
    [
        {"status": "reserved"},
        {"cancel_requested": True},
        {"receipt_sha256": "c" * 64},
        {"intent_sha256": "0" * 64},
        {"side_effect_class": "INVASIVE_EXPLOIT"},
    ],
)
async def test_tampered_or_cancelled_original_denied(signer, source_change):
    ledger = Ledger()
    request = source_request(ledger.row)
    ledger.row.update(source_change)
    source, _ = make_authority(ledger)
    with pytest.raises(BrowserSourceDenied):
        await source.admit(request)
    assert not ledger.committed


@pytest.mark.asyncio
async def test_missing_original_dispatch_event_denied(signer):
    ledger = Ledger()
    ledger.dispatch_event = False
    source, _ = make_authority(ledger)
    with pytest.raises(BrowserSourceDenied):
        await source.admit(source_request(ledger.row))
    assert not ledger.committed


@pytest.mark.asyncio
async def test_current_review_revocation_lease_or_flow_roe_denies(signer):
    for boundary in ("reviewer_revoked", "lease_changed", "approval_changed", "roe_revoked"):
        ledger = Ledger()
        source, actions = make_authority(ledger)
        if boundary == "roe_revoked":
            actions._authority.side_effect = MCPActionDenied(403, "Signed ROE was revoked")
        elif boundary == "reviewer_revoked":
            actions._approved_task.side_effect = MCPActionDenied(
                403, "Independent approving operator is disabled"
            )
        elif boundary == "approval_changed":
            actions._approved_task.return_value = {
                "action_id": ledger.row["action_id"],
                "approval_id": "apr-another-review",
                "lease_id": ledger.row["lease_id"],
                "lease_owner_id": ledger.row["lease_owner_id"],
            }
        else:
            actions._approved_task.return_value = {
                "action_id": ledger.row["action_id"],
                "approval_id": ledger.row["approval_id"],
                "lease_id": "lease-reassigned",
                "lease_owner_id": ledger.row["lease_owner_id"],
            }
        with pytest.raises(BrowserSourceDenied):
            await source.admit(source_request(ledger.row))
        assert not ledger.committed


@pytest.mark.asyncio
async def test_real_0027_reviewer_revocation_check_blocks_original_approval(monkeypatch):
    """Exercise original _approved_task SQL reader through disabled reviewer."""
    row = original_row()
    payload = {
        "planner_flow_revision": row["flow_revision"],
        "_flow_revision": row["flow_revision"],
        "mcp_flow_revision": row["flow_revision"],
        "_authorization_version": row["authorization_version"],
        "mcp_action_id": row["action_id"],
        "mcp_server_id": row["server_id"],
        "mcp_tool_name": row["tool_name"],
        "mcp_declaration_sha256": row["declaration_sha256"],
        "mcp_parameters_sha256": row["parameters_sha256"],
        "mcp_side_effect_class": row["side_effect_class"],
        "operator_approved": True,
        "approval_id": row["approval_id"],
        "url": URL,
    }
    fixtures = {
        "FROM tasks WHERE": {
            "id": row["task_id"],
            "flow_id": row["flow_id"],
            "subtask_id": row["subtask_id"],
            "assigned_agent_id": "agent-live",
            "status": "running",
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "scope_check": True,
            "approval_required": True,
            "type": "browser_navigation",
            "payload": payload,
        },
        "FROM execution_subtasks WHERE": {
            "execution_task_id": row["task_id"],
            "approval_required": True,
            "status": "running",
            "task_type": "browser_navigation",
        },
        "FROM approval_requests": {
            "status": "approved",
            "action_type": "browser_navigation",
            "operator_id": "independent-reviewer",
            "responded_at": datetime.utcnow(),
            "target": URL,
            "evidence": {"payload_sha256": "approved-fixture"},
        },
        "FROM operator_subject_controls": {"disabled": True},
    }

    class ReviewerPG:
        def __init__(self):
            self.query_log = []

        async def execute(self, stmt, parameters=None):
            query = str(stmt)
            self.query_log.append(query)
            for marker, value in fixtures.items():
                if marker in query:
                    return Result(row=value)
            raise AssertionError("Unexpected SQL after disabled reviewer")

    import ai_osop.memory.flow_mcp_action_dispatch as original

    monkeypatch.setattr(original, "matches_pinned_payload", lambda evidence, task: True)
    db = ReviewerPG()
    binding = {
        "engagement_id": row["engagement_id"],
        "flow_id": row["flow_id"],
        "revision": row["flow_revision"],
        "version": row["authorization_version"],
        "authorization_id": row["authorization_id"],
        "authorization_sha256": row["authorization_sha256"],
    }
    scope = ScopeEnforcer(
        ScopeDefinition(
            engagement_id=row["engagement_id"],
            domains=["example.org"],
        )
    )
    with pytest.raises(MCPActionDenied) as denied:
        await FlowMCPActionStore._approved_task(
            db,
            binding,
            row["owner_id"],
            row["task_id"],
            row["subtask_id"],
            row["server_id"],
            row["tool_name"],
            row["declaration_sha256"],
            row["parameters_sha256"],
            row["side_effect_class"],
            scope,
        )
    assert denied.value.status == 403
    assert any("operator_subject_controls" in query for query in db.query_log)
    assert not any("supervision_execution_leases" in query for query in db.query_log)


@pytest.mark.asyncio
async def test_live_roe_restrictions_and_existing_budget_receipt(signer):
    for roe, restrictions in (
        ({"allow_active_scanning": False}, []),
        ({}, ["no_active_scanning"]),
        ({}, ["no_side_effects"]),
    ):
        ledger = Ledger()
        ledger.roe = roe
        source, actions = make_authority(ledger)
        actions._authority.return_value["scope"]["restrictions"] = restrictions
        with pytest.raises(BrowserSourceDenied):
            await source.admit(source_request(ledger.row))
        assert not ledger.committed

    ledger = Ledger()
    ledger.roe = {"tool_call_budget_total": 1}
    source, actions = make_authority(ledger)
    with pytest.raises(BrowserSourceDenied) as unavailable:
        await source.admit(source_request(ledger.row))
    assert unavailable.value.status == 503
    assert not ledger.committed

    redis = SimpleNamespace(get=AsyncMock(return_value=b"1"))
    actions.memory._ensure_redis = AsyncMock(return_value=redis)
    received = await source.admit(source_request(ledger.row))
    assert received["claims"]["request_id"] in ledger.committed
    eng_key = hashlib.sha256(ledger.row["engagement_id"].encode()).hexdigest()[:24]
    receipt_digest = hashlib.sha256(
        ("browser-mcp.execute:" + ledger.row["request_id"]).encode()
    ).hexdigest()
    redis.get.assert_awaited_once_with(f"osop:tool-budget:{eng_key}:request:{receipt_digest}")


@pytest.mark.asyncio
async def test_missing_signer_and_unknown_commit_never_claim_issued(monkeypatch, signer):
    ledger = Ledger()
    source, actions = make_authority(ledger)
    monkeypatch.delenv("OSOP_BROWSER_SOURCE_SIGNING_PRIVATE_KEY_B64")
    with pytest.raises(BrowserSourceDenied) as absent:
        await source.admit(source_request(ledger.row))
    assert absent.value.status == 503
    actions._authority.assert_not_awaited()
    assert not ledger.committed
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_SIGNING_PRIVATE_KEY_B64", base64.b64encode(b"a" * 32).decode("ascii")
    )
    ledger.commit_fails = True
    with pytest.raises(BrowserSourceDenied) as failed:
        await source.admit(source_request(ledger.row))
    assert failed.value.status == 503
    assert not ledger.committed


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@example.org/path",
        "https://example.org/?token=abc",
        "https://example.org/#fragment",
        "http://example.org",
        "https://example.org.evil.com/path",
        "https://example.org\\@evil.test",
        "https://example.org:0/path",
        "https://example.org:65536/path",
    ],
)
def test_destination_parser_preserves_exact_pins(url):
    if url == "https://example.org.evil.com/path":
        # Syntactically valid but a DIFFERENT independently pinned origin.
        assert exact_origin(url) == "https://example.org.evil.com:443"
    else:
        with pytest.raises(BrowserSourceDenied):
            exact_origin(url)


@pytest.mark.asyncio
async def test_actual_asgi_route_service_auth_duplicate_json_and_issuance(monkeypatch, signer):
    ledger = Ledger()
    source, actions = make_authority(ledger)
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", SERVICE)
    monkeypatch.setenv("OSOP_BROWSER_MCP_BEARER_TOKEN", "other-provider-bearer-" + "s" * 32)
    monkeypatch.setitem(
        api.state, "orchestrator", SimpleNamespace(session_memory=object(), mcp_registry=object())
    )
    monkeypatch.setattr(api, "FlowMCPActionStore", lambda *_: actions)
    app = FastAPI()
    app.include_router(api.router)
    path = "/native-browser/source-preflight"
    headers = {"Authorization": "Bearer " + SERVICE}
    body = source_request(ledger.row)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://local.test"
    ) as client:
        assert (await client.post(path, json=body)).status_code == 401
        assert (
            await client.post(path, json=body, headers={"Authorization": "Bearer " + "other" * 10})
        ).status_code == 403
        assert (
            await client.post(path + "?token=leak", json=body, headers=headers)
        ).status_code == 403
        assert (await client.post(path, content="{}", headers=headers)).status_code == 415
        assert (
            await client.post(
                path, content=b"x" * 2050, headers={**headers, "Content-Type": "application/json"}
            )
        ).status_code == 413
        duplicated = json.dumps(body).replace('"task_id":', '"task_id":"task-evil","task_id":')
        response = await client.post(
            path, content=duplicated, headers={**headers, "Content-Type": "application/json"}
        )
        assert response.status_code == 422
        issued = await client.post(path, json=body, headers=headers)
        assert issued.status_code == 200
        assert issued.headers["cache-control"] == "no-store"
        verify_receipt(issued.json(), signer)
        repeated = await client.post(path, json=body, headers=headers)
        assert repeated.status_code == 409
        assert len(ledger.committed) == 1
