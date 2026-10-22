"""Adversarial mocked signed Flow MCP action admission; never contact a target."""

import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Response

from ai_osop.api.routers import flow_mcp_actions as api
from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, SubtaskRecord, Task
from ai_osop.mcp.protocol import (
    MCPExecuteResponse,
    MCPToolDefinition,
    MCPToolParameter,
    SideEffectClass,
)
from ai_osop.orchestrator import flow_mcp_action_executor as engine

EID = "eng-signed-mcp-test"
FID = "flow-signed-mcp-test"
TASK = "task-signed-mcp-test"
ROOT = "task-parent-mcp-test"
SID = "subtask-signed-mcp-test"
AID = "action-" + "a" * 32
ACTOR = {
    "sub": "tenant-owner",
    "role": "senior_operator",
    "claims": {"exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())},
}
PARAMS = {"target_url": "https://example.test/resource", "include_fields": False}


def _sha(value):
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


class FakeMemory:
    def __init__(self):
        self.signed = SimpleNamespace(
            version=5,
            policy_sha256="c" * 64,
            authorization_id="signed-roe-mcp",
        )
        self.session = SessionState(
            session_id=EID,
            created_by="tenant-owner",
            phase="reconnaissance",
            scope=ScopeDefinition(
                engagement_id=EID,
                domains=["example.test"],
                authorization_ref="signed-roe-mcp",
            ),
        )
        self.flow = FlowRecord(
            id=FID,
            engagement_id=EID,
            objective="Authorized read",
            revision=4,
        )
        self.step = SubtaskRecord(
            id=SID,
            flow_id=FID,
            engagement_id=EID,
            task_id=ROOT,
            title="Read metadata",
            approval_required=True,
            task_type="approved_read_metadata",
            agent_type=AgentType.RECON,
            status="dispatched",
            execution_task_id=TASK,
        )
        self.approved = True
        self.assert_signed_authorization = AsyncMock(side_effect=self._signed)
        self.load_session_state = AsyncMock(side_effect=lambda *_: self.session)
        self.load_flow = AsyncMock(side_effect=lambda *_: self.flow)
        self.list_subtasks = AsyncMock(side_effect=lambda *_: [self.step])
        self.is_task_approved = AsyncMock(side_effect=lambda *_: self.approved)
        self.load_task_authoritative = AsyncMock(side_effect=lambda *_: self.task)

    async def _signed(self, engagement_id, expected_version=None):
        if engagement_id != EID or expected_version != 5:
            raise PermissionError("No current signed policy")
        return self.signed

    async def consume_mcp_tool_budget(self, *args, **kwargs):
        return True


class FakeRegistry:
    def __init__(self, memory, declaration):
        self._budget_callback = memory.consume_mcp_tool_budget
        self._execution_event_callback = AsyncMock(return_value=True)
        self._servers = {
            "local_mcp": SimpleNamespace(
                server_id="local_mcp",
                _initialized=True,
                _tools={declaration.name: declaration},
                get_circuit_state=lambda: "closed",
            )
        }
        self.execute_tool = AsyncMock(
            return_value=MCPExecuteResponse(
                request_id="req-" + "e" * 32,
                status="success",
                result={"private": "NEVER LEAK"},
            )
        )


class FakeStore:
    def __init__(self):
        self.prepared = None
        self.prepare = AsyncMock(side_effect=self._prepare)
        self.get = AsyncMock(side_effect=self._get)
        self.list = AsyncMock(side_effect=self._list)
        self.reserve = AsyncMock(side_effect=self._reserve)
        self.settle = AsyncMock(side_effect=self._settle)

    async def _prepare(self, binding, actor, **kwargs):
        assert actor == ACTOR["sub"]
        assert kwargs["manifest_sha256"] == self.expected_manifest_sha256
        self.prepared = {
            "action_id": AID,
            "flow_id": FID,
            "engagement_id": EID,
            "task_id": kwargs["task_id"],
            "subtask_id": kwargs["subtask_id"],
            "server_id": kwargs["server_id"],
            "tool_name": kwargs["tool_name"],
            "status": "prepared",
            "parameters_sha256": kwargs["parameters_sha256"],
            "parameters": kwargs["parameters"],
        }
        return self.prepared

    async def _get(self, binding, actor, action_id):
        return self.prepared

    async def _list(self, binding, actor):
        return {
            "actions": [self.prepared] if self.prepared else [],
            "count": 1 if self.prepared else 0,
            "flow_id": FID,
        }

    async def _reserve(self, binding, actor, action_id):
        assert self.prepared["status"] == "prepared"
        self.prepared.update(status="reserved", request_id="req-" + "e" * 48)
        return {
            **self.prepared,
            "admitted_for_dispatch": True,
            "reservation_token": "res-" + "d" * 64,
        }

    async def _mark_dispatched(self, binding, actor, action_id, request_id, token):
        assert self.prepared["status"] == "reserved"
        assert token == "res-" + "d" * 64
        self.prepared["status"] = "unknown"
        return {**self.prepared, "dispatch_attempt_committed": True}

    async def _settle(self, binding, actor, action_id, request_id, status, provider_receipt=None):
        if status == "finished":
            assert isinstance(provider_receipt, dict)
        else:
            assert provider_receipt is None
        self.prepared["status"] = status
        return dict(self.prepared)


def fixture(monkeypatch):
    memory = FakeMemory()
    declaration = MCPToolDefinition(
        name="inspect_metadata",
        description="Opaque server description",
        parameters=[
            MCPToolParameter(name="target_url", type="string", description="Target"),
            MCPToolParameter(name="include_fields", type="boolean", description="Flag"),
        ],
        returns={"result": "private"},
        scope_check=True,
        side_effect_class=SideEffectClass.READ_ONLY,
    )
    memory.task = Task(
        id=TASK,
        engagement_id=EID,
        flow_id=FID,
        subtask_id=SID,
        parent_task_id=ROOT,
        type="approved_read_metadata",
        agent_type=AgentType.RECON,
        status="running",
        scope_check=True,
        approval_required=True,
        payload={
            "_authorization_version": 5,
            "approval_id": "apr-approved-mcp",
            "operator_approved": True,
            "target": PARAMS["target_url"],
            "mcp_action_id": AID,
            "mcp_server_id": "local_mcp",
            "mcp_tool_name": "inspect_metadata",
            "mcp_declaration_sha256": _sha(
                {
                    "server_id": "local_mcp",
                    "declaration": declaration.model_dump(mode="json"),
                }
            ),
            "mcp_parameters_sha256": _sha(PARAMS),
            "mcp_flow_revision": 4,
        },
    )
    registry = FakeRegistry(memory, declaration)
    store = FakeStore()
    store.expected_manifest_sha256 = _sha(
        {
            "server_id": "local_mcp",
            "declaration": declaration.model_dump(mode="json"),
        }
    )
    store.mark_dispatched = AsyncMock(side_effect=store._mark_dispatched)
    monkeypatch.setattr(engine, "SessionMemory", FakeMemory)
    monkeypatch.setattr(engine, "MCPRegistry", FakeRegistry)
    monkeypatch.setattr(engine, "check_tool_authorization", AsyncMock(return_value=None))
    service = engine.FlowMCPActionExecutor(memory, registry, store)
    return service, memory, registry, store


def binding():
    return {"flow_id": FID, "engagement_id": EID, "revision": 4, "version": 5}


def signed_provider_receipt(monkeypatch, *, request_id: str, task_id: str = TASK):
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({"local_mcp": {"test-key": base64.b64encode(public).decode("ascii")}}),
    )
    claims = {
        "request_id": request_id,
        "engagement_id": EID,
        "task_id": task_id,
        "server_id": "local_mcp",
        "status": "succeeded",
        "verified": True,
        "stopped": False,
        "issued_at": int(time.time()),
    }
    signature = key.sign(
        json.dumps(
            claims,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    )
    return {
        **claims,
        "attestation": {
            "kid": "test-key",
            "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        },
    }


@pytest.mark.asyncio
async def test_prepare_only_persists_preapproved_task_bound_action(monkeypatch):
    service, memory, registry, store = fixture(monkeypatch)
    result = await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    assert result["action_id"] == AID
    assert result["status"] == "prepared"
    assert store.prepare.await_count == 1
    assert memory.is_task_approved.await_count >= 1
    registry.execute_tool.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "revoked_signer",
        "foreign_owner",
        "foreign_flow",
        "paused_flow",
        "unsigned_task",
        "inert_marker",
        "unapproved",
        "foreign_subtask",
        "tampered_manifest",
        "tampered_parameters",
        "foreign_target",
        "invasive_declaration",
        "uninitialized_provider",
        "opaque_parameters",
    ],
)
async def test_prepare_denies_stale_or_forged_authority(monkeypatch, tamper):
    service, memory, registry, store = fixture(monkeypatch)
    params = dict(PARAMS)
    if tamper == "revoked_signer":
        memory.assert_signed_authorization.side_effect = PermissionError("private revoke")
    elif tamper == "foreign_owner":
        memory.session.created_by = "foreign"
    elif tamper == "foreign_flow":
        memory.flow.engagement_id = "eng-other"
    elif tamper == "paused_flow":
        memory.flow.status = "paused"
    elif tamper == "unsigned_task":
        memory.task.payload.pop("approval_id")
    elif tamper == "inert_marker":
        memory.step.task_type = "operator_mcp_capability_review"
    elif tamper == "unapproved":
        memory.approved = False
    elif tamper == "foreign_subtask":
        memory.step.engagement_id = "eng-other"
    elif tamper == "tampered_manifest":
        memory.task.payload["mcp_declaration_sha256"] = "0" * 64
    elif tamper == "tampered_parameters":
        memory.task.payload["mcp_parameters_sha256"] = "0" * 64
    elif tamper == "foreign_target":
        params["target_url"] = "https://unauthorized.invalid/private"
    elif tamper == "invasive_declaration":
        registry._servers["local_mcp"]._tools[
            "inspect_metadata"
        ].side_effect_class = SideEffectClass.INVASIVE_EXPLOIT
    elif tamper == "uninitialized_provider":
        registry._servers["local_mcp"]._initialized = False
    elif tamper == "opaque_parameters":
        params["raw_request"] = "GET /private HTTP/1.1\r\nHost: other.invalid"
    with pytest.raises((engine.FlowMCPActionDenied, PermissionError)):
        await service.prepare(
            binding(),
            ACTOR,
            task_id=TASK,
            subtask_id=SID,
            server_id="local_mcp",
            tool_name="inspect_metadata",
            parameters=params,
        )
    store.prepare.assert_not_awaited()
    registry.execute_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatch_exactly_once_after_reservation_and_no_result_leak(monkeypatch):
    service, _, registry, store = fixture(monkeypatch)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    result = await service.dispatch(binding(), ACTOR, AID)
    assert result["status"] == "unknown"
    assert registry.execute_tool.await_count == 1
    assert registry.execute_tool.await_args.kwargs["request_id"] == "req-" + "e" * 48
    assert store.mark_dispatched.await_count == 1
    assert "NEVER LEAK" not in repr(result)
    with pytest.raises(engine.FlowMCPActionDenied):
        await service.dispatch(binding(), ACTOR, AID)
    assert registry.execute_tool.await_count == 1


@pytest.mark.asyncio
async def test_ordinary_owner_can_dispatch_only_after_distinct_durable_approval(monkeypatch):
    service, memory, registry, store = fixture(monkeypatch)
    ordinary_owner = {**ACTOR, "role": "operator"}
    await service.prepare(
        binding(),
        ordinary_owner,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )

    async def prove_unknown_before_network(*args, **kwargs):
        assert store.prepared["status"] == "unknown"
        return MCPExecuteResponse(request_id=kwargs["request_id"], status="success")

    registry.execute_tool.side_effect = prove_unknown_before_network
    result = await service.dispatch(binding(), ordinary_owner, AID)
    assert result["status"] == "unknown"
    assert store.mark_dispatched.await_count == 1
    assert registry.execute_tool.await_count == 1
    assert memory.is_task_approved.await_count >= 2


@pytest.mark.asyncio
async def test_second_owner_request_cannot_repeat_reserved_or_unknown(monkeypatch):
    service, _, registry, store = fixture(monkeypatch)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    store.prepared["status"] = "reserved"
    with pytest.raises(engine.FlowMCPActionDenied):
        await service.dispatch(binding(), ACTOR, AID)
    store.reserve.assert_not_awaited()
    registry.execute_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_unconfirmed_durable_attempt_cannot_reach_provider(monkeypatch):
    service, _, registry, store = fixture(monkeypatch)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    store.mark_dispatched.side_effect = RuntimeError("PG ack lost")
    await service.dispatch(binding(), ACTOR, AID)
    registry.execute_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_ambiguous_transport_settles_unknown_without_replay(monkeypatch):
    service, _, registry, store = fixture(monkeypatch)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    registry.execute_tool.side_effect = TimeoutError("remote may have executed")
    result = await service.dispatch(binding(), ACTOR, AID)
    assert result["status"] == "unknown"
    assert store.reserve.await_count == 1
    assert store.mark_dispatched.await_count == 1
    assert registry.execute_tool.await_count == 1


@pytest.mark.asyncio
async def test_explicit_signed_receipt_reconciles_status_only_without_tool_retry(monkeypatch):
    service, _, registry, store = fixture(monkeypatch)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    result = await service.dispatch(binding(), ACTOR, AID)
    assert result["status"] == "unknown"
    signed = signed_provider_receipt(monkeypatch, request_id=store.prepared["request_id"])
    recorded = await service.reconcile(binding(), ACTOR, AID, signed)
    assert recorded["status"] == "finished"
    assert store.settle.await_args.kwargs["provider_receipt"] == signed
    assert registry.execute_tool.await_count == 1
    assert store.reserve.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    ["foreign_task", "foreign_request", "unsigned", "untrusted_key", "forged_verified", "stale"],
)
async def test_reconcile_rejects_forged_or_stale_provider_attestation(monkeypatch, tamper):
    service, _, registry, store = fixture(monkeypatch)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    await service.dispatch(binding(), ACTOR, AID)
    signed = signed_provider_receipt(monkeypatch, request_id=store.prepared["request_id"])
    if tamper == "foreign_task":
        signed["task_id"] = "task-foreign"
    elif tamper == "foreign_request":
        signed["request_id"] = "req-" + "0" * 48
    elif tamper == "unsigned":
        del signed["attestation"]
    elif tamper == "untrusted_key":
        signed["attestation"]["kid"] = "unknown-key"
    elif tamper == "forged_verified":
        signed["verified"] = False
    elif tamper == "stale":
        signed["issued_at"] -= 10000
    with pytest.raises(engine.FlowMCPActionDenied) as exc:
        await service.reconcile(binding(), ACTOR, AID, signed)
    assert exc.value.status == 409
    assert store.settle.await_count == 1  # UNKNOWN dispatch settlement only
    assert store.prepared["status"] == "unknown"
    assert registry.execute_tool.await_count == 1


@pytest.mark.asyncio
async def test_public_readback_filters_private_parameters_and_result(monkeypatch):
    service, _, _, _ = fixture(monkeypatch)
    monkeypatch.setattr(api, "_executor", lambda: service)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    got = await api.get_flow_mcp_action(
        FID,
        AID,
        Response(),
        expected_engagement_id=EID,
        expected_revision=4,
        expected_authorization_version=5,
        operator=ACTOR,
    )
    assert got["action_id"] == AID
    assert got["target_effect_verified"] is False
    assert got["safe_to_automatically_retry"] is False
    assert "example.test" not in repr(got)


@pytest.mark.asyncio
async def test_list_readback_uses_durable_catalog_and_never_exposes_params(monkeypatch):
    service, _, _, store = fixture(monkeypatch)
    monkeypatch.setattr(api, "_executor", lambda: service)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    response = Response()
    catalog = await api.list_flow_mcp_actions(
        FID,
        response,
        expected_engagement_id=EID,
        expected_revision=4,
        expected_authorization_version=5,
        operator=ACTOR,
    )
    assert catalog["actions"][0]["action_id"] == AID
    assert catalog["actions"][0]["execution_started"] is False
    assert "example.test" not in repr(catalog)
    assert "parameters" not in catalog["actions"][0]
    assert catalog["flow_revision"] == 4
    assert response.headers["Cache-Control"] == "private, no-store"
    assert store.list.await_count == 1


@pytest.mark.asyncio
async def test_http_rejects_missing_bearer_and_duplicate_json_without_reservation(monkeypatch):
    service, _, registry, store = fixture(monkeypatch)
    monkeypatch.setattr(api, "_executor", lambda: service)
    app = FastAPI()
    app.include_router(api.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        denied = await client.post(
            f"/flows/{FID}/mcp-actions",
            json={"task_id": TASK},
        )
    assert denied.status_code == 401
    store.prepare.assert_not_awaited()
    registry.execute_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_http_duplicate_confirmation_not_accepted_even_with_mock_auth(monkeypatch):
    service, _, _, store = fixture(monkeypatch)
    monkeypatch.setattr(api, "_executor", lambda: service)
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api._operator] = lambda: ACTOR
    raw = (
        '{"expected_engagement_id":"' + EID + '","expected_revision":4,'
        '"expected_authorization_version":5,"task_id":"' + TASK + '",'
        '"subtask_id":"' + SID + '","server_id":"local_mcp",'
        '"tool_name":"inspect_metadata","parameters":{},'
        '"explicit_human_confirmation":true,"explicit_human_confirmation":false}'
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        denied = await client.post(
            f"/flows/{FID}/mcp-actions",
            content=raw,
            headers={"content-type": "application/json"},
        )
    assert denied.status_code == 422
    store.prepare.assert_not_awaited()


@pytest.mark.asyncio
async def test_reconcile_route_rejects_duplicate_receipts_and_oversized_json(monkeypatch):
    service, _, registry, store = fixture(monkeypatch)
    monkeypatch.setattr(api, "_executor", lambda: service)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    await service.dispatch(binding(), ACTOR, AID)
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api._operator] = lambda: ACTOR
    body = {
        "expected_engagement_id": EID,
        "expected_revision": 4,
        "expected_authorization_version": 5,
        "explicit_human_confirmation": True,
        "provider_receipt": {},
    }
    repeated = json.dumps(body)[:-1] + ',"provider_receipt":{}}'
    huge = json.dumps({**body, "provider_receipt": {"opaque": "x" * 9000}})
    endpoint = f"/flows/{FID}/mcp-actions/{AID}/reconcile"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        dupe = await client.post(
            endpoint, content=repeated, headers={"content-type": "application/json"}
        )
        oversized = await client.post(
            endpoint, content=huge, headers={"content-type": "application/json"}
        )
    assert dupe.status_code == 422
    assert oversized.status_code == 413
    assert store.settle.await_count == 1  # original unknown dispatch only
    assert registry.execute_tool.await_count == 1


@pytest.mark.asyncio
async def test_receipt_does_not_promote_prepared_action_or_prove_target_effect(monkeypatch):
    service, _, registry, store = fixture(monkeypatch)
    await service.prepare(
        binding(),
        ACTOR,
        task_id=TASK,
        subtask_id=SID,
        server_id="local_mcp",
        tool_name="inspect_metadata",
        parameters=PARAMS,
    )
    valid_proof = signed_provider_receipt(monkeypatch, request_id="req-" + "e" * 48)
    with pytest.raises(engine.FlowMCPActionDenied) as exc:
        await service.reconcile(binding(), ACTOR, AID, valid_proof)
    assert exc.value.status == 409
    store.settle.assert_not_awaited()
    registry.execute_tool.assert_not_awaited()
