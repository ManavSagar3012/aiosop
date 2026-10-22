"""Adversarial, non-network qualification of current Flow MCP preflight."""

from __future__ import annotations

import copy
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import settings
from ai_osop.mcp.protocol import MCPRegistry, MCPToolDefinition, MCPToolParameter, SideEffectClass
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.flow_resource_folders import FlowResourceFolders
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.flow_mcp_action_approval_preflight import (
    FlowMCPActionApprovalPreflight,
    _resource_pointer,
)
from ai_osop.orchestrator.flow_mcp_action_executor import FlowMCPActionExecutor


ACTION = "action-" + "1" * 32
ARTIFACT = "artifact-" + "2" * 32
FOLDER = "folder-" + "3" * 32
SHA = "a" * 64
ART_SHA = "b" * 64
MANIFEST = "c" * 64
PARAMETERS = {"url": "https://owned.example/page", "depth": 2}


def tool():
    return MCPToolDefinition(
        name="fetch_page",
        description="Read a bounded approved page",
        parameters=[
            MCPToolParameter(name="url", type="string", description="Target"),
            MCPToolParameter(name="depth", type="integer", description="Depth", required=False),
        ],
        returns={"type": "object"},
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=True,
        scope_check=True,
    )


def binding():
    return {
        "engagement_id": "eng-durable",
        "flow_id": "flow-authorized",
        "revision": 6,
        "version": 3,
        "authorization_id": "auth-3",
        "authorization_sha256": SHA,
    }


def operator():
    return {
        "sub": "owner-1",
        "role": "operator",
        "claims": {"exp": int(datetime.now(timezone.utc).timestamp()) + 120},
        "token_sha256": "d" * 64,
    }


def payload(store):
    return {
        "mcp_action_id": ACTION,
        "mcp_flow_revision": 6,
        "mcp_server_id": "browser-mcp",
        "mcp_tool_name": "fetch_page",
        "mcp_declaration_sha256": store.declaration_sha256(tool(), "browser-mcp"),
        "mcp_parameters_sha256": store.parameters_sha256(PARAMETERS),
        "_authorization_version": 3,
        "approval_id": "apr-independent",
        "operator_approved": True,
        "url": PARAMETERS["url"],
    }


class Result:
    def __init__(self, value=None):
        self.value = value

    def mappings(self):
        return self

    def one_or_none(self):
        return self.value

    def scalar_one_or_none(self):
        return self.value


class DB:
    def __init__(self, obj):
        self.obj = obj
        self.read_queries = []
        self.disabled_rows = {"owner-1": False, "human-senior": False}
        self.revoked_token = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    @asynccontextmanager
    async def begin(self):
        yield self

    async def execute(self, statement, args=None):
        query = str(statement)
        self.read_queries.append((query, args))
        assert query.startswith("SELECT "), "Preflight must issue SELECT ONLY"
        if "FROM tasks" in query:
            return Result({"payload": copy.deepcopy(self.obj.task_payload)})
        if "FROM operator_token_revocations" in query:
            return Result("revoked" if self.revoked_token else None)
        if "FROM operator_subject_controls" in query:
            return Result(self.disabled_rows.get(args["actor"]))
        if "FROM flow_artifact_reviews" in query:
            return Result({"reviewer_sub": "human-senior"})
        raise AssertionError("Unexpected SQL; preflight must not call execution state change")


class Harness:
    def __init__(self):
        self.memory = SessionMemory()
        self.registry = MCPRegistry()
        self.registry._servers["browser-mcp"] = SimpleNamespace(
            server_id="browser-mcp",
            _initialized=True,
            _tools={"fetch_page": tool()},
            get_circuit_state=lambda: "closed",
        )
        self.store = FlowMCPActionStore(self.memory, self.registry)
        self.executor = object.__new__(FlowMCPActionExecutor)
        self.executor.memory = self.memory
        self.executor.registry = self.registry
        self.executor.store = self.store
        self.executor._authority = AsyncMock(return_value=object())
        self.preflight = FlowMCPActionApprovalPreflight(self.executor, self.store)
        self.task_payload = payload(self.store)
        self.row = {
            "engagement_id": "eng-durable",
            "flow_id": "flow-authorized",
            "owner_id": "owner-1",
            "flow_revision": 6,
            "authorization_version": 3,
            "authorization_id": "auth-3",
            "authorization_sha256": SHA,
            "action_id": ACTION,
            "task_id": "task-1",
            "subtask_id": "subtask-1",
            "server_id": "browser-mcp",
            "tool_name": "fetch_page",
            "side_effect_class": SideEffectClass.READ_ONLY.value,
            "declaration_sha256": self.store.declaration_sha256(tool(), "browser-mcp"),
            "parameters_sha256": self.store.parameters_sha256(PARAMETERS),
            "safe_parameters": copy.deepcopy(PARAMETERS),
            "status": "prepared",
            "cancel_requested": False,
            "approval_id": "apr-independent",
            "lease_id": "lease-current",
            "lease_owner_id": "worker-1",
        }
        self.db = DB(self)
        self.store._sessions = lambda: (lambda: self.db)
        self.store._authority = AsyncMock(
            return_value={"scope": {"engagement_id": "eng-durable", "domains": ["owned.example"]}}
        )
        self.store._row = AsyncMock(side_effect=lambda *_args, **_kwargs: copy.deepcopy(self.row))
        self.store._approved_task = AsyncMock(
            return_value={
                "action_id": ACTION,
                "approval_id": "apr-independent",
                "lease_id": "lease-current",
                "lease_owner_id": "worker-1",
            }
        )

    async def check(self, **updates):
        kw = dict(
            action_id=ACTION,
            task_id="task-1",
            subtask_id="subtask-1",
            server_id="browser-mcp",
            tool_name="fetch_page",
        )
        kw.update(updates)
        return await self.preflight.check(binding(), operator(), **kw)


@pytest.mark.asyncio
async def test_prepared_action_with_current_signed_approval_returns_sha_only() -> None:
    h = Harness()
    result = await h.check(expected_parameters_sha256=h.row["parameters_sha256"])
    assert result["allowed"] is True
    assert result["code"] == "preflight_eligible"
    assert result["action_status"] == "prepared"
    assert result["parameters_sha256"] == h.row["parameters_sha256"]
    assert result["provider_contacted"] is False
    assert result["approval_issued"] is False
    assert result["dispatch_performed"] is False
    assert result["reservation_performed"] is False
    assert result["guarantees_future_dispatch"] is False
    assert h.store._approved_task.await_count == 1
    assert h.executor._authority.await_count == 1
    assert len(h.db.read_queries) == 1
    assert "owned.example" not in str(result)
    assert "safe_parameters" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "reserved"),
        ("status", "unknown"),
        ("status", "finished"),
        ("cancel_requested", True),
        ("task_id", "task-other"),
        ("subtask_id", "subtask-foreign"),
        ("owner_id", "alien"),
        ("flow_revision", 5),
        ("authorization_sha256", "f" * 64),
        ("side_effect_class", "write"),
        ("declaration_sha256", "f" * 64),
    ],
)
async def test_stale_or_foreign_action_lineage_never_preflights(field, value):
    h = Harness()
    h.row[field] = value
    result = await h.check()
    assert result["allowed"] is False
    assert result["code"] == "action_unavailable"
    assert not h.db.read_queries


@pytest.mark.asyncio
async def test_uninitialized_registry_modified_schema_and_active_tool_denied():
    h = Harness()
    conn = h.registry._servers["browser-mcp"]
    conn._initialized = False
    assert (await h.check())["code"] == "declaration_denied"
    conn._initialized = True
    conn._tools["fetch_page"] = tool().model_copy(
        update={"side_effect_class": SideEffectClass.RECON_ACTIVE}
    )
    assert (await h.check())["code"] == "declaration_denied"
    conn._tools["fetch_page"] = tool().model_copy(update={"description": "replaced"})
    assert (await h.check())["code"] == "action_unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        {"url": "https://owned.example/page?key=secret"},
        {"url": "https://other.example/page"},
        {"url": "https://owned.example/page", "headers": "SECRET"},
        {"url": "https://owned.example/page", "depth": True},
        {"url": "https://owned.example/page", "depth": [2]},
    ],
)
async def test_tampered_durable_parameters_rejected_without_echo(params):
    h = Harness()
    h.row["safe_parameters"] = params
    response = await h.check()
    assert response["allowed"] is False
    assert response["code"] == "parameters_denied"
    assert "SECRET" not in str(response)
    assert "other.example" not in str(response)


@pytest.mark.asyncio
async def test_target_outside_exact_human_approved_task_or_scope_denied():
    h = Harness()
    h.task_payload["url"] = "https://owned.example/other"
    response = await h.check()
    assert response["code"] == "scope_denied"
    h = Harness()
    h.store._authority.return_value["scope"]["domains"] = ["not-owned.example"]
    response = await h.check()
    assert response["code"] == "scope_denied"


@pytest.mark.asyncio
async def test_durable_independent_approval_lease_failure_denied_without_secrets():
    h = Harness()
    h.store._approved_task.side_effect = RuntimeError("password=private-target.internal")
    response = await h.check()
    assert response["code"] == "approval_denied"
    assert "password" not in str(response)
    assert "private-target" not in str(response)


@pytest.mark.asyncio
async def test_flow_signed_authority_failure_precedes_any_pg_or_tool_reads():
    h = Harness()
    h.executor._authority.side_effect = RuntimeError("token-internal-secret")
    result = await h.check()
    assert result["code"] == "signed_flow_denied"
    h.store._row.assert_not_awaited()
    assert "token-internal-secret" not in str(result)


@pytest.mark.asyncio
async def test_explicit_query_sha_and_invalid_identifier_rejected():
    h = Harness()
    assert (await h.check(expected_parameters_sha256="f" * 64))["code"] == "action_unavailable"
    assert (await h.check(expected_parameters_sha256="secret"))["code"] == "invalid_request"
    assert (await h.check(action_id="action-../../escape"))["code"] == "invalid_request"
    # Manifest hints do not conjure unapproved resource attachments.
    no_resource = await h.check(expected_manifest_sha256="c" * 64)
    assert no_resource["allowed"] is True and no_resource["resource_bound"] is False


def bound_payload(h, *, folder=True):
    h.task_payload.update(
        resource_artifact_id=ARTIFACT,
        resource_artifact_sha256=ART_SHA,
        resource_authorization_sha256=SHA,
        resource_command_sha256="e" * 64,
    )
    if folder:
        h.task_payload["mcp_resource_binding"] = {
            "folder_id": FOLDER,
            "manifest_sha256": MANIFEST,
            "catalog_revision": 2,
        }


@pytest.mark.asyncio
async def test_bound_resource_requires_original_sha_and_independent_senior(monkeypatch):
    h = Harness()
    bound_payload(h)
    src = {
        "items": [
            {
                "artifact_id": ARTIFACT,
                "sha256": ART_SHA,
                "original_name": "safe.txt",
                "classification": "utf8_inert_text",
                "size_bytes": 9,
            }
        ]
    }
    snapshot = AsyncMock(return_value=src)
    review = AsyncMock(return_value=None)
    catalog = AsyncMock(return_value={"revision": 2})
    folders = AsyncMock(
        return_value=(
            [
                {
                    "id": FOLDER,
                    "flow_id": "flow-authorized",
                    "engagement_id": "eng-durable",
                    "name": "files",
                }
            ],
            [
                {
                    "engagement_id": "eng-durable",
                    "flow_id": "flow-authorized",
                    "folder_id": FOLDER,
                    "artifact_id": ARTIFACT,
                    "artifact_sha256": ART_SHA,
                }
            ],
        )
    )
    monkeypatch.setattr(FlowResourceFolders, "_snapshot", snapshot)
    monkeypatch.setattr(FlowResourceFolders, "_approved_review", review)
    monkeypatch.setattr(FlowResourceFolders, "_catalog_row", catalog)
    monkeypatch.setattr(FlowResourceFolders, "_rows", folders)
    result = await h.check(expected_manifest_sha256=MANIFEST)
    assert result["allowed"] is True
    assert result["resource_bound"] is True
    assert result["resource_artifact_sha256"] == ART_SHA
    snapshot.assert_awaited_once()
    review.assert_awaited_once()
    catalog.assert_awaited_once()
    folders.assert_awaited_once()
    h.task_payload["mcp_resource_binding"]["catalog_revision"] = 3
    assert (await h.check(expected_manifest_sha256=MANIFEST))["code"] == "resource_denied"
    h.task_payload["mcp_resource_binding"]["catalog_revision"] = 2
    src["items"][0]["sha256"] = "f" * 64
    assert (await h.check(expected_manifest_sha256=MANIFEST))["code"] == "resource_denied"
    src["items"][0]["sha256"] = ART_SHA
    review.side_effect = RuntimeError("private-review-note=SECRET")
    result = await h.check(expected_manifest_sha256=MANIFEST)
    assert result["code"] == "resource_denied" and "SECRET" not in str(result)


@pytest.mark.asyncio
async def test_resource_bindings_refuse_wrong_digest_or_missing_required_sha():
    h = Harness()
    bound_payload(h)
    assert (await h.check(expected_manifest_sha256="f" * 64))["code"] == "resource_denied"
    h.task_payload["mcp_resource_binding"]["manifest_sha256"] = MANIFEST
    h.task_payload["resource_authorization_sha256"] = "f" * 64
    assert (await h.check(expected_manifest_sha256=MANIFEST))["code"] == "resource_denied"
    h.task_payload.pop("resource_artifact_sha256")
    assert (await h.check(expected_manifest_sha256=MANIFEST))["code"] == "resource_denied"


@pytest.mark.parametrize(
    "bad",
    [
        {"resource_artifact_id": ARTIFACT},
        {
            "mcp_resource_binding": {
                "folder_id": FOLDER,
                "manifest_sha256": MANIFEST,
                "catalog_revision": True,
            }
        },
        {
            "resource_artifact_id": "../artifact",
            "resource_artifact_sha256": ART_SHA,
            "resource_authorization_sha256": SHA,
            "resource_command_sha256": "e" * 64,
        },
    ],
)
def test_partial_ambiguous_or_invalid_resource_pointer_denied(bad):
    with pytest.raises(Exception, match="Current immutable resource"):
        _resource_pointer(bad, MANIFEST)


def test_constructor_rejects_inconsistent_production_stores():
    h = Harness()
    other = FlowMCPActionStore(h.memory, h.registry)
    with pytest.raises(ValueError):
        FlowMCPActionApprovalPreflight(h.executor, other)


@pytest.mark.asyncio
async def test_no_provider_invocation_budget_or_hidden_mutation():
    h = Harness()
    h.registry.call_tool = AsyncMock(side_effect=AssertionError("no provider permitted"))
    h.memory.consume_mcp_tool_budget = AsyncMock(side_effect=AssertionError("no budget debit"))
    h.store.reserve = AsyncMock(side_effect=AssertionError("no reservation"))
    assert (await h.check())["allowed"] is True
    h.registry.call_tool.assert_not_awaited()
    h.memory.consume_mcp_tool_budget.assert_not_awaited()
    h.store.reserve.assert_not_awaited()


@pytest.mark.asyncio
async def test_current_owner_token_and_subject_revocations_fail_closed(monkeypatch):
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    h = Harness()
    assert (await h.check())["allowed"] is True
    h.db.revoked_token = True
    assert (await h.check())["code"] == "signed_flow_denied"
    h.db.revoked_token = False
    h.db.disabled_rows["owner-1"] = True
    assert (await h.check())["code"] == "signed_flow_denied"
    h.db.disabled_rows.pop("owner-1")
    assert (await h.check())["code"] == "signed_flow_denied"


@pytest.mark.asyncio
async def test_bound_resource_missing_or_disabled_senior_subject_denied(monkeypatch):
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    h = Harness()
    bound_payload(h, folder=False)
    monkeypatch.setattr(
        FlowResourceFolders,
        "_snapshot",
        AsyncMock(return_value={"items": [{"artifact_id": ARTIFACT, "sha256": ART_SHA}]}),
    )
    monkeypatch.setattr(FlowResourceFolders, "_approved_review", AsyncMock(return_value=None))
    h.db.disabled_rows.pop("human-senior")
    assert (await h.check(expected_manifest_sha256=MANIFEST))["code"] == "resource_denied"
    h.db.disabled_rows["human-senior"] = True
    assert (await h.check(expected_manifest_sha256=MANIFEST))["code"] == "resource_denied"
    h.db.disabled_rows["human-senior"] = False
    result = await h.check(expected_manifest_sha256=MANIFEST)
    assert result["allowed"] is True and result["resource_bound"] is True
