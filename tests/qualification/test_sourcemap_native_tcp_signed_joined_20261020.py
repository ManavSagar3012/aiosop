"""Joined SourceMap MCPRegistry -> real owned TCP Uvicorn -> native signed receipt.

Only the native/registry hop uses real 127.0.0.1 TCP. Central HTTPS preflight is
httpx.MockTransport with an independently signed fixture response: this suite
does not prove live HTTPS, PostgreSQL 0027/0035, or current signed Task/ROE.
The local registry approval and quota store is an explicitly in-memory fixture.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import stat
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Optional

import aiohttp
import pytest
import uvicorn

from ai_osop.core.models import AgentType, ScopeDefinition, SessionState, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.test_source_map_signed_original_intake_20261020 import (
    ACTION,
    APPROVAL,
    DIGEST,
    DOCUMENT,
    ENGAGEMENT,
    NATIVE,
    REQUEST_ID,
    SECRET,
    TASK,
    configure,
    request,
)


@pytest.fixture(autouse=True)
def _clear_registry_identity() -> Any:
    RequestContext.clear()
    yield
    RequestContext.clear()


class _LocalApprovalAndBudget:
    """Scoped in-memory simulation of the registry gate, never a PG authority."""

    def __init__(self) -> None:
        self.session = SessionState(
            session_id=ENGAGEMENT,
            scope=ScopeDefinition(
                engagement_id=ENGAGEMENT,
                domains=["authorized.example"],
                authorization_ref="local-fixture-only",
            ),
            roe={"allow_read_only": True},
            phase="reconnaissance",
        )
        self.task = Task(
            id=TASK,
            type="recon",
            agent_type=AgentType.RECON,
            engagement_id=ENGAGEMENT,
            status="running",
            payload={"approval_id": APPROVAL},
        )
        self.approved = True
        self.budget = 2
        self.spent = 0

    async def load_session_state(self, engagement_id: str) -> Optional[SessionState]:
        return self.session if engagement_id == ENGAGEMENT else None

    async def load_task(self, task_id: str) -> Optional[Task]:
        return self.task if task_id == TASK else None

    async def is_task_approved(self, task_id: str, engagement_id: str, approval_id: str) -> bool:
        return (
            self.approved
            and task_id == TASK
            and engagement_id == ENGAGEMENT
            and approval_id == APPROVAL
        )

    async def consume_mcp_tool_budget(
        self, engagement_id: str, tool_name: str, agent_id: Optional[str]
    ) -> bool:
        assert (engagement_id, tool_name) == (
            ENGAGEMENT,
            "source-map-mcp.inspect_local_original_sourcemap",
        )
        if self.spent >= self.budget:
            return False
        self.spent += 1
        return True


@asynccontextmanager
async def _owned_uvicorn(app: Any) -> AsyncIterator[int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(32)
    listener.setblocking(False)
    port = int(listener.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            access_log=False,
            lifespan="off",
        )
    )
    task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        for _ in range(100):
            if server.started:
                break
            if task.done():
                raise AssertionError("Owned native SourceMap listener exited")
            await asyncio.sleep(0.02)
        assert server.started
        yield port
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=5)
        except asyncio.TimeoutError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        listener.close()


async def _registry(
    port: int,
    memory: _LocalApprovalAndBudget,
    events: list[tuple[str, str, str, dict[str, Any]]],
) -> MCPRegistry:
    registry = MCPRegistry()
    registry.set_budget_callback(memory.consume_mcp_tool_budget)

    async def record(engagement: str, task_id: str, kind: str, metadata: dict[str, Any]) -> bool:
        events.append((engagement, task_id, kind, metadata))
        return True

    # A local event list observes the real MCPConnection reconciliation route;
    # it is NOT the production durable PostgreSQL event writer.
    registry.set_execution_event_callback(record)
    await registry.register_server("source-map-mcp", "127.0.0.1", port, NATIVE)
    initialized = await registry.initialize_server(
        "source-map-mcp", scope={}, credentials={}, session_id=ENGAGEMENT
    )
    assert initialized.status == "ready"
    assert initialized.capabilities == [
        "mcp_bound_receipts_v1",
        "original_sourcemap_signed_preflight_v1",
    ]
    assert [tool.name for tool in initialized.tools] == ["inspect_local_original_sourcemap"]
    assert initialized.tools[0].requires_approval is True
    assert initialized.tools[0].scope_check is True
    return registry


@pytest.mark.asyncio
async def test_real_tcp_registry_original_bytes_signed_receipt_and_restart_replay(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native, original, journal, central_requests = configure(monkeypatch, tmp_path)
    assert original.read_bytes() == DOCUMENT
    assert hashlib.sha256(original.read_bytes()).hexdigest() == DIGEST
    if os.name == "posix":
        assert not original.stat().st_mode & 0o222
    else:
        assert original.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY

    observed_binding: list[dict[str, str]] = []
    verified_bytes: list[bytes] = []
    actual_binding = native._source_binding
    actual_read = native._read_original_bytes

    def capture_binding(payload: Any) -> dict[str, str]:
        bound = actual_binding(payload)
        observed_binding.append(dict(bound))
        return bound

    def capture_original(root: Path, digest: str) -> bytes:
        contents = actual_read(root, digest)  # real double read and SHA check
        verified_bytes.append(contents)
        return contents

    monkeypatch.setattr(native, "_source_binding", capture_binding)
    monkeypatch.setattr(native, "_read_original_bytes", capture_original)
    memory = _LocalApprovalAndBudget()
    events: list[tuple[str, str, str, dict[str, Any]]] = []

    async with _owned_uvicorn(native.app) as port:
        registry = await _registry(port, memory, events)
        try:
            RequestContext.bind(
                engagement_id=ENGAGEMENT,
                task_id=TASK,
                flow_id="flow-fixture",
                subtask_id="subtask-fixture",
            )
            response = await registry.execute_tool(
                "source-map-mcp",
                "inspect_local_original_sourcemap",
                {"artifact_sha256": DIGEST},
                request_id=REQUEST_ID,
            )
            assert response.status == "success", response.model_dump()
            assert response.request_id == REQUEST_ID
            assert response.result is not None
            assert response.result["source_side_signed_authorization_verified"] is True
            assert response.result["source_original_bytes_sha256_verified"] is True
            assert response.result["credentials_disclosed"] is False
            assert response.result["sources"] == ["source_0.js", "source_1.js"]
            assert response.result["findings"][0]["secret_type_counts"]["aws_access_key"] == 1
            assert observed_binding == [
                {
                    "request_id": REQUEST_ID,
                    "engagement_id": ENGAGEMENT,
                    "task_id": TASK,
                    "server_id": "source-map-mcp",
                }
            ]
            assert verified_bytes == [DOCUMENT]
            assert len(central_requests) == 1
            assert central_requests[0]["body"] == {
                **observed_binding[0],
                "tool_name": "inspect_local_original_sourcemap",
                "artifact_sha256": DIGEST,
            }
            assert len(list(journal.glob("*.used"))) == 2
            completed = list(journal.glob("completed-*.json"))
            assert len(completed) == 1
            persisted = json.loads(completed[0].read_text(encoding="utf-8"))
            assert persisted["action_id"] == ACTION
            assert persisted["artifact_sha256"] == DIGEST
            assert persisted["metadata"] == response.result
            receipt = persisted["provider_receipt"]
            assert provider_receipt_is_signed(
                receipt, "source-map-mcp", REQUEST_ID, ENGAGEMENT, TASK
            )
            assert response.metadata["signed_provider_receipt"] == receipt
            assert [kind for _, _, kind, _ in events] == [
                "dispatch_accepted",
                "execution_started",
                "execution_finished",
                "reconciliation_result",
            ]
            assert events[-1][3]["status"] == "confirmed_finished"
            assert events[-1][3]["attested_receipt"] == receipt
            for sensitive in (SECRET, "private-test-password", "alice"):
                assert sensitive not in response.model_dump_json()
                assert sensitive not in completed[0].read_text(encoding="utf-8")

            # Duplicate request ID is fenced by the MCPConnection before TCP.
            duplicate = await registry.execute_tool(
                "source-map-mcp",
                "inspect_local_original_sourcemap",
                {"artifact_sha256": DIGEST},
                request_id=REQUEST_ID,
            )
            assert duplicate.status == "duplicate_request"
            assert len(central_requests) == 1
        finally:
            await registry.close_all()

        # A freshly connected registry has no in-process dedup cache. Native
        # fsynced Action/request tombstones must still stop original replay.
        recovered = await _registry(port, memory, events)
        try:
            replay = await recovered.execute_tool(
                "source-map-mcp",
                "inspect_local_original_sourcemap",
                {"artifact_sha256": DIGEST},
                request_id=REQUEST_ID,
            )
            assert replay.status == "unknown"  # native HTTP 503, outcome ambiguous
            assert "signed_provider_receipt" not in replay.metadata
            assert len(central_requests) == 2
            assert len(list(journal.glob("completed-*.json"))) == 1
            assert len(verified_bytes) == 1

            # Mock central may reissue the SAME approved Action under another
            # request ID; the native action tombstone independently fences it.
            memory.budget = 3
            new_request = await recovered.execute_tool(
                "source-map-mcp",
                "inspect_local_original_sourcemap",
                {"artifact_sha256": DIGEST},
                request_id="req-" + "2" * 48,
            )
            assert new_request.status == "unknown"
            assert "signed_provider_receipt" not in new_request.metadata
            assert len(central_requests) == 3
            assert len(list(journal.glob("action_id-*.used"))) == 1
            assert len(list(journal.glob("request_id-*.used"))) == 2
            assert len(list(journal.glob("completed-*.json"))) == 1
            assert len(verified_bytes) == 1
        finally:
            await recovered.close_all()


@pytest.mark.asyncio
async def test_real_tcp_forged_task_and_signature_never_mint_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native, _, journal, central_requests = configure(monkeypatch, tmp_path)
    async with _owned_uvicorn(native.app) as port:
        # Transport authorization alone does not confer signed Task identity.
        forged = request()
        forged["execution_binding"]["task_id"] = "task-foreign"
        async with aiohttp.ClientSession(headers={"Authorization": "Bearer " + NATIVE}) as client:
            async with client.post(
                f"http://127.0.0.1:{port}/mcp/execute",
                json=forged,
                allow_redirects=False,
            ) as reply:
                assert reply.status == 503
                result = await reply.json()
                assert result["status"] == "error"
                assert "provider_receipt" not in result
        assert len(central_requests) == 1
        assert not list(journal.iterdir())

    # Independent fixture issuer signs invalid signature bytes. Native
    # rejects it after the real registry TCP call, before original disk read.
    native, _, journal, central_requests = configure(
        monkeypatch, tmp_path / "bad-signature", corrupted=True
    )
    events: list[tuple[str, str, str, dict[str, Any]]] = []
    memory = _LocalApprovalAndBudget()
    async with _owned_uvicorn(native.app) as port:
        registry = await _registry(port, memory, events)
        try:
            RequestContext.bind(engagement_id=ENGAGEMENT, task_id=TASK)
            failed = await registry.execute_tool(
                "source-map-mcp",
                "inspect_local_original_sourcemap",
                {"artifact_sha256": DIGEST},
                request_id=REQUEST_ID,
            )
            assert failed.status == "unknown"
            assert "signed_provider_receipt" not in failed.metadata
            assert len(central_requests) == 1
            assert not list(journal.iterdir())
            assert [kind for _, _, kind, _ in events] == [
                "dispatch_accepted",
                "execution_started",
                "execution_unknown",
            ]
        finally:
            await registry.close_all()


@pytest.mark.asyncio
async def test_registry_context_approval_budget_and_native_bearer_fence_tcp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native, _, journal, central_requests = configure(monkeypatch, tmp_path)
    events: list[tuple[str, str, str, dict[str, Any]]] = []
    memory = _LocalApprovalAndBudget()
    async with _owned_uvicorn(native.app) as port:
        registry = await _registry(port, memory, events)
        try:
            missing_context = await registry.execute_tool(
                "source-map-mcp",
                "inspect_local_original_sourcemap",
                {"artifact_sha256": DIGEST},
                request_id="req-" + "a" * 48,
            )
            assert missing_context.status == "scope_context_missing"
            RequestContext.bind(engagement_id=ENGAGEMENT, task_id=TASK)
            memory.approved = False
            unapproved = await registry.execute_tool(
                "source-map-mcp",
                "inspect_local_original_sourcemap",
                {"artifact_sha256": DIGEST},
                request_id="req-" + "b" * 48,
            )
            assert unapproved.status == "approval_required"
            memory.approved = True
            memory.budget = 0
            over_budget = await registry.execute_tool(
                "source-map-mcp",
                "inspect_local_original_sourcemap",
                {"artifact_sha256": DIGEST},
                request_id="req-" + "c" * 48,
            )
            assert over_budget.status == "quota_exceeded"
            assert not central_requests
            assert not events
            assert not list(journal.iterdir())

            # Native endpoint additionally demands its own bearer before any
            # independent central issuer is contacted.
            async with aiohttp.ClientSession() as client:
                async with client.post(
                    f"http://127.0.0.1:{port}/mcp/execute",
                    json=request(),
                    allow_redirects=False,
                ) as reply:
                    assert reply.status == 503
                    assert "provider_receipt" not in await reply.json()
            assert not central_requests
            assert not list(journal.iterdir())
        finally:
            await registry.close_all()
