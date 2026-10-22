"""Cross-replica MCP request identity must commit before any target-side I/O."""

import asyncio
from types import SimpleNamespace
from pathlib import Path

import aiohttp
from aiohttp import web
from alembic import command
from alembic.config import Config
from sqlalchemy import func, inspect, select, update
import pytest

from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest
from ai_osop.memory.session_memory import SessionMemory, TaskORM
from ai_osop.memory.supervision_store import (
    SupervisionConflict,
    SupervisionEventORM,
    SupervisionMCPDispatchORM,
    SupervisionStore,
)
from tests.qualification.test_live_planner_execution import live


@pytest.mark.asyncio
async def test_real_loopback_mcp_http_executes_once_across_two_connection_instances(live):
    """Two local workers share the SQL fence, not a process-local request set."""
    maker, planner, _, flow, parent = live
    store = SupervisionStore(planner.session_memory)
    async with maker() as db, db.begin():
        await db.execute(update(TaskORM).where(TaskORM.id == parent.id).values(status="running"))

    class Memory(SessionMemory):
        async def retrieve_hot(self, key):
            return None

        async def consume_mcp_tool_budget(self, engagement_id, qualified_name, agent_id):
            return True

    memory = Memory.__new__(Memory)
    memory._async_session = maker

    request_id = "req-two-replicas-" + flow.id[-12:]
    http_calls = []

    async def handler(request):
        data = await request.json()
        http_calls.append(data["request_id"])
        return web.json_response({
            "request_id": data["request_id"], "status": "success", "result": {"safe": True}
        })

    status_calls = []

    async def status_handler(request):
        data = await request.json()
        status_calls.append(data["request_id"])
        return web.json_response({
            "request_id": data["request_id"], "status": "completed",
            "verified": True,
        })

    app = web.Application()
    app.router.add_post("/mcp/execute", handler)
    app.router.add_post("/mcp/request/status", status_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    async def callback(engagement_id, task_id, kind, metadata):
        if kind == "dispatch_accepted":
            return await store.claim_mcp_dispatch(
                engagement_id, task_id, metadata["server_id"],
                metadata["request_id"], metadata["tool_name"]
            )
        return await store.record_mcp_dispatch_event(
            engagement_id, task_id, metadata["server_id"], metadata["request_id"],
            kind, metadata.get("status", "unknown"),
        )

    try:
        async with aiohttp.ClientSession() as client:
            workers = [
                MCPConnection("loopback-proxy", "127.0.0.1", port, _session=client),
                MCPConnection("loopback-proxy", "127.0.0.1", port, _session=client),
            ]
            for conn in workers:
                conn._initialized = True
                conn._tools["get_status"] = SimpleNamespace(
                    timeout_seconds=4, requires_approval=False
                )
                conn.set_budget_callback(memory.consume_mcp_tool_budget)
                conn.set_execution_event_callback(callback)
            RequestContext.bind(engagement_id=flow.engagement_id, task_id=parent.id)
            try:
                responses = await asyncio.gather(*[
                    conn.execute(MCPExecuteRequest(
                        request_id=request_id,
                        tool_name="get_status", parameters={},
                    )) for conn in workers
                ])
            finally:
                RequestContext.clear()
            # A new replica has no original in-memory remote execution; use
            # the signed PostgreSQL identity and only the advertised status
            # endpoint to verify the result. The original tool is never replayed.
            recovered = MCPConnection(
                "loopback-proxy", "127.0.0.1", port, _session=client
            )
            recovered._initialized = True
            recovered._capabilities = ["mcp_request_status_v1"]
            recovered.set_execution_event_callback(callback)
            claim = await store.get_mcp_dispatch(
                flow.engagement_id, parent.id, "loopback-proxy", request_id
            )
            assert claim is not None and claim["status"] == "provider_returned"
            assert not recovered._executions
            reconciled = await recovered.reconcile_persisted_status(claim)
            assert reconciled["status"] == "confirmed_finished"
        assert sorted(item.status for item in responses) == ["audit_unavailable", "success"]
        assert http_calls == [request_id]
        assert status_calls == [request_id]
        persisted = await store.list_mcp_dispatches(flow.engagement_id, parent.id)
        assert len(persisted) == 1
        assert persisted[0]["status"] == "confirmed_finished"
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_two_real_connections_cannot_admit_same_remote_dispatch(live):
    maker, store, _, flow, parent = live
    first = SupervisionStore(store.session_memory)
    second = SupervisionStore(store.session_memory)
    async with maker() as db, db.begin():
        await db.execute(update(TaskORM).where(TaskORM.id == parent.id).values(status="running"))
    original = (
        flow.engagement_id, parent.id, "mcp-mock-local",
        "req-global-" + flow.id[-12:], "passive_probe",
    )
    decisions = await asyncio.gather(
        first.claim_mcp_dispatch(*original),
        second.claim_mcp_dispatch(*original),
    )
    assert sorted(decisions) == [False, True]
    # Different engagement/worker cannot reuse the same global server/request
    # identifier, including after a process restart.
    assert not await second.claim_mcp_dispatch(*original)
    async with maker() as db:
        rows = (await db.execute(select(SupervisionMCPDispatchORM).where(
            SupervisionMCPDispatchORM.request_id == original[3]
        ))).scalars().all()
        assert len(rows) == 1
        assert rows[0].authorization_version == 1
        assert rows[0].status == "accepted_unconfirmed"
        assert (await db.execute(select(func.count()).select_from(
            SupervisionEventORM
        ).where(
            SupervisionEventORM.engagement_id == flow.engagement_id,
            SupervisionEventORM.kind == "agent.mcp.dispatch_accepted",
        ))).scalar_one() == 1


@pytest.mark.asyncio
async def test_revocation_forbids_new_mcp_dispatch_but_preserves_remote_receipts(live):
    maker, planner, auth, flow, parent = live
    store = SupervisionStore(planner.session_memory)
    async with maker() as db, db.begin():
        await db.execute(update(TaskORM).where(TaskORM.id == parent.id).values(status="running"))
    original_id = "req-inflight-" + flow.id[-12:]
    pair = (flow.engagement_id, parent.id, "local-provider", original_id, "passive_probe")
    assert await store.claim_mcp_dispatch(*pair)
    assert await auth.revoke(flow.engagement_id, "operator-owner", 1, "revoke during remote")
    with pytest.raises(SupervisionConflict):
        await store.claim_mcp_dispatch(
            flow.engagement_id, parent.id, "local-provider",
            "req-revoked-" + flow.id[-12:], "passive_probe"
        )
    # Recording a matching historical observation is a database-only action,
    # not authorization to continue scanning.
    assert await store.record_mcp_dispatch_event(
        flow.engagement_id, parent.id, "local-provider", original_id,
        "execution_unknown", "unknown",
    )
    assert await store.record_mcp_dispatch_event(
        flow.engagement_id, parent.id, "local-provider", original_id,
        "reconciliation_result", "confirmed_stopped",
    )
    assert not await store.record_mcp_dispatch_event(
        flow.engagement_id, parent.id, "different-server", original_id,
        "reconciliation_result", "confirmed_stopped",
    )
    recorded = await store.list_mcp_dispatches(flow.engagement_id, parent.id)
    assert recorded[0]["status"] == "confirmed_stopped"
    assert recorded[0]["authorization_version"] == 1
    assert not any("authorization_ref" in str(row) for row in recorded)


@pytest.mark.asyncio
async def test_failed_mcp_audit_rolls_back_global_dispatch_claim(live):
    maker, planner, _, flow, parent = live
    store = SupervisionStore(planner.session_memory)
    async with maker() as db, db.begin():
        await db.execute(update(TaskORM).where(TaskORM.id == parent.id).values(status="running"))
    original_append = store._append_event

    async def unavailable_audit(*args, **kwargs):
        raise RuntimeError("audit storage down")

    store._append_event = unavailable_audit
    request_id = "req-rollback-" + flow.id[-12:]
    pair = (flow.engagement_id, parent.id, "local-provider", request_id, "passive_probe")
    with pytest.raises(RuntimeError, match="audit storage down"):
        await store.claim_mcp_dispatch(*pair)
    async with maker() as db:
        assert (await db.execute(select(func.count()).select_from(
            SupervisionMCPDispatchORM
        ).where(SupervisionMCPDispatchORM.request_id == request_id))).scalar_one() == 0
    store._append_event = original_append
    assert await store.claim_mcp_dispatch(*pair)


@pytest.mark.asyncio
async def test_remote_receipts_never_regress_verified_stop_or_accept_leaked_status(live):
    maker, planner, _, flow, parent = live
    store = SupervisionStore(planner.session_memory)
    async with maker() as db, db.begin():
        await db.execute(update(TaskORM).where(TaskORM.id == parent.id).values(status="running"))
    request_id = "req-guard-" + flow.id[-12:]
    args = (flow.engagement_id, parent.id, "mock-server", request_id, "passive_probe")
    assert await store.claim_mcp_dispatch(*args)
    assert await store.record_mcp_dispatch_event(
        flow.engagement_id, parent.id, "mock-server", request_id,
        "cancellation_result", "confirmed_stopped",
    )
    assert await store.record_mcp_dispatch_event(
        flow.engagement_id, parent.id, "mock-server", request_id,
        "execution_unknown", "Bearer SECRET_TOKEN_SHOULD_NOT_LEAK",
    )
    records = await store.list_mcp_dispatches(flow.engagement_id, parent.id)
    assert records[0]["status"] == "confirmed_stopped"
    async with maker() as db:
        events = (await db.execute(select(SupervisionEventORM.payload).where(
            SupervisionEventORM.engagement_id == flow.engagement_id,
            SupervisionEventORM.kind == "agent.mcp.execution_unknown",
        ))).scalars().all()
    assert events and events[0]["status"] == "unknown"
    assert "SECRET_TOKEN" not in str(events)


@pytest.mark.asyncio
async def test_live_mcp_dispatch_migration_downgrade_and_upgrade(live):
    """0010 is reversible; downgrading never grants duplicate execution."""
    maker, _, _, _, _ = live
    engine = maker.kw["bind"]
    root = Path(__file__).resolve().parents[2]

    def migrate(connection, operation, revision):
        cfg = Config(str(root / "alembic.ini"))
        cfg.set_main_option("script_location", str(root / "migrations"))
        cfg.attributes["connection"] = connection
        getattr(command, operation)(cfg, revision)

    async with engine.begin() as connection:
        assert await connection.run_sync(
            lambda sync: inspect(sync).has_table("supervision_mcp_dispatches")
        )
        await connection.run_sync(migrate, "downgrade", "0009")
        assert not await connection.run_sync(
            lambda sync: inspect(sync).has_table("supervision_mcp_dispatches")
        )
        await connection.run_sync(migrate, "upgrade", "head")
        assert await connection.run_sync(
            lambda sync: inspect(sync).has_table("supervision_mcp_dispatches")
        )
