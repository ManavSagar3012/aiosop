"""End-to-end proof that the full blind-oracle seam hangs together against a
live sink: namespaced OAST token mint -> agent validation with a mocked sandbox
surfacing ``oast_interaction`` -> ``ReceiptStore.record`` -> ``ReceiptStore.get``
round-trip -> ``verify_chain(engagement) is True``.

Marked ``integration``: requires a live Postgres (the ``exploit_receipts``
table). Skips cleanly when Postgres is absent.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.exploit_agent import ExploitValidationAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task

pytestmark = pytest.mark.integration


@pytest.fixture
async def sa_engine():
    """Real SQLAlchemy AsyncEngine via SessionMemory (Part I pattern)."""
    from ai_osop.memory.session_memory import SessionMemory

    sm = SessionMemory()
    try:
        await sm.connect()
    except Exception as e:
        pytest.skip(f"Postgres not available: {e}")
    try:
        from sqlalchemy import text

        async with sm._pg_engine.begin() as conn:
            await conn.execute(text("DELETE FROM exploit_receipts"))
    except Exception:
        pass
    yield sm._pg_engine
    await sm.close()


async def test_blind_ssrf_receipt_chain_verified(blind_sink_target, sa_engine, tmp_path):
    from ai_osop.adapters.oast_mcp import OASTAdapter
    from ai_osop.evidence.migrations import ensure_schema
    from ai_osop.evidence.store import ReceiptStore
    from ai_osop.safety.scope import AuditIntegrity

    url, seen = blind_sink_target

    # 1. Real ReceiptStore over the injected engine, evidence under tmp_path.
    await ensure_schema(sa_engine)
    store = ReceiptStore(
        sa_engine=sa_engine,
        integrity=AuditIntegrity(b"live-blind-verify-key"),
        evidence_root=tmp_path,
    )

    # 2. Mock OASTAdapter: register returns a token + sink callback URL; poll
    # returns an interaction carrying the probe context (the seam we are
    # exercising end-to-end is receipt capture, not a real OAST server).
    adapter = MagicMock(spec=OASTAdapter)
    adapter.register = AsyncMock(return_value=("tok-blind-1", f"{url}/cb/tok-blind-1"))
    adapter.poll = AsyncMock(
        return_value=[
            {
                "seq": 1,
                "interaction_id": "i1",
                "token": "tok-blind-1",
                "kind": "http",
                "context": {
                    "engagement_id": "eng-live-1",
                    "vuln_class": "blind_xss",
                    "injection_point": "body:comment",
                    "payload_hash": "abc",
                },
            }
        ]
    )

    # 3. Agent with mocked sandbox returning oast_interaction so the receipt
    # captures oracle_signals.oast_hit=True.
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "exploit-live"
    ctx.agent_type = AgentType.EXPLOIT_VALIDATION
    ctx.session_id = "eng-live-1"
    ctx.llm_client = AsyncMock()
    ctx.audit_callback = AsyncMock()
    ctx.graph_memory = AsyncMock()
    ctx.coordination_bus = AsyncMock()
    ctx.current_task = Task(
        type="validate_exploit",
        agent_type=AgentType.EXPLOIT_VALIDATION,
        payload={},
        engagement_id="eng-live-1",
    )
    agent = ExploitValidationAgent(ctx)
    agent.burp_adapter = AsyncMock()
    agent.oast_adapter = adapter
    agent.receipt_store = store
    agent._execute_in_sandbox = AsyncMock(
        return_value={
            "status": "success",
            "http_code": 200,
            "body": "",
            "oast_interaction": {"type": "http", "token": "tok-blind-1"},
        }
    )

    # 4. Mint the namespaced token through the agent path (validates the
    # caller-side schema and returns the sink callback).
    token, cb_url = await agent._mint_namespaced_token(
        vuln_class="blind_xss",
        injection_point="body:comment",
        payload="<script src=x>",
    )
    assert token == "tok-blind-1"
    assert cb_url == f"{url}/cb/tok-blind-1"

    # 5. Token-poll oracle confirms the blind class.
    ok, conf, _note = await agent._confirm_blind_by_token("blind_xss", token)
    assert ok is True and conf == 0.6

    # 6. Full validation seam with receipts enabled: agent records to the real
    # ReceiptStore via its injected ``record``.
    from ai_osop.core.config import settings

    settings.evidence_receipts_enabled = True
    try:
        result = await agent._validate_exploit(
            {
                "target": url,
                "payload": "<script src=x>",
                "vulnerability_id": "vuln-live-1",
                "approval_id": "apr-live-1",
                "vuln_class": "blind_xss",
            }
        )
    finally:
        settings.evidence_receipts_enabled = False

    assert result["confirmed"] is True
    assert result["confidence"] == 0.97  # OOB canary outranks body signature

    # 7. Round-trip: the row we just wrote must be fetchable and its HMAC
    # chain for the engagement must replay cleanly.
    receipts = await store.for_engagement("eng-live-1")
    assert len(receipts) == 1
    r = receipts[0]
    assert r.vuln_id == "vuln-live-1"
    assert r.oracle_signals.get("oast_hit") is True
    got = await store.get(r.receipt_id)
    assert got is not None and got.receipt_id == r.receipt_id
    assert await store.verify_chain("eng-live-1") is True
