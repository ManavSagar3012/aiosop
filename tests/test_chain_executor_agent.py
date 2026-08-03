"""Real chain execution: when the graph reports a validated foothold chain,
the ChainExecutorAgent drives linked exploit tasks end-to-end.

Refactor of exploit chaining from "reasoned but unexecuted" to "reasoned, planned,
and validated through the existing ExploitAgent pipeline (with dependencies)."."""

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task, Vulnerability


class _ChainGraph:
    def __init__(self, chains: List[Dict[str, Any]]):
        self._chains = chains

    async def find_vulnerability_chains(self, engagement_id: str) -> List[Dict[str, Any]]:
        return self._chains

    async def run_write_query(self, *args, **kwargs):
        pass

    async def run_read_query(self, *args, **kwargs):
        return []

    async def add_vulnerability(self, vuln):
        pass


def _make_chain(engage_id: str) -> List[Dict[str, Any]]:
    return [
        {
            "nodes": [
                {"endpoint_id": "ep-1", "url": "https://t/rest/user/login", "vuln": {"id": "v-1"}},
                {"endpoint_id": "ep-2", "url": "https://t/rest/basket/1", "vuln": {"id": "v-2"}},
            ],
            "likelihood": 0.9,
        }
    ]


@pytest.mark.asyncio
async def test_chain_executor_validates_each_chain_hop():
    ctx = MagicMock()
    ctx.graph_memory = _ChainGraph(_make_chain("eng-chained"))
    ctx.llm_client = AsyncMock()
    ctx.session_memory = MagicMock()
    ctx.vector_memory = MagicMock()
    ctx.agent_id = "chain-executor-1"
    executed: List[Dict[str, Any]] = []

    class _ExploitFacade:
        async def validate_exploit(
            self, endpoint: str, vuln_class: str, payload: Dict[str, Any]
        ) -> Dict[str, Any]:
            executed.append({"endpoint": endpoint, "payload": payload})
            return {
                "validated": True,
                "technique": vuln_class,
                "evidence": f"db error at {endpoint}",
            }

    exploit_tool = _ExploitFacade()

    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent

    agent = ChainExecutorAgent(ctx)
    # Inject the exploit facade
    agent._exploit = exploit_tool

    task = Task(
        type="execute_exploit_chain",
        agent_type=AgentType.ATTACK_CHAIN,
        payload={
            "engagement_id": "eng-chained",
            "foothold_auth": {"token": "bearer"},
        },
        engagement_id="eng-chained",
    )
    ctx.current_task = task

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert "chain_run" in result
    assert len(executed) == 2
    # Both hops in one chain execute (order preserved)
    assert executed[0]["endpoint"].endswith("/rest/user/login")
    assert executed[1]["endpoint"].endswith("/rest/basket/1")


@pytest.mark.asyncio
async def test_chain_hop_records_ledger_and_metrics():
    """After a two-hop chain, metrics show per-hop timing + step count, and the
    injected ledger saw the chain_executed transition per hop."""
    import ai_osop.core.metrics_a2 as metrics_a2

    metrics_a2.reset()

    transitions: List[Dict[str, Any]] = []

    class _LedgerStub:
        async def transition(self, event_id: str, to_state: str, reason: str = "") -> None:
            transitions.append({"event_id": event_id, "to_state": to_state})

    ctx = MagicMock()
    ctx.graph_memory = _ChainGraph(_make_chain("eng-ledger"))
    ctx.llm_client = AsyncMock()
    ctx.session_memory = MagicMock()
    ctx.vector_memory = MagicMock()
    ctx.agent_id = "chain-executor-2"

    class _ExploitFacade:
        async def validate_exploit(
            self, endpoint: str, vuln_class: str, payload: Dict[str, Any]
        ) -> Dict[str, Any]:
            return {"validated": True, "technique": vuln_class, "evidence": "ok"}

    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent

    agent = ChainExecutorAgent(ctx)
    agent._exploit = _ExploitFacade()
    agent.ledger = _LedgerStub()

    task = Task(
        type="execute_exploit_chain",
        agent_type=AgentType.ATTACK_CHAIN,
        payload={"engagement_id": "eng-ledger"},
        engagement_id="eng-ledger",
    )
    ctx.current_task = task

    result = await agent._execute(task)
    assert result["status"] == "success"
    # Ledger saw chain_executed for both hops
    assert {t["event_id"] for t in transitions} == {"v-1", "v-2"}
    assert all(t["to_state"] == "chain_executed" for t in transitions)
    # Metrics rendered: step counter reached 2 and hop histogram exists
    rendered = metrics_a2.render()
    assert "ai_osop_a2_chain_steps_executed_total" in rendered
    assert "ai_osop_a2_chain_hop_seconds_count" in rendered
    assert "ai_osop_a2_chain_execution_seconds" in rendered


@pytest.mark.asyncio
async def test_executor_aborts_on_first_hop_failure():
    from ai_osop.agents.base import AgentContext

    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "exec-1"
    ctx.agent_type = AgentType.ATTACK_CHAIN
    ctx.session_id = "eng-c"
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.find_vulnerability_chains = AsyncMock(
        return_value=[
            {
                "id": "chain-X",
                "nodes": [
                    {"url": "https://a", "vuln": {"id": "v-1", "type": "sqli", "payload": {}}},
                    {"url": "https://b", "vuln": {"id": "v-2", "type": "xss", "payload": {}}},
                    {"url": "https://c", "vuln": {"id": "v-3", "type": "rce", "payload": {}}},
                ],
            }
        ]
    )

    class _Facade:
        calls: int = 0

        async def validate_exploit(self, endpoint, vuln_class, payload):
            self.calls += 1
            return {"validated": self.calls == 1}  # hop 1 ok; hop 2 fails

    facade = _Facade()
    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent

    agent = ChainExecutorAgent(ctx)
    agent._exploit = facade

    task = Task(
        type="execute_exploit_chain",
        agent_type=AgentType.ATTACK_CHAIN,
        payload={},
        engagement_id="eng-c",
    )
    out = await agent._execute(task)

    assert facade.calls == 2  # stopped before hop 3
    assert len(out["chain_run"]) == 2
    assert out["status"] == "chain_failed"
    assert out.get("aborted_at_hop") == 1


@pytest.mark.asyncio
async def test_executor_records_receipt_per_attempted_hop(tmp_path):
    from ai_osop.agents.base import AgentContext

    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "exec-2"
    ctx.agent_type = AgentType.ATTACK_CHAIN
    ctx.session_id = "eng-r"
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.find_vulnerability_chains = AsyncMock(
        return_value=[
            {
                "id": "chain-R",
                "nodes": [
                    {"url": "https://a", "vuln": {"id": "v-1", "type": "sqli", "payload": {}}},
                    {"url": "https://b", "vuln": {"id": "v-2", "type": "xss", "payload": {}}},
                ],
            }
        ]
    )

    class _Facade:
        async def validate_exploit(self, endpoint, vuln_class, payload):
            return {"validated": True, "receipt_id": f"rcpt-underlying"}

    store = MagicMock()
    store.record = AsyncMock(return_value="sig-hop")
    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent

    agent = ChainExecutorAgent(ctx)
    agent._exploit = _Facade()
    agent.receipt_store = store

    task = Task(
        type="execute_exploit_chain",
        agent_type=AgentType.ATTACK_CHAIN,
        payload={},
        engagement_id="eng-r",
    )
    # DEVIATION from plan: the plan's exact test omits enabling the evidence flag,
    # but the impl gates emission on settings.evidence_receipts_enabled (per plan
    # step 3 and the Part I precedent in tests/test_exploit_agent.py). Enable it
    # here (and restore) so the receipt path actually runs.
    from ai_osop.core.config import settings

    settings.evidence_receipts_enabled = True
    try:
        await agent._execute(task)
    finally:
        settings.evidence_receipts_enabled = False

    assert store.record.await_count == 2
    hop0 = store.record.await_args_list[0].args[0]
    assert hop0.chain_id == "chain-R"
    assert hop0.hop_idx == 0
    assert hop0.vuln_id == "v-1"


@pytest.mark.asyncio
async def test_abort_chain_marks_hops_and_stops():
    from ai_osop.agents.base import AgentContext

    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "exec-3"
    ctx.agent_type = AgentType.ATTACK_CHAIN
    ctx.session_id = "eng-c"
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.find_vulnerability_chains = AsyncMock(
        return_value=[
            {
                "id": "chain-X",
                "nodes": [
                    {"url": "https://a", "vuln": {"id": "v-1", "type": "sqli", "payload": {}}},
                    {"url": "https://b", "vuln": {"id": "v-2", "type": "xss", "payload": {}}},
                ],
            }
        ]
    )

    class _Facade:
        def __init__(self):
            self.calls = 0

        async def validate_exploit(self, endpoint, vuln_class, payload):
            self.calls += 1
            return {"validated": True}

    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent

    agent = ChainExecutorAgent(ctx)
    agent._exploit = _Facade()
    agent._abort_flags.add("chain-X")

    task = Task(
        type="execute_exploit_chain",
        agent_type=AgentType.ATTACK_CHAIN,
        payload={"chain_id": "chain-X"},
        engagement_id="eng-c",
    )
    out = await agent._execute(task)
    assert out["status"] == "chain_failed"
    assert "aborted" in (out.get("note") or "")
    assert agent._exploit.calls == 0  # stopped before the first hop


@pytest.mark.asyncio
async def test_abort_chain_task_type_registers_flag_and_returns():
    from ai_osop.agents.base import AgentContext

    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "exec-4"
    ctx.agent_type = AgentType.ATTACK_CHAIN
    ctx.session_id = "eng-c"

    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent

    agent = ChainExecutorAgent(ctx)
    assert agent.supports_task_type("abort_chain")

    task = Task(
        type="abort_chain",
        agent_type=AgentType.ATTACK_CHAIN,
        payload={"chain_id": "chain-Z"},
        engagement_id="eng-c",
    )
    out = await agent._execute(task)
    assert "chain-Z" in agent._abort_flags
    assert out["status"] == "abort_registered"


@pytest.mark.asyncio
async def test_abort_records_chain_failed_ledger_state():
    """Gate (Task 26): when a hop aborts (boom in the exploit facade), the
    ledger MUST record a chain_failed transition for the affected vuln, and the
    outcome status must be chain_failed — leaving an auditable terminal state."""
    from ai_osop.agents.base import AgentContext

    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "exec-gate"
    ctx.agent_type = AgentType.ATTACK_CHAIN
    ctx.session_id = "eng-gate"
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.find_vulnerability_chains = AsyncMock(
        return_value=[
            {
                "id": "chain-G",
                "nodes": [
                    {"url": "https://a", "vuln": {"id": "v-1", "type": "sqli", "payload": {}}},
                ],
            }
        ]
    )

    class _BoomFacade:
        async def validate_exploit(self, endpoint, vuln_class, payload):
            raise RuntimeError("exploit boom")

    class _LedgerStub:
        def __init__(self):
            self.calls = []

        async def transition(self, event_id: str, to_state: str, reason: str = "") -> None:
            self.calls.append((event_id, to_state, reason))

    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent

    agent = ChainExecutorAgent(ctx)
    agent._exploit = _BoomFacade()
    ledger = _LedgerStub()
    agent.ledger = ledger

    task = Task(
        type="execute_exploit_chain",
        agent_type=AgentType.ATTACK_CHAIN,
        payload={"chain_id": "chain-G"},
        engagement_id="eng-gate",
    )
    out = await agent._execute(task)

    assert out["status"] == "chain_failed"
    assert ledger.calls, "ledger saw no transition — chain_failed state not recorded"
    assert any(
        event_id == "v-1" and to_state == "chain_failed"
        for (event_id, to_state, _reason) in ledger.calls
    ), f"expected ledger transition (v-1, chain_failed), got: {ledger.calls}"


@pytest.mark.asyncio
async def test_abort_records_chain_failed_ledger_state():
    """Abuse gate (Task 26): when the executor aborts mid-chain the ledger gets
    chain_failed, not chain_executed, for the aborted vuln."""
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "exec-abort"
    ctx.agent_type = AgentType.ATTACK_CHAIN
    ctx.session_id = "eng-ab"
    ctx.graph_memory = MagicMock()
    ctx.graph_memory.find_vulnerability_chains = AsyncMock(
        return_value=[
            {
                "id": "chain-AB",
                "nodes": [
                    {"url": "https://a", "vuln": {"id": "v-1", "type": "sqli", "payload": {}}},
                    {"url": "https://b", "vuln": {"id": "v-2", "type": "xss", "payload": {}}},
                ],
            }
        ]
    )

    from ai_osop.agents.chain_executor_agent import ChainExecutorAgent

    class _FailOnSecond:
        calls = 0

        async def validate_exploit(self, endpoint, vuln_class, payload):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("target unreachable")
            return {"validated": True, "receipt_id": "rcpt-hop-1"}

    ledger = MagicMock()
    ledger.transition = AsyncMock()
    agent = ChainExecutorAgent(ctx)
    agent._exploit = _FailOnSecond()
    agent.ledger = ledger

    task = Task(
        type="execute_exploit_chain",
        agent_type=AgentType.ATTACK_CHAIN,
        payload={"chain_id": "chain-AB"},
        engagement_id="eng-ab",
    )
    out = await agent._execute(task)

    assert out["status"] == "chain_failed"
    assert out["aborted_at_hop"] == 1
    # Ledger saw exactly one success (chain_executed) then one failure (chain_failed).
    # Transition calls are positional: transition(vuln_id, state, reason=...).
    calls = [
        c.args[1] if len(c.args) >= 2 else c.kwargs.get("to_state")
        for c in ledger.transition.await_args_list
    ]
    assert "chain_failed" in calls
    assert calls.count("chain_failed") >= 1
