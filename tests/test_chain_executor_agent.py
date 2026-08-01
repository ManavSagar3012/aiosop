"""Real chain execution: when the graph reports a validated foothold chain,
the ChainExecutorAgent drives linked exploit tasks end-to-end.

Refactor of exploit chaining from "reasoned but unexecuted" to "reasoned, planned,
and validated through the existing ExploitAgent pipeline (with dependencies)."."""

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

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
