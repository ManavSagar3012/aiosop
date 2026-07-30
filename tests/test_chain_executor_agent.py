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
        async def validate_exploit(self, endpoint: str, vuln_class: str, payload: Dict[str, Any]) -> Dict[str, Any]:
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
