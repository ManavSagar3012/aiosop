"""No signed task can bypass one-shot dispatch via the legacy HTTP analyzer."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.workflow_agent import PlaywrightAgent
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.core.diff_auth_analyzer import DiffAuthAnalyzer


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe", [False, True])
async def test_real_pg_agent_refuses_direct_multi_identity_http(unsafe):
    memory = SessionMemory.__new__(SessionMemory)
    analyzer = SimpleNamespace(analyze=AsyncMock())
    agent = SimpleNamespace(
        ctx=SimpleNamespace(session_memory=memory, session_id="eng-owned"),
        diff_auth_analyzer=analyzer,
    )
    with pytest.raises(PermissionError, match="verified replay evidence"):
        await PlaywrightAgent._execute_run_diff_auth_analysis(agent, {
            "engagement_id": "eng-owned", "workflow_id": "wf-owned",
            "user_a": "owner-a", "user_b": "target-b", "include_unsafe": unsafe,
        })
    analyzer.analyze.assert_not_awaited()


@pytest.mark.asyncio
async def test_legacy_api_workflow_discovery_is_tenant_scoped():
    class GraphContext:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def run(self, cypher, args):
            self.cypher, self.args = cypher, args
            async def rows():
                if False:
                    yield {}
            return rows()

    graph_ctx = GraphContext()
    analyzer = DiffAuthAnalyzer(None, SimpleNamespace(
        _driver=SimpleNamespace(session=lambda: graph_ctx)
    ))
    assert await analyzer._load_endpoints("eng-owned", "wf-original") == []
    assert "Workflow {id:$wid, engagement_id:$eid}" in graph_ctx.cypher
    assert "Endpoint {type: 'api', engagement_id:$eid}" in graph_ctx.cypher
    assert graph_ctx.args == {"wid": "wf-original", "eid": "eng-owned"}
