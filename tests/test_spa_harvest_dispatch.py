"""Wiring test: the recon agent dispatches spa_harvest to the SPA harvester and
persistent results land in graph memory through the governed client."""

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task


class _FakeCtx:
    def __init__(self):
        self.graph_memory = MagicMock()
        self.graph_memory.add_endpoint = AsyncMock()
        self.current_task = Task(
            type="spa_harvest",
            agent_type=AgentType.RECON,
            payload={},
            engagement_id="eng-123",
        )
        self.mcp_registry = MagicMock()
        self.session_memory = MagicMock()
        self.vector_memory = MagicMock()
        self.llm_client = MagicMock()
        self.agent_id = "agent-recon-1"


class _Client:
    def __init__(self):
        self.requests: List[str] = []

    async def get(self, url: str, **kw: Any):
        self.requests.append(url)
        r = MagicMock()
        r.status_code = 200
        r.headers = {}
        if url.endswith("main.js"):
            r.text = 'const api="/rest/products/search?q=x"; fetch(`${host}/rest/user/login`);'
        else:
            r.text = """
            <script src="/static/main.js"></script>
            <a href="/">home</a>
            <script>window.routes=["/rest/basket/1","/rest/products/search?q=y"];</script>
            """
        return r


class _CtxManager:
    def __init__(self, client):
        self._client = client

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *a):
        return False


@pytest.mark.asyncio
async def test_recon_dispatches_spa_harvest_to_harvester():
    """ReconAgent must support the spa_harvest task type and persist endpoints."""
    from ai_osop.agents.recon_agent import ReconAgent

    ctx = _FakeCtx()
    agent = ReconAgent(ctx)

    client = _Client()
    agent.get_governed_client = MagicMock(return_value=_CtxManager(client))

    task = Task(
        type="spa_harvest",
        agent_type=AgentType.RECON,
        payload={"url": "https://example.local", "target": "https://example.local"},
        engagement_id="eng-123",
    )
    ctx.current_task = task

    # Force the dispatch path so we need no other agent services
    result = await agent._execute(task)

    assert result["status"] == "completed"
    assert result["endpoints_persisted"] >= 1
    assert result["js_files_seen"] >= 1
    assert ctx.graph_memory.add_endpoint.await_count >= 2
    urls = [call.args[0].url for call in ctx.graph_memory.add_endpoint.await_args_list]
    assert any("/rest/products/search" in u for u in urls)
    assert any("/rest/user/login" in u for u in urls)
