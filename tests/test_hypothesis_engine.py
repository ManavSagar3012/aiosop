from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.context_manager_agent import ContextManagerAgent
from ai_osop.core.config import AgentType
from ai_osop.core.hypothesis_engine import HypothesisEngine
from ai_osop.core.models import Task


class FakeGraphMemory:
    def __init__(self):
        self.persisted = []

    async def get_all_nodes_for_engagement(self, engagement_id):
        return []

    async def get_all_edges_for_engagement(self, engagement_id):
        return []

    async def run_read_query(self, cypher, params=None):
        params = params or {}
        if "MATCH (e:Endpoint" in cypher:
            return [
                {
                    "id": "ep-1",
                    "url": "https://app.example.com/api/admin/users",
                    "path": "/api/admin/users",
                    "method": "POST",
                    "type": "api",
                    "technologies": ["Next.js", "React"],
                    "parameters": ["userId", "returnUrl"],
                    "query_keys": ["userId", "returnUrl"],
                    "body_schema_keys": ["id", "role"],
                    "auth_required": True,
                    "auth_class": "cookie",
                    "status_code": 200,
                    "workflow_id": "wf-1",
                },
                {
                    "id": "ep-graphql",
                    "url": "https://app.example.com/graphql",
                    "path": "/graphql",
                    "method": "POST",
                    "type": "api",
                    "technologies": ["GraphQL", "React"],
                    "parameters": ["query"],
                    "query_keys": [],
                    "body_schema_keys": ["query", "variables"],
                    "auth_required": True,
                    "auth_class": "bearer",
                    "status_code": 200,
                },
                {
                    "id": "ep-2",
                    "url": "https://app.example.com/checkout/coupon",
                    "path": "/checkout/coupon",
                    "method": "POST",
                    "type": "api",
                    "technologies": ["React"],
                    "parameters": ["coupon", "redirect"],
                    "query_keys": ["redirect"],
                    "body_schema_keys": ["coupon", "quantity"],
                    "auth_required": True,
                    "auth_class": "bearer",
                    "status_code": 200,
                },
                {
                    "id": "ep-3",
                    "url": "https://app.example.com/api/proxy",
                    "path": "/api/proxy",
                    "method": "GET",
                    "type": "api",
                    "technologies": ["Next.js"],
                    "parameters": ["url"],
                    "query_keys": ["url"],
                    "body_schema_keys": [],
                    "auth_required": False,
                    "auth_class": "anonymous",
                    "status_code": 200,
                },
            ]
        if "MATCH (a:Asset" in cypher:
            return [
                {
                    "id": "asset-1",
                    "value": "s3.bucket.example.com",
                    "type": "subdomain",
                    "source": "recon",
                    "metadata": {},
                    "confidence": 0.9,
                }
            ]
        return []

    async def get_hypotheses_by_engagement(self, engagement_id):
        return []

    async def add_hypothesis(self, hypothesis):
        self.persisted.append(hypothesis)
        return hypothesis.id


@pytest.mark.asyncio
async def test_hypothesis_engine_infers_researchable_hypotheses():
    gm = FakeGraphMemory()
    engine = HypothesisEngine(gm)

    hypotheses = await engine.generate_hypotheses("eng-1", focus="recon", limit=10)

    titles = {h.title for h in hypotheses}
    assert "Authorization bypass or IDOR across authenticated surface" in titles
    assert "GraphQL batching, alias abuse, or hidden mutation exposure" in titles
    assert "Client bundle or source-map leakage may expose hidden routes or secrets" in titles
    assert "URL-bearing parameters may support SSRF, open redirect, or token leakage" in titles
    assert "Business-logic or race-condition abuse may bypass workflow invariants" in titles


@pytest.mark.asyncio
async def test_hypothesis_engine_persists_generated_items():
    gm = FakeGraphMemory()
    engine = HypothesisEngine(gm)

    hypotheses = await engine.generate_and_persist("eng-1", focus="recon", limit=5)

    assert hypotheses
    assert len(gm.persisted) == len(hypotheses)


@pytest.mark.asyncio
async def test_context_manager_agent_generates_hypotheses():
    gm = FakeGraphMemory()
    session_memory = SimpleNamespace(store_agent_state=AsyncMock())
    ctx = SimpleNamespace(
        agent_id="context-1",
        agent_type=AgentType.CONTEXT_MANAGER,
        session_id="eng-1",
        graph_memory=gm,
        session_memory=session_memory,
        skill_engine=None,
        status="idle",
    )
    agent = ContextManagerAgent(ctx)
    await agent._setup_resources()

    task = Task(
        id="task-hyp-1",
        type="generate_hypotheses",
        agent_type=AgentType.CONTEXT_MANAGER,
        payload={"focus": "attack surface", "limit": 4},
        engagement_id="eng-1",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["hypotheses_count"] >= 1
    assert gm.persisted
    assert session_memory.store_agent_state.await_count >= 1
