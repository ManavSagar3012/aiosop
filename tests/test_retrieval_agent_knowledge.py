"""RetrievalAgent semantic-recall wiring (P2 learning brain).

Exercises the record -> recall loop through the agent using a real mock-mode
VectorMemory backend and a deterministic embedder (no DB, no LLM).
"""
import hashlib

import pytest
from unittest.mock import MagicMock

from ai_osop.agents.base import AgentContext
from ai_osop.agents.retrieval_agent import RetrievalAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.vector_memory import VectorMemory


def _embedder(dims: int = 32):
    async def _embed(text: str):
        vec = [0.0] * dims
        for tok in (text or "").lower().split():
            vec[int(hashlib.sha1(tok.encode()).hexdigest(), 16) % dims] += 1.0
        return vec

    return _embed


def _task(ttype: str, **payload):
    return Task(type=ttype, agent_type=AgentType.RETRIEVAL, payload=payload, engagement_id="e1")


@pytest.fixture
def agent():
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "retrieval-1"
    ctx.agent_type = AgentType.RETRIEVAL
    ctx.session_id = "s1"
    vm = VectorMemory("postgresql://unused")
    vm._mock_mode = True
    vm._mock_findings = []
    ctx.vector_memory = vm
    ctx.llm_client = MagicMock()
    ctx.llm_client.get_embedding = _embedder()
    return RetrievalAgent(ctx)


@pytest.mark.asyncio
async def test_record_then_recall_through_agent(agent):
    await agent._setup_resources()
    assert agent.findings_kb is not None  # wired to the vector backend

    r = await agent._execute(_task(
        "record_finding",
        finding={"vuln_type": "ssrf", "severity": "high", "title": "SSRF via url",
                 "description": "url param hits internal metadata", "id": "v1", "engagement_id": "e1"},
    ))
    assert r["status"] == "completed" and r["recorded"] is True

    await agent._execute(_task(
        "record_finding",
        finding={"vuln_type": "xss", "severity": "medium", "title": "Reflected XSS",
                 "description": "q param reflected unescaped", "id": "v2", "engagement_id": "e1"},
    ))

    rec = await agent._execute(_task("recall_findings", query="url param hits internal metadata ssrf", limit=2))
    assert rec["status"] == "completed"
    assert rec["results"], "expected a recalled finding"
    assert rec["results"][0]["metadata"]["finding_id"] == "v1"
    assert rec["results"][0]["score"] > 0.0


@pytest.mark.asyncio
async def test_recall_findings_requires_query(agent):
    await agent._setup_resources()
    r = await agent._execute(_task("recall_findings"))
    assert r["status"] == "error"


@pytest.mark.asyncio
async def test_keyword_path_still_works(agent):
    """The original methodology-lookup path is unchanged."""
    await agent._setup_resources()
    r = await agent._execute(_task("knowledge_query", vulnerability_class="ssrf"))
    assert r["status"] == "completed"
    assert "results" in r  # empty (no JSON files) but the path is intact
