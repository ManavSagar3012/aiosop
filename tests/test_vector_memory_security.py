"""Tenant-isolated mock semantic memory; legacy unscoped payloads never surface."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.vector_memory import VectorMemory

VECTOR = [1.0] + [0.0] * 1535


@pytest.fixture(autouse=True)
def clean_context():
    RequestContext.clear()
    yield
    RequestContext.clear()


@pytest.mark.asyncio
async def test_explicit_mock_memory_is_engagement_scoped_and_redacted(monkeypatch):
    monkeypatch.setenv("OSOP_MOCK_LLM", "true")
    memory = VectorMemory("unused://never-contacted")
    await memory.connect()
    await memory.store_payload(
        "xss", "Bearer SECRET_IDENTIFIER_12345678", VECTOR,
        {"target": "https://private.example/path?token=secret", "fitness": 0.9},
        engagement_id="eng-a", task_id="task-a",
    )
    assert not await memory.search_similar_payloads(
        VECTOR, engagement_id="eng-b", task_id="task-b"
    )
    stored = await memory.search_similar_payloads(
        VECTOR, engagement_id="eng-a", task_id="task-a"
    )
    assert len(stored) == 1
    assert "SECRET_IDENTIFIER" not in str(stored)
    assert "private.example" not in str(stored)
    assert stored[0]["content"] == "[REDACTED]"
    assert len(stored[0]["metadata"]["target_sha256"]) == 64
    await memory.close()


@pytest.mark.asyncio
async def test_signed_version_change_and_context_mismatch_deny_semantic_reads(monkeypatch):
    monkeypatch.setenv("OSOP_MOCK_LLM", "true")
    task = Task(
        id="task-owned", engagement_id="eng-owned", status="running",
        type="summarize_context", agent_type=AgentType.CONTEXT_MANAGER,
        payload={"_authorization_version": 1},
    )
    session = SimpleNamespace(
        assert_signed_authorization=AsyncMock(return_value=SimpleNamespace(version=1)),
        load_task_authoritative=AsyncMock(return_value=task),
    )
    memory = VectorMemory("unused://never-contacted", session_memory=session)
    await memory.connect()
    await memory.store_payload(
        "context_summary", "Confirmed asset inventory only", VECTOR, {},
        engagement_id="eng-owned", task_id=task.id, category="summary",
    )
    RequestContext.bind(engagement_id="eng-foreign", task_id=task.id)
    with pytest.raises(PermissionError, match="context differs"):
        await memory.search_similar_payloads(
            VECTOR, engagement_id="eng-owned", task_id=task.id, category="summary",
        )
    RequestContext.clear()
    session.assert_signed_authorization.return_value = SimpleNamespace(version=2)
    with pytest.raises(PermissionError):
        await memory.search_similar_payloads(
            VECTOR, engagement_id="eng-owned", task_id=task.id, category="summary",
        )


@pytest.mark.asyncio
async def test_semantic_memory_refuses_invalid_vector_category_or_implicit_authority(monkeypatch):
    monkeypatch.setenv("OSOP_MOCK_LLM", "true")
    memory = VectorMemory("unused://never-contacted")
    await memory.connect()
    with pytest.raises(ValueError, match="1536"):
        await memory.store_payload(
            "xss", "safe", [1.0, 0.0], {},
            engagement_id="eng-one", task_id="task-one",
        )
    with pytest.raises(ValueError, match="category"):
        await memory.store_payload(
            "xss", "safe", VECTOR, {},
            engagement_id="eng-one", task_id="task-one", category="arbitrary",
        )
    with pytest.raises(ValueError, match="limit"):
        await memory.search_similar_payloads(
            VECTOR, limit=1000, engagement_id="eng-one", task_id="task-one",
        )
    monkeypatch.setenv("OSOP_MOCK_LLM", "false")
    production = VectorMemory("postgresql://unreachable/no-db")
    with pytest.raises(RuntimeError, match="Signed engagement"):
        await production.connect()
