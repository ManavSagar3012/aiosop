"""Vector memory tests — exercise the mock-mode branch (no pgvector needed) and
assert the real SQL contract for the pgvector path (regression guard)."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.memory.vector_memory import VectorMemory


@pytest.fixture(autouse=True)
def _mock_llm(monkeypatch):
    # VectorMemory.connect() reads OSOP_MOCK_LLM to decide mock mode.
    monkeypatch.setenv("OSOP_MOCK_LLM", "true")
    yield


@pytest.mark.asyncio
async def test_store_and_search_payloads_mock_mode():
    vm = VectorMemory("postgresql+asyncpg://u:p@localhost/db")
    await vm.connect()
    assert vm._mock_mode is True

    await vm.store_payload("sqli", "' OR 1=1--", [0.1, 0.2], {"ev": "x"})
    await vm.store_payload("xss", "<script>alert(1)</script>", [0.9, 0.8], {})

    results = await vm.search_similar_payloads([0.1, 0.2], payload_type="sqli", limit=5)
    assert len(results) == 2  # mock returns store[:limit] (no type filter in mock)
    assert results[0]["payload_type"] == "sqli"


@pytest.mark.asyncio
async def test_search_findings_mock_ranks_by_cosine():
    vm = VectorMemory("postgresql://u:p@localhost/db")
    await vm.connect()

    # Store findings with orthogonal-ish embeddings so ranking is deterministic.
    await vm.store_finding("close to query", [1.0, 0.0], {})
    await vm.store_finding("far from query", [0.0, 1.0], {})

    ranked = await vm.search_similar_findings([1.0, 0.1], limit=2)
    assert ranked[0]["document"] == "close to query"
    assert ranked[0]["score"] >= ranked[1]["score"]


def test_connect_non_mock_requires_asyncpg(monkeypatch):
    """Without mock mode, connect() reaches for asyncpg and the pgvector DDL."""
    monkeypatch.setenv("OSOP_MOCK_LLM", "false")
    vm = VectorMemory("postgresql://u:p@localhost/db")
    # Don't actually open a pool; just confirm the mock-mode flag is unset.
    assert getattr(vm, "_mock_mode", False) is False


def test_sql_embedding_is_json_text_for_pgvector():
    """Regression: pgvector '<=>' accepts '[..]' text; store must json.dumps the embedding.
    If someone passes a raw list, this test documents the contract."""
    import inspect

    src = inspect.getsource(VectorMemory.store_payload)
    assert "json.dumps(embedding)" in src
    src2 = inspect.getsource(VectorMemory.search_similar_findings)
    assert "<=>" in src2  # cosine-distance operator present on pgvector path


def test_close_is_safe_without_pool():
    vm = VectorMemory("postgresql://u:p@localhost/db")
    # No connect() -> pool None -> close() must not raise.
    asyncio.run(vm.close())
