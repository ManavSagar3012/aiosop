"""Full-coverage tests for ai_osop.memory.vector_memory.

The real methods are guarded by ``self.pool`` (asyncpg). These tests stub
asyncpg's pool/connection semantics (``acquire()`` async context manager,
``execute``/``fetch``, ``close``) so the real VectorMemory code paths run
without needing a live Postgres/pgvector instance.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.memory import vector_memory as vmod
from ai_osop.memory.vector_memory import VectorMemory


class _AcquireCtx:
    """Async context manager matching asyncpg pool.acquire()."""

    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class StubPool:
    """Minimal stand-in for an asyncpg.Pool."""

    def __init__(self, *, fail_on_execute=None, fetch_rows=None):
        self.conn = MagicMock()
        self.conn.execute = AsyncMock(side_effect=fail_on_execute)
        self.conn.fetch = AsyncMock(return_value=fetch_rows if fetch_rows is not None else [])
        self.closed = False
        self.executed = self.conn.execute

    def acquire(self):
        return _AcquireCtx(self.conn)

    async def close(self):
        self.closed = True


def _no_mock_env(monkeypatch):
    monkeypatch.setenv("OSOP_MOCK_LLM", "false")


def _patch_asyncpg(monkeypatch, stub):
    """asyncpg is imported inside connect(); expose it on the module, then stub
    create_pool to return our pool."""
    import asyncpg

    monkeypatch.setattr(vmod, "asyncpg", asyncpg, raising=False)
    create_pool = AsyncMock(return_value=stub)
    monkeypatch.setattr(vmod.asyncpg, "create_pool", create_pool)
    return create_pool


async def test_connect_creates_pool_and_runs_pgvector_ddl(monkeypatch):
    """connect() in real mode must create the pool, enable the extension and
    create both tables with the configured embedding dimension."""
    _no_mock_env(monkeypatch)
    stub = StubPool()
    create_pool = _patch_asyncpg(monkeypatch, stub)

    from ai_osop.core.config import settings
    dim = int(getattr(settings, "llm_embedding_dim", 1536))

    vm = VectorMemory("postgresql+asyncpg://u:p@localhost/db")
    await vm.connect()

    # URI scheme rewritten for plain asyncpg
    create_pool.assert_awaited_once_with("postgresql://u:p@localhost/db")
    assert vm.pool is stub
    assert vm._mock_mode is False

    stmts = [call.args[0] for call in stub.conn.execute.await_args_list]
    assert len(stmts) == 3
    assert "CREATE EXTENSION IF NOT EXISTS vector" in stmts[0]
    assert f"vector({dim})" in stmts[1]
    assert "semantic_payloads" in stmts[1]
    assert f"vector({dim})" in stmts[2]
    assert "semantic_findings" in stmts[2]

    await vm.close()
    assert stub.closed is True


async def test_connect_ddl_failure_falls_back_to_mock(monkeypatch, caplog):
    """If the pgvector DDL fails, connect() must enable the in-memory mock
    store instead of propagating the error."""
    _no_mock_env(monkeypatch)
    stub = StubPool(fail_on_execute=RuntimeError("extension not available"))
    _patch_asyncpg(monkeypatch, stub)

    vm = VectorMemory("postgresql://u:p@localhost/db")
    await vm.connect()

    assert vm._mock_mode is True
    assert vm._mock_store == []
    assert vm._mock_findings == []

    # Mock-path storage now works and close() still releases the pool.
    calls_after_connect = stub.conn.execute.await_count
    await vm.store_payload("sqli", "' OR 1=1--", [0.1], {"k": "v"})
    assert vm._mock_store[0]["content"] == "' OR 1=1--"
    # store_payload took the mock branch -> no further execute calls.
    assert stub.conn.execute.await_count == calls_after_connect
    await vm.close()
    assert stub.closed is True


async def test_store_and_search_similar_payloads_real_path(monkeypatch):
    """store_payload/search_similar_payloads against the stubbed pool."""
    _no_mock_env(monkeypatch)
    stub = StubPool()
    _patch_asyncpg(monkeypatch, stub)
    vm = VectorMemory("postgresql://u:p@localhost/db")
    await vm.connect()

    meta = {"evidence": "x"}
    await vm.store_payload("sqli", "' OR 1=1--", [0.1, 0.2], meta)

    sql, p_type, content, emb, meta_json = stub.conn.execute.await_args.args
    assert "INSERT INTO semantic_payloads" in sql
    assert p_type == "sqli"
    assert content == "' OR 1=1--"
    assert emb == json.dumps([0.1, 0.2])
    assert json.loads(meta_json) == meta

    # Simulate pgvector rows (Record-like objects).
    stub.conn.fetch.return_value = [
        {"payload_type": "sqli", "content": "' OR 1=1--", "metadata": json.dumps(meta)}
    ]
    out = await vm.search_similar_payloads([0.1, 0.2], payload_type="sqli", limit=3)
    assert out == [{"payload_type": "sqli", "content": "' OR 1=1--", "metadata": meta}]

    q, arg1, emb_arg, limit_arg = stub.conn.fetch.await_args.args
    assert "FROM semantic_payloads" in q
    assert "WHERE payload_type = $1" in q
    assert "ORDER BY embedding <=> $2 LIMIT $3" in q
    assert arg1 == "sqli"
    assert emb_arg == json.dumps([0.1, 0.2])
    assert limit_arg == 3


async def test_search_similar_payloads_without_filter(monkeypatch):
    """Without payload_type the query must omit the WHERE clause and renumber
    the embedding/limit placeholders."""
    _no_mock_env(monkeypatch)
    stub = StubPool()
    _patch_asyncpg(monkeypatch, stub)
    vm = VectorMemory("postgresql://u:p@localhost/db")
    await vm.connect()

    stub.conn.fetch.return_value = []
    out = await vm.search_similar_payloads([1.0, 2.0], limit=7)
    assert out == []

    q, emb_arg, limit_arg = stub.conn.fetch.await_args.args
    assert "WHERE" not in q
    assert "ORDER BY embedding <=> $1 LIMIT $2" in q
    assert emb_arg == json.dumps([1.0, 2.0])
    assert limit_arg == 7


async def test_store_finding_real_path(monkeypatch):
    _no_mock_env(monkeypatch)
    stub = StubPool()
    _patch_asyncpg(monkeypatch, stub)
    vm = VectorMemory("postgresql://u:p@localhost/db")
    await vm.connect()

    meta = {"cwe": 89}
    await vm.store_finding("SQLi in /login", [0.5, 0.5], meta)

    sql, doc, emb, meta_json = stub.conn.execute.await_args.args
    assert "INSERT INTO semantic_findings" in sql
    assert doc == "SQLi in /login"
    assert emb == json.dumps([0.5, 0.5])
    assert json.loads(meta_json) == meta


async def test_search_similar_findings_real_path(monkeypatch):
    _no_mock_env(monkeypatch)
    stub = StubPool()
    _patch_asyncpg(monkeypatch, stub)
    vm = VectorMemory("postgresql://u:p@localhost/db")
    await vm.connect()

    meta = {"cwe": 89}
    stub.conn.fetch.return_value = [
        {"document": "doc-a", "metadata": json.dumps(meta), "score": 0.91},
        {"document": "doc-b", "metadata": json.dumps({}), "score": None},
    ]
    out = await vm.search_similar_findings([0.5, 0.5], limit=2)
    assert out == [
        {"document": "doc-a", "metadata": meta, "score": 0.91},
        {"document": "doc-b", "metadata": {}, "score": 0.0},
    ]

    q, emb_arg, limit_arg = stub.conn.fetch.await_args.args
    assert "FROM semantic_findings" in q
    assert "<=> $1" in q
    assert "LIMIT $2" in q
    assert emb_arg == json.dumps([0.5, 0.5])
    assert limit_arg == 2


async def test_mock_mode_store_and_search(monkeypatch):
    """Mock-mode path: store_payload, search limit truncation, store_finding
    and cosine-ranked search_similar_findings."""
    monkeypatch.setenv("OSOP_MOCK_LLM", "true")
    vm = VectorMemory("postgresql://u:p@localhost/db")
    await vm.connect()
    assert vm._mock_mode is True
    assert vm.pool is None

    for i in range(4):
        await vm.store_payload("xss", f"payload-{i}", [float(i)], {"i": i})
    out = await vm.search_similar_payloads([0.0], limit=3)
    assert len(out) == 3
    assert out == vm._mock_store[:3]

    # Orthogonal embeddings make cosine ranking deterministic.
    await vm.store_finding("close", [1.0, 0.0], {"a": 1})
    await vm.store_finding("far", [0.0, 1.0], {})
    ranked = await vm.search_similar_findings([1.0, 0.0], limit=2)
    assert [r["document"] for r in ranked] == ["close", "far"]
    assert ranked[0]["score"] > ranked[1]["score"]
    ranked_one = await vm.search_similar_findings([1.0, 0.0], limit=1)
    assert len(ranked_one) == 1

    await vm.close()  # pool is None -> no-op


async def test_close_releases_pool_real_path(monkeypatch):
    _no_mock_env(monkeypatch)
    stub = StubPool()
    _patch_asyncpg(monkeypatch, stub)
    vm = VectorMemory("postgresql://u:p@localhost/db")
    await vm.connect()
    await vm.close()
    assert stub.closed is True


async def test_close_without_pool_is_noop(monkeypatch):
    vm = VectorMemory("postgresql://u:p@localhost/db")
    await vm.close()  # must not raise
    assert vm.pool is None


def test_init_sets_defaults():
    vm = VectorMemory("postgresql://u:p@localhost/db")
    assert vm.uri == "postgresql://u:p@localhost/db"
    assert vm.pool is None
