"""Tests for the P2 findings-knowledge foundation (learning brain).

Uses a deterministic, text-dependent fake embedder so semantic ranking is
actually exercised offline — no LLM or DB required.
"""

import hashlib

import pytest

from ai_osop.core.findings_knowledge import (
    FindingsKnowledge,
    InMemoryVectorIndex,
    cosine_similarity,
    finding_to_document,
)


def _fake_embed_factory(dims: int = 32):
    """A deterministic bag-of-words embedder: same text -> same vector, and
    texts sharing words land near each other. Good enough to test ranking."""

    async def _embed(text: str):
        vec = [0.0] * dims
        for token in text.lower().split():
            h = int(hashlib.sha1(token.encode()).hexdigest(), 16)
            vec[h % dims] += 1.0
        return vec

    return _embed


class _Vuln:
    """Minimal stand-in for the Vulnerability model (duck-typed)."""

    def __init__(self, **kw):
        self.__dict__.update(kw)

    def is_simulated(self):
        return self.__dict__.get("_simulated", False)


def test_finding_to_document_is_deterministic_and_has_key_fields():
    v = _Vuln(
        vuln_type="ssrf",
        severity="high",
        title="Blind SSRF in webhook",
        cwe="CWE-918",
        description="url param fetches attacker host",
        endpoint_id="/api/webhook",
    )
    doc1 = finding_to_document(v)
    doc2 = finding_to_document(v)
    assert doc1 == doc2  # deterministic
    assert "ssrf" in doc1 and "high" in doc1 and "CWE-918" in doc1
    assert "/api/webhook" in doc1


def test_finding_to_document_accepts_dict():
    doc = finding_to_document({"vuln_type": "xss", "severity": "medium", "title": "Stored XSS"})
    assert "xss" in doc and "Stored XSS" in doc


def test_cosine_similarity_bounds():
    assert cosine_similarity([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)
    assert cosine_similarity([], [1.0]) == 0.0  # defensive: mismatch -> 0
    assert cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0  # zero vector -> 0


@pytest.mark.asyncio
async def test_record_then_recall_ranks_similar_finding_first():
    kb = FindingsKnowledge(_fake_embed_factory(), store=InMemoryVectorIndex())
    await kb.record_finding(
        _Vuln(
            vuln_type="ssrf",
            severity="high",
            title="Blind SSRF via url param",
            description="url param fetches internal metadata",
            engagement_id="e1",
            id="v1",
        )
    )
    await kb.record_finding(
        _Vuln(
            vuln_type="xss",
            severity="medium",
            title="Reflected XSS in search",
            description="q param reflected unescaped",
            engagement_id="e1",
            id="v2",
        )
    )
    await kb.record_finding(
        _Vuln(
            vuln_type="sqli",
            severity="critical",
            title="SQL injection in login",
            description="username param concatenated into query",
            engagement_id="e1",
            id="v3",
        )
    )

    hits = await kb.recall_similar("ssrf url param fetches internal metadata", limit=3)
    assert hits, "expected at least one recalled finding"
    assert hits[0].metadata["finding_id"] == "v1"  # the SSRF finding ranks first


@pytest.mark.asyncio
async def test_simulated_findings_are_not_recorded():
    store = InMemoryVectorIndex()
    kb = FindingsKnowledge(_fake_embed_factory(), store=store)
    stored = await kb.record_finding(
        _Vuln(vuln_type="ssrf", severity="high", title="Fake", description="x", _simulated=True)
    )
    assert stored is False
    assert len(store) == 0


@pytest.mark.asyncio
async def test_vector_memory_backend_round_trip():
    """FindingsKnowledge works over the pgvector-backed VectorMemory adapter
    (exercised here in mock mode — no DB needed)."""
    from ai_osop.core.findings_knowledge import VectorMemoryFindingsStore
    from ai_osop.memory.vector_memory import VectorMemory

    vm = VectorMemory("postgresql://unused")
    vm._mock_mode = True  # simulate a connected mock backend
    vm._mock_findings = []

    kb = FindingsKnowledge(_fake_embed_factory(), store=VectorMemoryFindingsStore(vm))
    await kb.record_finding(
        _Vuln(
            vuln_type="ssrf",
            severity="high",
            title="SSRF via url",
            description="url param hits metadata",
            engagement_id="e1",
            id="v1",
        )
    )
    await kb.record_finding(
        _Vuln(
            vuln_type="idor",
            severity="high",
            title="IDOR on invoice",
            description="id param enumerates invoices",
            engagement_id="e1",
            id="v2",
        )
    )

    assert len(vm._mock_findings) == 2  # persisted to the backend
    hits = await kb.recall_similar("url param hits metadata ssrf", limit=2)
    assert hits and hits[0].metadata["finding_id"] == "v1"
    assert hits[0].score > 0.0  # backend supplies a real similarity score


@pytest.mark.asyncio
async def test_recall_respects_min_score_and_empty_query():
    kb = FindingsKnowledge(_fake_embed_factory(), store=InMemoryVectorIndex())
    await kb.record_finding(
        _Vuln(vuln_type="ssrf", severity="high", title="SSRF", description="alpha", id="v1")
    )
    # A query with no shared tokens -> zero similarity -> filtered by min_score.
    assert await kb.recall_similar("zzz nonmatching tokens", limit=5, min_score=0.01) == []
    assert await kb.recall_similar("", limit=5) == []
