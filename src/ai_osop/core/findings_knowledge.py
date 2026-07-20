"""Findings knowledge base — the P2 "learning brain" foundation.

The single biggest untapped AI advantage in AI-OSOP is cross-engagement memory:
a confirmed finding on target A should make the platform smarter on target B.
Today findings are stored in the graph but never turned into *semantic* memory,
so nothing is reused. This module is the foundation of that loop:

    record_finding(vuln)   -> embed a text view of the finding and store it
    recall_similar(query)  -> embed the query, return the most similar past findings

Design goals
------------
- **Reuse, don't reinvent.** Embeddings come from the existing
  ``LiteLLMClient.get_embedding``; the production vector store is the existing
  pgvector-backed ``VectorMemory``. Both are *injected*, so this service has no
  hard dependency on either and runs fully in-memory for tests.
- **Pure core, thin I/O.** ``finding_to_document`` and ``cosine_similarity`` do
  no I/O and are trivially testable. ``InMemoryVectorIndex`` gives a real,
  dependency-free backend used by tests and as a graceful fallback.
- **Never learn from fiction.** Simulated/mock findings (``is_simulated``) are
  refused, so the corpus can never poison future reasoning with fabricated data.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol

from ai_osop.core.finding_view import to_finding_view

EmbedFn = Callable[[str], Awaitable[List[float]]]


def _get(obj: Any, name: str, default: Any = None) -> Any:
    """Read an attribute from a pydantic model *or* a plain dict."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _enum_value(v: Any) -> str:
    """Render an enum/plain value as its string form (VulnClass.SSRF -> 'ssrf')."""
    if v is None:
        return ""
    return str(getattr(v, "value", v))


def finding_to_document(finding: Any) -> str:
    """Build a stable, deterministic text representation of a finding for embedding.

    Accepts a ``Vulnerability`` model or an equivalent dict. The document leads
    with the highest-signal fields (type, severity, title, CWE) so semantically
    similar findings land near each other in embedding space. Deterministic:
    the same finding always yields the same document.
    """
    vuln_type = _enum_value(_get(finding, "vuln_type"))
    severity = _enum_value(_get(finding, "severity"))
    title = str(_get(finding, "title", "") or "")
    cwe = str(_get(finding, "cwe", "") or "")
    description = str(_get(finding, "description", "") or "")
    view = to_finding_view(finding)
    endpoint = str(view.get("url") or _get(finding, "endpoint_id", "") or "")

    parts = []
    if vuln_type:
        parts.append(f"type: {vuln_type}")
    if severity:
        parts.append(f"severity: {severity}")
    if cwe:
        parts.append(f"cwe: {cwe}")
    if title:
        parts.append(f"title: {title}")
    if endpoint:
        parts.append(f"endpoint: {endpoint}")
    if description:
        parts.append(f"description: {description}")
    return "\n".join(parts)


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Cosine similarity of two equal-length vectors. Returns 0.0 for a zero
    vector or a length mismatch (defensive — never raises on bad input)."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


@dataclass
class KnowledgeHit:
    """A recalled past finding with its similarity score."""

    score: float
    document: str
    metadata: Dict[str, Any]


class VectorStore(Protocol):
    """Minimal backend contract so production (pgvector) and tests (in-memory)
    are interchangeable."""

    async def add(
        self, embedding: List[float], document: str, metadata: Dict[str, Any]
    ) -> None: ...

    async def search(self, embedding: List[float], limit: int) -> List[KnowledgeHit]: ...


@dataclass
class InMemoryVectorIndex:
    """Dependency-free cosine-similarity index.

    Used by tests and as a graceful fallback when pgvector is unavailable. Not
    meant for very large corpora (linear scan), but correct and deterministic.
    """

    _rows: List[Dict[str, Any]] = field(default_factory=list)

    async def add(self, embedding: List[float], document: str, metadata: Dict[str, Any]) -> None:
        self._rows.append(
            {"embedding": list(embedding), "document": document, "metadata": dict(metadata)}
        )

    async def search(self, embedding: List[float], limit: int) -> List[KnowledgeHit]:
        scored = [
            KnowledgeHit(
                score=cosine_similarity(embedding, r["embedding"]),
                document=r["document"],
                metadata=r["metadata"],
            )
            for r in self._rows
        ]
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:limit]

    def __len__(self) -> int:  # convenience for tests / metrics
        return len(self._rows)


class VectorMemoryFindingsStore:
    """Adapts the pgvector-backed ``VectorMemory`` to the ``VectorStore`` protocol,
    so ``FindingsKnowledge`` gets durable, restart-surviving memory in production
    while tests keep using ``InMemoryVectorIndex``."""

    def __init__(self, vector_memory: Any) -> None:
        self._vm = vector_memory

    async def add(self, embedding: List[float], document: str, metadata: Dict[str, Any]) -> None:
        await self._vm.store_finding(document, embedding, metadata)

    async def search(self, embedding: List[float], limit: int) -> List[KnowledgeHit]:
        rows = await self._vm.search_similar_findings(embedding, limit=limit)
        return [
            KnowledgeHit(
                score=float(r.get("score", 0.0) or 0.0),
                document=r.get("document", ""),
                metadata=r.get("metadata", {}) or {},
            )
            for r in rows
        ]


class FindingsKnowledge:
    """Semantic memory over confirmed findings.

    Composes an embedding function with a vector store. Inject
    ``LiteLLMClient.get_embedding`` and a pgvector-backed store in production;
    inject a fake embedder + ``InMemoryVectorIndex`` in tests.
    """

    def __init__(self, embed_fn: EmbedFn, store: Optional[VectorStore] = None) -> None:
        self._embed = embed_fn
        self._store: VectorStore = store if store is not None else InMemoryVectorIndex()

    async def record_finding(self, finding: Any, *, skip_simulated: bool = True) -> bool:
        """Embed and store a finding. Returns True if stored, False if skipped.

        Refuses simulated/mock findings so fabricated data never enters the
        corpus (mirrors ``Vulnerability.is_simulated``).
        """
        if skip_simulated:
            is_sim = _get(finding, "is_simulated", None)
            try:
                if callable(is_sim) and is_sim():
                    return False
            except Exception:  # noqa: BLE001 - a broken guard must not block recording decisions
                pass

        document = finding_to_document(finding)
        if not document.strip():
            return False
        embedding = await self._embed(document)
        metadata = {
            "finding_id": _get(finding, "id", ""),
            "engagement_id": _get(finding, "engagement_id", ""),
            "vuln_type": _enum_value(_get(finding, "vuln_type")),
            "severity": _enum_value(_get(finding, "severity")),
            "title": str(_get(finding, "title", "") or ""),
            "cwe": str(_get(finding, "cwe", "") or ""),
            "confidence": _get(finding, "confidence", None),
        }
        await self._store.add(embedding, document, metadata)
        return True

    async def recall_similar(
        self, query: Any, *, limit: int = 5, min_score: float = 0.0
    ) -> List[KnowledgeHit]:
        """Return past findings most similar to ``query`` (a string or a finding).

        ``min_score`` filters weak matches so callers get signal, not noise.
        """
        query_text = query if isinstance(query, str) else finding_to_document(query)
        if not query_text.strip():
            return []
        embedding = await self._embed(query_text)
        hits = await self._store.search(embedding, limit=limit)
        return [h for h in hits if h.score >= min_score]
