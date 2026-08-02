"""
Vector Memory
Handles semantic payload storage and retrieval using PostgreSQL with pgvector.
"""

import json
from typing import Any, Dict, List, Optional


class VectorMemory:
    """
    Manages embedding-based storage and retrieval for payloads and exploits,
    enabling the Payload Mutation Agent to semantically search for similar
    payloads based on target context.

    Uses standard asyncpg (with pgvector extension assumed on the DB).
    """

    def __init__(self, uri: str):
        self.uri = uri
        self.pool = None

    async def connect(self):
        """Establish connection to Postgres and ensure pgvector exists."""
        # For P0 implementation, we are laying the structural groundwork.
        # If pgvector isn't available in standard CI, we fallback to mock for UAT.
        import os

        self._mock_mode = os.getenv("OSOP_MOCK_LLM", "false").lower() == "true"
        if self._mock_mode:
            self._mock_store = []
            self._mock_findings = []
            return

        import asyncpg

        uri = self.uri
        if uri.startswith("postgresql+asyncpg://"):
            uri = uri.replace("postgresql+asyncpg://", "postgresql://")
        self.pool = await asyncpg.create_pool(uri)
        async with self.pool.acquire() as conn:
            # Ensure the extension and tables exist. The vector width is driven by
            # settings.llm_embedding_dim so it always matches the configured
            # embedding model (default 1536; e.g. 768 for nomic-embed-text).
            from ai_osop.core.config import settings as _settings

            dim = int(getattr(_settings, "llm_embedding_dim", 1536))
            try:
                await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
                await conn.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS semantic_payloads (
                        id SERIAL PRIMARY KEY,
                        payload_type VARCHAR(50),
                        content TEXT,
                        embedding vector({dim}),
                        metadata JSONB
                    )
                """
                )
                # Findings knowledge (P2 learning brain): confirmed findings become
                # semantic memory so past engagements inform new ones.
                await conn.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS semantic_findings (
                        id SERIAL PRIMARY KEY,
                        document TEXT,
                        embedding vector({dim}),
                        metadata JSONB
                    )
                """
                )
            except Exception as e:
                print(f"WARN: Could not initialize pgvector: {e}")
                self._mock_mode = True
                self._mock_store = []
                self._mock_findings = []

    async def store_payload(
        self, payload_type: str, content: str, embedding: List[float], metadata: Dict[str, Any]
    ):
        """Store a payload with its semantic embedding."""
        if self._mock_mode:
            self._mock_store.append(
                {
                    "payload_type": payload_type,
                    "content": content,
                    "embedding": embedding,
                    "metadata": metadata,
                }
            )
            return

        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO semantic_payloads (payload_type, content, embedding, metadata)
                VALUES ($1, $2, $3, $4)
            """,
                payload_type,
                content,
                json.dumps(embedding),
                json.dumps(metadata),
            )

    async def search_similar_payloads(
        self, embedding: List[float], payload_type: Optional[str] = None, limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Retrieve payloads with similar embeddings using cosine distance."""
        if self._mock_mode:
            return self._mock_store[:limit]

        query = """
            SELECT payload_type, content, metadata
            FROM semantic_payloads
        """
        args = []
        if payload_type:
            query += " WHERE payload_type = $1"
            args.append(payload_type)

        query += f" ORDER BY embedding <=> ${len(args) + 1} LIMIT ${len(args) + 2}"
        args.extend([json.dumps(embedding), limit])

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
            return [
                {
                    "payload_type": row["payload_type"],
                    "content": row["content"],
                    "metadata": json.loads(row["metadata"]),
                }
                for row in rows
            ]

    async def store_finding(
        self, document: str, embedding: List[float], metadata: Dict[str, Any]
    ) -> None:
        """Persist a confirmed finding's semantic memory (P2 learning brain)."""
        if self._mock_mode:
            self._mock_findings.append(
                {"document": document, "embedding": embedding, "metadata": metadata}
            )
            return

        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO semantic_findings (document, embedding, metadata)
                VALUES ($1, $2, $3)
                """,
                document,
                json.dumps(embedding),
                json.dumps(metadata),
            )

    async def search_similar_findings(
        self, embedding: List[float], limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Return past findings most similar to ``embedding`` (cosine distance)."""
        if self._mock_mode:
            # Deterministic cosine rank so mock/CI runs are meaningful.
            from ai_osop.core.findings_knowledge import cosine_similarity

            scored = [
                {
                    "document": r["document"],
                    "metadata": r["metadata"],
                    "score": cosine_similarity(embedding, r["embedding"]),
                }
                for r in self._mock_findings
            ]
            scored.sort(key=lambda r: r["score"], reverse=True)
            return scored[:limit]

        async with self.pool.acquire() as conn:
            # 1 - cosine_distance = cosine_similarity for normalized vectors.
            rows = await conn.fetch(
                """
                SELECT document, metadata, 1 - (embedding <=> $1) AS score
                FROM semantic_findings
                ORDER BY embedding <=> $1
                LIMIT $2
                """,
                json.dumps(embedding),
                limit,
            )
            return [
                {
                    "document": row["document"],
                    "metadata": json.loads(row["metadata"]),
                    "score": float(row["score"]) if row["score"] is not None else 0.0,
                }
                for row in rows
            ]

    async def close(self):
        if self.pool:
            await self.pool.close()
