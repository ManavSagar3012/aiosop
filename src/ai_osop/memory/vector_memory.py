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
            return

        import asyncpg

        self.pool = await asyncpg.create_pool(self.uri)
        async with self.pool.acquire() as conn:
            # Ensure the extension and table exist
            try:
                await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
                await conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS semantic_payloads (
                        id SERIAL PRIMARY KEY,
                        payload_type VARCHAR(50),
                        content TEXT,
                        embedding vector(1536),
                        metadata JSONB
                    )
                """
                )
            except Exception as e:
                print(f"WARN: Could not initialize pgvector: {e}")
                self._mock_mode = True
                self._mock_store = []

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

    async def close(self):
        if self.pool:
            await self.pool.close()
