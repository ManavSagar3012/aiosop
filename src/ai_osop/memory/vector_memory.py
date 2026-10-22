"""Signed-engagement, tenant-isolated pgvector semantic knowledge.

Legacy semantic_payloads records are deliberately never read or migrated:
they were stored without engagement ownership or signed ROE provenance.
Production storage failures are errors, not an implicit switch to a mock.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from typing import Any, Dict, List, Optional

from ai_osop.core.telemetry import RequestContext


_CATEGORIES = frozenset({"payload", "summary", "guide", "answer", "code"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PAYLOAD_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,49}$")
_SECRETS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"(?i)\b(?:password|api[_-]?key|secret|token|authorization)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
)


def _safe_content(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise ValueError("Semantic content is empty or exceeds 4096 characters")
    cleaned = value
    for pattern in _SECRETS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    if not cleaned.strip():
        raise ValueError("Semantic content contains no safe text")
    return cleaned


def _safe_metadata(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Semantic metadata must be an object")
    result: Dict[str, Any] = {}
    for key in ("fitness", "source", "timestamp", "evidence_sha256"):
        candidate = value.get(key)
        if key == "fitness" and type(candidate) in (float, int) and math.isfinite(candidate):
            result[key] = max(0.0, min(1.0, float(candidate)))
        elif key in {"source", "timestamp"} and isinstance(candidate, str) and candidate:
            result[key] = _safe_content(candidate[:256])
        elif (
            key == "evidence_sha256" and isinstance(candidate, str)
            and re.fullmatch(r"[0-9a-f]{64}", candidate)
        ):
            result[key] = candidate
    # Never persist raw URLs/targets or entire external responses in metadata.
    target = value.get("target")
    if isinstance(target, str) and target:
        result["target_sha256"] = hashlib.sha256(target.encode("utf-8")).hexdigest()
    return result


def _embedding(value: List[float]) -> str:
    if (
        not isinstance(value, (list, tuple)) or len(value) != 1536
        or any(type(element) not in (int, float) or not math.isfinite(element) for element in value)
        or not any(element != 0 for element in value)
    ):
        raise ValueError("Semantic embedding requires 1536 finite non-zero-vector dimensions")
    # Explicit vector text is bound as an SQL parameter, never interpolated.
    return json.dumps([float(element) for element in value], separators=(",", ":"))


class VectorMemory:
    """Semantic retrieval strictly scoped to the current signed engagement."""

    def __init__(self, uri: str, session_memory: Optional[Any] = None) -> None:
        self.uri = uri
        self.session_memory = session_memory
        self.pool: Any = None
        self._mock_mode = False
        self._mock_store: List[Dict[str, Any]] = []

    async def connect(self) -> None:
        self._mock_mode = os.getenv("OSOP_MOCK_LLM", "false").lower() == "true"
        if self._mock_mode:
            self._mock_store = []
            return
        if self.session_memory is None:
            raise RuntimeError("Signed engagement store is required for vector memory")
        import asyncpg

        uri = self.uri.replace("postgresql+asyncpg://", "postgresql://", 1)
        self.pool = await asyncpg.create_pool(uri, min_size=1, max_size=10)
        try:
            async with self.pool.acquire() as connection:
                table = await connection.fetchval(
                    "SELECT to_regclass('public.supervision_semantic_knowledge')"
                )
                if table is None:
                    raise RuntimeError("Tenant-scoped vector migration 0011 is missing")
        except Exception:
            await self.pool.close()
            self.pool = None
            # Never fall back to an unscoped legacy payload table or mock DB.
            raise

    async def _authorize(self, engagement_id: str, task_id: str) -> int:
        if not (
            isinstance(engagement_id, str) and _IDENTIFIER.fullmatch(engagement_id)
            and isinstance(task_id, str) and _IDENTIFIER.fullmatch(task_id)
        ):
            raise PermissionError("Semantic knowledge requires a valid engagement and task")
        bound = RequestContext.get()
        if (
            (bound.get("engagement_id") and bound["engagement_id"] != engagement_id)
            or (bound.get("task_id") and bound["task_id"] != task_id)
        ):
            raise PermissionError("Semantic context differs from signed execution identity")
        if self._mock_mode and self.session_memory is None:
            return 0
        if self.session_memory is None:
            raise PermissionError("Semantic signed authority is not available")
        from ai_osop.core.models import Task

        try:
            authorization = await self.session_memory.assert_signed_authorization(engagement_id)
            task = await self.session_memory.load_task_authoritative(task_id)
            if (
                not isinstance(task, Task) or task.engagement_id != engagement_id
                or task.status != "running"
                or type(task.payload.get("_authorization_version")) is not int
                or task.payload["_authorization_version"] != authorization.version
            ):
                raise PermissionError("Semantic task execution is not authorized")
            return authorization.version
        except PermissionError:
            raise
        except Exception as exc:
            raise PermissionError("Signed semantic knowledge authorization unavailable") from exc

    @staticmethod
    def _validate_type(payload_type: str, category: str) -> None:
        if category not in _CATEGORIES:
            raise ValueError("Unsupported semantic knowledge category")
        if not isinstance(payload_type, str) or not _PAYLOAD_TYPE.fullmatch(payload_type):
            raise ValueError("Invalid semantic payload classification")

    @staticmethod
    async def _fence_write_transaction(
        connection: Any, engagement_id: str, task_id: str, version: int
    ) -> None:
        """Keep a signed task and its revocation fence stable through INSERT.

        An authorization checked before acquiring the pgvector pool can be
        revoked while this coroutine waits for its connection. Recheck under
        PostgreSQL row locks *in the same transaction as the write*. This
        lock order matches AuthorizationStore's session-then-ledger ordering.
        """
        parent = await connection.fetchval(
            "SELECT session_id FROM session_states WHERE session_id=$1 FOR SHARE",
            engagement_id,
        )
        signer = await connection.fetchrow(
            "SELECT version, status FROM signed_authorizations "
            "WHERE session_id=$1 ORDER BY version DESC LIMIT 1 FOR SHARE",
            engagement_id,
        )
        task = await connection.fetchrow(
            "SELECT status, payload FROM tasks "
            "WHERE id=$1 AND engagement_id=$2 FOR SHARE",
            task_id, engagement_id,
        )
        # SQLAlchemy decodes JSONB automatically, but the independent asyncpg
        # pool returns it as serialized JSON unless a codec was registered.
        # Parse only this internal task-authorization metadata, never eval.
        task_payload = task["payload"] if task is not None else None
        if isinstance(task_payload, str):
            try:
                task_payload = json.loads(task_payload)
            except (TypeError, ValueError):
                task_payload = None
        if (
            parent != engagement_id
            or signer is None
            or signer["version"] != version
            or signer["status"] != "active"
            or task is None
            or task["status"] != "running"
            or not isinstance(task_payload, dict)
            or type(task_payload.get("_authorization_version")) is not int
            or task_payload["_authorization_version"] != version
        ):
            raise PermissionError("Semantic write authorization changed before commit")

    async def store_payload(
        self,
        payload_type: str,
        content: str,
        embedding: List[float],
        metadata: Dict[str, Any],
        *,
        engagement_id: str,
        task_id: str,
        category: str = "payload",
    ) -> Any:
        """Persist only redacted data after verifying a running signed task."""
        self._validate_type(payload_type, category)
        text = _safe_content(content)
        properties = _safe_metadata(metadata)
        vector = _embedding(embedding)
        version = await self._authorize(engagement_id, task_id)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if self._mock_mode:
            if not any(
                item["engagement_id"] == engagement_id
                and item["authorization_version"] == version
                and item["category"] == category
                and item["payload_type"] == payload_type
                and item["digest"] == digest
                for item in self._mock_store
            ):
                self._mock_store.append({
                    "engagement_id": engagement_id, "task_id": task_id,
                    "authorization_version": version, "category": category,
                    "payload_type": payload_type, "content": text,
                    "embedding": tuple(embedding), "metadata": properties,
                    "digest": digest,
                })
            return digest
        if self.pool is None:
            raise RuntimeError("Vector memory storage is unavailable")
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await self._fence_write_transaction(
                    connection, engagement_id, task_id, version
                )
                value = await connection.fetchval(
                """
                INSERT INTO supervision_semantic_knowledge (
                  engagement_id, task_id, authorization_version, category,
                  payload_type, content, content_sha256, embedding, metadata
                ) VALUES (
                  $1, $2, $3, $4, $5, $6, $7, $8::vector, $9::jsonb
                )
                ON CONFLICT (
                  engagement_id, authorization_version, category,
                  payload_type, content_sha256
                ) DO UPDATE SET content_sha256 = EXCLUDED.content_sha256
                RETURNING id
                """,
                    engagement_id, task_id, version, category, payload_type,
                    text, digest, vector, json.dumps(properties),
                )
        return value

    async def search_similar_payloads(
        self,
        embedding: List[float],
        payload_type: Optional[str] = None,
        limit: int = 5,
        *,
        engagement_id: str,
        task_id: str,
        category: str = "payload",
    ) -> List[Dict[str, Any]]:
        """Search only the signed engagement's current authorization version."""
        if payload_type is not None:
            self._validate_type(payload_type, category)
        elif category not in _CATEGORIES:
            raise ValueError("Unsupported semantic knowledge category")
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("Semantic search limit must be between 1 and 20")
        vector = _embedding(embedding)
        version = await self._authorize(engagement_id, task_id)
        if self._mock_mode:
            records = [
                item for item in self._mock_store
                if item["engagement_id"] == engagement_id
                and item["authorization_version"] == version
                and item["category"] == category
                and (payload_type is None or item["payload_type"] == payload_type)
            ]
            return [
                {"payload_type": item["payload_type"],
                 "content": item["content"],
                 "metadata": dict(item["metadata"])}
                for item in records[:limit]
            ]
        if self.pool is None:
            raise RuntimeError("Vector memory storage is unavailable")
        async with self.pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT payload_type, content, metadata,
                  embedding <=> $4::vector AS cosine_distance
                FROM supervision_semantic_knowledge
                WHERE engagement_id = $1
                  AND authorization_version = $2
                  AND category = $3
                  AND ($5::text IS NULL OR payload_type = $5)
                ORDER BY embedding <=> $4::vector
                LIMIT $6
                """,
                engagement_id, version, category, vector, payload_type, limit,
            )
        # If the operator revoked/rotated authority while the query was
        # running, do not return the old signed-version data.
        if await self._authorize(engagement_id, task_id) != version:
            raise PermissionError("Semantic authorization version changed")
        return [
            {
                "payload_type": row["payload_type"],
                "content": row["content"],
                "metadata": (
                    json.loads(row["metadata"]) if isinstance(row["metadata"], str)
                    else dict(row["metadata"])
                ),
                "similarity": max(0.0, min(1.0, 1.0 - float(row["cosine_distance"]))),
            }
            for row in rows
        ]

    async def close(self) -> None:
        if self.pool is not None:
            await self.pool.close()
            self.pool = None
