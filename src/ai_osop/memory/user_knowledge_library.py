"""Strict signed-user admission for the existing independent 0039 library.

The shared worktree already provides OperatorGlobalLibrary, its own 0039
PostgreSQL tables, immutable original versions and owner-scoped CRUD. This
service deliberately reuses that **user-owned**, Flow-independent store.

This boundary requires the configured durable operator credential revocation
ledger and validates the presented signed JWT/OIDC bearer for each call. An
unavailable ledger, disabled revocation enforcement or invalid principal fails
closed. Writes are NOT transactional with token revocation: the current
OperatorGlobalLibrary owns a separate transaction. Do not expose this facade as
atomic multi-replica credential revocation or review-approved RAG ingestion.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Dict, Optional, Tuple

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from ai_osop.api.deps import verify_token
from ai_osop.core.config import settings
from ai_osop.memory.operator_global_library import KnowledgeDenied, OperatorGlobalLibrary


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class UserKnowledgeLibrary:
    """Authenticated user-owned CRUD without an execution-Flow binding.

    This is an opt-in service object. It is not registered as a new API route,
    tool, agent context provider or alternate migration: the already registered
    /operator/library API and 0039 schema remain authoritative. Trusted callers
    may use this stricter credential guard before that same durable store.
    """

    def __init__(self, session_memory: Any) -> None:
        self._library = OperatorGlobalLibrary(session_memory)

    @staticmethod
    async def _principal(bearer_token: str) -> Tuple[str, str]:
        if (
            type(bearer_token) is not str
            or not 1 <= len(bearer_token) <= 16384
            or bearer_token != bearer_token.strip()
            or any(ord(char) <= 32 or ord(char) == 127 for char in bearer_token)
        ):
            raise KnowledgeDenied(401, "Valid signed user credential required")
        # With this unset verify_token intentionally skips durable revocation.
        # Never silently admit users through that weaker configuration here.
        if getattr(settings, "operator_revocation_required", False) is not True:
            raise KnowledgeDenied(503, "Durable user revocation enforcement required")

        try:
            verified = await verify_token(
                credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=bearer_token),
                token=None,
            )
        except HTTPException as exc:
            raise KnowledgeDenied(exc.status_code, "Signed user credential denied") from exc
        except Exception as exc:
            raise KnowledgeDenied(503, "Signed user authority unavailable") from exc

        if type(verified) is not dict or verified.get("role") not in {
            "operator",
            "senior_operator",
        }:
            raise KnowledgeDenied(403, "Signed operator role required")
        claims = verified.get("claims")
        subject = verified.get("sub")
        if (
            type(claims) is not dict
            or type(claims.get("exp")) is not int
            or type(subject) is not str
            or not 1 <= len(subject) <= 256
        ):
            raise KnowledgeDenied(403, "Stable signed principal required")
        issuer = claims.get("iss")
        if issuer is None:
            issuer = "local-jwt"
        if (
            type(issuer) is not str
            or not 1 <= len(issuer) <= 128
            or any(ord(char) < 33 or ord(char) == 127 for char in issuer + subject)
        ):
            raise KnowledgeDenied(403, "Stable signed issuer and subject required")
        # Exactly match the existing registered API principal namespace.
        owner = hashlib.sha256((issuer + "\x00" + subject).encode("utf-8")).hexdigest()
        return issuer, owner

    async def create(
        self, bearer_token: str, *, title: str, doc_type: str, content: str
    ) -> Dict[str, Any]:
        issuer, owner = await self._principal(bearer_token)
        return await self._library.create(
            issuer, owner, title=title, doc_type=doc_type, content=content
        )

    async def get(self, bearer_token: str, doc_id: str) -> Dict[str, Any]:
        issuer, owner = await self._principal(bearer_token)
        result = await self._library.get(issuer, owner, doc_id)
        # Deny content release after a revocation that arrived during the DB
        # read. No claim of an atomic user-credential+document SQL snapshot.
        assert_same = await self._principal(bearer_token)
        if assert_same != (issuer, owner):
            raise KnowledgeDenied(403, "Current signed principal changed")
        return result

    async def search(
        self,
        bearer_token: str,
        *,
        query: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        issuer, owner = await self._principal(bearer_token)
        result = await self._library.search(issuer, owner, query=query, limit=limit, offset=offset)
        if await self._principal(bearer_token) != (issuer, owner):
            raise KnowledgeDenied(403, "Current signed principal changed")
        return result

    async def update(
        self,
        bearer_token: str,
        doc_id: str,
        expected_revision: int,
        *,
        title: str,
        doc_type: str,
        content: str,
    ) -> Dict[str, Any]:
        issuer, owner = await self._principal(bearer_token)
        return await self._library.update(
            issuer,
            owner,
            doc_id,
            expected_revision,
            title=title,
            doc_type=doc_type,
            content=content,
        )

    async def delete(
        self, bearer_token: str, doc_id: str, expected_revision: int
    ) -> Dict[str, Any]:
        issuer, owner = await self._principal(bearer_token)
        return await self._library.delete(issuer, owner, doc_id, expected_revision)

    async def get_exact(
        self,
        bearer_token: str,
        doc_id: str,
        *,
        expected_revision: int,
        expected_sha256: str,
    ) -> Dict[str, Any]:
        """Inert exact-byte snapshot for later independent human review.

        The returned bytes remain untrusted; successful matching does not
        constitute review approval or authorization to inject agent context.
        """
        if (
            type(expected_revision) is not int
            or expected_revision < 1
            or type(expected_sha256) is not str
            or _DIGEST.fullmatch(expected_sha256) is None
        ):
            raise KnowledgeDenied(422, "Exact document revision and digest required")
        result = await self.get(bearer_token, doc_id)
        content = result.get("content")
        actual_digest = result.get("sha256")
        try:
            content_digest = (
                hashlib.sha256(content.encode("utf-8", errors="strict")).hexdigest()
                if type(content) is str
                else None
            )
        except UnicodeError as exc:
            raise KnowledgeDenied(503, "User knowledge text integrity unavailable") from exc
        if (
            type(content) is not str
            or type(actual_digest) is not str
            or result.get("revision") != expected_revision
            or not hmac.compare_digest(actual_digest, expected_sha256)
            or content_digest is None
            or not hmac.compare_digest(content_digest, expected_sha256)
            or result.get("approved_for_agent_context") is not False
        ):
            raise KnowledgeDenied(409, "User knowledge version or digest changed")
        return result
