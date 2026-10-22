"""Durable, user-owned library independent of Flow and target authorization.

This is inert human-authored text, not a trusted tool instruction, model prompt,
target finding or evidence source. Original revisions are append-only in 0039.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import text

_ID = re.compile(r"lib-[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = (
    "d.id,d.current_revision,d.created_at,d.deleted_at,"
    "v.title,v.doc_type,v.content,v.content_bytes,v.sha256,v.created_at AS version_created_at"
)


class KnowledgeDenied(Exception):
    """A signed user/owner, revision, or storage check denied the operation."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _valid_title(value: Any) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > 128
        or len(value.encode("utf-8", errors="surrogatepass")) > 512
        or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    ):
        raise KnowledgeDenied(422, "Invalid user library title")
    return value.strip()


def _valid_kind(value: Any) -> str:
    if type(value) is not str or value not in ("guide", "answer", "code"):
        raise KnowledgeDenied(422, "Invalid user library document type")
    return value


def _valid_content(value: Any) -> tuple[str, int, str]:
    if type(value) is not str or any(
        (ord(c) < 32 and c not in "\r\n\t") or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF
        for c in value
    ):
        raise KnowledgeDenied(422, "Invalid inert user library text")
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise KnowledgeDenied(422, "User library requires UTF-8 text") from exc
    if not 1 <= len(raw) <= 8192:
        raise KnowledgeDenied(413, "User library content must contain 1 to 8192 UTF-8 bytes")
    return value, len(raw), hashlib.sha256(raw).hexdigest()


def _valid_page(limit: Any, offset: Any) -> None:
    if (
        type(limit) is not int
        or not 1 <= limit <= 50
        or type(offset) is not int
        or not 0 <= offset <= 1000
    ):
        raise KnowledgeDenied(422, "Invalid bounded library pagination")


def _identity(issuer: Any, owner: Any) -> tuple[str, str]:
    if (
        type(issuer) is not str
        or not 1 <= len(issuer) <= 128
        or type(owner) is not str
        or not 1 <= len(owner) <= 128
        or any(ord(c) < 33 or ord(c) == 127 for c in issuer + owner)
    ):
        raise KnowledgeDenied(403, "Authenticated library owner required")
    return issuer, owner


def _document_id(value: Any) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise KnowledgeDenied(404, "Library document not found")
    return value


def _projection(row: Dict[str, Any], *, with_content: bool = False) -> Dict[str, Any]:
    raw = row["content"].encode("utf-8", errors="strict")
    if (
        not 1 <= len(raw) <= 8192
        or len(raw) != row["content_bytes"]
        or type(row["sha256"]) is not str
        or not _SHA.fullmatch(row["sha256"])
        or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), row["sha256"])
    ):
        raise KnowledgeDenied(503, "Current library original content integrity unavailable")
    info = {
        "id": row["id"],
        "revision": row["current_revision"],
        "title": row["title"],
        "doc_type": row["doc_type"],
        "sha256": row["sha256"],
        "content_bytes": row["content_bytes"],
        "created_at": row["created_at"].isoformat(),
        "version_created_at": row["version_created_at"].isoformat(),
        "content_classification": "untrusted_user_text",
        "approved_for_agent_context": False,
        "verified_target_evidence": False,
    }
    if with_content:
        info["content"] = row["content"]
    return info


class OperatorGlobalLibrary:
    def __init__(self, session_memory: Any) -> None:
        self._maker = getattr(session_memory, "_async_session", None)

    def _sessions(self) -> Any:
        if not callable(self._maker):
            raise KnowledgeDenied(503, "Durable user library unavailable")
        return self._maker

    @staticmethod
    async def _current(db: Any, issuer: str, owner: str, doc_id: str) -> Optional[Dict[str, Any]]:
        # Lock the owner row FIRST. A joined SELECT ... FOR UPDATE under
        # PostgreSQL READ COMMITTED can re-evaluate a stale joined snapshot
        # after the concurrent writer moves current_revision, yielding a
        # spurious 404 instead of the proper stale-revision 409. The second
        # query runs only after waiting for the winning writer to commit.
        owner_row = (
            (
                await db.execute(
                    text(
                        "SELECT d.id,d.current_revision,d.created_at,d.deleted_at "
                        "FROM operator_global_library_documents d "
                        "WHERE d.id=:id AND d.principal_issuer=:issuer "
                        "AND d.principal_subject=:owner AND d.deleted_at IS NULL "
                        "FOR UPDATE OF d"
                    ),
                    {"id": doc_id, "issuer": issuer, "owner": owner},
                )
            )
            .mappings()
            .one_or_none()
        )
        if owner_row is None:
            return None
        version = (
            (
                await db.execute(
                    text(
                        "SELECT title,doc_type,content,content_bytes,sha256,"
                        "created_at AS version_created_at "
                        "FROM operator_global_library_versions "
                        "WHERE document_id=:id AND revision=:revision"
                    ),
                    {"id": doc_id, "revision": owner_row["current_revision"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if version is None:
            raise KnowledgeDenied(503, "Immutable library version no longer available")
        return {**owner_row, **version}

    async def create(
        self, issuer: str, owner: str, *, title: str, doc_type: str, content: str
    ) -> Dict[str, Any]:
        issuer, owner = _identity(issuer, owner)
        title, doc_type = _valid_title(title), _valid_kind(doc_type)
        content, size, digest = _valid_content(content)
        doc_id = "lib-" + uuid.uuid4().hex
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    # Per-owner transaction fencing serializes caps even when
                    # two API replicas create simultaneously on PostgreSQL.
                    # PostgreSQL TEXT cannot carry NUL. Digest the scoped
                    # issuer/subject tuple before using it as an advisory
                    # lock label; preserve the delimiter only in local bytes.
                    scoped_lock_label = hashlib.sha256(
                        (issuer + "\x00" + owner).encode("utf-8")
                    ).hexdigest()
                    await db.execute(
                        text("SELECT pg_advisory_xact_lock(hashtextextended(:owner,0))"),
                        {"owner": scoped_lock_label},
                    )
                    count = (
                        await db.execute(
                            text(
                                "SELECT COUNT(*) FROM operator_global_library_documents "
                                "WHERE principal_issuer=:issuer AND principal_subject=:owner "
                                "AND deleted_at IS NULL"
                            ),
                            {"issuer": issuer, "owner": owner},
                        )
                    ).scalar_one()
                    if type(count) is not int or count >= 128:
                        raise KnowledgeDenied(409, "User library document limit reached")
                    await db.execute(
                        text(
                            "INSERT INTO operator_global_library_documents "
                            "(id,principal_issuer,principal_subject,current_revision) "
                            "VALUES (:id,:issuer,:owner,1)"
                        ),
                        {"id": doc_id, "issuer": issuer, "owner": owner},
                    )
                    await db.execute(
                        text(
                            "INSERT INTO operator_global_library_versions "
                            "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                            "VALUES (:id,1,:title,:kind,:content,:size,:sha)"
                        ),
                        {
                            "id": doc_id,
                            "title": title,
                            "kind": doc_type,
                            "content": content,
                            "size": size,
                            "sha": digest,
                        },
                    )
                    row = await self._current(db, issuer, owner, doc_id)
                    if row is None:
                        raise KnowledgeDenied(503, "Library insert readback unavailable")
                    return _projection(row)
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable user library create unavailable") from exc

    async def get(self, issuer: str, owner: str, doc_id: str) -> Dict[str, Any]:
        issuer, owner = _identity(issuer, owner)
        doc_id = _document_id(doc_id)
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    row = await self._current(db, issuer, owner, doc_id)
                    if row is None:
                        raise KnowledgeDenied(404, "Library document not found")
                    return _projection(row, with_content=True)
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable user library read unavailable") from exc

    async def update(
        self,
        issuer: str,
        owner: str,
        doc_id: str,
        expected_revision: int,
        *,
        title: str,
        doc_type: str,
        content: str,
    ) -> Dict[str, Any]:
        issuer, owner = _identity(issuer, owner)
        doc_id = _document_id(doc_id)
        title, doc_type = _valid_title(title), _valid_kind(doc_type)
        content, size, digest = _valid_content(content)
        if type(expected_revision) is not int or expected_revision < 1:
            raise KnowledgeDenied(422, "Expected library revision required")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    old = await self._current(db, issuer, owner, doc_id)
                    if old is None:
                        raise KnowledgeDenied(404, "Library document not found")
                    if old["current_revision"] != expected_revision:
                        raise KnowledgeDenied(409, "Library revision changed")
                    # Commit the new immutable original before moving the
                    # current pointer, in the SAME database transaction.
                    new_revision = expected_revision + 1
                    if new_revision > 2147483646:
                        raise KnowledgeDenied(409, "Library revision exhausted")
                    await db.execute(
                        text(
                            "INSERT INTO operator_global_library_versions "
                            "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                            "VALUES (:id,:revision,:title,:kind,:content,:size,:sha)"
                        ),
                        {
                            "id": doc_id,
                            "revision": new_revision,
                            "title": title,
                            "kind": doc_type,
                            "content": content,
                            "size": size,
                            "sha": digest,
                        },
                    )
                    changed = (
                        await db.execute(
                            text(
                                "UPDATE operator_global_library_documents "
                                "SET current_revision=:next WHERE id=:id "
                                "AND principal_issuer=:issuer AND principal_subject=:owner "
                                "AND current_revision=:previous AND deleted_at IS NULL "
                                "RETURNING id"
                            ),
                            {
                                "next": new_revision,
                                "id": doc_id,
                                "issuer": issuer,
                                "owner": owner,
                                "previous": expected_revision,
                            },
                        )
                    ).scalar_one_or_none()
                    if changed != doc_id:
                        raise KnowledgeDenied(409, "Library revision changed")
                    row = await self._current(db, issuer, owner, doc_id)
                    if row is None:
                        raise KnowledgeDenied(503, "Library update readback unavailable")
                    return _projection(row)
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable user library update unavailable") from exc

    async def delete(
        self, issuer: str, owner: str, doc_id: str, expected_revision: int
    ) -> Dict[str, Any]:
        issuer, owner = _identity(issuer, owner)
        doc_id = _document_id(doc_id)
        if type(expected_revision) is not int or expected_revision < 1:
            raise KnowledgeDenied(422, "Expected library revision required")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    old = await self._current(db, issuer, owner, doc_id)
                    if old is None:
                        raise KnowledgeDenied(404, "Library document not found")
                    if old["current_revision"] != expected_revision:
                        raise KnowledgeDenied(409, "Library revision changed")
                    deleted = (
                        await db.execute(
                            text(
                                "UPDATE operator_global_library_documents SET deleted_at=now() "
                                "WHERE id=:id AND principal_issuer=:issuer "
                                "AND principal_subject=:owner AND current_revision=:revision "
                                "AND deleted_at IS NULL RETURNING id"
                            ),
                            {
                                "id": doc_id,
                                "issuer": issuer,
                                "owner": owner,
                                "revision": expected_revision,
                            },
                        )
                    ).scalar_one_or_none()
                    if deleted != doc_id:
                        raise KnowledgeDenied(409, "Library deletion conflict")
                    return {
                        "id": doc_id,
                        "status": "tombstoned",
                        "revision": expected_revision,
                        "safe_for_execution": False,
                    }
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable user library delete unavailable") from exc

    async def search(
        self,
        issuer: str,
        owner: str,
        *,
        query: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        issuer, owner = _identity(issuer, owner)
        _valid_page(limit, offset)
        if query is not None and (
            type(query) is not str
            or not 1 <= len(query.strip()) <= 128
            or any(ord(c) < 32 or ord(c) == 127 for c in query)
        ):
            raise KnowledgeDenied(422, "Invalid bounded library query")
        where = (
            "d.principal_issuer=:issuer AND d.principal_subject=:owner " "AND d.deleted_at IS NULL"
        )
        if query is not None:
            where += " AND (strpos(lower(v.title),lower(:query))>0 OR strpos(lower(v.content),lower(:query))>0)"
        params = {
            "issuer": issuer,
            "owner": owner,
            "query": query.strip() if query else None,
            "limit": limit + 1,
            "offset": offset,
        }
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    rows = (
                        (
                            await db.execute(
                                text(
                                    f"SELECT {_FIELDS} FROM operator_global_library_documents d "
                                    "JOIN operator_global_library_versions v ON "
                                    "v.document_id=d.id AND v.revision=d.current_revision "
                                    f"WHERE {where} ORDER BY d.created_at DESC,d.id DESC "
                                    "LIMIT :limit OFFSET :offset"
                                ),
                                params,
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if len(rows) > limit + 1:
                        raise KnowledgeDenied(503, "Library page exceeds bounds")
                    return {
                        "items": [_projection(r) for r in rows[:limit]],
                        "has_more": len(rows) > limit,
                        "content_classification": "untrusted_user_text",
                        "approved_for_agent_context": False,
                    }
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable user library search unavailable") from exc
