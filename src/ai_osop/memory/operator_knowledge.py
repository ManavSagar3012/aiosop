"""Owner-scoped, inert operator knowledge in authoritative PostgreSQL.

PentAGI's user-managed guide/answer/code CRUD inspired this intentionally
non-vector interface. Documents never become agent instructions or verified
evidence; no retrieval hook into prompts or executable tooling exists here.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore, _identity

MAX_CONTENT_BYTES = 8192
MAX_DOCUMENTS = 128
MAX_PAGE = 50
MAX_OFFSET = 1000
_DOC_ID = re.compile(r"knowledge-[0-9a-f]{32}\Z")
_KINDS = frozenset({"guide", "answer", "code"})
_COLUMNS = (
    "id,engagement_id,flow_id,owner_id,title,doc_type,content,content_bytes,"
    "sha256,revision,source_flow_revision,authorization_version,"
    "authorization_sha256,created_at,updated_at,deleted_at"
)


class KnowledgeDenied(Exception):
    """Denied, invalid, stale, missing or unavailable knowledge operation."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _valid_title(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 128
        or len(value.encode("utf-8", errors="surrogatepass")) > 512
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or any(0xD800 <= ord(c) <= 0xDFFF for c in value)
    ):
        raise KnowledgeDenied(422, "Invalid knowledge title")
    return value.strip()


def _valid_content(value: str) -> tuple[str, int, str]:
    if not isinstance(value, str) or any(
        (ord(c) < 32 and c not in "\r\n\t") or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF
        for c in value
    ):
        raise KnowledgeDenied(422, "Invalid inert knowledge text")
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise KnowledgeDenied(422, "Knowledge must be UTF-8 text") from exc
    if not 1 <= len(raw) <= MAX_CONTENT_BYTES:
        raise KnowledgeDenied(413, "Knowledge text exceeds 8192 UTF-8 bytes or is empty")
    return value, len(raw), hashlib.sha256(raw).hexdigest()


def _valid_kind(value: str) -> str:
    if value not in _KINDS or not isinstance(value, str):
        raise KnowledgeDenied(422, "Unsupported operator knowledge type")
    return value


def _valid_page(limit: int, offset: int) -> None:
    if (
        type(limit) is not int
        or not 1 <= limit <= MAX_PAGE
        or type(offset) is not int
        or not 0 <= offset <= MAX_OFFSET
    ):
        raise KnowledgeDenied(422, "Invalid bounded pagination")


def _valid_document_id(document_id: str) -> None:
    if not isinstance(document_id, str) or _DOC_ID.fullmatch(document_id) is None:
        raise KnowledgeDenied(404, "Knowledge document not found")


def _metadata(row: Dict[str, Any]) -> Dict[str, Any]:
    """Only explicit, display-safe metadata; intentionally omit owner ID."""
    return {
        "id": row["id"],
        "flow_id": row["flow_id"],
        "title": row["title"],
        "doc_type": row["doc_type"],
        "revision": row["revision"],
        "sha256": row["sha256"],
        "content_bytes": row["content_bytes"],
        "source_flow_revision": row["source_flow_revision"],
        "authorization_version": row["authorization_version"],
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat(),
        "content_classification": "untrusted_operator_text",
        "approved_for_agent_context": False,
    }


class OperatorKnowledgeStore:
    def __init__(self, session_memory: Any) -> None:
        self.session_memory = session_memory

    def _sessions(self) -> Any:
        maker = getattr(self.session_memory, "_async_session", None)
        if not callable(maker):
            raise KnowledgeDenied(503, "Durable operator knowledge unavailable")
        return maker

    @staticmethod
    async def _fence(
        db: Any,
        flow_id: str,
        owner: str,
        flow_revision: int,
        authorization_version: int,
        *,
        writing: bool = False,
    ) -> tuple[str, str]:
        # Shared PostgreSQL locks and verified signed-policy check are held
        # in this exact transaction through every subsequent document query.
        try:
            return await FlowArtifactStore._fence(
                db,
                flow_id,
                owner,
                flow_revision,
                authorization_version,
                writing=writing,
            )
        except ArtifactDenied as exc:
            raise KnowledgeDenied(exc.status, str(exc)) from exc

    @staticmethod
    def _validate_identity(
        flow_id: str,
        owner: str,
        flow_revision: int,
        authorization_version: int,
    ) -> None:
        try:
            _identity(flow_id, owner, flow_revision, authorization_version)
        except ArtifactDenied as exc:
            raise KnowledgeDenied(exc.status, str(exc)) from exc

    @staticmethod
    def _assert_row(
        row: Dict[str, Any],
        *,
        sid: str,
        flow_id: str,
        owner: str,
        flow_revision: int,
        authorization_version: int,
        authorization_sha256: str,
    ) -> None:
        if (
            row["engagement_id"] != sid
            or row["flow_id"] != flow_id
            or row["owner_id"] != owner
            or row["authorization_version"] != authorization_version
            or not isinstance(row["authorization_sha256"], str)
            or not hmac.compare_digest(row["authorization_sha256"], authorization_sha256)
        ):
            raise KnowledgeDenied(409, "Knowledge authorization lineage changed")
        # The signed Flow fence authenticates the CURRENT revision, but a
        # source row must also originate in that Flow's history, not a future
        # or maliciously substituted revision. A plausible SHA field from a
        # SELECT is not proof of the original UTF-8 text: independently
        # recompute it before projecting even metadata-only citations.
        if (
            type(row.get("source_flow_revision")) is not int
            or not 0 <= row["source_flow_revision"] <= flow_revision
            or type(row.get("revision")) is not int
            or row["revision"] < 1
        ):
            raise KnowledgeDenied(409, "Knowledge source Flow revision unavailable")
        OperatorKnowledgeStore._verified_content(row)

    @staticmethod
    def _verified_content(row: Dict[str, Any]) -> str:
        content = row["content"]
        if not isinstance(content, str):
            raise KnowledgeDenied(503, "Knowledge content integrity unavailable")
        try:
            raw = content.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise KnowledgeDenied(503, "Knowledge content integrity unavailable") from exc
        if (
            not 1 <= len(raw) <= MAX_CONTENT_BYTES
            or len(raw) != row["content_bytes"]
            or not isinstance(row["sha256"], str)
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), row["sha256"])
        ):
            raise KnowledgeDenied(503, "Knowledge content integrity unavailable")
        return content

    @staticmethod
    async def _one(
        db: Any, sid: str, flow_id: str, owner: str, document_id: str
    ) -> Optional[Dict[str, Any]]:
        return (
            (
                await db.execute(
                    text(
                        f"SELECT {_COLUMNS} FROM operator_knowledge_documents "
                        "WHERE engagement_id=:sid AND flow_id=:fid AND owner_id=:owner "
                        "AND id=:id AND deleted_at IS NULL FOR UPDATE"
                    ),
                    {"sid": sid, "fid": flow_id, "owner": owner, "id": document_id},
                )
            )
            .mappings()
            .one_or_none()
        )

    async def create(
        self,
        flow_id: str,
        owner: str,
        flow_revision: int,
        authorization_version: int,
        *,
        title: str,
        doc_type: str,
        content: str,
    ) -> Dict[str, Any]:
        self._validate_identity(flow_id, owner, flow_revision, authorization_version)
        title = _valid_title(title)
        doc_type = _valid_kind(doc_type)
        content, size, digest = _valid_content(content)
        identifier = "knowledge-" + uuid.uuid4().hex
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    sid, auth_sha = await self._fence(
                        db,
                        flow_id,
                        owner,
                        flow_revision,
                        authorization_version,
                        writing=True,
                    )
                    occupied = (
                        await db.execute(
                            text(
                                "SELECT COUNT(*) FROM operator_knowledge_documents "
                                "WHERE engagement_id=:sid AND flow_id=:fid AND owner_id=:owner "
                                "AND deleted_at IS NULL"
                            ),
                            {"sid": sid, "fid": flow_id, "owner": owner},
                        )
                    ).scalar_one()
                    if type(occupied) is not int or occupied >= MAX_DOCUMENTS:
                        raise KnowledgeDenied(409, "Operator knowledge document limit reached")
                    row = (
                        (
                            await db.execute(
                                text(
                                    "INSERT INTO operator_knowledge_documents "
                                    "(id,engagement_id,flow_id,owner_id,title,doc_type,content,"
                                    "content_bytes,sha256,revision,source_flow_revision,"
                                    "authorization_version,authorization_sha256) "
                                    "VALUES (:id,:sid,:fid,:owner,:title,:kind,:content,:bytes,:sha,1,"
                                    ":flow_revision,:version,:auth_sha) "
                                    f"RETURNING {_COLUMNS}"
                                ),
                                {
                                    "id": identifier,
                                    "sid": sid,
                                    "fid": flow_id,
                                    "owner": owner,
                                    "title": title,
                                    "kind": doc_type,
                                    "content": content,
                                    "bytes": size,
                                    "sha": digest,
                                    "flow_revision": flow_revision,
                                    "version": authorization_version,
                                    "auth_sha": auth_sha,
                                },
                            )
                        )
                        .mappings()
                        .one()
                    )
                    self._assert_row(
                        row,
                        sid=sid,
                        flow_id=flow_id,
                        owner=owner,
                        flow_revision=flow_revision,
                        authorization_version=authorization_version,
                        authorization_sha256=auth_sha,
                    )
                    return _metadata(row)
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable operator knowledge create unavailable") from exc

    async def list(
        self,
        flow_id: str,
        owner: str,
        flow_revision: int,
        authorization_version: int,
        *,
        limit: int = 20,
        offset: int = 0,
        doc_type: Optional[str] = None,
        query: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._validate_identity(flow_id, owner, flow_revision, authorization_version)
        _valid_page(limit, offset)
        if doc_type is not None:
            _valid_kind(doc_type)
        if query is not None and (
            not isinstance(query, str)
            or not query.strip()
            or len(query) > 128
            or any(ord(c) < 32 or ord(c) == 127 for c in query)
        ):
            raise KnowledgeDenied(422, "Invalid bounded search query")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    sid, auth_sha = await self._fence(
                        db, flow_id, owner, flow_revision, authorization_version
                    )
                    # Parameterized STRPOS treats %/_ and regex metacharacters
                    # literally, with no SQL string construction from input.
                    conditions = (
                        "engagement_id=:sid AND flow_id=:fid AND owner_id=:owner "
                        "AND deleted_at IS NULL AND authorization_version=:version "
                        "AND authorization_sha256=:auth_sha"
                    )
                    params: Dict[str, Any] = {
                        "sid": sid,
                        "fid": flow_id,
                        "owner": owner,
                        "version": authorization_version,
                        "auth_sha": auth_sha,
                        "limit": limit + 1,
                        "offset": offset,
                    }
                    if doc_type is not None:
                        conditions += " AND doc_type=:kind"
                        params["kind"] = doc_type
                    if query is not None:
                        conditions += (
                            " AND (strpos(lower(title),lower(:needle))>0 "
                            "OR strpos(lower(content),lower(:needle))>0)"
                        )
                        params["needle"] = query.strip()
                    rows = (
                        (
                            await db.execute(
                                text(
                                    f"SELECT {_COLUMNS} FROM operator_knowledge_documents "
                                    f"WHERE {conditions} ORDER BY created_at DESC,id DESC "
                                    "LIMIT :limit OFFSET :offset"
                                ),
                                params,
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if len(rows) > limit + 1:
                        raise KnowledgeDenied(503, "Knowledge page exceeds requested bounds")
                    output = []
                    for row in rows[:limit]:
                        self._assert_row(
                            row,
                            sid=sid,
                            flow_id=flow_id,
                            owner=owner,
                            flow_revision=flow_revision,
                            authorization_version=authorization_version,
                            authorization_sha256=auth_sha,
                        )
                        # Search/list never return document text or excerpts;
                        # GET requires explicit document selection.
                        output.append(_metadata(row))
                    return {
                        "items": output,
                        "has_more": len(rows) > limit,
                        "limit": limit,
                        "offset": offset,
                    }
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable operator knowledge listing unavailable") from exc

    async def get(
        self,
        flow_id: str,
        owner: str,
        flow_revision: int,
        authorization_version: int,
        document_id: str,
    ) -> Dict[str, Any]:
        self._validate_identity(flow_id, owner, flow_revision, authorization_version)
        _valid_document_id(document_id)
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    sid, auth_sha = await self._fence(
                        db, flow_id, owner, flow_revision, authorization_version
                    )
                    row = await self._one(db, sid, flow_id, owner, document_id)
                    if row is None:
                        raise KnowledgeDenied(404, "Knowledge document not found")
                    self._assert_row(
                        row,
                        sid=sid,
                        flow_id=flow_id,
                        owner=owner,
                        flow_revision=flow_revision,
                        authorization_version=authorization_version,
                        authorization_sha256=auth_sha,
                    )
                    return {**_metadata(row), "untrusted_content": self._verified_content(row)}
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable operator knowledge read unavailable") from exc

    async def update(
        self,
        flow_id: str,
        owner: str,
        flow_revision: int,
        authorization_version: int,
        document_id: str,
        *,
        expected_revision: int,
        title: str,
        doc_type: str,
        content: str,
    ) -> Dict[str, Any]:
        self._validate_identity(flow_id, owner, flow_revision, authorization_version)
        _valid_document_id(document_id)
        if type(expected_revision) is not int or expected_revision < 1:
            raise KnowledgeDenied(422, "Invalid document revision")
        title = _valid_title(title)
        doc_type = _valid_kind(doc_type)
        content, size, digest = _valid_content(content)
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    sid, auth_sha = await self._fence(
                        db,
                        flow_id,
                        owner,
                        flow_revision,
                        authorization_version,
                        writing=True,
                    )
                    previous = await self._one(db, sid, flow_id, owner, document_id)
                    if previous is None:
                        raise KnowledgeDenied(404, "Knowledge document not found")
                    self._assert_row(
                        previous,
                        sid=sid,
                        flow_id=flow_id,
                        owner=owner,
                        flow_revision=flow_revision,
                        authorization_version=authorization_version,
                        authorization_sha256=auth_sha,
                    )
                    if previous["revision"] != expected_revision:
                        raise KnowledgeDenied(409, "Knowledge document revision changed")
                    row = (
                        (
                            await db.execute(
                                text(
                                    "UPDATE operator_knowledge_documents SET title=:title,doc_type=:kind,"
                                    "content=:content,content_bytes=:bytes,sha256=:sha,revision=revision+1,"
                                    "updated_at=now() WHERE id=:id AND flow_id=:fid AND engagement_id=:sid "
                                    "AND owner_id=:owner AND authorization_version=:version "
                                    "AND authorization_sha256=:auth_sha AND revision=:expected "
                                    "AND deleted_at IS NULL "
                                    f"RETURNING {_COLUMNS}"
                                ),
                                {
                                    "id": document_id,
                                    "sid": sid,
                                    "fid": flow_id,
                                    "owner": owner,
                                    "version": authorization_version,
                                    "auth_sha": auth_sha,
                                    "expected": expected_revision,
                                    "title": title,
                                    "kind": doc_type,
                                    "content": content,
                                    "bytes": size,
                                    "sha": digest,
                                },
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if row is None:
                        raise KnowledgeDenied(409, "Knowledge document revision changed")
                    self._assert_row(
                        row,
                        sid=sid,
                        flow_id=flow_id,
                        owner=owner,
                        flow_revision=flow_revision,
                        authorization_version=authorization_version,
                        authorization_sha256=auth_sha,
                    )
                    return _metadata(row)
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable operator knowledge update unavailable") from exc

    async def delete(
        self,
        flow_id: str,
        owner: str,
        flow_revision: int,
        authorization_version: int,
        document_id: str,
        *,
        expected_revision: int,
    ) -> Dict[str, Any]:
        self._validate_identity(flow_id, owner, flow_revision, authorization_version)
        _valid_document_id(document_id)
        if type(expected_revision) is not int or expected_revision < 1:
            raise KnowledgeDenied(422, "Invalid document revision")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    sid, auth_sha = await self._fence(
                        db,
                        flow_id,
                        owner,
                        flow_revision,
                        authorization_version,
                        writing=True,
                    )
                    previous = await self._one(db, sid, flow_id, owner, document_id)
                    if previous is None:
                        raise KnowledgeDenied(404, "Knowledge document not found")
                    self._assert_row(
                        previous,
                        sid=sid,
                        flow_id=flow_id,
                        owner=owner,
                        flow_revision=flow_revision,
                        authorization_version=authorization_version,
                        authorization_sha256=auth_sha,
                    )
                    if previous["revision"] != expected_revision:
                        raise KnowledgeDenied(409, "Knowledge document revision changed")
                    deleted = (
                        (
                            await db.execute(
                                text(
                                    "UPDATE operator_knowledge_documents "
                                    "SET deleted_at=now(),updated_at=now(),revision=revision+1 "
                                    "WHERE id=:id AND engagement_id=:sid AND flow_id=:fid "
                                    "AND owner_id=:owner AND revision=:expected "
                                    "AND authorization_version=:version AND authorization_sha256=:auth_sha "
                                    "AND deleted_at IS NULL RETURNING id,revision,deleted_at"
                                ),
                                {
                                    "id": document_id,
                                    "sid": sid,
                                    "fid": flow_id,
                                    "owner": owner,
                                    "expected": expected_revision,
                                    "version": authorization_version,
                                    "auth_sha": auth_sha,
                                },
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if deleted is None:
                        raise KnowledgeDenied(409, "Knowledge document revision changed")
                    return {
                        "id": deleted["id"],
                        "revision": deleted["revision"],
                        "deleted": True,
                        "deleted_at": deleted["deleted_at"].isoformat(),
                    }
        except KnowledgeDenied:
            raise
        except Exception as exc:
            raise KnowledgeDenied(503, "Durable operator knowledge deletion unavailable") from exc

    async def search(
        self,
        flow_id: str,
        owner: str,
        flow_revision: int,
        authorization_version: int,
        *,
        query: str,
        limit: int = 20,
        offset: int = 0,
        doc_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self.list(
            flow_id,
            owner,
            flow_revision,
            authorization_version,
            limit=limit,
            offset=offset,
            doc_type=doc_type,
            query=query,
        )
