"""Inert operator-authored knowledge CRUD under a signed Flow authorization fence."""

from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.memory.operator_knowledge import KnowledgeDenied, OperatorKnowledgeStore

router = APIRouter(prefix="/flows", tags=["operator-knowledge"])


class KnowledgeBody(BaseModel):
    title: str = Field(min_length=1, max_length=128)
    doc_type: Literal["guide", "answer", "code"]
    content: str = Field(min_length=1, max_length=8192)


class KnowledgeUpdate(KnowledgeBody):
    expected_document_revision: int = Field(ge=1)


class KnowledgeDelete(BaseModel):
    expected_document_revision: int = Field(ge=1)


def _store() -> OperatorKnowledgeStore:
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if memory is None:
        raise HTTPException(503, "Durable operator knowledge unavailable")
    return OperatorKnowledgeStore(memory)


def _failure(exc: KnowledgeDenied) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


def _no_cache(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


@router.post("/{flow_id}/operator-knowledge", status_code=201)
async def create_operator_knowledge(
    flow_id: str,
    body: KnowledgeBody,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    try:
        result = await _store().create(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
            title=body.title,
            doc_type=body.doc_type,
            content=body.content,
        )
    except KnowledgeDenied as exc:
        raise _failure(exc) from exc
    _no_cache(response)
    return result


@router.get("/{flow_id}/operator-knowledge")
async def list_operator_knowledge(
    flow_id: str,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0, le=1000),
    doc_type: Optional[Literal["guide", "answer", "code"]] = None,
    query: Optional[str] = Query(default=None, min_length=1, max_length=128),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    try:
        result = await _store().list(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
            limit=limit,
            offset=offset,
            doc_type=doc_type,
            query=query,
        )
    except KnowledgeDenied as exc:
        raise _failure(exc) from exc
    _no_cache(response)
    return result


@router.get("/{flow_id}/operator-knowledge/search")
async def search_operator_knowledge(
    flow_id: str,
    response: Response,
    query: str = Query(min_length=1, max_length=128),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0, le=1000),
    doc_type: Optional[Literal["guide", "answer", "code"]] = None,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    try:
        result = await _store().search(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
            query=query,
            limit=limit,
            offset=offset,
            doc_type=doc_type,
        )
    except KnowledgeDenied as exc:
        raise _failure(exc) from exc
    _no_cache(response)
    return result


@router.get("/{flow_id}/operator-knowledge/{document_id}")
async def get_operator_knowledge(
    flow_id: str,
    document_id: str,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    try:
        result = await _store().get(
            flow_id, operator["sub"], expected_revision, expected_authorization_version, document_id
        )
    except KnowledgeDenied as exc:
        raise _failure(exc) from exc
    _no_cache(response)
    return result


@router.put("/{flow_id}/operator-knowledge/{document_id}")
async def update_operator_knowledge(
    flow_id: str,
    document_id: str,
    body: KnowledgeUpdate,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    try:
        result = await _store().update(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
            document_id,
            expected_revision=body.expected_document_revision,
            title=body.title,
            doc_type=body.doc_type,
            content=body.content,
        )
    except KnowledgeDenied as exc:
        raise _failure(exc) from exc
    _no_cache(response)
    return result


@router.delete("/{flow_id}/operator-knowledge/{document_id}")
async def delete_operator_knowledge(
    flow_id: str,
    document_id: str,
    body: KnowledgeDelete,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    try:
        result = await _store().delete(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
            document_id,
            expected_revision=body.expected_document_revision,
        )
    except KnowledgeDenied as exc:
        raise _failure(exc) from exc
    _no_cache(response)
    return result
