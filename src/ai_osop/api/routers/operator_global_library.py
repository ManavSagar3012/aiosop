"""Inert user-owned library REST API; no Flow or target execution authority."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.memory.operator_global_library import KnowledgeDenied, OperatorGlobalLibrary

_MAX_JSON_WIRE = 65536


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate user library JSON field")
        result[key] = value
    return result


def _strict_json(raw: bytes) -> None:
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Invalid JSON number")),
            parse_float=lambda value: _finite_json_float(value),
        )
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise HTTPException(422, "Strict user library JSON required") from exc
    if type(payload) is not dict:
        raise HTTPException(422, "User library JSON object required")


def _finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Nonfinite user library number")
    return number


class _BoundedUserLibraryRoute(APIRoute):
    """Bound original mutating JSON before FastAPI/Pydantic parses the body."""

    def get_route_handler(self):
        original = super().get_route_handler()
        if not ({"POST", "PUT", "DELETE"} & (self.methods or set())):
            return original

        async def bounded(request: Request):
            media = request.headers.getlist("content-type")
            if len(media) != 1 or media[0].lower().split(";", 1)[0].strip() != "application/json":
                raise HTTPException(415, "User library requires application/json")
            sizes = request.headers.getlist("content-length")
            if len(sizes) > 1 or (
                sizes
                and (
                    not sizes[0]
                    or len(sizes[0]) > 5
                    or not sizes[0].isascii()
                    or not sizes[0].isdecimal()
                    or int(sizes[0]) > _MAX_JSON_WIRE
                )
            ):
                raise HTTPException(413, "User library JSON body exceeds bounds")
            accepted = bytearray()
            async for chunk in request.stream():
                if len(accepted) + len(chunk) > _MAX_JSON_WIRE:
                    raise HTTPException(413, "User library JSON body exceeds bounds")
                accepted.extend(chunk)
            if not accepted:
                raise HTTPException(422, "Strict user library JSON required")
            request._body = bytes(accepted)
            _strict_json(request._body)
            return await original(request)

        return bounded


router = APIRouter(
    prefix="/operator/library",
    tags=["operator-global-library"],
    route_class=_BoundedUserLibraryRoute,
)


class LibraryDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    title: StrictStr = Field(min_length=1, max_length=128)
    doc_type: StrictStr = Field(pattern=r"^(guide|answer|code)$")
    content: StrictStr = Field(min_length=1, max_length=8192)


class LibraryUpdate(LibraryDocument):
    expected_revision: StrictInt = Field(ge=1)


class LibraryDelete(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: StrictInt = Field(ge=1)


def _identity(operator: Dict[str, Any]) -> tuple[str, str]:
    claims = operator.get("claims")
    subject = operator.get("sub")
    if (
        not isinstance(claims, dict)
        or type(claims.get("exp")) is not int
        or operator.get("role") not in ("operator", "senior_operator")
        or type(subject) is not str
        or not 1 <= len(subject) <= 256
    ):
        raise HTTPException(403, "Signed user identity required")
    issuer = claims.get("iss") or "local-jwt"
    if (
        type(issuer) is not str
        or not 1 <= len(issuer) <= 128
        or any(ord(char) < 33 or ord(char) == 127 for char in issuer + subject)
    ):
        raise HTTPException(403, "Stable signed principal namespace required")
    # Stable bounded issuer/subject pseudonym. The existing trusted OIDC auth
    # maps its real issuer+subject to a distinct oidc-* authenticated actor.
    owner = hashlib.sha256((issuer + "\x00" + subject).encode("utf-8")).hexdigest()
    return issuer, owner


def _store() -> OperatorGlobalLibrary:
    memory = getattr(state.get("orchestrator"), "session_memory", None)
    if memory is None:
        raise HTTPException(503, "Durable user library unavailable")
    return OperatorGlobalLibrary(memory)


def _headers(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


def _denied(error: KnowledgeDenied) -> HTTPException:
    return HTTPException(status_code=error.status, detail=str(error))


@router.post("/documents", status_code=201)
async def create_document(
    body: LibraryDocument,
    response: Response,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    issuer, owner = _identity(operator)
    try:
        result = await _store().create(
            issuer, owner, title=body.title, doc_type=body.doc_type, content=body.content
        )
    except KnowledgeDenied as error:
        raise _denied(error) from error
    _headers(response)
    return result


@router.get("/documents")
async def search_documents(
    response: Response,
    query: Optional[str] = Query(default=None, min_length=1, max_length=128),
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0, le=1000),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    issuer, owner = _identity(operator)
    try:
        result = await _store().search(issuer, owner, query=query, limit=limit, offset=offset)
    except KnowledgeDenied as error:
        raise _denied(error) from error
    _headers(response)
    return result


@router.get("/documents/{document_id}")
async def get_document(
    document_id: str,
    response: Response,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    issuer, owner = _identity(operator)
    try:
        result = await _store().get(issuer, owner, document_id)
    except KnowledgeDenied as error:
        raise _denied(error) from error
    _headers(response)
    return result


@router.put("/documents/{document_id}")
async def update_document(
    document_id: str,
    body: LibraryUpdate,
    response: Response,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    issuer, owner = _identity(operator)
    try:
        result = await _store().update(
            issuer,
            owner,
            document_id,
            body.expected_revision,
            title=body.title,
            doc_type=body.doc_type,
            content=body.content,
        )
    except KnowledgeDenied as error:
        raise _denied(error) from error
    _headers(response)
    return result


@router.delete("/documents/{document_id}")
async def delete_document(
    document_id: str,
    body: LibraryDelete,
    response: Response,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    issuer, owner = _identity(operator)
    try:
        result = await _store().delete(issuer, owner, document_id, body.expected_revision)
    except KnowledgeDenied as error:
        raise _denied(error) from error
    _headers(response)
    return result
