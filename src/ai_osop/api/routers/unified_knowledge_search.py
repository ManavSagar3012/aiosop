"""Read-only two-source operator knowledge discovery with explicit provenance.

This endpoint joins *results*, not authorization: the independent 0039
principal-owned library and the 0019/0038 Flow-owned documents each execute
their own authoritative PostgreSQL scope fence.  No text is passed into
agents, no MCP tool or model is invoked, and there is no cross-store atomic
snapshot or claim of target-side evidence.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.api.routers.operator_global_library import _identity
from ai_osop.memory.operator_global_library import (
    KnowledgeDenied as GlobalKnowledgeDenied,
    OperatorGlobalLibrary,
)
from ai_osop.memory.operator_knowledge import (
    KnowledgeDenied as FlowKnowledgeDenied,
    OperatorKnowledgeStore,
)

router = APIRouter(prefix="/operator/search", tags=["operator-knowledge-discovery"])
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._:-]{1,59}\Z")
_GLOBAL_DOCUMENT = re.compile(r"lib-[0-9a-f]{32}\Z")
_FLOW_DOCUMENT = re.compile(r"knowledge-[0-9a-f]{32}\Z")
_SAFE_FIELDS = frozenset(
    {
        "id",
        "flow_id",
        "title",
        "doc_type",
        "revision",
        "sha256",
        "content_bytes",
        "created_at",
        "version_created_at",
        "updated_at",
        "source_flow_revision",
        "authorization_version",
    }
)


def _safe_items(page: Any, *, source: str, flow_id: Optional[str], limit: int) -> Dict[str, Any]:
    if (
        type(page) is not dict
        or type(page.get("items")) is not list
        or len(page["items"]) > limit
        or type(page.get("has_more")) is not bool
        or page.get("approved_for_agent_context", False) is not False
    ):
        raise HTTPException(503, "Knowledge source provenance unavailable")
    results = []
    seen = set()
    for item in page["items"]:
        if (
            type(item) is not dict
            or type(item.get("id")) is not str
            or item["id"] in seen
            or not (
                (_GLOBAL_DOCUMENT if source == "global" else _FLOW_DOCUMENT).fullmatch(item["id"])
            )
            or type(item.get("title")) is not str
            or not 1 <= len(item["title"]) <= 128
            or any(
                ord(ch) < 32 or ord(ch) == 127 or 0xD800 <= ord(ch) <= 0xDFFF
                for ch in item["title"]
            )
            or item.get("doc_type") not in ("guide", "answer", "code")
            or type(item.get("revision")) is not int
            or item["revision"] < 1
            or type(item.get("sha256")) is not str
            or not _SHA.fullmatch(item["sha256"])
            or type(item.get("content_bytes")) is not int
            or not 1 <= item["content_bytes"] <= 8192
            or item.get("approved_for_agent_context") is not False
            or (source == "flow" and item.get("flow_id") != flow_id)
            or (source == "global" and "flow_id" in item)
            or (source == "global" and item.get("content_classification") != "untrusted_user_text")
            or (
                source == "flow" and item.get("content_classification") != "untrusted_operator_text"
            )
        ):
            raise HTTPException(503, "Knowledge source metadata mismatch")
        seen.add(item["id"])
        # Never return content, excerpts, owner identifiers or provider-defined
        # verified/certified flags.  This is discovery of inert original text.
        metadata = {name: item[name] for name in _SAFE_FIELDS if name in item}
        results.append(
            {
                **metadata,
                "source": "user_global_0039" if source == "global" else "flow_local_0019_0038",
                "trust": "untrusted_human_text",
                "verified_target_evidence": False,
                "approved_for_agent_context": False,
                "safe_for_execution": False,
                "reportable": False,
            }
        )
    return {"items": results, "has_more": page["has_more"]}


@router.get("/knowledge")
async def unified_knowledge_search(
    response: Response,
    query: str = Query(min_length=1, max_length=128),
    limit_per_source: int = Query(default=10, ge=1, le=10),
    flow_id: Optional[str] = None,
    expected_flow_revision: Optional[int] = Query(default=None, ge=0),
    expected_authorization_version: Optional[int] = Query(default=None, ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Search user-global and optionally current signed Flow-owned metadata.

    Caller-supplied Flow identity is never authority: OperatorKnowledgeStore
    independently checks the persisted owner, signed Flow revision and ROE.
    """
    if (
        not query.strip()
        or any(
            ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in query
        )
        or ((flow_id is None) != (expected_flow_revision is None))
        or ((flow_id is None) != (expected_authorization_version is None))
        or (flow_id is not None and not _FLOW.fullmatch(flow_id))
    ):
        raise HTTPException(422, "Bounded search and complete signed Flow identity required")
    memory = getattr(state.get("orchestrator"), "session_memory", None)
    if memory is None:
        raise HTTPException(503, "Durable knowledge search unavailable")
    issuer, owner = _identity(operator)
    try:
        global_page = await OperatorGlobalLibrary(memory).search(
            issuer,
            owner,
            query=query,
            limit=limit_per_source,
            offset=0,
        )
        global_result = _safe_items(
            global_page,
            source="global",
            flow_id=None,
            limit=limit_per_source,
        )
        pages = {"user_global_0039": global_result}
        if flow_id is not None:
            flow_page = await OperatorKnowledgeStore(memory).search(
                flow_id,
                operator["sub"],
                expected_flow_revision,
                expected_authorization_version,
                query=query,
                limit=limit_per_source,
                offset=0,
            )
            pages["flow_local_0019_0038"] = _safe_items(
                flow_page,
                source="flow",
                flow_id=flow_id,
                limit=limit_per_source,
            )
    except (GlobalKnowledgeDenied, FlowKnowledgeDenied) as exc:
        # A denied Flow must not fall back to a misleading partial global
        # success. No ownership/engagement identifiers enter the error body.
        raise HTTPException(exc.status, "Knowledge search scope unavailable") from exc
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return {
        "status": "metadata_only",
        "query": query,
        "sources": pages,
        "atomic_cross_source_snapshot": False,
        "synthesis_performed": False,
        "independent_target_effect_verified": False,
        "approved_for_agent_context": False,
        "safe_for_execution": False,
        "reportable": False,
    }
