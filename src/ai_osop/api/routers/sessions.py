"""AI-OSOP Session Router

User session CRUD for authenticated differential testing.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from ai_osop.api.deps import (
    UserSessionImportRequest,
    UserSessionResponse,
    assert_engagement_access,
    require_role,
    state,
    verify_token,
)
from ai_osop.auth.session_store import UserSessionNotFound

router = APIRouter(prefix="/engagements", tags=["sessions"])


def _session_response(sess) -> UserSessionResponse:
    return UserSessionResponse(
        engagement_id=sess.engagement_id,
        user_label=sess.user_label,
        cookie_count=len(sess.cookies),
        has_bearer=bool(sess.bearer_token),
        has_csrf=bool(sess.csrf_token),
        has_local_storage=bool(sess.local_storage),
        captured_at=sess.captured_at.isoformat() if sess.captured_at else "",
        expires_at=sess.expires_at.isoformat() if sess.expires_at else None,
        metadata=sess.metadata_blob or {},
    )


async def _trigger_authenticated_discovery(session_id: str) -> None:
    """Auto-dispatch hook: after a session import, kick off autonomous discovery."""
    if state["orchestrator"] is None:
        return
    try:
        await state["orchestrator"].ensure_authenticated_discovery(session_id)
    except Exception as e:
        import logging

        logging.getLogger("ai_osop.api.sessions").warning(
            f"ensure_authenticated_discovery failed for {session_id}: {e}"
        )


@router.put("/{session_id}/sessions/{user_label}", response_model=UserSessionResponse)
async def put_user_session(
    session_id: str,
    user_label: str,
    body: UserSessionImportRequest,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Import or replace a user-session (cookies + tokens) for an engagement."""
    await assert_engagement_access(operator, session_id)
    if state["session_store"] is None:
        raise HTTPException(status_code=503, detail="session_store not initialized")
    if body.user_label and body.user_label != user_label:
        raise HTTPException(status_code=400, detail="path user_label != body user_label")
    sess = await state["session_store"].save_session(
        engagement_id=session_id,
        user_label=user_label,
        cookies=body.cookies,
        bearer_token=body.bearer_token,
        local_storage=body.local_storage,
        session_storage=body.session_storage,
        csrf_token=body.csrf_token,
        extra_headers=body.extra_headers,
        user_agent=body.user_agent,
        metadata_blob={**body.metadata, "imported_by": operator.get("sub", "?")},
    )
    await _trigger_authenticated_discovery(session_id)
    return _session_response(sess)


@router.post("/{session_id}/sessions", response_model=UserSessionResponse)
async def post_user_session(
    session_id: str,
    body: UserSessionImportRequest,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Create-or-replace a user-session (POST variant)."""
    await assert_engagement_access(operator, session_id)
    if state["session_store"] is None:
        raise HTTPException(status_code=503, detail="session_store not initialized")
    if not body.user_label:
        raise HTTPException(status_code=400, detail="user_label is required")
    sess = await state["session_store"].save_session(
        engagement_id=session_id,
        user_label=body.user_label,
        cookies=body.cookies,
        bearer_token=body.bearer_token,
        local_storage=body.local_storage,
        session_storage=body.session_storage,
        csrf_token=body.csrf_token,
        extra_headers=body.extra_headers,
        user_agent=body.user_agent,
        metadata_blob={**body.metadata, "imported_by": operator.get("sub", "?")},
    )
    await _trigger_authenticated_discovery(session_id)
    return _session_response(sess)


@router.get("/{session_id}/sessions", response_model=List[UserSessionResponse])
async def list_user_sessions(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """List all captured user sessions for an engagement."""
    await assert_engagement_access(operator, session_id)
    if state["session_store"] is None:
        raise HTTPException(status_code=503, detail="session_store not initialized")
    sessions = await state["session_store"].list_sessions(session_id)
    return [_session_response(s) for s in sessions]


@router.get("/{session_id}/sessions/{user_label}", response_model=UserSessionResponse)
async def get_user_session(
    session_id: str,
    user_label: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Get metadata for a single user session (does not return secrets)."""
    await assert_engagement_access(operator, session_id)
    if state["session_store"] is None:
        raise HTTPException(status_code=503, detail="session_store not initialized")
    try:
        sess = await state["session_store"].get_session(session_id, user_label)
    except UserSessionNotFound:
        raise HTTPException(status_code=404, detail="user session not found")
    return _session_response(sess)


@router.delete("/{session_id}/sessions/{user_label}")
async def delete_user_session(
    session_id: str,
    user_label: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Revoke a captured user session."""
    await assert_engagement_access(operator, session_id)
    if state["session_store"] is None:
        raise HTTPException(status_code=503, detail="session_store not initialized")
    deleted = await state["session_store"].delete_session(session_id, user_label)
    if not deleted:
        raise HTTPException(status_code=404, detail="user session not found")
    return {"deleted": True, "engagement_id": session_id, "user_label": user_label}
