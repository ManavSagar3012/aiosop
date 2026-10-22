"""AI-OSOP Engagement Router

All engagement lifecycle endpoints: create, list, get, transition, halt.
"""

import asyncio
import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text

from ai_osop.api.deps import (
    CreateEngagementRequest,
    RevokeAuthorizationRequest,
    assert_engagement_access,
    require_role,
    state,
    verify_token,
)
from ai_osop.core.exceptions import WorkflowException, WorkflowTransitionError
from ai_osop.core.models import ScopeDefinition, SessionState
from ai_osop.orchestrator.orchestrator import EngagementPhase

router = APIRouter(prefix="/engagements", tags=["engagements"])

_SAFE_REPORT_ID = re.compile(r"[A-Za-z0-9_-]{1,96}\Z")
_REPORT_RECORD_LIMIT = 200
_REPORT_IO_TIMEOUT_SECONDS = 5.0
_REPORT_SEVERITIES = ("critical", "high", "medium", "low", "info")
_REPORT_PHASES = frozenset(
    (
        "initialized",
        "reconnaissance",
        "vulnerability_discovery",
        "exploitation",
        "post_exploitation",
        "reporting",
        "completed",
        "halted",
    )
)


async def _report_bearer_operator(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    """Never accept report credentials in URLs, including in development."""
    if any(key.lower() == "token" for key in request.query_params):
        raise HTTPException(status_code=403, detail="Bearer header required")
    operator = await verify_token(credentials=credentials, token=None)
    if operator.get("role") not in {"operator", "senior_operator"}:
        raise HTTPException(status_code=403, detail="Operator role required")
    return operator


async def _verified_report_severity_counts(graph: Any, session_id: str) -> Counter:
    """Count only graph-validated records with stored evidence; never read contents.

    ReportingAgent's draft reports currently contain placeholder evidence and
    LLM prose, so neither draft files nor arbitrary graph fields are safe to
    treat as an operator-verified printable report.
    """
    cypher = (
        "MATCH (v:Vulnerability) WHERE v.engagement_id = $sid "
        "AND v.validated = true AND v.evidence IS NOT NULL "
        "AND trim(v.evidence) <> '' AND trim(v.evidence) <> '[]' "
        "RETURN v.severity AS severity LIMIT $limit"
    )
    counts: Counter = Counter()
    seen = 0
    async with graph._driver.session() as db_session:
        result = await db_session.run(
            cypher, {"sid": session_id, "limit": _REPORT_RECORD_LIMIT + 1}
        )
        async for row in result:
            seen += 1
            if seen > _REPORT_RECORD_LIMIT:
                raise HTTPException(
                    status_code=503,
                    detail="Verified summary exceeds the safe report limit",
                )
            severity = row.get("severity") if isinstance(row, dict) else row["severity"]
            normalized = severity.lower() if isinstance(severity, str) else ""
            counts[normalized if normalized in _REPORT_SEVERITIES else "unclassified"] += 1
    return counts


@router.get("/{session_id}/report")
async def get_engagement_report(
    session_id: str,
    response: Response,
    operator: Dict[str, Any] = Depends(_report_bearer_operator),
) -> Dict[str, Any]:
    """Safe printable JSON: only bounded, graph-validated evidence totals.

    No HTML, uploaded report files, URL targets, descriptions, raw evidence,
    agent narratives or session secrets cross this API boundary.
    """
    if not _SAFE_REPORT_ID.fullmatch(session_id):
        raise HTTPException(status_code=404, detail="Engagement not found")

    await assert_engagement_access(operator, session_id)
    orchestrator = state["orchestrator"]
    try:
        # Revalidate against durable owner/engagement state: a cached session
        # must not be able to grant a former owner access after a restart/race.
        session = await asyncio.wait_for(
            orchestrator.session_memory.load_session_state(session_id),
            timeout=_REPORT_IO_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Authoritative engagement state unavailable"
        ) from exc
    if session is None or session.session_id != session_id:
        raise HTTPException(status_code=503, detail="Authoritative engagement state unavailable")
    if operator.get("role") != "senior_operator" and (
        not session.created_by or session.created_by != operator.get("sub")
    ):
        raise HTTPException(status_code=403, detail="Engagement access denied")

    try:
        counts = await asyncio.wait_for(
            _verified_report_severity_counts(orchestrator.graph_memory, session_id),
            timeout=_REPORT_IO_TIMEOUT_SECONDS,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Verified evidence summary unavailable"
        ) from exc

    total = sum(counts.values())
    phase = session.phase if session.phase in _REPORT_PHASES else "unknown"
    if total:
        severity_lines = "\n".join(
            f"- {level.title()}: {counts.get(level, 0)}"
            for level in (*_REPORT_SEVERITIES, "unclassified")
        )
        body = (
            f"AI-OSOP EVIDENCE SUMMARY\nEngagement: {session_id}\n"
            f"Phase: {phase}\n\n"
            "Availability: LIMITED VERIFIED SUMMARY (not a signed final report)\n"
            f"Graph-validated records with stored evidence: {total}\n"
            f"Severity counts:\n{severity_lines}\n\n"
            "Verification boundary: records have a graph validation flag and "
            "stored evidence; this endpoint does not independently examine "
            "evidence or establish that an exploit succeeded. Raw evidence, "
            "identifiers, targets and unapproved narrative are excluded.\n"
        )
        availability = "limited_verified_summary"
    else:
        body = (
            f"AI-OSOP REPORT AVAILABILITY\nEngagement: {session_id}\n"
            f"Phase: {phase}\n\n"
            "Availability: NO VERIFIED REPORT DATA\n"
            "No graph-validated records with stored evidence were available. "
            "No findings, risk rating, security clearance or report approval "
            "can be inferred from this absence.\n"
        )
        availability = "no_verified_evidence"
    # The digest identifies precisely these safe printable bytes, not a
    # cryptographic signature or attestation of their evidence.
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return {
        "report_id": f"summary-{digest}",
        "availability": availability,
        "markdown": body,
        "verified_record_count": total,
    }


@router.post("", response_model=SessionState)
async def create_engagement(
    request: CreateEngagementRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Create new penetration testing engagement."""
    if not isinstance(request.signed_roe, dict):
        raise HTTPException(status_code=403, detail="Verified signed ROE is required")
    cleaned_domains = []
    for d in request.domains:
        d = d.replace("https://", "").replace("http://", "")
        if "/" in d:
            d = d.split("/")[0]
        cleaned_domains.append(d)

    scope = ScopeDefinition(
        engagement_id=request.engagement_id,
        domains=cleaned_domains,
        ips=request.ips,
        exclusions=request.exclusions,
        allowed_techniques=request.allowed_techniques,
        restrictions=request.restrictions,
        approval_required_for=request.approval_required_for,
        testing_window_start=request.testing_window_start,
        testing_window_end=request.testing_window_end,
        authorization_ref=request.authorization_ref
        or (
            request.signed_roe.get("policy", {}).get("authorization_id")
            if isinstance(request.signed_roe.get("policy"), dict)
            else None
        ),
    )

    try:
        session = await state["orchestrator"].create_engagement(
            scope,
            request.roe,
            created_by=operator.get("sub"),
            signed_roe=request.signed_roe,
        )
    except Exception as exc:
        # Never expose a verifier key, policy, target or raw signature.
        raise HTTPException(
            status_code=403, detail="Signed authorization cannot be established"
        ) from exc
    return session


@router.get("", response_model=List[SessionState])
async def list_engagements(operator: Dict[str, Any] = Depends(verify_token)):
    """List all active engagements sorted by creation time (latest last)."""
    sessions = list(state["orchestrator"]._sessions.values())
    sessions.sort(key=lambda x: x.created_at, reverse=True)
    # Ownership filter: operators see only their own engagements;
    # senior_operator sees all.
    if operator.get("role") != "senior_operator":
        sessions = [s for s in sessions if s.created_by == operator.get("sub")]
    return sessions


@router.get("/{session_id}")
async def get_engagement(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get engagement details."""
    session = await assert_engagement_access(operator, session_id)
    return session


@router.get("/{session_id}/authorization/status")
async def get_engagement_authorization_status(
    session_id: str,
    response: Response,
    operator: Dict[str, Any] = Depends(_report_bearer_operator),
) -> Dict[str, Any]:
    """Owner-scoped PostgreSQL signed authorization status, including revoked.

    No signature, policy, owner, revocation reason, or raw secret crosses the API.
    Legacy engagements without a ledger are UNVERIFIED, never active.
    """
    if not _SAFE_REPORT_ID.fullmatch(session_id):
        raise HTTPException(status_code=404, detail="Engagement not found")
    orchestrator = state["orchestrator"]
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"

    async def read_latest() -> tuple[Any, Any]:
        # Read from PostgreSQL, NOT cached sessions or active-only authorization
        # guards (which cannot observe a revoked last version).
        async with orchestrator.session_memory._async_session() as db:
            async with db.begin():
                owner = (
                    (
                        await db.execute(
                            text(
                                "SELECT session_id, created_by FROM session_states "
                                "WHERE session_id = :sid FOR SHARE"
                            ),
                            {"sid": session_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if owner is None:
                    return None, None
                if operator.get("role") != "senior_operator" and (
                    not owner["created_by"] or owner["created_by"] != operator.get("sub")
                ):
                    return owner, "denied"
                latest = (
                    (
                        await db.execute(
                            text(
                                "SELECT version, status, kid, policy_sha256, "
                                "canonical_policy FROM signed_authorizations "
                                "WHERE session_id = :sid "
                                "ORDER BY version DESC LIMIT 1 FOR SHARE"
                            ),
                            {"sid": session_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                # Only advertise 'active' when the canonical persisted
                # signature, current signing key, signed owner/scope and time
                # windows STILL pass the actual dispatch authorization guard.
                # Revoked rows bypass this active-only guard so they remain
                # visible, including after key retirement.
                if latest is not None and latest["status"] == "active":
                    from ai_osop.memory.authorization_store import (
                        AuthorizationDenied,
                        guard_sql,
                    )

                    try:
                        await guard_sql(db, session_id)
                    except AuthorizationDenied:
                        return owner, {**dict(latest), "status": "unverified"}
                return owner, latest

    try:
        owner, latest = await asyncio.wait_for(read_latest(), timeout=_REPORT_IO_TIMEOUT_SECONDS)
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Authoritative authorization state unavailable"
        ) from exc
    if owner is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if latest == "denied":
        raise HTTPException(status_code=403, detail="Engagement access denied")
    if latest is None:
        return {
            "status": "unverified",
            "version": None,
            "key_id": None,
            "expires_at": None,
            "policy_sha256": None,
            "remote_execution_outcome": "unknown",
        }

    try:
        from ai_osop.safety.signed_roe import canonical_json_bytes

        version = latest["version"]
        persisted_status = latest["status"]
        kid = latest["kid"]
        digest = latest["policy_sha256"]
        policy = latest["canonical_policy"]
        if (
            type(version) is not int
            or version <= 0
            or persisted_status not in {"active", "revoked", "unverified"}
            or not isinstance(kid, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", kid)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(policy, dict)
            or policy.get("version") != version
            or policy.get("key_id") != kid
            or policy.get("engagement_id") != session_id
            or hashlib.sha256(canonical_json_bytes(policy)).hexdigest() != digest
        ):
            raise ValueError("Invalid authoritative authorization metadata")
        expires_at = policy.get("expires_at")
        if not isinstance(expires_at, str) or not expires_at.endswith("Z"):
            raise ValueError("Invalid authorization expiration")
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            raise ValueError("Missing authorization expiration timezone")
        expiry = expiry.astimezone(timezone.utc)
        status = (
            "expired"
            if persisted_status in {"active", "unverified"} and datetime.now(timezone.utc) >= expiry
            else persisted_status
        )
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(
            status_code=503, detail="Authoritative authorization metadata invalid"
        ) from exc
    return {
        "status": status,
        "version": version,
        "key_id": kid,
        "expires_at": expiry.isoformat().replace("+00:00", "Z"),
        "policy_sha256": digest,
        "remote_execution_outcome": "unknown",
    }


@router.post("/{session_id}/authorization/revoke")
async def revoke_engagement_authorization(
    session_id: str,
    request: RevokeAuthorizationRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """Revoke signed authority via PostgreSQL CAS, then request local halt.

    Revocation is authoritative regardless of whether stopping an external
    Temporal/MCP action can be confirmed. Never report remote termination
    without a verified provider receipt.
    """
    from ai_osop.memory.authorization_store import AuthorizationStore

    await assert_engagement_access(operator, session_id)
    orchestrator = state["orchestrator"]
    store = AuthorizationStore(orchestrator.session_memory)
    try:
        changed = await store.revoke(
            session_id,
            operator,
            expected_version=request.expected_version,
            reason=request.reason,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=409, detail="Revocation failed or authorization state changed"
        ) from exc
    if changed is not True:
        raise HTTPException(status_code=409, detail="Authorization version is stale")
    halt_requested = False
    try:
        await orchestrator.halt_engagement(session_id, "Signed ROE revoked: " + request.reason)
        halt_requested = True
    except Exception:
        # DB revocation was already committed, so report partial propagation,
        # not a rollback or a confirmed remote stop.
        pass
    return {
        "status": "revoked",
        "authorization_version": request.expected_version,
        "halt_request_accepted": halt_requested,
        "remote_execution_outcome": "unknown",
    }


@router.post("/{session_id}/revoke-authority")
async def revoke_authority_immediate(
    session_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """Real-time emergency revocation kill switch: updates Redis, halts orchestrator and sandbox."""
    await assert_engagement_access(operator, session_id)
    orchestrator = state.get("orchestrator")
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator unavailable")

    sm = orchestrator.session_memory
    # 1. Update Redis revocation flag immediately (< 5ms)
    if hasattr(sm, "store_hot"):
        try:
            await sm.store_hot(
                f"engagement:revoked:{session_id}",
                {"revoked": True, "ts": datetime.utcnow().isoformat()},
                ttl=86400,
            )
        except Exception:
            pass

    # 2. Immediate halt
    halt_requested = False
    try:
        await orchestrator.halt_engagement(session_id, "Real-time authority revocation kill switch triggered")
        halt_requested = True
    except Exception:
        pass

    return {
        "status": "revoked",
        "engagement_id": session_id,
        "halt_request_accepted": halt_requested,
        "revoked_at": datetime.utcnow().isoformat(),
    }



@router.post("/{session_id}/transition")
async def transition_phase(
    session_id: str,
    new_phase: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Transition engagement to new phase."""
    await assert_engagement_access(operator, session_id)
    try:
        phase = EngagementPhase(new_phase)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid phase: {new_phase}")

    try:
        session = await state["orchestrator"].transition_phase(session_id, phase)
        return session
    except WorkflowException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except WorkflowTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        import logging

        logging.getLogger("ai_osop.api.engagements").exception("transition_phase_failed")
        raise HTTPException(status_code=400, detail="Phase transition failed")


@router.post("/{session_id}/halt")
async def halt_engagement(
    session_id: str,
    reason: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Emergency halt engagement."""
    await assert_engagement_access(operator, session_id)
    await state["orchestrator"].halt_engagement(session_id, reason)
    return {"status": "halted", "session_id": session_id, "reason": reason}
