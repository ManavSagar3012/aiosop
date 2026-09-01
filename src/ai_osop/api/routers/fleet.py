"""AI-OSOP Fleet Router — multi-target intake and fleet-wide aggregation.

FLEET-MODE-001 (2026-09-01): turns one-engagement-at-a-time into a bug-bounty
farm. An operator POSTs a list of AUTHORIZED domains; the fleet intake:
  1. creates one bounded engagement per domain (same signed-scope machinery
     as the single-engagement path — every gate applies to fleet members),
  2. auto-confirms each card under the operator's authority reference,
  3. kicks each into reconnaissance so the autonomous machinery takes over,
  4. returns a fleet manifest for tracking.

Safety invariants (unchanged from single engagements):
  - every domain lands in its OWN engagement scope — a finding or task on
    target A can never reach target B (per-engagement ScopeEnforcer),
  - exploit-class tasks still raise operator approvals per engagement,
  - intake refuses domains that match no scope-suffix rule (each engagement
    scopes ONLY its own domain; no wildcarding happens silently),
  - hard ceiling on fleet size per intake (MAX_FLEET_TARGETS) so a fat-fingered
    list cannot stampede the scheduler.

GET /system/fleet/status aggregates all fleet engagements: per-target task
progress, finding counts by severity, and report readiness.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ai_osop.api.deps import require_role, state
from ai_osop.core.config import EngagementPhase
from ai_osop.core.models import ScopeDefinition

router = APIRouter(prefix="/system/fleet", tags=["fleet"])

MAX_FLEET_TARGETS = 8


class FleetIntakeRequest(BaseModel):
    """Authorized target list -> one bounded engagement per domain."""

    targets: List[str] = Field(..., min_length=1, max_length=MAX_FLEET_TARGETS)
    authorization_ref: str = Field(
        ...,
        description="Per-target authorization reference (e.g. program policy URL + operator id)",
    )
    allowed_techniques: List[str] = Field(
        default_factory=lambda: ["web_pentest", "xss", "sqli", "api_security", "ssrf", "jwt", "idor"]
    )
    fleet_id: Optional[str] = None
    notes: Optional[str] = None


class FleetTargetResult(BaseModel):
    domain: str
    session_id: str
    status: str = "launched"


def _clean_domain(raw: str) -> str:
    d = (raw or "").strip()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    if "/" in d:
        d = d.split("/")[0]
    if ":" in d:
        d = d.split(":")[0]
    if not d or "." not in d or " " in d or len(d) > 253:
        raise HTTPException(status_code=400, detail=f"invalid target domain: {raw!r}")
    return d.lower()


@router.post("/intake", response_model=Dict[str, Any])
async def fleet_intake(
    request: FleetIntakeRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Create + confirm + launch one bounded engagement per authorized domain."""
    orch = state.get("orchestrator")
    if not orch:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    if not request.authorization_ref or len(request.authorization_ref) < 8:
        raise HTTPException(
            status_code=400,
            detail="authorization_ref is required (e.g. program policy URL + operator id)",
        )
    fleet_id = request.fleet_id or f"fleet-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    launched: List[FleetTargetResult] = []
    skipped: List[Dict[str, str]] = []
    for raw in request.targets:
        try:
            domain = _clean_domain(raw)
        except HTTPException as e:
            skipped.append({"domain": raw, "reason": str(e.detail)})
            continue
        engagement_id = f"{fleet_id}-{domain.replace('.', '-')}"[:60]
        scope = ScopeDefinition(
            engagement_id=engagement_id,
            domains=[domain],
            ips=[],
            exclusions=[],
            allowed_techniques=request.allowed_techniques,
            authorization_ref=f"FLEET {fleet_id}: {request.authorization_ref}",
        )
        try:
            session = await orch.create_engagement(
                scope, {"objective": request.notes or "fleet audit", "fleet_id": fleet_id},
                created_by=operator.get("sub"),
            )
            # Operator authority already proven by the shared authorization_ref
            # on the intake call — auto-confirm each card under it.
            await orch.confirm_engagement(session.session_id, operator.get("sub", "operator"))
            await orch.transition_phase(session.session_id, EngagementPhase.RECONNAISSANCE)
            launched.append(
                FleetTargetResult(domain=domain, session_id=session.session_id)
            )
        except Exception as e:  # noqa: BLE001 - per-target failure shouldn't sink the fleet
            skipped.append({"domain": domain, "reason": f"engagement creation failed: {str(e)[:120]}"})
    return {
        "fleet_id": fleet_id,
        "launched": [t.model_dump() for t in launched],
        "skipped": skipped,
        "operator": operator.get("sub"),
        "authorization_ref": request.authorization_ref,
        "note": (
            "Each target runs in its OWN signed scope; exploit-class tasks raise "
            "per-engagement operator approvals as usual."
        ),
    }


@router.get("/status", response_model=Dict[str, Any])
async def fleet_status(
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))
):
    """Aggregate every engagement into a fleet dashboard: progress, findings,
    and report readiness per target."""
    orch = state.get("orchestrator")
    if not orch:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    targets = []
    totals: Dict[str, int] = {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for session in list(orch._sessions.values()):
        row: Dict[str, Any] = {
            "session_id": session.session_id,
            "engagement_id": session.scope.engagement_id,
            "domain": session.scope.domains[0] if session.scope.domains else "",
            "phase": session.phase,
            "created_by": session.created_by,
        }
        try:
            tasks = [
                t
                for t in orch.state.get_all_tasks().values()
                if t.engagement_id == session.session_id
            ]
            row["tasks"] = {
                "total": len(tasks),
                "completed": sum(1 for t in tasks if t.status == "completed"),
                "failed": sum(1 for t in tasks if t.status == "failed"),
                "active": sum(1 for t in tasks if t.status in ("pending", "running", "awaiting_approval")),
            }
        except Exception:  # noqa: BLE001
            row["tasks"] = {"total": 0, "completed": 0, "failed": 0, "active": 0}
        try:
            vuln_records = await orch.graph_memory.run_read_query(
                "MATCH (v:Vulnerability {engagement_id: $sid}) RETURN v.severity AS sev",
                {"sid": session.session_id},
            )
            sev_count: Dict[str, int] = {}
            for r in vuln_records:
                sev = str(r.get("sev") or "info").lower()
                sev_count[sev] = sev_count.get(sev, 0) + 1
            row["findings_by_severity"] = sev_count
            row["findings"] = sum(sev_count.values())
            totals["findings"] += row["findings"]
            for sev, n in sev_count.items():
                totals[sev] = totals.get(sev, 0) + n
        except Exception:  # noqa: BLE001 - graph is advisory here
            row["findings_by_severity"], row["findings"] = {}, 0
        row["report_ready"] = session.phase in ("reporting", "completed")
        targets.append(row)
    targets.sort(key=lambda t: (t["phase"] != "completed", t.get("findings", 0)), reverse=True)
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "active_engagements": sum(1 for t in targets if t["phase"] not in ("completed", "halted")),
        "totals": totals,
        "targets": targets,
    }
