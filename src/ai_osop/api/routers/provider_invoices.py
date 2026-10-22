"""Senior operator invoice attestations and read-only provider cost observations.

Invoice documents stay outside this API. An attestation is human-supplied
billing evidence, never a provider-verified receipt or execution outcome.
Opt-in OpenAI Costs API observations are independent project aggregates and
do not reconcile individual calls or mutate the model ledger.
"""

import asyncio
import decimal
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Type, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError
from sqlalchemy import select

from ai_osop.api.deps import _oidc_config, state, verify_token
from ai_osop.core.config import settings
from ai_osop.memory.authorization_store import AuthorizationDenied, guard_sql
from ai_osop.memory.model_usage import (
    ModelBudgetExceeded,
    ModelUsageLedger,
    _amount,
    _limit,
)
from ai_osop.memory.provider_invoice_trust import (
    OpenAICostSource,
    ProviderCostInvalid,
    ProviderCostUnavailable,
    require_bound_engagement,
    trust_mode,
    verify_observation,
)
from ai_osop.memory.session_memory import SessionStateORM
from ai_osop.memory.supervision_store import SupervisionConflict

router = APIRouter(prefix="/supervision/engagements", tags=["supervision"])


_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"
_DIGEST = r"^[0-9a-f]{64}$"
_MODEL = r"^[A-Za-z0-9_.:/-]{1,90}$"
_MONEY = r"^(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,8})?$"
_DELTA = r"^-?(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,8})?$"
_MAX_JSON_BYTES = 4096


class InvoiceEvidence(BaseModel):
    """Exact original call binding and invoice metadata; no actor/role fields."""

    model_config = ConfigDict(extra="forbid", strict=True)

    expected_task_id: str = Field(min_length=1, max_length=64, pattern=_IDENTIFIER)
    expected_model: str = Field(min_length=1, max_length=90, pattern=_MODEL)
    expected_operation: str = Field(pattern=r"^(completion|embedding)$")
    expected_authorization_version: StrictInt = Field(ge=1)
    provider: str = Field(min_length=1, max_length=90, pattern=_IDENTIFIER)
    invoice_reference: str = Field(min_length=1, max_length=128, pattern=_IDENTIFIER)
    invoice_line_id: str = Field(min_length=1, max_length=128, pattern=_IDENTIFIER)
    invoice_sha256: str = Field(pattern=_DIGEST)


class InvoiceReconciliation(InvoiceEvidence):
    billed_cost_usd: str = Field(pattern=_MONEY)
    input_tokens: Optional[StrictInt] = Field(default=None, ge=0, le=2**63 - 1)
    output_tokens: Optional[StrictInt] = Field(default=None, ge=0, le=2**63 - 1)


class InvoiceAdjustment(InvoiceEvidence):
    adjustment_id: str = Field(min_length=1, max_length=128, pattern=_IDENTIFIER)
    cost_delta_usd: str = Field(pattern=_DELTA)


class ProviderCostsQuery(BaseModel):
    """Bounded completed UTC-day window; project is fixed by server policy."""

    model_config = ConfigDict(extra="forbid", strict=True)
    start_time: StrictInt = Field(ge=0)
    end_time: StrictInt = Field(ge=0)


_InvoiceModel = TypeVar("_InvoiceModel", bound=BaseModel)


async def _metadata(request: Request, schema: Type[_InvoiceModel]) -> _InvoiceModel:
    """Bound and validate evidence without reflecting invoice uploads/errors."""
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(status_code=415, detail="Invoice metadata must be JSON")
    chunks = bytearray()
    async for part in request.stream():
        if len(chunks) + len(part) > _MAX_JSON_BYTES:
            raise HTTPException(status_code=413, detail="Invoice metadata exceeds size limit")
        chunks.extend(part)
    try:
        return schema.model_validate_json(bytes(chunks))
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Invalid invoice metadata") from exc


async def _verified_senior(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    """Require individually identified, unexpired senior JWT in bearer header."""
    if credentials is None or credentials.scheme.lower() != "bearer" or request.query_params:
        raise HTTPException(status_code=403, detail="Bearer header required")
    # A shared development API token cannot identify a human. Accept only
    # signed, expiring senior identities from local JWT or configured OIDC;
    # the verifier still validates the caller and durable owner separately.
    if not settings.jwt_secret and _oidc_config() is None:
        raise HTTPException(status_code=503, detail="Operator JWT verification unavailable")
    operator = await verify_token(credentials=credentials, token=None)
    claims = operator.get("claims")
    expiry = claims.get("exp") if isinstance(claims, dict) else None
    subject = operator.get("sub")
    if (
        operator.get("role") != "senior_operator"
        or not isinstance(subject, str)
        or not 0 < len(subject) <= 64
        or not subject.strip()
    ):
        raise HTTPException(status_code=403, detail="Senior operator identity required")
    if type(expiry) is not int or expiry <= datetime.now(timezone.utc).timestamp():
        raise HTTPException(status_code=401, detail="Valid operator JWT expiry required")
    return operator


async def _owned_ledger(engagement_id: str, operator: Dict[str, Any]) -> ModelUsageLedger:
    """Fail closed on durable engagement ownership, including for senior roles."""
    if not isinstance(engagement_id, str) or not 0 < len(engagement_id) <= 64:
        raise HTTPException(status_code=404, detail="Engagement not found")
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    sessions = getattr(memory, "_async_session", None)
    if not callable(sessions):
        raise HTTPException(status_code=503, detail="Authoritative billing store unavailable")

    async def lookup_owner() -> Optional[str]:
        async with sessions() as db:
            return (
                await db.execute(
                    select(SessionStateORM.created_by).where(
                        SessionStateORM.session_id == engagement_id
                    )
                )
            ).scalar_one_or_none()

    try:
        created_by = await asyncio.wait_for(lookup_owner(), timeout=5.0)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Engagement ownership unavailable") from exc
    if created_by is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if created_by != operator["sub"]:
        raise HTTPException(status_code=403, detail="Engagement access denied")
    return ModelUsageLedger(memory)


@router.get("/{engagement_id}/model-usage/provider-capabilities")
async def read_provider_capabilities(
    engagement_id: str,
    response: Response,
    operator: Dict[str, Any] = Depends(_verified_senior),
) -> Dict[str, Any]:
    """Read local operator-declared routes, never contact paid providers.

    A signed, tenant-owned engagement is required even for this read-only
    catalog. Its presence does not certify remote model availability.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    await _owned_ledger(engagement_id, operator)
    from ai_osop.core.provider_routing import configured_routes

    try:
        routes = configured_routes()
        entries = routes.capability_report() if routes is not None else []
        if not isinstance(entries, list) or len(entries) > 100:
            raise ValueError("Capability catalog exceeds bounded result set")
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Provider catalog unavailable") from exc
    return {
        "engagement_id": engagement_id,
        "routes": entries,
        "provider_currently_available_verified": False,
        "provider_native_cost_ceiling_verified": False,
        "signed_budget_admission_still_required": True,
    }


def _model_budget_explanation(roe: Dict[str, Any], summary: Dict[str, Any]) -> Dict[str, Any]:
    """Explain definite quota blockers from signed limits and a PG snapshot.

    This deliberately never returns an admissible decision. ModelUsageLedger
    .reserve is the sole atomic cross-replica spending authority; its Task,
    approval, Flow, lease, ROE and budget checks cannot run in an operator GET.
    """
    reasons = []
    count_limit = _limit(roe, "llm_call_budget_total")
    cost_limit = _limit(roe, "llm_cost_budget_usd", fractional=True)
    precharge = _limit(roe, "llm_precharge_max_call_usd", fractional=True)
    integer_keys = ("calls", "unknown_calls", "unpriced_calls", "unreconciled_cost_calls")
    if not isinstance(summary, dict) or summary.get("engagement_id") is None:
        raise ValueError("Missing authoritative model ledger")
    if any(type(summary.get(key)) is not int or summary[key] < 0 for key in integer_keys):
        raise ValueError("Invalid authoritative model ledger counts")
    if summary["unknown_calls"] > summary["calls"] or summary["unpriced_calls"] > summary["calls"]:
        raise ValueError("Inconsistent authoritative model ledger counts")
    outstanding = _amount(summary.get("outstanding_precharge_usd"))
    if count_limit is None and cost_limit is None:
        reasons.append("signed_model_budget_missing")
    if count_limit is not None and summary["calls"] >= count_limit:
        reasons.append("signed_call_quota_exhausted")
    if summary["unknown_calls"] or summary["unreconciled_cost_calls"]:
        reasons.append("unreconciled_provider_outcome")
    spent = None
    if cost_limit is not None:
        if precharge is None or precharge <= 0:
            reasons.append("signed_precharge_missing")
        if summary["unpriced_calls"]:
            reasons.append("unpriced_provider_cost")
        if summary["calls"] == 0:
            spent = decimal.Decimal(0)
        elif summary.get("invoice_adjusted_cost_usd") is not None:
            spent = _amount(summary["invoice_adjusted_cost_usd"])
        if spent is None:
            reasons.append("cost_ledger_incomplete")
        if spent is not None and precharge is not None and precharge > 0:
            ceiling = _amount(precharge.quantize(decimal.Decimal("0.00000001"), rounding=decimal.ROUND_CEILING))
            if spent + outstanding + ceiling > cost_limit:
                reasons.append("signed_cost_budget_exhausted")
    return {
        "reasons": reasons,
        "budget": {
            "signed_call_limit": int(count_limit) if count_limit is not None else None,
            "recorded_calls": summary["calls"],
            "unresolved_calls": summary["unknown_calls"],
            "unpriced_calls": summary["unpriced_calls"],
            "signed_cost_limit_usd": str(cost_limit) if cost_limit is not None else None,
            "signed_max_precharge_usd": str(precharge) if precharge is not None else None,
            "known_adjusted_cost_usd": str(spent) if spent is not None else None,
            "outstanding_precharge_usd": str(outstanding),
            "provider_native_cost_ceiling_verified": False,
        },
    }


@router.get("/{engagement_id}/model-usage/provider-admission-explanation")
async def read_provider_admission_explanation(
    engagement_id: str,
    response: Response,
    operator: Dict[str, Any] = Depends(_verified_senior),
) -> Dict[str, Any]:
    """Explain operator-visible blockers; no provider calls or model reservation."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    ledger = await _owned_ledger(engagement_id, operator)
    # A missing/revoked signer is UNKNOWN rather than a legitimate budget
    # rejection. The signed source is checked using currently trusted keys;
    # raw ROE from an unverified engagement row cannot authorize anything.
    try:
        async with ledger._sessions() as db:
            async with db.begin():
                from ai_osop.memory.authorization_store import VerifiedAuthorization

                signed = await guard_sql(db, engagement_id)
                if (
                    not isinstance(signed, VerifiedAuthorization)
                    or signed.session_id != engagement_id
                    or type(signed.version) is not int
                    or signed.version <= 0
                ):
                    raise AuthorizationDenied("Signed authorization verification unavailable")
                stored = (
                    await db.execute(
                        select(SessionStateORM).where(SessionStateORM.session_id == engagement_id)
                        .with_for_update(read=True)
                    )
                ).scalar_one_or_none()
                if stored is None or stored.created_by != operator["sub"]:
                    raise HTTPException(status_code=403, detail="Engagement access denied")
                if not isinstance(stored.roe, dict):
                    raise ModelBudgetExceeded("Signed model budget unavailable")
                roe = dict(stored.roe)
                phase = stored.phase
    except HTTPException:
        raise
    except AuthorizationDenied:
        return {
            "engagement_id": engagement_id,
            "scope": "engagement_not_individual_flow",
            "status": "unavailable",
            "reasons": ["signed_authorization_unavailable"],
            "routes": [],
            "budget": None,
            "signed_roe_current_at_read": False,
            "admission_attempted": False,
            "execution_admitted": False,
            "provider_called": False,
            "reservation_created": False,
            "provider_native_cost_ceiling_verified": False,
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Signed model admission readback unavailable") from exc

    from ai_osop.core.provider_routing import configured_routes

    try:
        configured = configured_routes()
        declarations = configured.capability_report() if configured is not None else []
        if not isinstance(declarations, list) or len(declarations) > 16:
            raise ValueError("Invalid operator route declarations")
        summary = await asyncio.wait_for(ledger.summary(engagement_id), timeout=5.0)
        if summary.get("engagement_id") != engagement_id:
            raise ValueError("Model ledger engagement mismatch")
        explained = _model_budget_explanation(roe, summary)
        reasons = explained["reasons"]
        if phase in {"halted", "completed"}:
            reasons.append("engagement_closed")
        if configured is None:
            reasons.append("provider_routes_not_configured")
        elif configured.version != 2:
            reasons.append("trusted_v2_route_policy_missing")
        if not declarations or all(route.get("deployment") != "locally_configured" for route in declarations):
            reasons.append("no_locally_configured_deployment")
        # Allowlist fields explicitly; capability_report may include source
        # diagnostics, never propagate credentials or arbitrary nested data.
        routes = []
        for entry in declarations:
            if not isinstance(entry, dict) or entry.get("deployment") not in {
                "locally_configured", "unavailable"
            }:
                raise ValueError("Provider route declaration unavailable")
            routes.append({
                "provider": entry["provider"],
                "model": entry["model"],
                "operations": entry["operations"],
                "configured_capabilities": entry.get("configured_capabilities", []),
                "allowed_roles": entry.get("allowed_roles", []),
                "deployment": entry["deployment"],
                "provider_served_model_verified": False,
                "provider_capability_verified": False,
            })
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Provider admission explanation unavailable") from exc
    return {
        "engagement_id": engagement_id,
        "scope": "engagement_not_individual_flow",
        "status": "blocked" if reasons else "requires_atomic_admission",
        "reasons": reasons,
        "routes": routes,
        "budget": explained["budget"],
        "signed_roe_current_at_read": True,
        "admission_attempted": False,
        "execution_admitted": False,
        "provider_called": False,
        "reservation_created": False,
        "provider_native_cost_ceiling_verified": False,
    }


async def _commit(attestation: Any) -> bool:
    try:
        accepted = await asyncio.wait_for(attestation, timeout=10.0)
    except SupervisionConflict as exc:
        raise HTTPException(
            status_code=409, detail="Invoice evidence conflicts with durable state"
        ) from exc
    except (PermissionError, AuthorizationDenied) as exc:
        raise HTTPException(
            status_code=409, detail="Signed billing authorization is not current"
        ) from exc
    except ModelBudgetExceeded as exc:
        raise HTTPException(status_code=409, detail="Signed billing budget is unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invoice metadata is invalid") from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Durable invoice reconciliation unavailable"
        ) from exc
    if type(accepted) is not bool:
        raise HTTPException(status_code=503, detail="Durable invoice receipt unavailable")
    return accepted


@router.post("/{engagement_id}/model-usage/calls/{call_id}/invoice/reconcile")
async def reconcile_invoice(
    engagement_id: str,
    call_id: str,
    request: Request,
    operator: Dict[str, Any] = Depends(_verified_senior),
) -> Dict[str, Any]:
    """Explicit senior attestation; never asserts provider verification."""
    try:
        mode = trust_mode()
    except ProviderCostUnavailable as exc:
        raise HTTPException(
            status_code=503, detail="Provider invoice trust mode unavailable"
        ) from exc
    if mode == "verified_only":
        raise HTTPException(status_code=403, detail="Operator invoice attestation is disabled")
    payload = await _metadata(request, InvoiceReconciliation)
    ledger = await _owned_ledger(engagement_id, operator)
    stored = await _commit(
        ledger.reconcile_provider_invoice(
            engagement_id,
            call_id,
            **payload.model_dump(),
            actor_id=operator["sub"],
            actor_role="senior_operator",
        )
    )
    return {
        "call_id": call_id,
        "status": "reconciled" if stored else "already_reconciled",
        "source": "operator_attested",
        "provider_verified": False,
        "execution_outcome": "unknown",
        "safe_to_retry": False,
    }


@router.post("/{engagement_id}/model-usage/calls/{call_id}/invoice/adjust")
async def adjust_invoice(
    engagement_id: str,
    call_id: str,
    request: Request,
    operator: Dict[str, Any] = Depends(_verified_senior),
) -> Dict[str, Any]:
    """Append-only billing adjustment; original provider facts remain unchanged."""
    try:
        mode = trust_mode()
    except ProviderCostUnavailable as exc:
        raise HTTPException(
            status_code=503, detail="Provider invoice trust mode unavailable"
        ) from exc
    if mode == "verified_only":
        raise HTTPException(status_code=403, detail="Operator invoice attestation is disabled")
    payload = await _metadata(request, InvoiceAdjustment)
    ledger = await _owned_ledger(engagement_id, operator)
    stored = await _commit(
        ledger.adjust_provider_invoice(
            engagement_id,
            call_id,
            **payload.model_dump(),
            actor_id=operator["sub"],
            actor_role="senior_operator",
        )
    )
    return {
        "call_id": call_id,
        "status": "recorded" if stored else "already_recorded",
        "source": "operator_attested",
        "provider_verified": False,
        "execution_outcome": "unknown",
        "safe_to_retry": False,
    }


@router.post("/{engagement_id}/model-usage/provider-costs/openai/observe")
async def observe_openai_provider_costs(
    engagement_id: str,
    request: Request,
    operator: Dict[str, Any] = Depends(_verified_senior),
) -> Dict[str, Any]:
    """Read a configured OpenAI project cost aggregate; no invoice or task mutation.

    A provider admin credential proves the response came from the costs API.
    API cost buckets do not contain AI-OSOP call IDs, and comparing a project
    reporting window to an engagement's lifetime sum is informational only.
    """
    try:
        mode = trust_mode()
    except ProviderCostUnavailable as exc:
        raise HTTPException(status_code=503, detail="Provider cost source unavailable") from exc
    if mode == "operator_only":
        raise HTTPException(status_code=503, detail="Provider cost source is disabled")
    query = await _metadata(request, ProviderCostsQuery)
    ledger = await _owned_ledger(engagement_id, operator)
    try:
        # Engagement ownership alone does NOT authorize disclosure of the
        # administrator's organization/project-wide costs. Require a
        # server-pinned one-engagement binding; a shared project cannot be
        # safely attributed to any particular Flow or model call.
        require_bound_engagement(engagement_id)
        evidence = await asyncio.wait_for(
            OpenAICostSource().observe(
                start_time=query.start_time,
                end_time=query.end_time,
            ),
            timeout=20.0,
        )
        # Verify the provider source's exact fixed-project/window/freshness
        # contract before querying the local usage ledger. Do not trust a
        # substitute adapter, stale observation, malformed provider snapshot,
        # or source flag that claims individual call-cost verification.
        evidence = verify_observation(
            evidence,
            start_time=query.start_time,
            end_time=query.end_time,
        )
        # Current DB-wide summary is all-time per engagement; do not pretend
        # it matches the provider's configured project and bounded time range.
        current = await asyncio.wait_for(ledger.summary(engagement_id), timeout=5.0)
        if not isinstance(current, dict):
            raise ProviderCostUnavailable("Local billing summary is unavailable")
        # Persist one append-only provider aggregate digest. If the ledger
        # cannot record it, never return HTTP 200 with seemingly authenticated
        # source evidence. Idempotent replay returns observation_recorded=False
        # only when the ledger method returned that confirmed Boolean.
        append_observation = getattr(ledger, "audit_openai_cost_observation", None)
        if not callable(append_observation):
            raise ProviderCostUnavailable("Provider aggregate audit is unavailable")
        observation_recorded = await asyncio.wait_for(
            append_observation(engagement_id, operator["sub"], evidence),
            timeout=10.0,
        )
        if type(observation_recorded) is not bool:
            raise ProviderCostUnavailable("Provider aggregate audit is unconfirmed")
    except ProviderCostInvalid as exc:
        raise HTTPException(status_code=422, detail="Provider cost evidence is invalid") from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Provider cost evidence unavailable") from exc
    return {
        "engagement_id": engagement_id,
        **evidence,
        "local_ledger_scope": "engagement_lifetime",
        "local_ledger": {
            "provider_reported_cost_usd": current.get("provider_reported_cost_usd"),
            "operator_attested_invoice_cost_usd": current.get("operator_attested_invoice_cost_usd"),
            "invoice_adjusted_cost_usd": current.get("invoice_adjusted_cost_usd"),
            "unreconciled_cost_calls": current.get("unreconciled_cost_calls"),
        },
        "provider_project_comparable_to_engagement": False,
        "provider_project_exclusivity_verified": False,
        "project_access_binding": "server_configured_engagement",
        "individual_call_cost_verified": False,
        "execution_outcome": "unknown",
        "safe_to_retry": False,
        "ledger_mutated": False,
        "observation_recorded": observation_recorded,
    }


@router.post("/{engagement_id}/model-usage/calls/{call_id}/invoice/verify-source")
async def verify_individual_provider_cost(
    engagement_id: str,
    call_id: str,
    request: Request,
    operator: Dict[str, Any] = Depends(_verified_senior),
) -> Dict[str, Any]:
    """Fail closed: OpenAI Costs buckets cannot certify AI-OSOP call charges.

    Never map an aggregate to call_id using operator-supplied metadata, a
    local token estimate, or a provider request ID absent from the Costs API.
    """
    await _owned_ledger(engagement_id, operator)
    if not isinstance(call_id, str) or not 0 < len(call_id) <= 64:
        raise HTTPException(status_code=404, detail="Model call not found")
    raise HTTPException(
        status_code=409,
        detail="Provider cost source does not attest individual model calls",
    )
