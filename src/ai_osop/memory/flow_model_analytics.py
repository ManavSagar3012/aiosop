"""Read-only, tenant/Flow-bound model usage facts for operator supervision.

The underlying model ledger records provider testimony and operator invoice
adjustments, NOT provider-certified per-call billing. A NULL usage or cost is
unknown, never zero. TaskORM is the only authority for Flow attribution.
"""

import decimal
import re
from typing import Any, Dict, List

from sqlalchemy import and_, case, func, select

from ai_osop.memory.model_usage import ModelUsageORM
from ai_osop.memory.session_memory import TaskORM


class FlowModelAnalyticsUnavailable(RuntimeError):
    """The complete bounded, authoritative result could not be established."""


_ENGAGEMENT = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,59}\Z")
_MAX_GROUPS = 200
_MAX_COUNT = 2**63 - 1


def _count(value: Any) -> int:
    count = int(value or 0)
    if count < 0 or count > _MAX_COUNT:
        raise FlowModelAnalyticsUnavailable("Model usage counts invalid")
    return count


def _money(value: Any) -> str:
    try:
        amount = decimal.Decimal(str(value if value is not None else 0))
        if not amount.is_finite() or amount < 0 or amount > decimal.Decimal("9999999999.99999999"):
            raise ValueError()
        return str(amount.quantize(decimal.Decimal("0.00000001")))
    except (decimal.DecimalException, ValueError) as exc:
        raise FlowModelAnalyticsUnavailable("Model usage cost aggregation invalid") from exc


async def read_flow_model_analytics(
    memory: Any,
    *,
    engagement_id: str,
    flow_id: str,
) -> Dict[str, Any]:
    """Aggregate the complete bounded PG join; never read Redis or inferred IDs.

    The source ledger may contain model calls not assigned to a TaskORM. Those
    calls are expressly OUTSIDE this Flow report; we never assign them by
    timestamps, model names, provider traces or an agent's assertion.
    """
    if (
        not isinstance(engagement_id, str)
        or not _ENGAGEMENT.fullmatch(engagement_id)
        or not isinstance(flow_id, str)
        or not _FLOW.fullmatch(flow_id)
    ):
        raise ValueError("Invalid engagement or Flow identity")
    factory = getattr(memory, "_async_session", None)
    if not callable(factory):
        raise FlowModelAnalyticsUnavailable("Authoritative model ledger unavailable")

    settled = func.sum(case((ModelUsageORM.status == "settled", 1), else_=0))
    uncertain = func.sum(case((ModelUsageORM.status != "settled", 1), else_=0))
    unpriced = func.sum(case((ModelUsageORM.billed_cost_usd.is_(None), 1), else_=0))
    input_unknown = func.sum(case((ModelUsageORM.input_tokens.is_(None), 1), else_=0))
    output_unknown = func.sum(case((ModelUsageORM.output_tokens.is_(None), 1), else_=0))
    columns = (
        ModelUsageORM.model,
        ModelUsageORM.operation,
        TaskORM.agent_type,
        func.count(ModelUsageORM.call_id),
        settled,
        uncertain,
        unpriced,
        input_unknown,
        output_unknown,
        func.sum(ModelUsageORM.input_tokens),
        func.sum(ModelUsageORM.output_tokens),
        func.sum(ModelUsageORM.billed_cost_usd),
    )
    stmt = (
        select(*columns)
        .join(
            TaskORM,
            and_(
                ModelUsageORM.task_id == TaskORM.id,
                ModelUsageORM.engagement_id == TaskORM.engagement_id,
            ),
        )
        .where(
            ModelUsageORM.engagement_id == engagement_id,
            TaskORM.engagement_id == engagement_id,
            TaskORM.flow_id == flow_id,
        )
        .group_by(ModelUsageORM.model, ModelUsageORM.operation, TaskORM.agent_type)
        .order_by(ModelUsageORM.model, ModelUsageORM.operation, TaskORM.agent_type)
        .limit(_MAX_GROUPS + 1)
    )
    async with factory() as db:
        result = await db.execute(stmt)
        rows = result.all()
    if len(rows) > _MAX_GROUPS:
        raise FlowModelAnalyticsUnavailable("Flow has too many model usage groups")

    groups: List[Dict[str, Any]] = []
    total_calls = 0
    total_uncertain = 0
    total_unpriced = 0
    for row in rows:
        (
            model,
            operation,
            agent_type,
            n,
            n_settled,
            n_uncertain,
            n_unpriced,
            missing_input,
            missing_output,
            input_sum,
            output_sum,
            cost_sum,
        ) = row
        if (
            not isinstance(model, str)
            or not 1 <= len(model) <= 90
            or not isinstance(operation, str)
            or operation not in {"completion", "embedding"}
            or not isinstance(agent_type, str)
            or not 1 <= len(agent_type) <= 64
        ):
            raise FlowModelAnalyticsUnavailable("Unrecognized model usage dimension")
        n = _count(n)
        n_settled = _count(n_settled)
        n_uncertain = _count(n_uncertain)
        n_unpriced = _count(n_unpriced)
        missing_input = _count(missing_input)
        missing_output = _count(missing_output)
        if (
            not n
            or n_settled + n_uncertain != n
            or any(m > n for m in (n_unpriced, missing_input, missing_output))
        ):
            raise FlowModelAnalyticsUnavailable("Model usage aggregation inconsistent")
        total_calls += n
        total_uncertain += n_uncertain
        total_unpriced += n_unpriced
        if total_calls > _MAX_COUNT:
            raise FlowModelAnalyticsUnavailable("Model usage exceeds supported bounds")
        groups.append(
            {
                "model": model,
                "operation": operation,
                "agent_type": agent_type,
                "calls": n,
                "settled_calls": n_settled,
                "unknown_outcome_calls": n_uncertain,
                "unpriced_calls": n_unpriced,
                "input_tokens": _count(input_sum) if missing_input == 0 else None,
                "output_tokens": _count(output_sum) if missing_output == 0 else None,
                "known_ledger_cost_usd": _money(cost_sum),
                "total_cost_complete": n_unpriced == 0 and n_uncertain == 0,
            }
        )
    return {
        "engagement_id": engagement_id,
        "flow_id": flow_id,
        "source": "postgresql_task_attributed_model_ledger",
        "attribution": "same_tenant_task_flow_join_only",
        "unattributed_model_calls_included": False,
        "groups": groups,
        "group_count": len(groups),
        "calls": total_calls,
        "unknown_outcome_calls": total_uncertain,
        "unpriced_calls": total_unpriced,
        "complete_for_attributed_calls": True,
        "provider_native_cost_verified": False,
        "provider_native_hard_cap_verified": False,
        "external_execution_outcome_verified": False,
    }
