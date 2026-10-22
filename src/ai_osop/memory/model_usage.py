"""PostgreSQL admission and provider-reported billing facts for model calls.

Engagement locks serialize spending decisions across replicas. A provider
request may be accepted before our client receives a result: ambiguous costs
are kept UNKNOWN, never silently valued as zero or retried for free.
"""

import decimal
import hashlib
import json
import math
import re
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Numeric, String, func, select, case

from ai_osop.core.call_provenance import provider_usage, safe_label
from ai_osop.memory.session_memory import Base
from ai_osop.memory.supervision_store import SupervisionConflict, SupervisionStore
from ai_osop.memory.supervision_store import (
    SupervisionControlORM,
    SupervisionEventORM,
    SupervisionExecutionLeaseORM,
)
from ai_osop.memory.session_memory import (
    ApprovalRequestORM,
    ExecutionFlowORM,
    SessionStateORM,
    TaskORM,
)
from ai_osop.core.models import ScopeDefinition
from ai_osop.safety.scope import action_requires_approval
from ai_osop.safety.approval_binding import matches_pinned_payload


_INVOICE_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_INVOICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")
_MONEY = decimal.Decimal("0.00000001")
_MAX_MONEY = decimal.Decimal("9999999999.99999999")


def _amount(value: Any, *, allow_negative: bool = False) -> decimal.Decimal:
    """Exact USD amount compatible with the existing NUMERIC(18,8) column."""
    if isinstance(value, bool) or not isinstance(value, (str, decimal.Decimal, int)):
        raise ValueError("Invoice amount must be an exact decimal string")
    try:
        amount = decimal.Decimal(value)
        if (
            not amount.is_finite()
            or abs(amount) > _MAX_MONEY
            or amount != amount.quantize(_MONEY)
            or (amount < 0 and not allow_negative)
        ):
            raise ValueError("Invoice amount is out of range or precision")
    except (decimal.InvalidOperation, decimal.DecimalException, ValueError) as exc:
        raise ValueError("Invalid invoice monetary amount") from exc
    return amount.quantize(_MONEY)


def _invoice_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _INVOICE_ID.fullmatch(value):
        raise ValueError(f"Invalid {name} identity")
    return value


def _invoice_context(
    *,
    provider: str,
    invoice_reference: str,
    invoice_line_id: str,
    invoice_sha256: str,
    billed_cost_usd: Any,
    adjustment: bool = False,
) -> Dict[str, Any]:
    """Retain evidence digests; never persist invoice numbers or raw content."""
    label = _invoice_id(provider, "provider")
    reference = _invoice_id(invoice_reference, "invoice")
    line = _invoice_id(invoice_line_id, "invoice line")
    if not isinstance(invoice_sha256, str) or not _INVOICE_DIGEST.fullmatch(invoice_sha256):
        raise ValueError("Invalid invoice document digest")
    return {
        "provider": label,
        "currency": "USD",
        "invoice_sha256": invoice_sha256,
        "invoice_line_sha256": hashlib.sha256(
            (label + "\x00" + reference + "\x00" + line).encode("utf-8")
        ).hexdigest(),
        "amount": str(_amount(billed_cost_usd, allow_negative=adjustment)),
    }


def _tokens(value: Optional[int]) -> Optional[int]:
    if value is not None and (type(value) is not int or not 0 <= value <= 2**63 - 1):
        raise ValueError("Invalid invoice token count")
    return value


class ModelBudgetExceeded(RuntimeError):
    """The signed engagement's model quota cannot authorize another request."""


class ModelOutcomeUncertain(RuntimeError):
    """A provider may have executed, but settlement could not be persisted."""


class ModelUsageORM(Base):
    __tablename__ = "supervision_model_usage"

    call_id = Column(String(64), primary_key=True)
    engagement_id = Column(String(64), ForeignKey("session_states.session_id"), nullable=False)
    task_id = Column(String(64), nullable=True)
    model = Column(String(90), nullable=False)
    operation = Column(String(24), nullable=False)
    status = Column(String(24), nullable=False)
    input_tokens = Column(BigInteger, nullable=True)
    output_tokens = Column(BigInteger, nullable=True)
    billed_cost_usd = Column(Numeric(18, 8), nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now())


def _limit(roe: Dict[str, Any], key: str, *, fractional: bool = False) -> Optional[decimal.Decimal]:
    raw = roe.get(key)
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw):
        raise ModelBudgetExceeded("Model spending limit is malformed")
    if raw < 0 or (not fractional and int(raw) != raw):
        raise ModelBudgetExceeded("Model spending limit is malformed")
    return decimal.Decimal(str(raw))


class ModelUsageLedger(SupervisionStore):
    @staticmethod
    async def _verify_provider_execution_lease(
        db: Any,
        engagement_id: str,
        task_id: str,
        task: Any,
        model: str,
        operation: str,
    ) -> None:
        """Verify current signed, claimed execution within the spend transaction.

        `reserve` already holds the engagement FOR UPDATE row plus signed ROE
        guard. For explicitly opted-in v2 routing, lock and refresh Task, Flow
        and dispatched execution lease in the SAME transaction before a
        budget hold. The outer reservation independently requires RUNNING for
        all versions; legacy v1's historical Flow/lease-less execution is
        not expanded or misrepresented as v2 lease-verified admission.
        A remote effect after commit may still be UNKNOWN.
        """
        from ai_osop.core.provider_routing import configured_routes

        routes = configured_routes()
        if routes is None or routes.version != 2:
            return  # v1 history retained; outer reserve rejects unclaimed statuses.
        routes.resolve(model, operation)  # v2 preflight Task ContextVar.
        # Capture the exact Task authorized by _guard before refreshing the
        # identity-mapped row; a concurrent Task update may happen between
        # _guard's initial unlocked Task read and the following FOR UPDATE.
        if task is None:
            raise ModelBudgetExceeded("Model usage requires a signed claimed Task")
        initial = (
            task.id,
            task.engagement_id,
            task.status,
            task.assigned_agent_id,
            task.started_at,
            task.completed_at,
            task.flow_id,
            task.agent_type,
            json.dumps(task.payload, sort_keys=True) if isinstance(task.payload, dict) else None,
        )
        locked = (
            await db.execute(
                select(TaskORM)
                .where(TaskORM.id == task_id, TaskORM.engagement_id == engagement_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if locked is None:
            raise ModelBudgetExceeded("Current model Task no longer exists")
        current = (
            locked.id,
            locked.engagement_id,
            locked.status,
            locked.assigned_agent_id,
            locked.started_at,
            locked.completed_at,
            locked.flow_id,
            locked.agent_type,
            json.dumps(locked.payload, sort_keys=True)
            if isinstance(locked.payload, dict)
            else None,
        )
        if initial != current:
            raise ModelBudgetExceeded("Claimed signed model Task changed before reservation")
        payload = locked.payload if isinstance(locked.payload, dict) else {}
        expected_revision = payload.get("planner_flow_revision", payload.get("_flow_revision"))
        if (
            locked.status != "running"
            or not isinstance(locked.assigned_agent_id, str)
            or not locked.assigned_agent_id.strip()
            or not isinstance(locked.started_at, datetime)
            or locked.completed_at is not None
            or not isinstance(locked.flow_id, str)
            or not re.fullmatch(r"flow-[A-Za-z0-9._:-]{1,59}", locked.flow_id)
            or type(payload.get("_authorization_version")) is not int
            or payload["_authorization_version"] <= 0
            or type(expected_revision) is not int
            or expected_revision < 0
            or (
                "_flow_revision" in payload
                and "planner_flow_revision" in payload
                and payload["_flow_revision"] != payload["planner_flow_revision"]
            )
        ):
            raise ModelBudgetExceeded("Model usage requires a claimed RUNNING signed Task")

        flow = (
            await db.execute(
                select(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == locked.flow_id,
                    ExecutionFlowORM.engagement_id == engagement_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            flow is None
            or flow.status != "running"
            or type(flow.revision) is not int
            or flow.revision != expected_revision
        ):
            raise ModelBudgetExceeded("Signed model Flow is not RUNNING at pinned revision")

        lease = (
            await db.execute(
                select(SupervisionExecutionLeaseORM)
                .where(
                    SupervisionExecutionLeaseORM.engagement_id == engagement_id,
                    SupervisionExecutionLeaseORM.task_id == task_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            lease is None
            or lease.state != "dispatched"
            or type(lease.owner_id) is not str
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", lease.owner_id)
            or type(lease.lease_id) is not str
            or not re.fullmatch(r"lease-[A-Za-z0-9._:-]{1,58}", lease.lease_id)
            or not isinstance(lease.expires_at, datetime)
            or lease.expires_at <= datetime.utcnow()
        ):
            raise ModelBudgetExceeded("Dispatched model execution lease is unavailable")

    async def audit_openai_cost_observation(
        self,
        engagement_id: str,
        actor_id: str,
        observation: Dict[str, Any],
    ) -> bool:
        """Append an aggregate source digest under the engagement PG lock.

        This must be called only after the server independently fetched the
        OpenAI Costs API using its private administrator key; no client input
        can attest individual call costs. Distinct corrected project snapshots
        are append-only, and identical snapshots are idempotent.
        """
        from ai_osop.memory.provider_invoice_trust import (
            ProviderCostInvalid,
            _project,
            trust_mode,
        )

        engagement_id = _invoice_id(engagement_id, "engagement")
        actor_id = _invoice_id(actor_id, "operator")
        if max(len(engagement_id), len(actor_id)) > 64:
            raise PermissionError("Billing observation identity exceeds bounds")
        if (
            not isinstance(observation, dict)
            or observation.get("source") != "openai_organization_costs_api"
            or observation.get("source_authenticated") is not True
            or observation.get("individual_call_cost_verified") is not False
            or observation.get("ledger_mutated") is not False
            or observation.get("currency") != "USD"
            or observation.get("source_scope") != "configured_openai_project"
        ):
            raise ProviderCostInvalid("Untrusted provider aggregate observation")
        project_sha = observation.get("project_sha256")
        start, end = observation.get("start_time"), observation.get("end_time")
        if (
            not isinstance(project_sha, str)
            or not _INVOICE_DIGEST.fullmatch(project_sha)
            or trust_mode() not in {"openai_costs", "verified_only"}
            or project_sha != hashlib.sha256(_project().encode("utf-8")).hexdigest()
        ):
            raise ProviderCostInvalid("Provider project scope is invalid")
        from ai_osop.memory.provider_invoice_trust import _range

        _range(start, end)
        cost = observation.get("provider_cost_usd")
        present = observation.get("provider_cost_data_present")
        if type(present) is not bool or (present is False) != (cost is None):
            raise ProviderCostInvalid("Provider cost observation is incomplete")
        if present:
            if not isinstance(cost, str):
                raise ProviderCostInvalid("Provider aggregate amount is invalid")
            try:
                value = decimal.Decimal(cost)
            except decimal.InvalidOperation as exc:
                raise ProviderCostInvalid("Provider aggregate amount is invalid") from exc
            if (
                not value.is_finite()
                or value < 0
                or value > decimal.Decimal("1000000000")
                or value.as_tuple().exponent < -12
            ):
                raise ProviderCostInvalid("Provider aggregate amount is invalid")
        counters = {}
        for field, limit in (("pages", 4), ("buckets", 124), ("cost_lines", 512)):
            count = observation.get(field)
            if type(count) is not int or not 0 <= count <= limit:
                raise ProviderCostInvalid("Provider aggregate count is invalid")
            counters[field] = count
        if counters["pages"] < 1 or (present and not counters["cost_lines"]):
            raise ProviderCostInvalid("Provider aggregate evidence is incomplete")
        snapshot = {
            "project_sha256": project_sha,
            "window_start_utc": start,
            "window_end_utc": end,
            "currency": "USD",
            "cost_usd": cost,
            "data_present": present,
            **counters,
        }
        digest = hashlib.sha256(
            json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        metadata = {
            "status": "provider_aggregate_observed",
            "source": "openai_organization_costs_api",
            "source_authenticated": True,
            "project_sha256": project_sha,
            "start_time": start,
            "end_time": end,
            "snapshot_sha256": digest,
            "per_call_cost_verified": False,
            "provider_native_cap_verified": False,
        }
        key = "openai-costs:" + digest
        async with self._sessions() as db:
            async with db.begin():
                owner = (
                    await db.execute(
                        select(SessionStateORM.created_by)
                        .where(SessionStateORM.session_id == engagement_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if owner is None or owner != actor_id:
                    raise PermissionError("Billing observation engagement ownership denied")
                prior = (
                    await db.execute(
                        select(SupervisionEventORM).where(
                            SupervisionEventORM.engagement_id == engagement_id,
                            SupervisionEventORM.idempotency_key == key,
                        )
                    )
                ).scalar_one_or_none()
                if prior is not None:
                    if (
                        prior.kind != "llm.provider_cost_observed"
                        or prior.actor_id != actor_id
                        or prior.payload != metadata
                        or prior.task_id is not None
                    ):
                        raise SupervisionConflict("Provider cost observation identity conflicts")
                    return False
                await self._append_event(
                    db,
                    engagement_id,
                    None,
                    "llm.provider_cost_observed",
                    actor_id,
                    metadata,
                    idempotency_key=key,
                )
                return True

    @staticmethod
    def _adjustment_posting(
        original: decimal.Decimal,
        delta: decimal.Decimal,
    ) -> Dict[str, Any]:
        """Balanced, append-only expense/payable postings for an operator claim.

        The signs remain visible as debits and credits; a negative correction
        cannot mint a cost below zero. No posting is provider-authoritative.
        """
        original = _amount(original)
        delta = _amount(delta, allow_negative=True)
        after = original + delta
        if not decimal.Decimal(0) <= after <= _MAX_MONEY:
            raise SupervisionConflict("Invoice adjustment exceeds safe billing bounds")
        debit = max(delta, decimal.Decimal(0))
        credit = max(-delta, decimal.Decimal(0))
        return {
            "version": 1,
            "expense_debit_usd": str(debit),
            "expense_credit_usd": str(credit),
            "payable_debit_usd": str(credit),
            "payable_credit_usd": str(debit),
            "balance_before_usd": str(original),
            "balance_after_usd": str(after),
        }

    @staticmethod
    def _validate_adjustment_posting(payload: Dict[str, Any], delta: decimal.Decimal) -> None:
        """Protect new journal records against imbalance and forged refunds."""
        posting = payload.get("posting")
        if posting is None:  # Pre-journal legacy records retain their semantics.
            return
        if (
            not isinstance(posting, dict)
            or set(posting)
            != {
                "version",
                "expense_debit_usd",
                "expense_credit_usd",
                "payable_debit_usd",
                "payable_credit_usd",
                "balance_before_usd",
                "balance_after_usd",
            }
            or type(posting["version"]) is not int
            or posting["version"] != 1
        ):
            raise ModelBudgetExceeded("Invoice correction journal is malformed")
        try:
            before = _amount(posting["balance_before_usd"])
            after = _amount(posting["balance_after_usd"])
            expected = ModelUsageLedger._adjustment_posting(before, delta)
        except (ValueError, SupervisionConflict) as exc:
            raise ModelBudgetExceeded("Invoice correction journal is malformed") from exc
        if posting != expected or after != before + delta:
            raise ModelBudgetExceeded("Invoice correction journal is unbalanced")

    @staticmethod
    def _validate_adjustment_history(
        row: Any,
        events: list[Any],
        invoice_base: Dict[str, decimal.Decimal],
    ) -> None:
        """Rebuild per-call postings from original immutable amount in event order."""
        current = (
            decimal.Decimal(str(row.billed_cost_usd))
            if row.billed_cost_usd is not None
            else invoice_base.get(row.call_id)
        )
        if current is None:
            return
        for event in events:
            if (
                event.kind != "llm.invoice_adjustment"
                or event.payload.get("call_id") != row.call_id
            ):
                continue
            delta = _amount(event.payload["amount"], allow_negative=True)
            posting = event.payload.get("posting")
            if posting is not None and _amount(posting["balance_before_usd"]) != current:
                raise ModelBudgetExceeded("Invoice correction journal balance disagrees with base")
            current += delta
            if not decimal.Decimal(0) <= current <= _MAX_MONEY:
                raise ModelBudgetExceeded("Invoice correction journal exceeds billed balance")

    @staticmethod
    async def _precharge_events(db: Any, engagement_id: str) -> Dict[str, decimal.Decimal]:
        """Return immutable operator-declared holds for authorized model calls.

        Supervision audit/outbox is in the same transaction as the reserved
        usage row. Never infer a missing event's price as zero.
        """
        result = await db.execute(
            select(SupervisionEventORM).where(
                SupervisionEventORM.engagement_id == engagement_id,
                SupervisionEventORM.kind == "llm.precharge_reserved",
            )
        )
        holds: Dict[str, decimal.Decimal] = {}
        for event in result.scalars().all():
            if event.kind != "llm.precharge_reserved":
                continue
            metadata = event.payload
            if (
                not isinstance(metadata, dict)
                or metadata.get("source") != "signed_operator_worst_case"
                or type(metadata.get("version")) is not int
                or metadata["version"] <= 0
                or not isinstance(metadata.get("call_id"), str)
                or metadata["call_id"] in holds
            ):
                raise ModelBudgetExceeded("Committed model precharge evidence is invalid")
            try:
                hold = _amount(metadata.get("amount"))
            except ValueError as exc:
                raise ModelBudgetExceeded("Committed model precharge amount is invalid") from exc
            if hold <= 0:
                raise ModelBudgetExceeded("Committed model precharge amount is invalid")
            holds[metadata["call_id"]] = hold
        return holds

    @staticmethod
    async def _invoice_events(db: Any, engagement_id: str) -> list[Any]:
        """Read immutable invoice evidence under the engagement transaction lock."""
        result = await db.execute(
            select(SupervisionEventORM)
            .where(
                SupervisionEventORM.engagement_id == engagement_id,
                SupervisionEventORM.kind.in_(
                    [
                        "llm.invoice_reconciled",
                        "llm.invoice_adjustment",
                    ]
                ),
            )
            .order_by(SupervisionEventORM.sequence)
        )
        return [
            event
            for event in result.scalars().all()
            if event.kind in {"llm.invoice_reconciled", "llm.invoice_adjustment"}
        ]

    @staticmethod
    def _invoice_totals(
        events: list[Any],
    ) -> tuple[Dict[str, decimal.Decimal], Dict[str, decimal.Decimal]]:
        """Calculate invoice-only base prices and append-only adjustment sums."""
        base: Dict[str, decimal.Decimal] = {}
        delta: Dict[str, decimal.Decimal] = {}
        for event in events:
            payload = event.payload
            if (
                not isinstance(payload, dict)
                or not isinstance(payload.get("call_id"), str)
                or payload.get("currency") != "USD"
                or not _INVOICE_DIGEST.fullmatch(str(payload.get("invoice_sha256", "")))
                or not _INVOICE_DIGEST.fullmatch(str(payload.get("invoice_line_sha256", "")))
            ):
                raise ModelBudgetExceeded("Invoice evidence is unavailable")
            call = payload["call_id"]
            try:
                value = _amount(
                    payload["amount"], allow_negative=event.kind == "llm.invoice_adjustment"
                )
            except (KeyError, ValueError) as exc:
                raise ModelBudgetExceeded("Invoice evidence is malformed") from exc
            if event.kind == "llm.invoice_adjustment":
                ModelUsageLedger._validate_adjustment_posting(payload, value)
                delta[call] = delta.get(call, decimal.Decimal(0)) + value
            else:
                if call in base:
                    raise ModelBudgetExceeded("Duplicate invoice reconciliation evidence")
                base[call] = value
        return base, delta

    @staticmethod
    def _invoice_line_is_unused(events: list[Any], line_digest: str) -> bool:
        return not any(
            isinstance(event.payload, dict)
            and event.payload.get("invoice_line_sha256") == line_digest
            for event in events
        )

    @staticmethod
    async def _signed_invoice_guard(
        db: Any,
        engagement_id: str,
        task_id: str,
        actor_id: str,
        actor_role: str,
        expected_authorization_version: int,
    ) -> Any:
        """Lock PG engagement and verify the current signer in this transaction."""
        if (
            actor_role != "senior_operator"
            or not isinstance(actor_id, str)
            or len(actor_id) > 64
            or not _INVOICE_ID.fullmatch(actor_id)
        ):
            raise PermissionError("Senior operator authorization is required")
        if type(expected_authorization_version) is not int or expected_authorization_version < 1:
            raise PermissionError("Signed invoice authorization version is required")
        from ai_osop.memory.authorization_store import guard_sql

        _, task = await ModelUsageLedger._guard(
            db,
            engagement_id,
            task_id,
            actor_id=actor_id,
            actor_role=actor_role,
        )
        signed = await guard_sql(
            db,
            engagement_id,
            expected_version=expected_authorization_version,
        )
        if (
            task is None
            or not isinstance(task.payload, dict)
            or type(task.payload.get("_authorization_version")) is not int
            or task.payload["_authorization_version"] != signed.version
        ):
            raise PermissionError("Original model call authorization changed")
        return task

    async def reconcile_provider_invoice(
        self,
        engagement_id: str,
        call_id: str,
        *,
        expected_task_id: str,
        expected_model: str,
        expected_operation: str,
        expected_authorization_version: int,
        provider: str,
        invoice_reference: str,
        invoice_line_id: str,
        invoice_sha256: str,
        billed_cost_usd: Any,
        actor_id: str,
        actor_role: str,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
    ) -> bool:
        """Senior-operator attestation of one invoice line for an uncertain call.

        No provider request is issued and no execution result is asserted.
        The original call, model, operation and signature version are pinned.
        A provider-settled row with an absent cost retains its provider fields;
        its invoice base cost lives only in the immutable audit event.
        """
        engagement_id = _invoice_id(engagement_id, "engagement")
        call_id = _invoice_id(call_id, "call")
        expected_task_id = _invoice_id(expected_task_id, "task")
        if max(len(engagement_id), len(call_id), len(expected_task_id)) > 64:
            raise ValueError("Oversized model call identity")
        if safe_label(expected_model) != expected_model or expected_operation not in {
            "completion",
            "embedding",
        }:
            raise ValueError("Invalid original model operation")
        evidence = _invoice_context(
            provider=provider,
            invoice_reference=invoice_reference,
            invoice_line_id=invoice_line_id,
            invoice_sha256=invoice_sha256,
            billed_cost_usd=billed_cost_usd,
        )
        if "/" in expected_model and expected_model.split("/", 1)[0] != provider:
            raise ValueError("Invoice provider does not match the original model")
        input_tokens = _tokens(input_tokens)
        output_tokens = _tokens(output_tokens)
        async with self._sessions() as db:
            async with db.begin():
                await self._signed_invoice_guard(
                    db,
                    engagement_id,
                    expected_task_id,
                    actor_id,
                    actor_role,
                    expected_authorization_version,
                )
                row = (
                    await db.execute(
                        select(ModelUsageORM)
                        .where(
                            ModelUsageORM.engagement_id == engagement_id,
                            ModelUsageORM.call_id == call_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    row is None
                    or row.task_id != expected_task_id
                    or row.model != expected_model
                    or row.operation != expected_operation
                    or row.status not in {"reserved", "unknown", "settled"}
                ):
                    raise SupervisionConflict("Model invoice call identity or state changed")
                events = await self._invoice_events(db, engagement_id)
                base, _ = self._invoice_totals(events)
                metadata = {
                    "status": "operator_attested",
                    "call_id": call_id,
                    "version": expected_authorization_version,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    **evidence,
                }
                prior = next(
                    (
                        event
                        for event in events
                        if event.kind == "llm.invoice_reconciled"
                        and event.payload.get("call_id") == call_id
                    ),
                    None,
                )
                if prior is not None:
                    if prior.actor_id == actor_id and prior.payload == metadata:
                        return False
                    raise SupervisionConflict("Original invoice evidence is immutable")
                if row.status == "settled" and row.billed_cost_usd is not None:
                    raise SupervisionConflict("Settled provider cost requires an adjustment")
                if row.status in {"reserved", "unknown"} and (
                    row.billed_cost_usd is not None
                    or row.input_tokens is not None
                    or row.output_tokens is not None
                ):
                    raise SupervisionConflict("Unsettled call already contains billing facts")
                if not self._invoice_line_is_unused(events, evidence["invoice_line_sha256"]):
                    raise SupervisionConflict("Invoice line already allocated")
                if row.status in {"reserved", "unknown"}:
                    row.status = "settled"
                    row.input_tokens = input_tokens
                    row.output_tokens = output_tokens
                    row.billed_cost_usd = _amount(billed_cost_usd)
                    row.updated_at = datetime.utcnow()
                elif input_tokens is not None or output_tokens is not None:
                    # The original provider usage counts are immutable, even
                    # if the operator later obtains a more complete invoice.
                    raise SupervisionConflict("Original settled token facts are immutable")
                await self._append_event(
                    db,
                    engagement_id,
                    expected_task_id,
                    "llm.invoice_reconciled",
                    actor_id,
                    metadata,
                    idempotency_key="model-invoice:" + call_id,
                )
                return True

    async def adjust_provider_invoice(
        self,
        engagement_id: str,
        call_id: str,
        *,
        adjustment_id: str,
        expected_task_id: str,
        expected_model: str,
        expected_operation: str,
        expected_authorization_version: int,
        provider: str,
        invoice_reference: str,
        invoice_line_id: str,
        invoice_sha256: str,
        cost_delta_usd: Any,
        actor_id: str,
        actor_role: str,
    ) -> bool:
        """Append a signed, operator-attested charge/credit without changing facts."""
        engagement_id = _invoice_id(engagement_id, "engagement")
        call_id = _invoice_id(call_id, "call")
        adjustment_id = _invoice_id(adjustment_id, "adjustment")
        expected_task_id = _invoice_id(expected_task_id, "task")
        if max(len(engagement_id), len(call_id), len(expected_task_id)) > 64:
            raise ValueError("Oversized model call identity")
        if safe_label(expected_model) != expected_model or expected_operation not in {
            "completion",
            "embedding",
        }:
            raise ValueError("Invalid original model operation")
        evidence = _invoice_context(
            provider=provider,
            invoice_reference=invoice_reference,
            invoice_line_id=invoice_line_id,
            invoice_sha256=invoice_sha256,
            billed_cost_usd=cost_delta_usd,
            adjustment=True,
        )
        if _amount(cost_delta_usd, allow_negative=True) == 0:
            raise ValueError("A billing correction must change the amount")
        if "/" in expected_model and expected_model.split("/", 1)[0] != provider:
            raise ValueError("Invoice provider does not match the original model")
        key = (
            "model-adjust:"
            + hashlib.sha256((engagement_id + "\x00" + adjustment_id).encode("utf-8")).hexdigest()
        )
        async with self._sessions() as db:
            async with db.begin():
                await self._signed_invoice_guard(
                    db,
                    engagement_id,
                    expected_task_id,
                    actor_id,
                    actor_role,
                    expected_authorization_version,
                )
                row = (
                    await db.execute(
                        select(ModelUsageORM)
                        .where(
                            ModelUsageORM.engagement_id == engagement_id,
                            ModelUsageORM.call_id == call_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if (
                    row is None
                    or row.task_id != expected_task_id
                    or row.model != expected_model
                    or row.operation != expected_operation
                    or row.status != "settled"
                ):
                    raise SupervisionConflict("Adjustment requires a settled matching model call")
                events = await self._invoice_events(db, engagement_id)
                base, deltas = self._invoice_totals(events)
                self._validate_adjustment_history(row, events, base)
                metadata = {
                    "status": "operator_attested",
                    "call_id": call_id,
                    "version": expected_authorization_version,
                    "adjustment_id_sha256": key[-64:],
                    **evidence,
                }
                prior = next((event for event in events if event.idempotency_key == key), None)
                if prior is not None:
                    if (
                        prior.kind == "llm.invoice_adjustment"
                        and prior.actor_id == actor_id
                        and {key: value for key, value in prior.payload.items() if key != "posting"}
                        == metadata
                    ):
                        return False
                    raise SupervisionConflict("Adjustment identifier was used for different facts")
                if not self._invoice_line_is_unused(events, evidence["invoice_line_sha256"]):
                    raise SupervisionConflict("Invoice line already allocated")
                original = (
                    decimal.Decimal(str(row.billed_cost_usd))
                    if row.billed_cost_usd is not None
                    else base.get(call_id)
                )
                if original is None:
                    raise SupervisionConflict("Cannot adjust an unpriced settled model call")
                before = original + deltas.get(call_id, decimal.Decimal(0))
                posting = self._adjustment_posting(
                    before,
                    _amount(cost_delta_usd, allow_negative=True),
                )
                metadata["posting"] = posting
                await self._append_event(
                    db,
                    engagement_id,
                    expected_task_id,
                    "llm.invoice_adjustment",
                    actor_id,
                    metadata,
                    idempotency_key=key,
                )
                return True

    async def list_unreconciled(
        self,
        engagement_id: str,
        *,
        limit: int = 100,
    ) -> list[Dict[str, Any]]:
        """Expose safely bounded unresolved paid-call identities for review.

        A reservation may have reached the provider before a crash. Operators
        need to see the distinct call IDs; unknown fees are NOT zero and this
        method never settles, retries or adjusts a bill without provider proof.
        """
        if not isinstance(engagement_id, str) or not engagement_id or len(engagement_id) > 64:
            raise ValueError("Invalid engagement identity")
        if not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("Invalid reconciliation page limit")
        async with self._sessions() as db:
            records = (
                (
                    await db.execute(
                        select(ModelUsageORM)
                        .where(
                            ModelUsageORM.engagement_id == engagement_id,
                            ModelUsageORM.status.in_(["reserved", "unknown"]),
                        )
                        .order_by(ModelUsageORM.created_at.desc(), ModelUsageORM.call_id)
                        .limit(limit)
                    )
                )
                .scalars()
                .all()
            )
        return [
            {
                "call_id": row.call_id,
                "task_id": row.task_id,
                "operation": row.operation,
                "status": row.status,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "provider_cost_usd": None,
                "safe_to_retry": False,
                "invoice_reconciled": False,
            }
            for row in records
        ]

    async def summary(self, engagement_id: str) -> Dict[str, Any]:
        """DB-wide aggregate: never mistake unknown billed cost for zero."""
        async with self._sessions() as db:
            values = (
                await db.execute(
                    select(
                        func.count(ModelUsageORM.call_id),
                        func.sum(case((ModelUsageORM.status == "settled", 1), else_=0)),
                        func.sum(case((ModelUsageORM.status != "settled", 1), else_=0)),
                        func.sum(case((ModelUsageORM.billed_cost_usd.is_(None), 1), else_=0)),
                        func.sum(ModelUsageORM.billed_cost_usd),
                        func.sum(ModelUsageORM.input_tokens),
                        func.sum(ModelUsageORM.output_tokens),
                    ).where(ModelUsageORM.engagement_id == engagement_id)
                )
            ).one()
            rows = (
                (
                    await db.execute(
                        select(ModelUsageORM).where(ModelUsageORM.engagement_id == engagement_id)
                    )
                )
                .scalars()
                .all()
            )
            invoice_events = await self._invoice_events(db, engagement_id)
            invoice_base, adjustments = self._invoice_totals(invoice_events)
            holds = await self._precharge_events(db, engagement_id)
        total = int(values[0] or 0)
        unresolved_cost = 0
        effective_total = decimal.Decimal(0)
        direct_provider_total = decimal.Decimal(0)
        outstanding_hold = decimal.Decimal(0)
        direct_input_tokens = 0
        direct_output_tokens = 0
        has_direct_input_tokens = False
        has_direct_output_tokens = False
        attested_input_tokens = 0
        attested_output_tokens = 0
        has_attested_input_tokens = False
        has_attested_output_tokens = False
        for row in rows:
            self._validate_adjustment_history(row, invoice_events, invoice_base)
            if row.call_id in holds and (
                row.status != "settled"
                or (row.billed_cost_usd is None and row.call_id not in invoice_base)
            ):
                outstanding_hold += holds[row.call_id]
            if row.call_id not in invoice_base and row.billed_cost_usd is not None:
                direct_provider_total += decimal.Decimal(str(row.billed_cost_usd))
            # Invoice-based reconciliations may populate token columns, but
            # that operator evidence is not a provider-reported usage receipt.
            if row.call_id in invoice_base:
                if row.input_tokens is not None:
                    attested_input_tokens += int(row.input_tokens)
                    has_attested_input_tokens = True
                if row.output_tokens is not None:
                    attested_output_tokens += int(row.output_tokens)
                    has_attested_output_tokens = True
            else:
                if row.input_tokens is not None:
                    direct_input_tokens += int(row.input_tokens)
                    has_direct_input_tokens = True
                if row.output_tokens is not None:
                    direct_output_tokens += int(row.output_tokens)
                    has_direct_output_tokens = True
            base = (
                decimal.Decimal(str(row.billed_cost_usd))
                if row.billed_cost_usd is not None
                else invoice_base.get(row.call_id)
            )
            if row.status != "settled" or base is None:
                unresolved_cost += 1
                continue
            effective = base + adjustments.get(row.call_id, decimal.Decimal(0))
            if effective < 0 or effective > _MAX_MONEY:
                raise ModelBudgetExceeded("Invoice adjustment ledger is inconsistent")
            effective_total += effective
        return {
            "engagement_id": engagement_id,
            "calls": total,
            "settled_calls": int(values[1] or 0),
            "unknown_calls": int(values[2] or 0),
            "unpriced_calls": int(values[3] or 0),
            # Do not relabel operator-attested invoice reconciliation as a
            # direct provider response merely because it occupies the same
            # immutable billed_cost_usd column.
            "provider_reported_cost_usd": (
                str(direct_provider_total)
                if any(
                    row.call_id not in invoice_base and row.billed_cost_usd is not None
                    for row in rows
                )
                else None
            ),
            "operator_attested_invoice_cost_usd": (
                str(sum(invoice_base.values(), decimal.Decimal(0))) if invoice_base else None
            ),
            "provider_reported_input_tokens": (
                direct_input_tokens if has_direct_input_tokens else None
            ),
            "provider_reported_output_tokens": (
                direct_output_tokens if has_direct_output_tokens else None
            ),
            "operator_attested_invoice_input_tokens": (
                attested_input_tokens if has_attested_input_tokens else None
            ),
            "operator_attested_invoice_output_tokens": (
                attested_output_tokens if has_attested_output_tokens else None
            ),
            "cost_complete": total > 0 and unresolved_cost == 0,
            "invoice_adjusted_cost_usd": (
                str(effective_total) if total and unresolved_cost == 0 else None
            ),
            "invoice_adjustment_total_usd": str(sum(adjustments.values(), decimal.Decimal(0))),
            "operator_attested_invoice_credits_usd": str(
                -sum(
                    (
                        delta
                        for event in invoice_events
                        if event.kind == "llm.invoice_adjustment"
                        for delta in [_amount(event.payload["amount"], allow_negative=True)]
                        if delta < 0
                    ),
                    decimal.Decimal(0),
                )
            ),
            "operator_attested_invoice_charges_usd": str(
                sum(
                    (
                        delta
                        for event in invoice_events
                        if event.kind == "llm.invoice_adjustment"
                        for delta in [_amount(event.payload["amount"], allow_negative=True)]
                        if delta > 0
                    ),
                    decimal.Decimal(0),
                )
            ),
            "individual_provider_cost_verified": False,
            "unreconciled_cost_calls": unresolved_cost,
            "outstanding_precharge_usd": str(outstanding_hold),
            # A signed/operator-estimated maximum is NOT proof of a provider
            # native dollar cap. Expose this explicitly to prevent false
            # "hard external cost ceiling" claims in operator dashboards.
            "provider_native_cost_ceiling_verified": False,
        }

    async def reserve(
        self, engagement_id: str, task_id: Optional[str], model: str, operation: str
    ) -> str:
        """Admit one provider invocation atomically under signed ROE quotas."""
        if (
            operation not in {"completion", "embedding"}
            or not isinstance(engagement_id, str)
            or not engagement_id
            or engagement_id == "api-bootstrap"
            or not isinstance(task_id, str)
            or not task_id
        ):
            raise ModelBudgetExceeded(
                "A persisted engagement and executing task are required for model usage"
            )
        label = safe_label(model)
        if label == "unknown":
            raise ModelBudgetExceeded("An explicit model identifier is required")
        call_id = "call-" + uuid.uuid4().hex
        async with self._sessions() as db:
            async with db.begin():
                try:
                    engagement, task = await self._guard(
                        db, engagement_id, task_id, require_window=True
                    )
                except SupervisionConflict as exc:
                    raise ModelBudgetExceeded(
                        "Engagement is not authorized for model usage"
                    ) from exc
                if task is None:
                    raise ModelBudgetExceeded(
                        "Model usage requires an authoritative execution task"
                    )
                if task.status != "running":
                    raise ModelBudgetExceeded(
                        "Model usage requires a claimed RUNNING Task"
                    )
                # Route preflight may have read a previous Task/Flow/lease.
                # Recheck their immutable signed/current authority under
                # THIS transaction's engagement FOR UPDATE before precharge.
                await self._verify_provider_execution_lease(
                    db, engagement_id, task_id, task, model, operation
                )
                if task is not None:
                    if task.approval_required or action_requires_approval(
                        task.type, ScopeDefinition(**engagement.scope)
                    ):
                        approval_id = (task.payload or {}).get("approval_id")
                        approved = (
                            (
                                await db.execute(
                                    select(ApprovalRequestORM).where(
                                        ApprovalRequestORM.id == approval_id,
                                        ApprovalRequestORM.task_id == task_id,
                                        ApprovalRequestORM.engagement_id == engagement_id,
                                        ApprovalRequestORM.status == "approved",
                                    )
                                )
                            ).scalar_one_or_none()
                            if isinstance(approval_id, str)
                            else None
                        )
                        if approved is None or (
                            task.type != "planner_inference"
                            and not matches_pinned_payload(approved.evidence, task.payload)
                        ):
                            raise ModelBudgetExceeded(
                                "Consequential task approval is missing or stale"
                            )
                    latest = (
                        await db.execute(
                            select(SupervisionControlORM)
                            .where(
                                SupervisionControlORM.engagement_id == engagement_id,
                                SupervisionControlORM.task_id == task_id,
                                SupervisionControlORM.action.in_(
                                    ["pause", "resume", "cancel", "stop"]
                                ),
                            )
                            .order_by(
                                SupervisionControlORM.created_at.desc(),
                                SupervisionControlORM.request_id.desc(),
                            )
                            .limit(1)
                        )
                    ).scalar_one_or_none()
                    if latest is not None and latest.action in {"pause", "cancel", "stop"}:
                        raise ModelBudgetExceeded("Operator control forbids further model calls")
                roe = engagement.roe if isinstance(engagement.roe, dict) else {}
                count_limit = _limit(roe, "llm_call_budget_total")
                cost_limit = _limit(roe, "llm_cost_budget_usd", fractional=True)
                ceiling = None
                if cost_limit is not None:
                    # A value signed by the engagement's operator is a
                    # *declared worst case*, NOT a provider-enforced cap.
                    # Never manufacture one from LiteLLM's price catalog or
                    # token output limits. Fail closed when unavailable.
                    ceiling = _limit(roe, "llm_precharge_max_call_usd", fractional=True)
                    if ceiling is None or ceiling <= 0:
                        raise ModelBudgetExceeded(
                            "Signed worst-case precharge is required for cost admission"
                        )
                    try:
                        # Round UP: SQL NUMERIC(18,8) may not round down a hold.
                        ceiling = _amount(
                            ceiling.quantize(
                                _MONEY,
                                rounding=decimal.ROUND_CEILING,
                            )
                        )
                    except (ValueError, decimal.InvalidOperation) as exc:
                        raise ModelBudgetExceeded(
                            "Signed worst-case precharge is not representable"
                        ) from exc
                if count_limit is None and cost_limit is None:
                    # Authorization to assess targets is separate from an
                    # authorization to spend on external model providers.
                    raise ModelBudgetExceeded("Signed engagement has no model usage budget")
                rows = (
                    (
                        await db.execute(
                            select(ModelUsageORM).where(
                                ModelUsageORM.engagement_id == engagement_id
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                # A fully unknown billed outcome may exceed the signed
                # operator's hypothetical ceiling; never give it a refund.
                # Concurrent RESERVED requests are allowed only when their
                # atomically persisted holds fit in the remaining budget.
                if any(row.status == "unknown" for row in rows) or (
                    cost_limit is None and any(row.status != "settled" for row in rows)
                ):
                    raise ModelBudgetExceeded("Provider usage has an unreconciled outcome")
                if count_limit is not None and len(rows) >= count_limit:
                    raise ModelBudgetExceeded("Engagement model-call quota exhausted")
                if cost_limit is not None:
                    invoice_events = await self._invoice_events(db, engagement_id)
                    invoice_base, adjustments = self._invoice_totals(invoice_events)
                    holds = await self._precharge_events(db, engagement_id)
                    committed = decimal.Decimal(0)
                    for row in rows:
                        self._validate_adjustment_history(row, invoice_events, invoice_base)
                        if row.status == "reserved":
                            hold = holds.get(row.call_id)
                            if hold is None:
                                # Legacy in-flight calls have no durable
                                # precharge and can never be valued at zero.
                                raise ModelBudgetExceeded(
                                    "In-flight model call lacks committed precharge"
                                )
                            committed += hold
                            continue
                        if row.status != "settled":
                            raise ModelBudgetExceeded("Provider usage has an unreconciled outcome")
                        original = (
                            decimal.Decimal(str(row.billed_cost_usd))
                            if row.billed_cost_usd is not None
                            else invoice_base.get(row.call_id)
                        )
                        if original is None:
                            raise ModelBudgetExceeded("Provider cost has an unreconciled receipt")
                        effective = original + adjustments.get(row.call_id, decimal.Decimal(0))
                        if not decimal.Decimal(0) <= effective <= _MAX_MONEY:
                            raise ModelBudgetExceeded("Invoice cost ledger is inconsistent")
                        committed += effective
                    if committed >= cost_limit:
                        raise ModelBudgetExceeded("Engagement billed-cost quota exhausted")
                    if committed + ceiling > cost_limit:
                        raise ModelBudgetExceeded(
                            "Engagement worst-case precharge exceeds signed cost budget"
                        )
                elif any(row.status != "settled" for row in rows):
                    raise ModelBudgetExceeded("Provider usage has an unreconciled outcome")
                db.add(
                    ModelUsageORM(
                        call_id=call_id,
                        engagement_id=engagement_id,
                        task_id=task_id,
                        model=label,
                        operation=operation,
                        status="reserved",
                    )
                )
                if cost_limit is not None:
                    signed_version = (task.payload or {}).get("_authorization_version")
                    if type(signed_version) is not int or signed_version <= 0:
                        raise ModelBudgetExceeded(
                            "Task is missing current signed authorization version"
                        )
                    # An auditable durable hold is written alongside the
                    # admitted call. The engagement row is FOR UPDATE under
                    # _guard across every cross-replica cost admission.
                    await self._append_event(
                        db,
                        engagement_id,
                        task_id,
                        "llm.precharge_reserved",
                        "model-ledger",
                        {
                            "status": "reserved",
                            "call_id": call_id,
                            "amount": str(ceiling),
                            "version": signed_version,
                            "source": "signed_operator_worst_case",
                        },
                        idempotency_key="model-precharge:" + call_id,
                    )
        return call_id

    async def settle(
        self, call_id: str, engagement_id: str, response: Any, *, delivered: bool
    ) -> bool:
        """Record only provider-declared fields, never inferred token pricing."""
        usage = (
            provider_usage(response)
            if delivered
            else {
                "input_tokens": None,
                "output_tokens": None,
                "billed_cost_usd": None,
            }
        )
        input_tokens = _tokens(usage["input_tokens"])
        output_tokens = _tokens(usage["output_tokens"])
        billed_cost = (
            _amount(str(usage["billed_cost_usd"])) if usage["billed_cost_usd"] is not None else None
        )
        async with self._sessions() as db:
            async with db.begin():
                # Serialize settlement/refund with every spend admission via
                # the SAME per-engagement PG row lock as _guard. Do not use
                # the active signed/window guard: billing must be recordable
                # even after the operator revokes or closes engagement.
                parent = (
                    await db.execute(
                        select(SessionStateORM.session_id)
                        .where(SessionStateORM.session_id == engagement_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if parent is None:
                    return False
                row = (
                    await db.execute(
                        select(ModelUsageORM)
                        .where(
                            ModelUsageORM.call_id == call_id,
                            ModelUsageORM.engagement_id == engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if row is None or row.status != "reserved":
                    return False
                holds = await self._precharge_events(db, engagement_id)
                hold = holds.get(call_id)
                if delivered and billed_cost is not None and hold is not None:
                    refunded = max(hold - billed_cost, decimal.Decimal(0))
                    exceeded = max(billed_cost - hold, decimal.Decimal(0))
                    # Provider billing may exceed our signed operator's
                    # ceiling, which is NOT a provider-enforced hard cap.
                    # Record the real charge, preserve the breach, and
                    # block new cost admission using actual billed totals.
                    await self._append_event(
                        db,
                        engagement_id,
                        row.task_id,
                        "llm.precharge_settled",
                        "model-ledger",
                        {
                            "status": "over_estimate" if exceeded else "priced",
                            "call_id": call_id,
                            "reserved_usd": str(hold),
                            "applied_to_bill_usd": str(min(hold, billed_cost)),
                            "billed_usd": str(billed_cost),
                            "released_usd": str(refunded),
                            "excess_usd": str(exceeded),
                            "source": "model_provider_response",
                            "provider_native_cap_verified": False,
                        },
                        idempotency_key="model-precharge-settled:" + call_id,
                    )
                row.status = "settled" if delivered else "unknown"
                row.input_tokens = input_tokens
                row.output_tokens = output_tokens
                row.billed_cost_usd = billed_cost
                row.updated_at = datetime.utcnow()
                await self._append_event(
                    db,
                    engagement_id,
                    row.task_id,
                    "llm.provider_usage",
                    "model-ledger",
                    {"status": row.status, "call_id": call_id},
                    idempotency_key="model-usage:" + call_id,
                )
                return True
