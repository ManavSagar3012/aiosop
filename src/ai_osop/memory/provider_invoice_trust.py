"""Read-only independently authenticated provider cost observations.

OpenAI's organization Costs API is authenticated with an administrator API
key supplied only by the server environment. It reports aggregate project
cost buckets, never a signed invoice for an individual AI-OSOP model call.
This adapter performs no SQL mutations and does not use a model provider.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Optional

import httpx

_COSTS_URL = "https://api.openai.com/v1/organization/costs"
_PROJECT_ID = re.compile(r"proj_[A-Za-z0-9_-]{1,120}\Z")
_ENGAGEMENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}\Z")
_CURSOR = re.compile(r"[A-Za-z0-9._~+/=-]{1,512}\Z")
_MAX_PAGE_BYTES = 64 * 1024
_MAX_PAGES = 4
_MAX_RESULTS = 512
_MAX_DAYS = 31
_ONE_DAY = 86400
_MAX_AMOUNT = Decimal("1000000000")
_SOURCE_FIELDS = frozenset(
    {
        "source",
        "source_authenticated",
        "source_scope",
        "project_sha256",
        "start_time",
        "end_time",
        "provider_cost_usd",
        "provider_cost_data_present",
        "currency",
        "pages",
        "buckets",
        "cost_lines",
        "individual_call_cost_verified",
        "provider_hard_cost_cap_verified",
        "ledger_mutated",
        "source_checked_at_utc",
    }
)
_MAX_PROOF_AGE_SECONDS = 60


class ProviderCostUnavailable(RuntimeError):
    """The provider source, response, or secure configuration is unavailable."""


class ProviderCostInvalid(ValueError):
    """Cost source yielded incomplete, conflicting, or non-USD evidence."""


def trust_mode() -> str:
    """Select an explicit trust mode. Never infer verification from operator input."""
    mode = os.environ.get("OSOP_PROVIDER_INVOICE_TRUST_MODE", "operator_only")
    if mode not in {"operator_only", "openai_costs", "verified_only"}:
        raise ProviderCostUnavailable("Provider cost trust mode is invalid")
    return mode


def _project() -> str:
    project = os.environ.get("OSOP_PROVIDER_INVOICE_OPENAI_PROJECT_ID", "")
    if not _PROJECT_ID.fullmatch(project):
        raise ProviderCostUnavailable("A fixed provider project scope is required")
    return project


def require_bound_engagement(engagement_id: str) -> None:
    """Require an explicit server-declared entitlement before project disclosure.

    Durable ownership of *an* engagement does not prove entitlement to an
    organization-wide project aggregate. Until a signed project-scoping
    registry exists, only the exact engagement explicitly bound in server
    configuration can request this project. No API input can choose the
    project or change this binding. Configuration is NOT cryptographic proof
    that the project contains only that engagement's activity; do not derive
    per-call or exclusively tenant-owned cost from the aggregate.
    """
    bound = os.environ.get("OSOP_PROVIDER_INVOICE_OPENAI_ENGAGEMENT_ID", "")
    if (
        type(engagement_id) is not str
        or not _ENGAGEMENT_ID.fullmatch(engagement_id)
        or not _ENGAGEMENT_ID.fullmatch(bound)
        or engagement_id != bound
    ):
        raise ProviderCostUnavailable("Provider project is not bound to this engagement")
    _project()


def _key() -> str:
    value = os.environ.get("OPENAI_ADMIN_KEY", "")
    if (
        not isinstance(value, str)
        or not value.startswith("sk-")
        or not 20 <= len(value) <= 512
        or any(ch.isspace() or ord(ch) < 33 or ord(ch) > 126 for ch in value)
    ):
        raise ProviderCostUnavailable("An OpenAI administrator key is required")
    return value


def _no_duplicates(items: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ProviderCostInvalid("Duplicate provider response key")
        result[key] = value
    return result


def _no_constants(raw: str) -> None:
    raise ProviderCostInvalid("Nonfinite provider cost")


def _parse_page(raw: bytes) -> Dict[str, Any]:
    try:
        data = json.loads(
            raw,
            parse_float=Decimal,
            parse_constant=_no_constants,
            object_pairs_hook=_no_duplicates,
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ProviderCostInvalid("Invalid provider costs page") from exc
    if not isinstance(data, dict) or data.get("object") != "page":
        raise ProviderCostInvalid("Unexpected provider costs page")
    if type(data.get("has_more")) is not bool or not isinstance(data.get("data"), list):
        raise ProviderCostInvalid("Incomplete provider costs page")
    if len(data["data"]) > _MAX_DAYS:
        raise ProviderCostInvalid("Too many provider cost buckets")
    return data


def _money(value: Any) -> Decimal:
    if type(value) not in {int, Decimal}:
        raise ProviderCostInvalid("Provider cost amount is not a numeric value")
    try:
        amount = Decimal(str(value))
    except (ValueError, InvalidOperation) as exc:
        raise ProviderCostInvalid("Invalid provider cost amount") from exc
    if (
        not amount.is_finite()
        or amount < 0
        or amount > _MAX_AMOUNT
        or amount.as_tuple().exponent < -12
    ):
        raise ProviderCostInvalid("Provider cost amount exceeds verified bounds")
    return amount


def _range(start_time: int, end_time: int, now: Optional[int] = None) -> None:
    now_seconds = int(time.time()) if now is None else now
    if (
        type(start_time) is not int
        or type(end_time) is not int
        or start_time < 0
        or start_time % _ONE_DAY
        or end_time % _ONE_DAY
        or end_time <= start_time
        or end_time - start_time > _MAX_DAYS * _ONE_DAY
        or end_time > now_seconds - (now_seconds % _ONE_DAY)
    ):
        raise ProviderCostInvalid("Cost range must cover at most 31 completed UTC days")


def verify_observation(
    evidence: Any,
    *,
    start_time: int,
    end_time: int,
) -> Dict[str, Any]:
    """Verify independent source metadata again at the API trust boundary.

    Only the adapter fetches the administrator-scoped OpenAI endpoint. This
    does not authenticate individual invoice lines or provider request IDs.
    A stale, incomplete, or substituted adapter payload must never be emitted
    as server-verified evidence or recorded by the model ledger.
    """
    _range(start_time, end_time)
    if (
        type(evidence) is not dict
        or frozenset(evidence) != _SOURCE_FIELDS
        or evidence.get("source") != "openai_organization_costs_api"
        or evidence.get("source_authenticated") is not True
        or evidence.get("source_scope") != "configured_openai_project"
        or evidence.get("individual_call_cost_verified") is not False
        or evidence.get("provider_hard_cost_cap_verified") is not False
        or evidence.get("ledger_mutated") is not False
        or evidence.get("currency") != "USD"
        or type(evidence.get("start_time")) is not int
        or type(evidence.get("end_time")) is not int
        or evidence["start_time"] != start_time
        or evidence["end_time"] != end_time
    ):
        raise ProviderCostInvalid("Provider aggregate attestation is incomplete")
    digest = hashlib.sha256(_project().encode("utf-8")).hexdigest()
    if type(evidence.get("project_sha256")) is not str or evidence["project_sha256"] != digest:
        raise ProviderCostInvalid("Provider aggregate project changed")
    checked = evidence.get("source_checked_at_utc")
    now = int(time.time())
    if type(checked) is not int or not 0 <= now - checked <= _MAX_PROOF_AGE_SECONDS:
        raise ProviderCostInvalid("Provider aggregate observation is stale")
    pages = evidence.get("pages")
    buckets = evidence.get("buckets")
    lines = evidence.get("cost_lines")
    if (
        type(pages) is not int
        or not 1 <= pages <= _MAX_PAGES
        or type(buckets) is not int
        or not 0 <= buckets <= (end_time - start_time) // _ONE_DAY
        or type(lines) is not int
        or not 0 <= lines <= _MAX_RESULTS
        or (lines > 0 and buckets == 0)
        or type(evidence.get("provider_cost_data_present")) is not bool
        or evidence["provider_cost_data_present"] != (lines > 0)
    ):
        raise ProviderCostInvalid("Provider aggregate coverage is incomplete")
    value = evidence["provider_cost_usd"]
    if lines == 0:
        if value is not None:
            raise ProviderCostInvalid("Missing provider costs must remain unknown")
    elif type(value) is not str:
        raise ProviderCostInvalid("Provider cost is not an exact decimal")
    else:
        try:
            amount = Decimal(value)
        except InvalidOperation as exc:
            raise ProviderCostInvalid("Provider cost is invalid") from exc
        if (
            not amount.is_finite()
            or amount < 0
            or amount > _MAX_AMOUNT
            or amount.as_tuple().exponent < -12
        ):
            raise ProviderCostInvalid("Provider cost is invalid")
    return dict(evidence)


class OpenAICostSource:
    """Read exactly one configured project from OpenAI's organization Costs API."""

    async def observe(
        self,
        *,
        start_time: int,
        end_time: int,
    ) -> Dict[str, Any]:
        mode = trust_mode()
        if mode not in {"openai_costs", "verified_only"}:
            raise ProviderCostUnavailable("Provider costs are not enabled")
        _range(start_time, end_time)
        project = _project()
        admin_key = _key()
        cursor: Optional[str] = None
        visited: set[str] = set()
        bucket_days: set[int] = set()
        unique_lines: set[tuple[int, str]] = set()
        count = 0
        total = Decimal(0)
        pages = 0
        # A single hardcoded HTTPS origin/path and no redirects, proxies,
        # user-controlled hosts, or request body. Do not log credentials.
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            for _ in range(_MAX_PAGES):
                # Match the official OpenAI Python SDK Querystring's default
                # array_format="repeat" (not bracketed array parameters).
                params: list[tuple[str, Any]] = [
                    ("start_time", start_time),
                    ("end_time", end_time),
                    ("bucket_width", "1d"),
                    ("limit", _MAX_DAYS),
                    ("project_ids", project),
                    ("group_by", "project_id"),
                    ("group_by", "line_item"),
                ]
                if cursor is not None:
                    params.append(("page", cursor))
                try:
                    async with client.stream(
                        "GET",
                        _COSTS_URL,
                        params=params,
                        headers={
                            "Authorization": "Bearer " + admin_key,
                            "Accept": "application/json",
                            "Accept-Encoding": "identity",
                        },
                    ) as response:
                        if response.status_code != 200:
                            raise ProviderCostUnavailable("OpenAI Costs API unavailable")
                        length = response.headers.get("content-length")
                        if length is not None:
                            try:
                                parsed_length = int(length)
                            except ValueError as exc:
                                raise ProviderCostInvalid(
                                    "Invalid provider response length"
                                ) from exc
                            if not 0 <= parsed_length <= _MAX_PAGE_BYTES:
                                raise ProviderCostInvalid("Provider cost page exceeds size limit")
                        if (
                            response.headers.get("content-type", "").split(";", 1)[0].lower()
                            != "application/json"
                        ):
                            raise ProviderCostInvalid("Provider costs must be JSON")
                        if (
                            response.headers.get("content-encoding", "identity").lower()
                            != "identity"
                        ):
                            raise ProviderCostInvalid("Encoded cost response is unsupported")
                        raw = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(raw) + len(chunk) > _MAX_PAGE_BYTES:
                                raise ProviderCostInvalid("Provider cost page exceeds size limit")
                            raw.extend(chunk)
                except (httpx.HTTPError, OSError, TimeoutError) as exc:
                    raise ProviderCostUnavailable("Provider cost request failed") from exc
                page = _parse_page(bytes(raw))
                pages += 1
                for bucket in page["data"]:
                    if not isinstance(bucket, dict) or bucket.get("object") != "bucket":
                        raise ProviderCostInvalid("Invalid provider cost bucket")
                    start, end = bucket.get("start_time"), bucket.get("end_time")
                    if (
                        type(start) is not int
                        or type(end) is not int
                        or start < start_time
                        or end > end_time
                        or end - start != _ONE_DAY
                        or start % _ONE_DAY
                        or start in bucket_days
                    ):
                        raise ProviderCostInvalid("Overlapping or out-of-range provider bucket")
                    bucket_days.add(start)
                    results = bucket.get("results")
                    if not isinstance(results, list) or len(results) > 128:
                        raise ProviderCostInvalid("Provider cost lines are incomplete")
                    for result in results:
                        count += 1
                        if count > _MAX_RESULTS:
                            raise ProviderCostInvalid("Too many provider cost lines")
                        if (
                            not isinstance(result, dict)
                            or result.get("object") != "organization.costs.result"
                            or result.get("project_id") != project
                        ):
                            raise ProviderCostInvalid("Provider project mismatch")
                        line = result.get("line_item")
                        if line is not None and (not isinstance(line, str) or len(line) > 256):
                            raise ProviderCostInvalid("Invalid provider cost line")
                        identity = (start, line or "")
                        if identity in unique_lines:
                            raise ProviderCostInvalid("Duplicated provider cost line")
                        unique_lines.add(identity)
                        money = result.get("amount")
                        if not isinstance(money, dict) or money.get("currency") != "usd":
                            raise ProviderCostInvalid("Provider returned non-USD cost")
                        total += _money(money.get("value"))
                        if total > _MAX_AMOUNT:
                            raise ProviderCostInvalid(
                                "Aggregate provider cost exceeds verified bounds"
                            )
                has_more, next_page = page["has_more"], page.get("next_page")
                if not has_more:
                    if next_page is not None:
                        raise ProviderCostInvalid("Conflicting provider pagination")
                    break
                if (
                    not isinstance(next_page, str)
                    or not _CURSOR.fullmatch(next_page)
                    or next_page in visited
                ):
                    raise ProviderCostInvalid("Provider pagination is invalid or repeated")
                visited.add(next_page)
                cursor = next_page
            else:
                raise ProviderCostInvalid("Provider cost pagination exceeds limit")
        # Never return IDs, raw invoice lines, keys, or unbounded responses.
        observed = {
            "source": "openai_organization_costs_api",
            "source_authenticated": True,
            "source_scope": "configured_openai_project",
            "project_sha256": hashlib.sha256(project.encode()).hexdigest(),
            "start_time": start_time,
            "end_time": end_time,
            "provider_cost_usd": str(total) if count else None,
            "provider_cost_data_present": count > 0,
            "currency": "USD",
            "pages": pages,
            "buckets": len(bucket_days),
            "cost_lines": count,
            "individual_call_cost_verified": False,
            "provider_hard_cost_cap_verified": False,
            "ledger_mutated": False,
            "source_checked_at_utc": int(time.time()),
        }
        return verify_observation(observed, start_time=start_time, end_time=end_time)
