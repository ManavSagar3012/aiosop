"""Global Prometheus exposition cannot reveal raw tenant IDs or provider data."""

from unittest.mock import MagicMock

import pytest

from ai_osop.core import observability


def test_engagement_cost_metrics_aggregate_without_tenant_labels(monkeypatch):
    metric = MagicMock()
    monkeypatch.setattr(observability, "ENGAGEMENT_COST_USD", metric)
    secret_engagements = [
        "eng-customer-a-sensitive",
        "eng-customer-b-sensitive",
        "eng-" + "x" * 10000,
    ]
    for engagement_id in secret_engagements:
        observability.record_engagement_cost(engagement_id, 0.25)
    assert metric.labels.call_count == 3
    assert all(call.kwargs == {"engagement_id": "all"} for call in metric.labels.call_args_list)
    assert metric.labels.return_value.inc.call_count == 3
    assert all("sensitive" not in str(call) for call in metric.labels.call_args_list)


@pytest.mark.parametrize("invalid", [-10.0, float("nan"), float("inf"), True, "SECRET"])
def test_invalid_or_uncertain_billing_amount_not_recorded_as_cost(monkeypatch, invalid):
    metric = MagicMock()
    monkeypatch.setattr(observability, "ENGAGEMENT_COST_USD", metric)
    observability.record_engagement_cost("eng-any", invalid)
    metric.labels.assert_not_called()


def test_invalid_model_name_never_creates_secret_label(monkeypatch):
    calls, tokens, costs = MagicMock(), MagicMock(), MagicMock()
    monkeypatch.setattr(observability, "LLM_CALLS_TOTAL", calls)
    monkeypatch.setattr(observability, "LLM_TOKENS_TOTAL", tokens)
    monkeypatch.setattr(observability, "LLM_COST_USD", costs)
    observability.record_llm_call(
        model="model-token=SECRET\n" + "x" * 1000,
        operation="arbitrary operator operation=SECRET",
        tokens_input=4,
        tokens_output=-5,
        cost_usd=float("nan"),
    )
    calls.labels.assert_called_once_with(model="unknown", operation="unknown")
    tokens.labels.assert_called_once_with(model="unknown", type="input")
    costs.labels.assert_not_called()
