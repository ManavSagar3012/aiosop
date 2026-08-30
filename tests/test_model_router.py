"""Unit tests for the model routing decision module."""

from __future__ import annotations

import pytest

from ai_osop.core.model_router import ModelRouter, TaskCategory


@pytest.fixture()
def router() -> ModelRouter:
    return ModelRouter()


def test_classification_routes_to_fastest_model(router: ModelRouter) -> None:
    assert router.route(TaskCategory.CLASSIFICATION) == "ollama/phi3:latest"


def test_reasoning_routes_to_highest_quality(router: ModelRouter) -> None:
    assert router.route(TaskCategory.REASONING) == "gpt-4o"
    assert router.route(TaskCategory.REPORT_GENERATION) == "gpt-4o"


def test_extraction_balances_speed_and_quality(router: ModelRouter) -> None:
    assert router.route(TaskCategory.EXTRACTION) == "gpt-4o-mini"


def test_visual_analysis_restricted_to_vision_models(router: ModelRouter) -> None:
    assert router.route(TaskCategory.VISUAL_ANALYSIS) in {"gpt-4o", "gpt-4o-mini"}


def test_fallback_when_primary_fails(router: ModelRouter) -> None:
    for _ in range(ModelRouter.FAILURE_THRESHOLD):
        router.record_failure("gpt-4o")
    assert router.route(TaskCategory.REASONING) == "gpt-4o-mini"

    # Recovery resets consecutive failures, primary returns to service.
    router.record_success("gpt-4o")
    assert router.route(TaskCategory.REASONING) == "gpt-4o"


def test_fallback_chain_exhaustion_last_resort(router: ModelRouter) -> None:
    for name in ("gpt-4o", "gpt-4o-mini", "ollama/qwen3:8b", "ollama/phi3:latest"):
        for _ in range(ModelRouter.FAILURE_THRESHOLD):
            router.record_failure(name)
    report = router.get_health_report()
    assert report["healthy_count"] == 0
    assert router.route(TaskCategory.REASONING) == "gpt-4o"  # still returns best candidate


def test_latency_tracking_updates_health_report(router: ModelRouter) -> None:
    router.record_latency("gpt-4o", 1.0)
    router.record_latency("gpt-4o", 2.0)

    entry = router.get_health_report()["models"]["gpt-4o"]
    assert entry["avg_latency_s"] == pytest.approx(1.5)
    assert entry["max_latency_s"] == pytest.approx(2.0)
    assert entry["samples"] == 2
    assert entry["healthy"] is True

    untouched = router.get_health_report()["models"]["ollama/phi3:latest"]
    assert untouched["samples"] == 0
    assert untouched["avg_latency_s"] is None


def test_complexity_hint_shifts_routing(router: ModelRouter) -> None:
    assert router.route(TaskCategory.REASONING, "fast") != "gpt-4o"
