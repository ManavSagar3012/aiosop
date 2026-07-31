"""A2 metrics tests: writing MyRegistry-independent counters to the black-box
registry. Define realistic test expectations against the concrete interface."""  # noqa: E501
from ai_osop.core import metrics_a2


def test_metric_exists_and_renders():
    names = [
        "ai_osop_findings_detected_total",
        "ai_osop_chain_steps_executed_total",
        "ai_osop_chain_success_total",
        "ai_osop_time_to_finding_seconds",
    ]
    for n in names:
        assert hasattr(metrics_a2, n.split("_")[-1] if n.endswith("_total") else n)
        assert callable(getattr(metrics_a2, n.split("_")[-1] if n.endswith("_total") else n))


def test_counters_increment_and_label_values():
    metrics_a2.reset()
    metrics_a2.findings_detected(vuln_class="sqli", endpoint="/login")
    metrics_a2.findings_detected(vuln_class="sqli", endpoint="/search")

    # Confirm render() contains the expected increment count, not blank.
    txt = metrics_a2.render()
    assert "ai_osop_findings_detected_total" in txt
    counters = [l for l in txt.splitlines() if "ai_osop_findings_detected_total" in l and not l.startswith("#")]
    total = sum(int(float(l.rsplit(" ", 1)[-1])) for l in counters if l.rsplit(" ", 1)[-1].strip().isdigit())
    assert total >= 2, f"expected >=2 increments, got {total}: {counters}"


def test_chain_timer_smoke():
    metrics_a2.reset()
    with metrics_a2.time_chain_execution("test-chain"):
        pass
    text = metrics_a2.render()
    assert "ai_osop_chain_execution_seconds" in text


def test_reset_clears_counts():
    metrics_a2.findings_validated(vuln_class="xss", trust_tier="high")
    metrics_a2.reset()
    text = metrics_a2.render()
    assert "ai_osop_findings_validated_total" not in text

