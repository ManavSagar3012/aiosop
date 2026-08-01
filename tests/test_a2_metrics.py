"""A2 metrics tests: writing MyRegistry-independent counters to the black-box
registry. Define realistic test expectations against the concrete interface."""  # noqa: E501

from ai_osop.core import metrics_a2


def test_metric_exists_and_renders():
    # The module exposes named functions that increment prefixed ai_osop_a2_*
    # counters; the render() output carries those names (Prometheus exposition).
    assert callable(metrics_a2.findings_detected)
    assert callable(metrics_a2.chain_steps_executed)
    assert callable(metrics_a2.chain_success)
    assert callable(metrics_a2.time_to_finding)
    assert callable(metrics_a2.tool_call)
    assert callable(metrics_a2.findings_validated)
    assert callable(metrics_a2.time_chain_execution)


def test_counters_increment_and_label_values():
    metrics_a2.reset()
    metrics_a2.findings_detected(vuln_class="sqli", endpoint="/login")
    metrics_a2.findings_detected(vuln_class="sqli", endpoint="/search")

    # Confirm render() contains the expected increment count, not blank.
    txt = metrics_a2.render()
    assert "ai_osop_a2_findings_detected_total" in txt
    counters = [
        l
        for l in txt.splitlines()
        if "ai_osop_a2_findings_detected_total" in l and not l.startswith("#")
    ]
    vals = []
    for l in counters:
        tail = l.rsplit(" ", 1)[-1].strip()
        if tail.replace(".", "", 1).isdigit():
            vals.append(float(tail))
    assert sum(vals) >= 2, f"expected >=2 increments, got {vals}: {counters}"


def test_chain_timer_smoke():
    metrics_a2.reset()
    with metrics_a2.time_chain_execution("test-chain"):
        pass
    text = metrics_a2.render()
    assert "ai_osop_a2_chain_execution_seconds" in text


def test_reset_clears_counts():
    metrics_a2.findings_validated(vuln_class="xss", trust_tier="high")
    metrics_a2.reset()
    text = metrics_a2.render()
    assert "ai_osop_a2_findings_validated_total" not in text


def test_finding_tokens_counter_renders():
    metrics_a2.reset()
    metrics_a2.finding_llm_tokens(120, model="gpt-4o", vuln_class="idor")
    out = metrics_a2.render()
    assert (
        'ai_osop_a2_finding_llm_tokens_total{model="gpt-4o",vuln_class="idor"} 120.0' in out
        or 'ai_osop_a2_finding_llm_tokens_total{model="gpt-4o",vuln_class="idor"} 120' in out
    )
