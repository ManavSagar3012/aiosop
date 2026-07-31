"""A2 metrics: counters, timers, and string-render checks tune out
external fragments. Prefixed `ai_osop_a2_` to avoid collisions with the core
Prometheus metrics that ship with the platform."""

from ai_osop.core import metrics_a2


def test_findings_and_time_series_render():
    metrics_a2.reset()

    # KNOWN=positive shape only
    metrics_a2.findings_detected(vuln_class="sqli", endpoint="/rest/user/login")
    metrics_a2.findings_validated(vuln_class="sqli", trust_tier="high")
    metrics_a2.chain_steps_executed(2, chain_id="c-1")
    metrics_a2.chain_success(chain_id="c-1", hops=2)
    metrics_a2.tool_call(tool="scan_endpoint", outcome="success")
    metrics_a2.time_to_finding(4.2, vuln_class="sqli")

    text = metrics_a2.render()
    assert "ai_osop_a2_findings_detected_total" in text
    assert "ai_osop_a2_chain_steps_executed_total" in text
    assert "ai_osop_a2_chain_success_total" in text
    assert "ai_osop_a2_tool_calls_total" in text
    assert "ai_osop_a2_time_to_finding_seconds" in text


def test_timer_observed():
    metrics_a2.reset()
    with metrics_a2.time_chain_execution(chain_id="c-1"):
        pass
    txt = metrics_a2.render()
    assert "ai_osop_a2_chain_execution_seconds" in txt


def test_reset_works_without_error():
    metrics_a2.reset()
    metrics_a2.findings_detected(vuln_class="x", endpoint="/a")
    assert "ai_osop_a2_findings_detected_total" in metrics_a2.render()
    metrics_a2.reset()
