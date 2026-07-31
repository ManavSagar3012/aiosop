"""A2 metrics module: prometheus-compatible counters for platform analytics.

Originally part of the commit titled 'A2 Validate Ledger Metrics' that was lost;
recreated here so instrumentation helpers stay in the codebase alongside the
registry factory via ``MetricsRegistry``.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ai_osop.core.metrics import MetricsRegistry


def reset() -> None:
    MetricsRegistry.reset()


def findings_detected(vuln_class: str, endpoint: str) -> None:
    MetricsRegistry.get().counter(
        "ai_osop_findings_detected_total", 1, vuln_class=vuln_class, endpoint=endpoint
    )


def findings_validated(vuln_class: str, trust_tier: str) -> None:
    MetricsRegistry.get().counter(
        "ai_osop_findings_validated_total", 1, vuln_class=vuln_class, trust_tier=trust_tier
    )


def chain_steps_executed(count: int, chain_id: str) -> None:
    MetricsRegistry.get().counter(
        "ai_osop_chain_steps_executed_total", count, chain_id=chain_id
    )


def chain_success(chain_id: str, hops: int) -> None:
    MetricsRegistry.get().counter(
        "ai_osop_chain_success_total", 1, chain_id=chain_id
    )


def time_chain_execution(chain_id: str):
    return MetricsRegistry.get().time(
        "ai_osop_chain_execution_seconds", chain_id=chain_id
    )


def tool_call(tool: str, outcome: str) -> None:
    MetricsRegistry.get().counter(
        "ai_osop_tool_calls_total", 1, tool=tool, outcome=outcome
    )


def time_to_finding(seconds: float, vuln_class: str) -> None:
    MetricsRegistry.get().gauge(
        "ai_osop_time_to_finding_seconds", seconds, vuln_class=vuln_class
    )


def render() -> str:
    return MetricsRegistry.get().render()
