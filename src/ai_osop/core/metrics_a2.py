"""Minimal metrics_a2 logic: renderable by Prometheus, produces outputs assertable in tests.

Fenced from import cycles against core.metrics' MetricsRegistry.
"""

from contextlib import contextmanager
from typing import Any, Dict, Iterator, cast

from prometheus_client import REGISTRY, Counter, Histogram

# Scoped name->collector map to avoid global collisions.
_COUNTERS: Dict[str, Any] = {}
_HISTOGRAMS: Dict[str, Any] = {}


def _get(name: str, labels: tuple = ()) -> Counter:
    key = f"{name}{{'sorted_labels':{labels}}}"
    if key not in _COUNTERS:
        for coll in list(REGISTRY._collector_to_names):
            if getattr(coll, "_name", "") == name:
                _COUNTERS[key] = coll
                return cast(Counter, coll)
        c = Counter(name, name, labels, registry=REGISTRY)
        _COUNTERS[key] = c
    return cast(Counter, _COUNTERS[key])


def _get_hist(name: str, labels: tuple = ()) -> Histogram:
    key = f"{name}{{'sorted_labels':{labels}}}"
    if key not in _HISTOGRAMS:
        for coll in list(REGISTRY._collector_to_names):
            if getattr(coll, "_name", "") == name:
                _HISTOGRAMS[key] = coll
                return cast(Histogram, coll)
        h = Histogram(name, name, labels, registry=REGISTRY)
        _HISTOGRAMS[key] = h
    return cast(Histogram, _HISTOGRAMS[key])


def chain_hop_seconds(seconds: float, chain_id: str, hop_idx: str) -> None:
    h = _get_hist("ai_osop_a2_chain_hop_seconds", ("chain_id", "hop_idx"))
    h.labels(chain_id=chain_id, hop_idx=hop_idx).observe(seconds)


def finding_llm_tokens(tokens: int, model: str, vuln_class: str) -> None:
    c = _get("ai_osop_a2_finding_llm_tokens_total", ("model", "vuln_class"))
    c.labels(model=model, vuln_class=vuln_class).inc(tokens)


def reset() -> None:
    # Unregister our own collectors from the default prometheus REGISTRY so a
    # reset truly clears state between tests. Iterate over a copy to be safe.
    for coll in list(REGISTRY._collector_to_names.keys()):
        names = REGISTRY._collector_to_names.get(coll) or []
        if any(n.startswith("ai_osop_a2_") for n in names):
            try:
                REGISTRY.unregister(coll)
            except KeyError:
                pass
    _COUNTERS.clear()
    _HISTOGRAMS.clear()


def findings_detected(vuln_class: str, endpoint: str) -> None:
    c = _get("ai_osop_a2_findings_detected_total", ("vuln_class", "endpoint"))
    c.labels(vuln_class=vuln_class, endpoint=endpoint).inc()


def findings_validated(vuln_class: str, trust_tier: str) -> None:
    c = _get("ai_osop_a2_findings_validated_total", ("vuln_class", "trust_tier"))
    c.labels(vuln_class=vuln_class, trust_tier=trust_tier).inc()


def chain_steps_executed(count: int, chain_id: str) -> None:
    c = _get("ai_osop_a2_chain_steps_executed_total", ("chain_id",))
    c.labels(chain_id=chain_id).inc(count)


def chain_success(chain_id: str, hops: int) -> None:
    c = _get("ai_osop_a2_chain_success_total", ("chain_id",))
    c.labels(chain_id=chain_id).inc()


@contextmanager
def time_chain_execution(chain_id: str) -> Iterator[None]:
    c = _get("ai_osop_a2_chain_execution_seconds", ("chain_id",))
    import time

    start = time.time()
    try:
        yield
    finally:
        c.labels(chain_id=chain_id).inc(time.time() - start)


def tool_call(tool: str, outcome: str) -> None:
    c = _get("ai_osop_a2_tool_calls_total", ("tool", "outcome"))
    c.labels(tool=tool, outcome=outcome).inc()


def time_to_finding(seconds: float, vuln_class: str) -> None:
    c = _get("ai_osop_a2_time_to_finding_seconds", ("vuln_class",))
    c.labels(vuln_class=vuln_class).inc(seconds)


def render() -> str:
    from prometheus_client import generate_latest

    return generate_latest(REGISTRY).decode()
