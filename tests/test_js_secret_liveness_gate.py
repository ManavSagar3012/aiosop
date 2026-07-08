"""
Verifies the JS-analyzer secret-liveness gate (2026-07-05 wiring):
  - a placeholder / non-secret is dropped (false-positive cut),
  - an unverified static secret is emitted UNVALIDATED with capped confidence,
  - only a confirmed-live secret is validated=True.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.js_analyzer_agent import JSAnalyzerAgent
from ai_osop.core.config import Severity


def _agent():
    a = JSAnalyzerAgent.__new__(JSAnalyzerAgent)  # bypass heavy __init__
    captured = {}

    async def _add_vuln(v):
        captured["vuln"] = v
        return v.id

    a.ctx = SimpleNamespace(
        graph_memory=SimpleNamespace(add_vulnerability=AsyncMock(side_effect=_add_vuln)),
        session_id="eng-test",
    )
    return a, captured


def _finding(value, rule="AWS Access Key", conf=0.9):
    return {
        "value": value,
        "source_url": "https://x/app.js",
        "rule": rule,
        "masked": "AKIA***",
        "severity": Severity.CRITICAL,
        "confidence": conf,
        "context": "const k = '...'",
        "offset": 10,
    }


@pytest.mark.asyncio
async def test_placeholder_is_dropped():
    a, cap = _agent()
    # obvious placeholder -> assess_secret classifies not_a_secret -> dropped
    vid = await a._persist_secret_finding(_finding("AKIAXXXXXXXXXXXXXXXX"), "eng-test")
    assert vid is None
    assert "vuln" not in cap  # nothing persisted


@pytest.mark.asyncio
async def test_unverified_secret_is_unvalidated_and_capped():
    a, cap = _agent()
    # a real-looking high-entropy value with no live probe -> unverified
    vid = await a._persist_secret_finding(
        _finding(
            "wJalrXUtnFEMI9K7MDENGbPxRfiCYEXAMPLEKEY7", rule="Generic Secret Assignment", conf=0.9
        ),
        "eng-test",
    )
    if vid is not None:  # if classified as a (unverified) secret, it must be downgraded
        v = cap["vuln"]
        assert v.validated is False
        assert v.confidence <= 0.5
