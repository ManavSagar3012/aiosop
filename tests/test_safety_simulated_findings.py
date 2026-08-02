"""Regression tests for the simulated-finding guard (OSOP-P0-02).

Invariant: a fabricated/mock Vulnerability must NOT be persisted into the real graph
(and therefore cannot reach the corpus, reports, or dashboard counts) unless the operator
explicitly sets OSOP_ALLOW_SIMULATED_FINDINGS=true.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

import ai_osop.core.config as config
from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Vulnerability
from ai_osop.memory.graph_memory import GraphMemory


def _vuln(**kw) -> Vulnerability:
    base = dict(
        vuln_type=VulnClass.SQLI,
        severity=Severity.HIGH,
        title="Blind SQL Injection",
        description="d",
        tool_source="burp",
        confidence=0.9,
        engagement_id="eng-1",
        evidence=[],
    )
    base.update(kw)
    return Vulnerability(**base)


def test_is_simulated_detection():
    assert _vuln(tool_source="vuln-agent-mock").is_simulated() is True
    assert _vuln(title="Blind SQL Injection (Simulated)").is_simulated() is True
    assert _vuln(evidence=[{"provenance": "simulated"}]).is_simulated() is True
    assert _vuln().is_simulated() is False


def _graph_memory_with_fake_driver():
    gm = GraphMemory.__new__(GraphMemory)  # bypass real Neo4j connect
    # If add_vulnerability ever reaches the DB, .session() will be used; make it explode
    # so a leak past the guard is caught loudly rather than silently passing.
    gm._driver = MagicMock()
    gm._driver.session = MagicMock(side_effect=AssertionError("DB write should not happen"))
    return gm


@pytest.fixture
def restore_flag():
    v = config.settings.allow_simulated_findings
    yield
    config.settings.allow_simulated_findings = v


async def test_simulated_vuln_not_persisted_by_default(restore_flag):
    config.settings.allow_simulated_findings = False
    gm = _graph_memory_with_fake_driver()
    v = _vuln(tool_source="vuln-agent-mock", evidence=[{"provenance": "simulated"}])
    # Returns the id but performs NO DB write (driver.session would raise if reached).
    result = await gm.add_vulnerability(v)
    assert result == v.id


async def test_real_vuln_attempts_persistence(restore_flag):
    """A real (non-simulated) finding passes the guard and reaches the DB layer."""
    config.settings.allow_simulated_findings = False
    gm = _graph_memory_with_fake_driver()
    with pytest.raises(AssertionError, match="DB write should not happen"):
        await gm.add_vulnerability(_vuln())  # not simulated -> proceeds to DB (which we trap)
