"""AIOSOP-CALIBRATION-CLOSED: findings emitted through persist_finding are
calibrated against REAL recorded outcomes — the loop is no longer open.

Regression: the calibration engine RECORDED validation outcomes
(graph_memory.validate_vulnerability -> record_outcome -> finding_corpus) but
the confidence stamped at emission time (persist_finding, the single
chokepoint every standalone scanner + the vuln agent routes through) was never
derived from them — it used the scanner's hardcoded constant. That made the
recorded corpus a dead signal.

These tests use a REAL ConfidenceCalibrationEngine over a stub SessionMemory
with the same shape the production store exposes, and pin BOTH directions:
a class with strong positive evidence is pulled UP, a class with strong
negative evidence is pulled DOWN, and a cold class is returned unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.enums import AgentType, VulnClass
from ai_osop.core.models import Task, Vulnerability


class _StubCalibrationStore:
    """SessionMemory-shaped stub exposing the count-aware reader the engine uses."""

    def __init__(self, n_valid: int, n_total: int) -> None:
        self._n_valid = n_valid
        self._n_total = n_total

    async def get_historical_outcome_counts(
        self, finding_type: str, workflow_intent: Optional[str] = None
    ) -> tuple[int, int]:
        return (self._n_valid, self._n_total)

    async def get_historical_success_rate(
        self, finding_type: str, workflow_intent: Optional[str] = None
    ) -> float:
        return 0.5  # unused when the count reader exists


def _make_agent(store: _StubCalibrationStore) -> BaseVulnerabilityAgent:
    """Bypass BaseAgent.__init__ (which demands a full AgentContext) so we can
    drive persist_finding directly with the pieces it touches."""
    from ai_osop.agents.base_vuln_agent import (
        BaseVulnerabilityAgent as _Base,
    )

    # BaseVulnerabilityAgent is abstract; subclass with the abstract members
    # stubbed so __new__ can produce an instance.
    class _Concrete(_Base):
        @property
        def agent_type(self) -> AgentType:
            return AgentType.VULN_ANALYSIS

        async def _execute(self, task: Task) -> Dict[str, Any]:
            return {}

        async def _setup_resources(self) -> None:
            pass

        async def _cleanup_resources(self) -> None:
            pass

    agent = _Concrete.__new__(_Concrete)
    ctx = MagicMock()
    ctx.session_memory = store
    ctx.current_task = Task(
        type="sqli_scan", agent_type=AgentType.VULN_ANALYSIS, engagement_id="eng-t"
    )
    ctx.graph_memory.add_vulnerability = AsyncMock(return_value="vuln-1")
    agent.ctx = ctx
    agent.findings = {}
    agent.logger = MagicMock()
    return agent


def _vuln(confidence: float = 0.9) -> Vulnerability:
    return Vulnerability(
        id="vuln-cal-1",
        vuln_type=VulnClass.SQLI,
        severity="high",
        title="SQLi",
        description="probe",
        tool_source="test",
        confidence=confidence,
        engagement_id="eng-t",
    )


@pytest.mark.asyncio
async def test_positive_evidence_raises_emitted_confidence():
    """10 accepts / 0 rejects -> the emitted finding's confidence is pulled UP
    from the scanner constant by the Beta-Binomial posterior."""
    agent = _make_agent(_StubCalibrationStore(n_valid=10, n_total=10))
    vuln = _vuln(confidence=0.9)

    await agent.persist_finding(vuln)

    assert vuln.confidence > 0.9
    # The raw (pre-calibration) belief is preserved for the audit trail.
    assert vuln.yield_metadata.get("raw_confidence") == pytest.approx(0.9, abs=1e-4)
    assert vuln.yield_metadata.get("calibration") == "empirical"
    assert agent.ctx.graph_memory.add_vulnerability.await_count == 1


@pytest.mark.asyncio
async def test_negative_evidence_lowers_emitted_confidence():
    """0 accepts / 10 rejects -> the emitted confidence is pulled DOWN."""
    agent = _make_agent(_StubCalibrationStore(n_valid=0, n_total=10))
    vuln = _vuln(confidence=0.9)

    await agent.persist_finding(vuln)

    assert vuln.confidence < 0.9


@pytest.mark.asyncio
async def test_cold_class_unchanged():
    """No recorded outcomes -> the scanner's raw confidence is emitted verbatim
    (no fabricated boost on cold start)."""
    agent = _make_agent(_StubCalibrationStore(n_valid=0, n_total=0))
    vuln = _vuln(confidence=0.9)

    await agent.persist_finding(vuln)

    assert vuln.confidence == pytest.approx(0.9)
    # No calibration metadata is stamped — nothing was applied.
    assert "calibration" not in vuln.yield_metadata


@pytest.mark.asyncio
async def test_calibration_failure_never_blocks_persistence():
    """A broken calibration reader must not prevent the finding from persisting."""
    class _BrokenStore:
        async def get_historical_outcome_counts(self, finding_type, workflow_intent=None):
            raise RuntimeError("postgres down")

    agent = _make_agent(_BrokenStore())
    vuln = _vuln(confidence=0.9)

    await agent.persist_finding(vuln)

    # The graph write still happened with the ORIGINAL confidence.
    assert agent.ctx.graph_memory.add_vulnerability.await_count == 1
    assert vuln.confidence == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_ledger_state_follows_calibrated_confidence():
    """The validation-ledger trust_score must reflect the CALIBRATED value, so
    the audit trail and the emitted graph agree."""
    agent = _make_agent(_StubCalibrationStore(n_valid=0, n_total=20))
    vuln = _vuln(confidence=0.9)  # 0/20 accepts pulls well below 0.7

    await agent.persist_finding(vuln)

    assert vuln.confidence < 0.7
    assert agent.ctx.graph_memory.add_vulnerability.await_count == 1
