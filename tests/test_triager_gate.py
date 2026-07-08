"""Tests for Sprint 1.3 — Triager Gate.

The gate must NEVER emit a finding that lacks:
  - captured evidence, AND
  - confidence >= 0.50

It must ALWAYS drop duplicates. It must flag NEEDS_POC when evidence is present
but PoC is missing, and ESCALATE when more evidence is needed.
"""

import pytest

from ai_osop.core.models import (
    AttackChain,
    ChainStatus,
    EvidencePackage,
    EvidenceProvenance,
    PrimitiveLedger,
    PrimitiveType,
    TriageVerdict,
)
from ai_osop.core.triager_gate import TriagerGate

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _prim(confidence=0.75, target="http://example.com/vuln", **kw):
    return PrimitiveLedger(
        primitive_type=PrimitiveType.NUCLEI_SIGNAL,
        engagement_id="eng-test",
        source="nuclei",
        dedup_key="dk-test",
        target=target,
        confidence=confidence,
        **kw,
    )


def _chain(confidence=0.75, poc_script=None):
    return AttackChain(
        engagement_id="eng-test",
        primitive_ids=["prim-1"],
        confidence=confidence,
        poc_script=poc_script or [],
        status=ChainStatus.PENDING_POC,
    )


def _evidence(
    raw_requests=None,
    raw_responses=None,
    screenshots=None,
    replay_script=None,
):
    return EvidencePackage(
        finding_id="chain-test",
        engagement_id="eng-test",
        raw_requests=raw_requests or [],
        raw_responses=raw_responses or [],
        screenshots=screenshots or [],
        replay_script=replay_script or [],
        provenance=EvidenceProvenance.LIVE,
    )


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


class TestTriagerGate:
    def test_emit_when_all_criteria_met(self):
        gate = TriagerGate()
        prim = _prim(confidence=0.80)
        chain = _chain(confidence=0.80, poc_script=["curl", "http://example.com"])
        evidence = _evidence(raw_requests=[{"url": "http://example.com"}])
        report = gate.evaluate(prim, chain=chain, evidence=evidence)
        assert report.verdict == TriageVerdict.EMIT
        assert report.has_poc is True
        assert report.has_captured_evidence is True
        assert report.is_duplicate is False

    def test_drop_duplicate(self):
        gate = TriagerGate(emitted_dedup_keys=["chain-already-emitted"])
        prim = _prim(confidence=0.90)
        chain = _chain(confidence=0.90, poc_script=["curl", "http://x"])
        chain.id = "chain-already-emitted"
        evidence = _evidence(raw_requests=[{"url": "http://x"}])
        report = gate.evaluate(prim, chain=chain, evidence=evidence)
        assert report.verdict == TriageVerdict.DROP
        assert report.is_duplicate is True

    def test_escalate_when_no_evidence(self):
        gate = TriagerGate()
        prim = _prim(confidence=0.70)
        chain = _chain(confidence=0.70, poc_script=["curl", "http://x"])
        evidence = _evidence()  # empty evidence
        report = gate.evaluate(prim, chain=chain, evidence=evidence)
        assert report.verdict in (TriageVerdict.ESCALATE, TriageVerdict.NEEDS_POC)
        assert report.has_captured_evidence is False

    def test_needs_poc_when_evidence_but_no_poc(self):
        gate = TriagerGate()
        prim = _prim(confidence=0.70)
        chain = _chain(confidence=0.70, poc_script=[])  # no PoC
        evidence = _evidence(raw_requests=[{"url": "http://x"}])
        report = gate.evaluate(prim, chain=chain, evidence=evidence)
        assert report.verdict == TriageVerdict.NEEDS_POC
        assert report.has_poc is False
        assert report.has_captured_evidence is True

    def test_escalate_when_confidence_too_low(self):
        gate = TriagerGate()
        prim = _prim(confidence=0.30)
        chain = _chain(confidence=0.30, poc_script=["curl", "http://x"])
        evidence = _evidence(raw_requests=[{"url": "http://x"}])
        report = gate.evaluate(prim, chain=chain, evidence=evidence)
        # Low confidence → at least one blocker → not EMIT
        assert report.verdict != TriageVerdict.EMIT

    def test_escalate_when_empty_target(self):
        gate = TriagerGate()
        prim = _prim(confidence=0.80, target="")
        chain = _chain(confidence=0.80, poc_script=["curl", "http://x"])
        evidence = _evidence(raw_requests=[{"url": "http://x"}])
        report = gate.evaluate(prim, chain=chain, evidence=evidence)
        assert report.verdict != TriageVerdict.EMIT
        assert any("target" in b.lower() for b in report.blockers)

    def test_high_confidence_without_poc_emits(self):
        """High confidence (>=0.85) with evidence but no PoC is waived."""
        gate = TriagerGate()
        prim = _prim(confidence=0.90)
        chain = _chain(confidence=0.90, poc_script=[])  # no PoC
        evidence = _evidence(raw_requests=[{"url": "http://x"}])
        report = gate.evaluate(prim, chain=chain, evidence=evidence)
        assert report.verdict == TriageVerdict.EMIT

    def test_dedup_register_after_emit(self):
        """After EMIT, a second call with same chain.id is a DROP."""
        gate = TriagerGate()
        prim = _prim(confidence=0.80)
        chain = _chain(confidence=0.80, poc_script=["curl", "http://x"])
        evidence = _evidence(raw_requests=[{"url": "http://x"}])
        r1 = gate.evaluate(prim, chain=chain, evidence=evidence)
        assert r1.verdict == TriageVerdict.EMIT
        # Second call with same chain.id → DROP
        r2 = gate.evaluate(prim, chain=chain, evidence=evidence)
        assert r2.verdict == TriageVerdict.DROP

    def test_reproducibility_score_with_poc_and_evidence(self):
        gate = TriagerGate()
        prim = _prim(confidence=0.80)
        chain = _chain(confidence=0.80, poc_script=["curl", "http://x"])
        evidence = _evidence(raw_requests=[{"url": "http://x"}])
        report = gate.evaluate(prim, chain=chain, evidence=evidence)
        # score = 0.4 (poc) + 0.3 (evidence) + 0.8*0.3 = 0.94
        assert report.reproducibility_score >= 0.7

    def test_no_chain_uses_primitive_confidence(self):
        gate = TriagerGate()
        prim = _prim(confidence=0.55)
        evidence = _evidence(raw_requests=[{"url": "http://x"}])
        # Provide a replay_script directly in evidence (no chain)
        evidence.replay_script = ["curl", "http://x"]
        report = gate.evaluate(prim, chain=None, evidence=evidence)
        assert report.confidence == 0.55
