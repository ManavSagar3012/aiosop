"""Sprint 1.3 — Triager Gate wiring into the chain-first consume loop.

The TriagerGate existed and was tested, but nothing ran composed chains through it,
so no chain was ever gated before becoming report-ready. These tests prove the wiring:

  - gate_chains stamps each chain with a verdict and the honest ChainStatus
    (EMIT->VALIDATED, ESCALATE/NEEDS_POC->PENDING_POC, DROP->DROPPED),
  - analyze_primitives runs the gate when one is supplied (and stays byte-compatible
    when it is not, so the pure path is unchanged),
  - a chain only reaches EMIT/VALIDATED when it carries BOTH a PoC and captured
    evidence (the reproducibility rule),
  - chain ids are deterministic so persistence is idempotent and the gate can dedup,
  - the orchestrator consume pass persists gated chains and promotes only the
    EMIT-ready ones, isolating per-engagement failures.

Everything is hermetic — no DB, no network.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.chain_analysis import (
    analyze_primitives,
    evidence_from_primitive,
    gate_chains,
    primitive_from_node,
    vuln_to_primitive,
)
from ai_osop.core.models import (
    ChainStatus,
    EvidencePackage,
    PrimitiveLedger,
    PrimitiveType,
    TriageVerdict,
    Vulnerability,
)
from ai_osop.core.triager_gate import TriagerGate
from ai_osop.orchestrator.orchestrator import Orchestrator


def _prim(ptype, target, sev="high", conf=0.7, evidence=None):
    raw = {"evidence": evidence} if evidence is not None else {}
    return PrimitiveLedger(
        primitive_type=ptype,
        engagement_id="e1",
        source="vuln:test",
        dedup_key=f"{ptype.value}:{target}",
        target=target,
        severity_hint=sev,
        confidence=conf,
        raw=raw,
    )


def _colocated(evidence=None):
    return [
        _prim(PrimitiveType.IDOR_HINT, "https://x/api/user", "high", evidence=evidence),
        _prim(PrimitiveType.AUTH_SIGNAL, "https://x/api/user", "critical", evidence=evidence),
    ]


# --------------------------------------------------------------------------- #
# gate_chains + analyze_primitives(gate=...)                                   #
# --------------------------------------------------------------------------- #

def test_chain_without_evidence_is_not_emit():
    """A composed chain with a PoC but no captured evidence must NOT be report-ready."""
    out = analyze_primitives(_colocated(), gate=TriagerGate())
    report = out["reports"][0]
    chain = out["chains"][0]
    assert report.verdict == TriageVerdict.ESCALATE  # missing captured evidence
    assert chain.status == ChainStatus.PENDING_POC
    assert chain.triage_report_id == report.id  # stamped back onto the chain


def test_chain_with_poc_and_evidence_is_emit():
    """PoC (composer-generated) + captured evidence -> EMIT / VALIDATED."""
    prims = _colocated(evidence=[{"request": "GET /", "response": "200"}])
    root = sorted(prims, key=lambda p: p.severity_hint == "critical", reverse=True)[0]
    ev = evidence_from_primitive(root)
    assert ev is not None and ev.raw_responses  # evidence carried through

    out = analyze_primitives(prims, gate=TriagerGate(), evidence_by_primitive={root.id: ev})
    report = out["reports"][0]
    assert report.verdict == TriageVerdict.EMIT
    assert report.has_poc and report.has_captured_evidence
    assert out["chains"][0].status == ChainStatus.VALIDATED


def test_gate_drops_duplicate_chain():
    """A dedup_key already seen by the gate -> DROP / DROPPED."""
    prims = _colocated(evidence=[{"r": 1}])
    root = sorted(prims, key=lambda p: p.severity_hint == "critical", reverse=True)[0]
    ev = evidence_from_primitive(root)

    first = analyze_primitives(prims, gate=TriagerGate(), evidence_by_primitive={root.id: ev})
    emitted_key = first["chains"][0].id  # gate dedups on chain.id

    # A fresh gate pre-seeded with that key must now DROP the identical chain.
    gate = TriagerGate(emitted_dedup_keys=[emitted_key])
    second = analyze_primitives(prims, gate=gate, evidence_by_primitive={root.id: ev})
    assert second["reports"][0].verdict == TriageVerdict.DROP
    assert second["chains"][0].status == ChainStatus.DROPPED


def test_analyze_without_gate_is_unchanged():
    """No gate supplied -> no 'reports' key, status stays the composer's pending_poc."""
    out = analyze_primitives(_colocated())
    assert "reports" not in out
    assert out["chains"][0].status == ChainStatus.PENDING_POC


def test_chain_id_is_deterministic():
    a = analyze_primitives(_colocated())["chains"][0].id
    b = analyze_primitives(_colocated())["chains"][0].id
    assert a == b  # stable across runs -> idempotent persistence + cross-pass dedup


def test_gate_chains_skips_unknown_root():
    """gate_chains ignores a chain with no matching root primitive rather than crashing."""
    out = analyze_primitives(_colocated())
    chain = out["chains"][0]
    reports = gate_chains([chain], roots={}, gate=TriagerGate())
    assert reports == []


# --------------------------------------------------------------------------- #
# vuln_to_primitive carries evidence; primitive_from_node roundtrips           #
# --------------------------------------------------------------------------- #

def test_vuln_to_primitive_carries_evidence():
    v = Vulnerability(
        vuln_type="idor",
        severity="high",
        title="t",
        description="d",
        engagement_id="e1",
        confidence=0.8,
        tool_source="test",
        endpoint_id="https://x/api",
        evidence=[{"request": "GET /api/1", "response": "200 {owner:2}"}],
    )
    p = vuln_to_primitive(v)
    assert p.raw["evidence"] == v.evidence
    ev = evidence_from_primitive(p)
    assert ev is not None and ev.raw_responses == v.evidence


def test_primitive_from_node_roundtrip():
    node = {
        "id": "p1",
        "primitive_type": "idor_hint",
        "engagement_id": "e1",
        "dedup_key": "idor_hint:t",
        "source": "s",
        "target": "t",
        "raw": '{"evidence": [{"r": 1}]}',
        "confidence": 0.6,
        "severity_hint": "high",
        "tags": ["idor"],
        "escalated_from": "",
        "chain_id": "",
        "promoted": False,
        "finding_id": None,
    }
    p = primitive_from_node(node)
    assert p.primitive_type == PrimitiveType.IDOR_HINT
    assert p.raw == {"evidence": [{"r": 1}]}
    assert p.confidence == 0.6
    assert p.promoted_to_finding is False


# --------------------------------------------------------------------------- #
# Orchestrator consume pass (_analyze_chains_once)                             #
# --------------------------------------------------------------------------- #

def _node(ptype, target, evidence=None):
    import json
    raw = {"evidence": evidence} if evidence is not None else {}
    return {
        "id": f"{ptype}:{target}",
        "primitive_type": ptype,
        "engagement_id": "eng-1",
        "dedup_key": f"{ptype}:{target}",
        "source": "vuln:test",
        "target": target,
        "raw": json.dumps(raw),
        "confidence": 0.7,
        "severity_hint": "high",
        "tags": [],
        "escalated_from": "",
        "chain_id": "",
        "promoted": False,
        "finding_id": None,
    }


def _orch(sessions, ledger):
    orch = Orchestrator.__new__(Orchestrator)  # skip heavy __init__
    orch.state = SimpleNamespace(sessions=sessions)
    orch.graph_memory = SimpleNamespace(primitive_ledger=ledger)
    return orch


@pytest.mark.asyncio
async def test_consume_pass_persists_chains_but_does_not_promote_unproven():
    """Co-located primitives without evidence -> chain persisted, but NOT promoted
    (gate withholds EMIT), so nothing becomes report-ready on unproven signal."""
    ledger = MagicMock()
    ledger.query_unpromoted = AsyncMock(return_value=[
        _node("idor_hint", "https://x/api/user"),
        _node("auth_signal", "https://x/api/user"),
    ])
    ledger.upsert_chain = AsyncMock()
    ledger.promote_to_finding = AsyncMock()
    orch = _orch({"eng-1": object()}, ledger)

    out = await orch._analyze_chains_once()

    assert out["chains"] == 1
    assert out["emit"] == 0
    ledger.upsert_chain.assert_awaited_once()
    ledger.promote_to_finding.assert_not_awaited()  # unproven -> not promoted


@pytest.mark.asyncio
async def test_consume_pass_promotes_emit_ready_chain():
    """Co-located primitives WITH captured evidence -> chain EMITs and its primitives
    are promoted so future passes don't re-chain them."""
    ev = [{"request": "GET /api/1", "response": "200"}]
    ledger = MagicMock()
    ledger.query_unpromoted = AsyncMock(return_value=[
        _node("idor_hint", "https://x/api/user", evidence=ev),
        _node("auth_signal", "https://x/api/user", evidence=ev),
    ])
    ledger.upsert_chain = AsyncMock()
    ledger.promote_to_finding = AsyncMock()
    orch = _orch({"eng-1": object()}, ledger)

    out = await orch._analyze_chains_once()

    assert out["chains"] == 1
    assert out["emit"] == 1
    ledger.upsert_chain.assert_awaited_once()
    assert ledger.promote_to_finding.await_count == 2  # both primitives promoted


@pytest.mark.asyncio
async def test_consume_pass_noop_without_ledger():
    orch = _orch({"eng-1": object()}, None)
    assert await orch._analyze_chains_once() == {"chains": 0, "emit": 0}


@pytest.mark.asyncio
async def test_consume_pass_skips_single_primitive_engagements():
    ledger = MagicMock()
    ledger.query_unpromoted = AsyncMock(return_value=[_node("idor_hint", "https://x/api/user")])
    ledger.upsert_chain = AsyncMock()
    orch = _orch({"eng-1": object()}, ledger)
    out = await orch._analyze_chains_once()
    assert out == {"chains": 0, "emit": 0}
    ledger.upsert_chain.assert_not_awaited()


@pytest.mark.asyncio
async def test_consume_pass_isolates_per_engagement_query_failure():
    """One engagement's query raising must not abort the others."""
    ledger = MagicMock()
    ledger.query_unpromoted = AsyncMock(side_effect=[
        RuntimeError("boom"),
        [_node("idor_hint", "https://x/api/user"), _node("auth_signal", "https://x/api/user")],
    ])
    ledger.upsert_chain = AsyncMock()
    ledger.promote_to_finding = AsyncMock()
    orch = _orch({"eng-bad": object(), "eng-ok": object()}, ledger)

    out = await orch._analyze_chains_once()

    assert out["chains"] == 1  # the good engagement still processed
    assert ledger.query_unpromoted.await_count == 2
