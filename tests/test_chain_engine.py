"""Attack-chain correlation (charter 14): findings -> explainable chains."""
from types import SimpleNamespace

import pytest
from unittest.mock import AsyncMock, MagicMock

from ai_osop.core import chain_engine as che
from ai_osop.core import confidence_engine as ce
from ai_osop.core.models import Severity, Vulnerability, VulnClass


def _v(title, fclass, url="https://t.example", state=ce.UNTESTED,
       conf=0.7, sev=Severity.MEDIUM):
    v = Vulnerability(title=title, description=title,
                      vuln_type=VulnClass.UNKNOWN, severity=sev,
                      tool_source="nuclei", engagement_id="eng-chain",
                      confidence=conf, evidence=[])
    v.yield_metadata = {"finding_class": fclass, "url": url}
    v.validation_state = state
    return v


def test_role_classification():
    assert che.classify_chain_role(_v("SQL Injection", "vulnerability")) == "injection"
    assert che.classify_chain_role(
        _v("Broken Access Control IDOR", "vulnerability")) == "authz_bypass"
    assert che.classify_chain_role(
        _v("Source map disclosed", "weakness")) == "info_disclosure"
    # observations and rejected findings are never eligible
    assert che.classify_chain_role(_v("AWS detected", "observation")) is None
    rej = _v("SQL Injection", "vulnerability")
    rej.validation_state = ce.REJECTED
    assert che.classify_chain_role(rej) is None


def test_recon_guided_injection_chain_forms():
    fs = [
        _v("Directory listing exposed", "weakness"),
        _v("SQL Injection on login", "vulnerability", conf=0.8),
    ]
    chains, stats = che.correlate_chains(fs)
    assert stats["chains"] == 1
    c = chains[0]
    assert c.name == "recon_guided_injection"
    assert {s["role"] for s in c.steps} == {"info_disclosure", "injection"}
    assert c.confidence == pytest.approx(0.8 * 0.75, abs=0.35)  # min-member driven
    assert [m for m in c.member_ids] != []


def test_cross_surface_never_correlates():
    fs = [
        _v("Directory listing exposed", "weakness", url="https://a.example"),
        _v("SQL Injection on login", "vulnerability", url="https://b.example"),
    ]
    chains, stats = che.correlate_chains(fs)
    assert chains == [] and stats["chains"] == 0


def test_rejected_members_excluded():
    inj = _v("SQL Injection", "vulnerability")
    inj.validation_state = ce.REJECTED
    fs = [_v("Directory listing exposed", "weakness"), inj]
    chains, stats = che.correlate_chains(fs)
    assert chains == []
    assert stats["rejected_excluded"] == 1


def test_validated_chain_escalates_severity():
    info = _v("Source map disclosed", "weakness", sev=Severity.LOW)
    sqli = _v("SQL Injection", "vulnerability", sev=Severity.HIGH)
    sqli.validation_state = ce.VALIDATED
    info.validation_state = ce.VALIDATED  # escalation requires ALL steps validated
    sqli.yield_metadata["confidence_scores"] = {"confidence": 0.95}
    info.yield_metadata["confidence_scores"] = {"confidence": 0.9}
    chains, _ = che.correlate_chains([info, sqli])
    assert chains[0].severity == "critical"  # high escalated, all validated
    assert chains[0].validated_steps == 2


def test_identity_object_access_rule():
    fs = [
        _v("IDOR on /api/order", "vulnerability"),
        _v("Server information disclosure", "weakness"),
    ]
    chains, _ = che.correlate_chains(fs)
    assert chains and chains[0].name == "identity_object_access"


@pytest.mark.asyncio
async def test_persist_chains_maps_onto_attack_path_api():
    from ai_osop.core.chain_engine import persist_chains

    fs = [
        _v("Directory listing exposed", "weakness"),
        _v("SQL Injection on login", "vulnerability", conf=0.8),
    ]
    chains, _ = che.correlate_chains(fs)
    gm = MagicMock()
    gm.add_attack_path = AsyncMock(return_value="path-x")
    ids = await persist_chains(gm, chains, "eng-chain")
    # engine preserves the chain's own stable id across persistence
    assert ids == [chains[0].id]
    kwargs = gm.add_attack_path.await_args.args[0]
    assert set(kwargs.node_ids) == {m.id for m in fs}
    assert kwargs.engagement_id == "eng-chain"
    assert 0 <= kwargs.risk_score <= 10
    assert kwargs.validation_state == ce.UNTESTED

    # best-effort: a failing store must not raise
    gm2 = MagicMock()
    gm2.add_attack_path = AsyncMock(side_effect=RuntimeError("neo4j down"))
    ids2 = await persist_chains(gm2, chains, "eng-chain")
    assert ids2 == []
