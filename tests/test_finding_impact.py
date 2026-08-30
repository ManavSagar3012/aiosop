"""Impact scoring: deterministic, auditable, per-finding (charter 13)."""
from types import SimpleNamespace

import pytest

from ai_osop.core.finding_impact import (
    FindingImpact, quantify_finding, quantify_batch, top_impact)


def _v(**kw):
    d = dict(title="Test", id="v-1", vuln_type="sqli", severity="high",
             entry_point=False, requires_auth=True, exploitability="unknown",
             validated=False, correlated_ids=[], confidence=0.7,
             yield_metadata={"finding_class": "vulnerability"})
    d.update(kw)
    return SimpleNamespace(**d)


def test_unauth_reachable_scores_higher():
    authed = quantify_finding(_v(requires_auth=True))
    unauth = quantify_finding(_v(requires_auth=False))
    assert unauth.score > authed.score
    assert "without authentication" in unauth.narrative


def test_validated_boosts():
    v = _v(validated=True)
    s = quantify_finding(v)
    assert "VALIDATED" in s.narrative
    assert s.score > quantify_finding(_v(validated=False)).score


def test_chain_correlation_adds():
    solo = quantify_finding(_v(correlated_ids=[]))
    chained = quantify_finding(_v(correlated_ids=["v-2", "v-3"]))
    assert chained.score > solo.score
    assert chained.chain_potential == 2


def test_observation_capped():
    obs = _v(yield_metadata={"finding_class": "observation"})
    assert quantify_finding(obs).score <= 2.0


def test_rce_outscores_xss():
    rce = quantify_finding(_v(vuln_type="rce"))
    xss = quantify_finding(_v(vuln_type="xss"))
    assert rce.score > xss.score


def test_batch_and_top():
    fs = [_v(id=f"v-{i}", vuln_type=t) for i, t in
          enumerate(["rce", "xss", "csrf"])]
    batch = quantify_batch(fs)
    assert len(batch) == 3
    top = top_impact(fs, limit=1)
    assert top[0].vuln_type == "rce"


def test_data_access_and_privilege_labels():
    high = quantify_finding(_v(requires_auth=False, validated=True,
                               exploitability="high"))
    assert high.data_access_risk in ("critical", "high")
    assert high.privilege_risk in ("critical", "high")
