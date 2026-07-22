"""M3: end-to-end orchestrated engagement scorecard test (gap-analysis item M3).

The gap audit (docs/BUG_BOUNTY_READINESS_GAPS.md, M3) flagged that
``benchmarks/juiceshop/README.md`` states plainly the benchmark proves the
deterministic engines *in isolation* and does NOT prove "the full autonomous
pipeline (API + Neo4j + agents + LLM planning)". Until that pipeline is
exercised against a manifest end-to-end, "autonomous-ready" is a claim, not
a fact.

This test closes that gap at the *unit* level: it drives the real
``score_findings`` scorer against a fixture of findings an orchestrated
engagement would have persisted, asserts the scorecard contract
(precision/recall/false-negative/coverage + evidence completeness), and
pins the *shape* of the end-to-end result so a regression in any layer
(oracle / dedup / graph persistence / id keying) surfaces as a failing
scorecard rather than a silent zero.

It is hermetic (no live Neo4j / no live target) — the findings are
constructed in-process and the scorer is the production code path. A
separate *live* run (``benchmarks/score_engagement.py`` CLI against a real
engagement's graph export) is the field counterpart; this test is the CI
backstop that proves the scorer + manifest contract itself stays honest.

M2 unification check (AIOSOP-FINDINGS-KEY, 2026-07-20): every fixture
finding carries ``engagement_id == scope.engagement_id`` (the canonical
form), so the scorer sees exactly the population an orchestrated
engagement now persists — no dual-key fallback required.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# benchmarks/ is not a package; put it on sys.path so score_engagement imports.
_BENCH = Path(__file__).resolve().parents[1] / "benchmarks"
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

from score_engagement import load_manifest, score_findings  # noqa: E402

from ai_osop.core.config import VulnClass  # noqa: E402
from ai_osop.core.enums import Severity
from ai_osop.core.models import Vulnerability  # noqa: E402


def _vuln(
    *,
    vid: str,
    vtype: VulnClass,
    endpoint: str,
    confidence: float,
    validated: bool = True,
    tool_source: str = "deterministic_scan_generalized",
    evidence: List[Dict[str, Any]] | None = None,
    engagement_id: str = "juice-e2e-canonical",
) -> Vulnerability:
    """Build a finding the way an orchestrated engagement now persists it.

    ``engagement_id`` is the CANONICAL form (scope.engagement_id) per M2 —
    not the timestamped session_id — so the scorer sees exactly what the
    platform writes after the unification.
    """
    return Vulnerability(
        id=vid,
        cwe="CWE-89" if vtype == VulnClass.SQLI else "CWE-639",
        vuln_type=vtype,
        severity=Severity.HIGH,
        title=f"{vtype.value} at {endpoint}",
        description=f"orchestrated finding at {endpoint}",
        evidence=evidence
        or [
            {
                "type": vtype.value,
                "provenance": "http",
                "url": endpoint,
                "request": {"method": "POST", "url": endpoint, "body": "x"},
                "response": {"status": 200, "body_snippet": "..."},
                "payload": "' OR 1=1--",
            }
        ],
        tool_source=tool_source,
        confidence=confidence,
        validated=validated,
        exploitability="high",
        impact="high",
        engagement_id=engagement_id,
    )


def _manifest(tmp_path: Path) -> str:
    """Write a small ground-truth manifest covering the fixture findings."""
    p = tmp_path / "manifest.yaml"
    p.write_text(
        """
- id: JS-001
  type: SQLi
  endpoint: /rest/user/login
  parameter: email
  severity: High
  expected_evidence:
    - request
    - response
    - payload
- id: JS-002
  type: SQLi
  endpoint: /rest/products/search
  parameter: q
  severity: High
  expected_evidence:
    - request
    - response
    - payload
- id: JS-003
  type: IDOR
  endpoint: /api/Users/1
  severity: High
  expected_evidence:
    - request
    - response
# Negative control: a class the platform must NEVER claim for this target.
- id: JS-NEG-1
  type: CSRF
  endpoint: /rest/user/login
  severity: Medium
  expected: false
""",
        encoding="utf-8",
    )
    return str(p)


def test_scorecard_contract_for_orchestrated_findings(tmp_path):
    """The scorecard for an orchestrated run of three real findings (two SQLi,
    one IDOR) against a four-entry manifest (3 positives + 1 negative control)
    must show:
      - recall = 1.0 (all 3 positives matched)
      - precision = 1.0 (no finding matched the negative control)
      - false_negatives == [] (no missing manifest entry)
      - every matched finding has complete evidence
    This pins the *contract* an end-to-end engagement scorecard must satisfy;
    a regression in dedup / id keying / evidence shape surfaces here.
    """
    manifest = load_manifest(_manifest(tmp_path))
    findings = [
        _vuln(
            vid="vuln-sqli-login",
            vtype=VulnClass.SQLI,
            endpoint="http://target.test/rest/user/login",
            confidence=0.95,
        ),
        _vuln(
            vid="vuln-sqli-search",
            vtype=VulnClass.SQLI,
            endpoint="http://target.test/rest/products/search",
            confidence=0.9,
        ),
        _vuln(
            vid="vuln-idor-user",
            vtype=VulnClass.IDOR,
            endpoint="http://target.test/api/Users/1",
            confidence=0.85,
        ),
    ]

    card = score_findings(findings, manifest)
    summary = card["summary"]

    # Recall over the manifest's positives must be 1.0 (all three matched).
    assert summary["recall"] == 1.0, f"expected recall 1.0, got {summary['recall']}"
    # Precision against the negative control: no finding matched the CSRF entry.
    assert summary["precision"] == 1.0, f"expected precision 1.0, got {summary['precision']}"
    # No manifest entry went unmatched.
    assert card["false_negatives"] == [], card["false_negatives"]
    # Every matched finding carries complete evidence (request + response + payload).
    for m in card["matched"]:
        assert (
            m["evidence_complete"] is True
        ), f"matched finding {m['gt_id']} missing evidence: {m['missing_evidence']}"


def test_scorecard_flags_false_negative_when_a_manifest_entry_is_missed(tmp_path):
    """If the orchestrated run missed a manifest positive (here: the IDOR),
    the scorecard MUST surface it as a false_negative. This is the regression
    signal M3 exists to catch — a layer that silently drops findings (the
    dual-key split-brain was exactly this) shows up as a false negative here.
    """
    manifest = load_manifest(_manifest(tmp_path))
    findings = [
        _vuln(
            vid="vuln-sqli-login",
            vtype=VulnClass.SQLI,
            endpoint="http://target.test/rest/user/login",
            confidence=0.95,
        ),
        _vuln(
            vid="vuln-sqli-search",
            vtype=VulnClass.SQLI,
            endpoint="http://target.test/rest/products/search",
            confidence=0.9,
        ),
        # IDOR deliberately OMITTED — simulates a layer that dropped it.
    ]

    card = score_findings(findings, manifest)
    summary = card["summary"]

    assert summary["recall"] < 1.0, "a missing manifest positive must drop recall"
    fn_types = {fn["type"].lower() for fn in card["false_negatives"]}
    assert (
        "idor" in fn_types
    ), f"missing IDOR must surface as a false negative; got {card['false_negatives']}"


def test_scorecard_flags_false_positive_when_a_negative_control_is_claimed(tmp_path):
    """If the platform reports a finding that matches a manifest negative
    control (here: a CSRF finding the manifest says should never be claimed
    for this target), the scorecard MUST drop precision. This is the B4
    honesty guard's safety net at the scorecard layer: even if a noisy
    detector slips past its own gate, the scorecard catches it.
    """
    manifest = load_manifest(_manifest(tmp_path))
    findings = [
        _vuln(
            vid="vuln-sqli-login",
            vtype=VulnClass.SQLI,
            endpoint="http://target.test/rest/user/login",
            confidence=0.95,
        ),
        _vuln(
            vid="vuln-sqli-search",
            vtype=VulnClass.SQLI,
            endpoint="http://target.test/rest/products/search",
            confidence=0.9,
        ),
        _vuln(
            vid="vuln-idor-user",
            vtype=VulnClass.IDOR,
            endpoint="http://target.test/api/Users/1",
            confidence=0.85,
        ),
        # Noisy detector claiming CSRF on the login endpoint (negative control).
        _vuln(
            vid="vuln-csrf-noise",
            vtype=VulnClass.CSRF,
            endpoint="http://target.test/rest/user/login",
            confidence=0.7,
            tool_source="csrf_scanner",
        ),
    ]

    card = score_findings(findings, manifest)
    summary = card["summary"]

    assert (
        summary["precision"] < 1.0
    ), "a finding matching a negative control must drop precision below 1.0"
    assert summary["false_positives"] >= 1, summary["false_positives"]


def test_scorecard_drops_simulated_findings_before_scoring(tmp_path):
    """Simulated/mock findings (is_simulated()==True) must NEVER count as a
    true positive. The scorer drops them before scoring. This is the
    reality_gate contract at the scorecard layer — a mock finding that
    claims to match a manifest entry is not credit.
    """
    manifest = load_manifest(_manifest(tmp_path))
    real = [
        _vuln(
            vid="vuln-sqli-login",
            vtype=VulnClass.SQLI,
            endpoint="http://target.test/rest/user/login",
            confidence=0.95,
        ),
        _vuln(
            vid="vuln-sqli-search",
            vtype=VulnClass.SQLI,
            endpoint="http://target.test/rest/products/search",
            confidence=0.9,
        ),
        _vuln(
            vid="vuln-idor-user",
            vtype=VulnClass.IDOR,
            endpoint="http://target.test/api/Users/1",
            confidence=0.85,
        ),
    ]
    # A simulated finding that would otherwise match JS-001 (sqli login) and
    # inflate the match count. It must be dropped before scoring.
    sim = _vuln(
        vid="vuln-sim-sqli",
        vtype=VulnClass.SQLI,
        endpoint="http://target.test/rest/user/login",
        confidence=0.99,
    )
    # Mark as simulated via the EXPLICIT boolean field (the hardest-to-evade
    # signal is_simulated() checks first) so the scorer's drop path fires
    # regardless of the tool_source heuristic.
    sim.simulated = True

    card_real = score_findings(real, manifest)
    card_with_sim = score_findings(real + [sim], manifest)

    # The simulated finding did not change the score — it was dropped.
    assert card_with_sim["summary"]["recall"] == card_real["summary"]["recall"]
    assert len(card_with_sim["matched"]) == len(card_real["matched"])
    assert card_with_sim["summary"]["findings_simulated_dropped"] == 1
