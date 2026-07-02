"""Chain analysis — feed (vuln->primitive) + consume (escalate/compose) tests.

Proves the glue that turns the disconnected primitive/escalation/chain modules into a
working loop: a confirmed Vulnerability maps to the right escalatable primitive type,
and a set of co-located primitives composes a proof-carrying chain while a lone signal
still yields an escalation ("never stop at a signal"). Hermetic — no DB, no network.
"""
import pytest

from ai_osop.core.chain_analysis import analyze_primitives, vuln_to_primitive
from ai_osop.core.models import PrimitiveLedger, PrimitiveType, Vulnerability


def _vuln(vuln_type, **kw):
    return Vulnerability(
        vuln_type=vuln_type,
        severity=kw.pop("severity", "high"),
        title=kw.pop("title", f"{vuln_type} finding"),
        description=kw.pop("description", "desc"),
        engagement_id=kw.pop("engagement_id", "e1"),
        confidence=kw.pop("confidence", 0.8),
        tool_source=kw.pop("tool_source", "test"),
        **kw,
    )


def _prim(ptype, target, sev="high"):
    return PrimitiveLedger(
        primitive_type=ptype, engagement_id="e1", source="vuln:test",
        dedup_key=f"{ptype.value}:{target}", target=target, severity_hint=sev, confidence=0.7,
    )


@pytest.mark.parametrize("vuln_type,expected", [
    ("idor", PrimitiveType.IDOR_HINT),
    ("bola", PrimitiveType.IDOR_HINT),
    ("mass_assignment", PrimitiveType.IDOR_HINT),
    ("ssrf", PrimitiveType.SSRF_HINT),
    ("exposed_secret", PrimitiveType.JS_SECRET),
    ("jwt_abuse", PrimitiveType.AUTH_SIGNAL),
    ("subdomain_takeover", PrimitiveType.DNS_RECORD),
    ("sqli", PrimitiveType.GENERIC),   # no bespoke escalation -> generic, still recorded
])
def test_vuln_maps_to_expected_primitive_type(vuln_type, expected):
    p = vuln_to_primitive(_vuln(vuln_type, endpoint_id="https://x/api"))
    assert p.primitive_type == expected
    assert p.promoted_to_finding is True      # it already IS a confirmed finding
    assert p.finding_id  # linked back to the vuln
    assert p.dedup_key == f"{vuln_type}:https://x/api"


def test_two_colocated_primitives_compose_a_chain():
    prims = [
        _prim(PrimitiveType.IDOR_HINT, "https://x/api/user", "high"),
        _prim(PrimitiveType.AUTH_SIGNAL, "https://x/api/user", "critical"),
    ]
    out = analyze_primitives(prims)
    assert len(out["chains"]) == 1
    chain = out["chains"][0]
    assert chain.severity == "critical"           # max severity across the chain
    assert chain.poc_script                        # a PoC was generated
    assert getattr(chain.status, "value", chain.status) == "pending_poc"  # not fabricated; awaits triage gate
    # escalation suggested the right next steps
    techniques = {e.suggested_technique for e in out["escalations"]}
    assert "idor_cross_account_verify" in techniques
    assert "differential_auth_verify" in techniques


def test_single_primitive_is_a_lead_not_a_chain():
    out = analyze_primitives([_prim(PrimitiveType.IDOR_HINT, "https://x/api/user")])
    assert out["chains"] == []          # one signal is a lead, not a chain
    assert len(out["escalations"]) >= 1  # but we never stop at a signal


def test_primitives_on_different_targets_do_not_chain():
    prims = [
        _prim(PrimitiveType.IDOR_HINT, "https://x/api/a"),
        _prim(PrimitiveType.SSRF_HINT, "https://x/api/b"),
    ]
    out = analyze_primitives(prims)
    assert out["chains"] == []          # not co-located -> no chain
    assert len(out["escalations"]) >= 2


def test_empty_input_is_safe():
    out = analyze_primitives([])
    assert out == {"chains": [], "escalations": []}
