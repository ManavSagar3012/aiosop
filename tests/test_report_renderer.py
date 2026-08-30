"""Report renderer: charter 21 truth-telling structure end-to-end."""
from types import SimpleNamespace

from ai_osop.core import confidence_engine as ce
from ai_osop.core.report_renderer import render_engagement_report


def _f(title, fclass, state, sev="medium", conf=0.7, expl=None):
    v = SimpleNamespace(
        title=title, id=f"v-{title[:8]}", severity=SimpleNamespace(value=sev),
        confidence=conf, evidence=[{"x": 1}],
        validation_state=state,
        yield_metadata={"finding_class": fclass,
                        "confidence_scores": {"confidence": conf},
                        "observation_count": 1},
    )
    if expl:
        v.yield_metadata["validation"] = {"explanation": expl}
    return v


def _chain():
    steps = [{"order": 1, "role": "info_disclosure", "title": "Source map",
              "finding_id": "v-sourcemap", "validated": True},
             {"order": 2, "role": "injection", "title": "SQLi login",
              "finding_id": "v-sqli", "validated": True}]
    return SimpleNamespace(id="chain-abc", name="recon_guided_injection",
                           title="Disclosed internals guided injection",
                           surface="t.example", steps=steps, member_ids=[],
                           impact="Unauthorized data access",
                           confidence=0.9, severity="critical",
                           validated_steps=2)


def test_full_structure_and_headline_truth():
    fs = [
        _f("SQLi reproduced", "vulnerability", ce.VALIDATED, sev="high"),
        _f("SSRF guess", "vulnerability", ce.UNTESTED),
        _f("Missing headers", "weakness", ce.APPLICABLE),
        _f("AWS detected", "observation", ce.UNTESTED),
        _f("WAF FP", "observation", ce.REJECTED,
           expl="catch-all host; detector prone to false positives"),
    ]
    md = render_engagement_report(fs, chains=[_chain()],
                                  engagement_id="eng-r")
    assert "**Confirmed vulnerabilities: 1**" in md  # NOT inflated by noise
    for header in ("## Confirmed Vulnerabilities", "## Security Weaknesses",
                   "## Candidate Vulnerabilities", "## Informational Observations",
                   "## Rejected Observations", "## Attack Chains"):
        assert header in md
    assert "**[HIGH]** SQLi reproduced" in md
    assert "rejection reason: catch-all host" in md
    # chain appendix with per-step checkboxes and impact
    assert "[x] step 2 (injection): SQLi login" in md
    assert "impact:" in md
    assert md.index("Confirmed Vulnerabilities") < md.index("Rejected Observations")


def test_empty_engagement_renders_clean():
    md = render_engagement_report([], chains=[], engagement_id="eng-empty")
    assert "**Confirmed vulnerabilities: 0**" in md
    assert "_None._" in md
    assert "_No multi-step attack paths correlated._" in md
