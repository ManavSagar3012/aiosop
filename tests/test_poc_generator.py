"""Auto-PoC generator tests (Sprint 2.6 / roadmap Phase 1.4).

Proves the "5-minute reproducibility" lever: a confirmed finding yields a copy-pasteable,
shell-safe, runnable PoC built deterministically from its captured evidence — and an
honest MANUAL fallback (never a fabricated command) when the evidence is insufficient.
Hermetic — no network, nothing is executed.
"""

import shlex

import pytest

from ai_osop.core.bounty_report import render_bounty_report
from ai_osop.core.models import Vulnerability
from ai_osop.core.poc_generator import PoCArtifact, generate_poc, render_poc_markdown


def _v(vuln_type, evidence, **kw):
    return Vulnerability(
        vuln_type=vuln_type,
        severity=kw.pop("severity", "high"),
        title=f"{vuln_type} finding",
        description="desc",
        engagement_id="e1",
        confidence=kw.pop("confidence", 0.9),
        tool_source="test",
        evidence=[evidence],
        **kw,
    )


# --------------------------------------------------------------------------- #
# Runnable builders per class                                                  #
# --------------------------------------------------------------------------- #


def test_sqli_poc_is_runnable_and_shell_safe():
    """A payload full of quotes/spaces must survive shlex quoting intact."""
    payload = "' OR '1'='1' -- -"
    v = _v(
        "sqli",
        {"url": "https://x/search", "parameter": "q", "payloads": [payload], "method": "GET"},
    )
    art = generate_poc(v)
    assert art.kind == "curl" and art.reproducible
    cmd = art.commands[0]
    # The rendered command must parse back to argv, and the payload round-trips exactly.
    argv = shlex.split(cmd)
    assert argv[0] == "curl"
    assert f"q={payload}" in argv  # exact payload preserved through --data-urlencode


def test_ssrf_poc_has_collaborator_placeholder():
    v = _v("ssrf", {"url": "https://x/fetch", "injection": "target"})
    art = generate_poc(v)
    assert art.reproducible
    assert "COLLABORATOR_URL" in art.commands[0]
    assert any("Collaborator" in n or "OAST" in n for n in art.notes)


def test_mass_assignment_poc_sends_privileged_field():
    v = _v(
        "mass_assignment",
        {"url": "https://x/api/users", "accepted_fields": {"role": "admin"}, "method": "PUT"},
    )
    art = generate_poc(v)
    argv = shlex.split(art.commands[0])
    assert "PUT" in argv
    assert '{"role": "admin"}' in argv


def test_access_control_poc_uses_auth_header():
    v = _v("jwt_abuse", {"url": "https://x/admin", "technique": "alg_none"})
    art = generate_poc(v)
    argv = shlex.split(art.commands[0])
    assert "Authorization: Bearer <FORGED_JWT>" in argv
    assert any("alg_none" in n for n in art.notes)


def test_race_condition_poc_is_concurrent():
    v = _v("race_condition", {"url": "https://x/redeem", "concurrency": 25, "method": "POST"})
    art = generate_poc(v)
    assert art.kind == "shell" and art.reproducible
    assert "seq 25" in art.commands[0] and "-P 25" in art.commands[0]


def test_csrf_poc_is_autosubmitting_html():
    v = _v("csrf", {"url": "https://x/transfer", "method": "POST"})
    art = generate_poc(v)
    assert art.kind == "html"
    assert "<form" in art.commands[0] and "submit()" in art.commands[0]


def test_subdomain_takeover_poc_resolves_host():
    v = _v(
        "subdomain_takeover",
        {"host": "dangling.x.com", "service": "S3", "signature": "NoSuchBucket"},
    )
    art = generate_poc(v)
    assert art.kind == "shell"
    assert "dig" in art.commands[0] and "dangling.x.com" in art.commands[0]


# --------------------------------------------------------------------------- #
# Honest fallback — never fabricate                                            #
# --------------------------------------------------------------------------- #


def test_unmapped_class_falls_back_to_manual():
    """A class with no builder must return a non-reproducible MANUAL artifact."""
    v = _v("graphql", {"url": "https://x/hidden"})
    art = generate_poc(v)
    assert art.kind == "manual"
    assert art.reproducible is False
    assert art.commands == []


def test_missing_evidence_falls_back_to_manual():
    """A mapped class but empty evidence (no url) cannot build a command -> manual."""
    v = _v("sqli", {})  # no url/parameter
    art = generate_poc(v)
    assert art.kind == "manual" and art.reproducible is False


def test_generate_poc_never_raises_on_empty_evidence():
    v = Vulnerability(
        vuln_type="ssrf",
        severity="high",
        title="t",
        description="d",
        engagement_id="e1",
        confidence=0.5,
        tool_source="test",
        evidence=[],
    )
    art = generate_poc(v)
    assert isinstance(art, PoCArtifact)
    assert art.kind == "manual"


# --------------------------------------------------------------------------- #
# Markdown rendering + report integration                                      #
# --------------------------------------------------------------------------- #


def test_render_markdown_fenced_block_for_runnable():
    v = _v("sqli", {"url": "https://x/s", "parameter": "q", "payloads": ["1"]})
    md = render_poc_markdown(v)
    assert "```bash" in md and "curl" in md


def test_render_markdown_blockquote_for_manual():
    v = _v("graphql", {"url": "https://x/hidden"})
    md = render_poc_markdown(v)
    assert md.strip().startswith(">")
    assert "```" not in md


def test_report_embeds_proof_of_concept_section():
    v = _v("sqli", {"url": "https://x/search", "parameter": "q", "payloads": ["' OR 1=1-- -"]})
    report = render_bounty_report(v, program="acme")
    assert "## Proof of Concept" in report
    assert "curl" in report
    # Section ordering: PoC sits between Steps to Reproduce and Impact.
    assert (
        report.index("## Steps to Reproduce")
        < report.index("## Proof of Concept")
        < report.index("## Impact")
    )
