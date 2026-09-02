"""Engagement Report Renderer (charter section 21/18).

Consumes build_report_sections() + persisted AttackChains and emits the
truth-telling structure the operator mandated:

    EXECUTIVE SUMMARY (headline = CONFIRMED vulnerabilities ONLY)
    Confirmed vulnerabilities
    Security weaknesses
    Candidate vulnerabilities (awaiting validation)
    Informational observations
    Rejected observations (fixed / false positives, WITH reasons)
    Attack chains

Markdown-first; deterministic ordering (severity desc within each section).
"""

import datetime
from typing import Any, Dict, List

from ai_osop.core.finding_intelligence import (
    _sev_rank,
)

_SECTIONS_MD = {
    "confirmed_vulnerabilities": "## Confirmed Vulnerabilities",
    "security_weaknesses": "## Security Weaknesses",
    "candidate_vulnerabilities": "## Candidate Vulnerabilities (awaiting validation)",
    "informational": "## Informational Observations",
    "rejected": "## Rejected Observations",
}


def _finding_line(v) -> str:
    sev = str(v.severity.value if hasattr(v.severity, "value") else v.severity).upper()
    meta = v.yield_metadata or {}
    conf = meta.get("confidence_scores", {}).get("confidence", getattr(v, "confidence", 0.5))
    ev_n = len(v.evidence or [])
    obs = meta.get("observation_count")
    obs_note = f" · {obs} merged observations" if obs and obs > 1 else ""
    return (
        f"- **[{sev}]** {v.title} — confidence {conf:.2f}, "
        f"evidence artifacts {ev_n}{obs_note}, id `{v.id}`"
    )


def render_engagement_report(
    findings, chains=None, engagement_id: str = "", fmt: str = "markdown"
) -> str:
    from ai_osop.core.finding_intelligence import build_report_sections

    built = build_report_sections(findings)
    sections = built["sections"]
    counts = built["counts"]
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines: List[str] = [
        f"# Security Assessment Report — {engagement_id}",
        f"_Generated {now}_",
        "",
        "## Executive Summary",
        "",
        f"- **Confirmed vulnerabilities: {counts['headline_vulnerability_count']}**"
        " ← headline number",
        f"- Security weaknesses: {counts['security_weaknesses']}",
        f"- Candidates awaiting validation: {counts['candidate_vulnerabilities']}",
        f"- Informational observations: {counts['informational']}",
        f"- Rejected (false positives / fixed): {counts['rejected']}",
        f"- Attack chains correlated: {len(chains or [])}",
        "",
    ]

    order = [
        "confirmed_vulnerabilities",
        "security_weaknesses",
        "candidate_vulnerabilities",
        "informational",
        "rejected",
    ]
    for key in order:
        items = sorted(sections[key], key=_sev_rank, reverse=True)
        lines += [_SECTIONS_MD[key], ""]
        if not items:
            lines += ["_None._", ""]
            continue
        for v in items:
            lines.append(_finding_line(v))
            if key == "rejected":
                expl = (v.yield_metadata or {}).get("validation", {}).get("explanation", "")
                if expl:
                    lines.append(f"  - rejection reason: {expl}")
        lines.append("")

    chains = chains or []
    lines += ["## Attack Chains", ""]
    if not chains:
        lines += ["_No multi-step attack paths correlated._", ""]
    for c in chains:
        lines.append(
            f"- **[{str(c.severity).upper()}]** {c.title} (`{c.id}`) — "
            f"confidence {c.confidence:.2f}, surface `{c.surface}`, "
            f"{c.validated_steps}/{len(c.steps)} steps validated"
        )
        for s in c.steps:
            mark = "x" if s.get("validated") else " "
            lines.append(
                f"  - [{mark}] step {s['order']} ({s['role']}): "
                f"{s['title']} (`{s['finding_id']}`)"
            )
        lines.append(f"  - impact: {c.impact}")
    lines.append("")

    return "\n".join(lines)
