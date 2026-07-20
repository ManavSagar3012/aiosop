"""Bounty report generator.

Turns persisted, validated findings for an engagement into a submittable
HackerOne-grade markdown report: severity-ranked summary table plus a per-finding
section with CWE/OWASP, evidence, and concrete reproduction steps derived from the
oracle evidence. Reads findings straight from graph_memory — the same records the
deterministic scan persisted — so the report reflects verified reality, not an LLM
summary.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from ai_osop.core.finding_view import to_finding_view

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _evidence_list(f: Dict[str, Any]) -> List[Dict[str, Any]]:
    ev = f.get("evidence")
    if isinstance(ev, str):  # Neo4j stores nested evidence as a JSON string
        try:
            ev = json.loads(ev)
        except Exception:
            ev = [{"raw": ev}]
    if isinstance(ev, dict):
        ev = [ev]
    return ev or []


def _repro(f: Dict[str, Any], ev0: Dict[str, Any], view: Dict[str, Any]) -> List[str]:
    tech = str(ev0.get("technique") or ev0.get("type") or "")
    ep = view.get("url") or "the affected endpoint"
    payload = ev0.get("payload")
    vt = (f.get("vuln_type") or "").lower()
    if "auth_bypass" in tech:
        return [
            f'Send `POST {ep}` with body `{{"email": "{payload}", "password": "anything"}}`.',
            "Observe the server issues a valid session token despite invalid credentials — a SQL-injection authentication bypass.",
        ]
    if "error_based" in tech:
        param = view.get("param")
        return [
            f"Send `{view.get('method') or 'GET'} {ep}` with the vulnerable parameter"
            + (f" `{param}`" if param else "")
            + f" set to `{payload}`.",
            "Observe a 5xx response carrying a raw SQL/DB parse error, confirming unsanitized input reaches the query.",
        ]
    if "jwt" in vt:
        return [
            "Obtain a valid JWT for any account.",
            f"Forge a token using the `{ev0.get('technique', 'signature/kid')}` weakness and send it to `{ep}`.",
            "Observe the forged identity is accepted — authentication bypass via broken token verification.",
        ]
    if "mass_assignment" in vt:
        return [
            f"Send the create/update request to `{ep}` including privileged field(s) "
            f"{ev0.get('accepted_fields') or ev0.get('injected')}.",
            "Read the object back and observe the privileged value was persisted — privilege escalation.",
        ]
    if "idor" in vt or "broken_access" in vt:
        return [
            f"As a low-privileged user, request `{ep}` referencing another user's object id.",
            "Observe you receive data you are not authorized to access.",
        ]
    steps = [f"Target `{ep}`" + (f" with payload `{payload}`." if payload else ".")]
    if ev0.get("proof"):
        steps.append(str(ev0["proof"]))
    return steps


def _render_finding(i: int, f: Dict[str, Any]) -> str:
    ev = _evidence_list(f)
    ev0 = ev[0] if ev else {}
    view = to_finding_view(f)
    sev = (f.get("severity") or "unknown").upper()
    lines = [f"### {i}. [{sev}] {f.get('title', 'Untitled finding')}", ""]
    meta = []
    if f.get("cwe"):
        meta.append(f"**CWE:** {f['cwe']}")
    if ev0.get("owasp"):
        meta.append(f"**OWASP:** {ev0['owasp']}")
    ep = view.get("url")
    if ep:
        meta.append(f"**Endpoint:** `{ep}`" + (f" ({view['method']} · {view['param']})" if view.get("param") else f" ({view['method']})"))
    if f.get("confidence") is not None:
        meta.append(f"**Confidence:** {f['confidence']}" + (" (validated)" if f.get("validated") else ""))
    if meta:
        lines += [" · ".join(meta), ""]
    if f.get("description"):
        lines += [str(f["description"]), ""]
    lines.append("**Proof of concept / evidence:**")
    shown = False
    for k in ("payload", "proof", "db_error_excerpt", "technique", "token_prefix", "accepted_fields", "http_status"):
        if ev0.get(k):
            lines.append(f"- {k.replace('_', ' ')}: `{ev0[k]}`")
            shown = True
    if not shown:
        lines.append("- (oracle-validated; see engagement graph for raw request/response)")
    lines.append("")
    lines.append("**Reproduction:**")
    lines += [f"{n}. {s}" for n, s in enumerate(_repro(f, ev0, view), 1)]
    lines.append("")
    return "\n".join(lines)


async def generate_bounty_report(engagement_id: str, graph_memory: Any, target: str = "") -> str:
    """Render a markdown bounty report from an engagement's validated findings."""
    findings = await graph_memory.get_vulnerabilities_by_engagement(engagement_id)
    findings = [f for f in (findings or []) if f.get("validated")]
    findings.sort(key=lambda f: _SEV_ORDER.get((f.get("severity") or "").lower(), 9))

    counts: Dict[str, int] = {}
    for f in findings:
        s = (f.get("severity") or "?").lower()
        counts[s] = counts.get(s, 0) + 1

    out = [
        f"# Security Assessment Report — {target or engagement_id}",
        "",
        f"Engagement: `{engagement_id}`  ",
        f"Validated findings: **{len(findings)}**  ",
        "Severity breakdown: "
        + (", ".join(f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda x: _SEV_ORDER.get(x[0], 9))) or "none"),
        "",
        "| # | Severity | Type | CWE | Title |",
        "|---|----------|------|-----|-------|",
    ]
    for i, f in enumerate(findings, 1):
        out.append(
            f"| {i} | {(f.get('severity') or '').upper()} | {f.get('vuln_type', '')} | "
            f"{f.get('cwe', '')} | {f.get('title', '')} |"
        )
    out += ["", "---", ""]
    for i, f in enumerate(findings, 1):
        out.append(_render_finding(i, f))
    return "\n".join(out)
