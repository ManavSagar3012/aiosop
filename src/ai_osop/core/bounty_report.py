"""Triager-grade bug-bounty report rendering + duplicate signatures.

The platform now CONFIRMS findings; this is the last mile to income — turning a
validated Vulnerability into a report a triager can reproduce in seconds and a
signature that flags likely duplicates before submission (duplicates are the #1
reason good bugs pay $0).
"""

import hashlib
import json
from typing import Any, Dict, List
from urllib.parse import urlparse

from ai_osop.core.models import Vulnerability
from ai_osop.core.poc_generator import render_poc_markdown

# Per-class impact + remediation guidance (CWE-anchored). Generic fallback below.
_IMPACT = {
    "ssrf": "An attacker can make the server issue requests to internal services and "
    "cloud metadata endpoints, potentially exfiltrating credentials and pivoting.",
    "sqli": "An attacker can read or modify arbitrary database contents, leading to full "
    "data compromise and potential authentication bypass.",
    "xss": "An attacker can execute script in victims' browsers, enabling session theft, "
    "account takeover, and actions performed as the victim.",
    "jwt_abuse": "An attacker can forge tokens to impersonate any user, including admins, "
    "resulting in full authentication bypass.",
    "broken_access_control": "An attacker can take over other users' accounts or access "
    "resources beyond their privilege level.",
    "mass_assignment": "An attacker can set protected attributes (e.g. role=admin), "
    "escalating privileges.",
    "csrf": "An attacker can force authenticated victims to perform state-changing "
    "actions without consent.",
    "subdomain_takeover": "An attacker can serve arbitrary content under the victim's "
    "domain, enabling phishing, cookie theft, and OAuth abuse.",
    "exposed_secret": "The exposed credential is live and grants real access to the "
    "associated service.",
    "race_condition": "An attacker can bypass once-only limits (double-spend, coupon "
    "reuse), causing direct financial loss.",
}
_REMEDIATION = {
    "ssrf": "Validate and allow-list outbound URLs; block link-local/metadata ranges; "
    "disable unused URL schemes; require egress filtering.",
    "sqli": "Use parameterized queries / prepared statements; never concatenate input.",
    "xss": "Context-aware output encoding; a strict CSP; avoid innerHTML with untrusted data.",
    "jwt_abuse": "Pin the verification algorithm; reject 'none'; rotate to strong keys; "
    "validate kid against a fixed key set.",
    "broken_access_control": "Enforce server-side authorization on every object/action.",
    "mass_assignment": "Allow-list bindable fields; never bind privileged attributes from input.",
    "csrf": "Require anti-CSRF tokens and SameSite cookies on state-changing requests.",
    "subdomain_takeover": "Remove dangling DNS records pointing at unclaimed services.",
    "exposed_secret": "Revoke and rotate the credential immediately; remove it from "
    "client-side code; use a secrets manager.",
    "race_condition": "Use atomic operations / row locks / idempotency keys on once-only actions.",
}
_CVSS = {  # rough representative vectors for the report header
    "critical": "9.8 (Critical)",
    "high": "8.1 (High)",
    "medium": "5.4 (Medium)",
    "low": "3.1 (Low)",
    "info": "0.0 (Informational)",
}


def _vt(vuln: Vulnerability) -> str:
    vt = vuln.vuln_type
    return vt.value if hasattr(vt, "value") else str(vt)


def _sev(vuln: Vulnerability) -> str:
    s = vuln.severity
    return (s.value if hasattr(s, "value") else str(s)).lower()


def _primary_endpoint(ev: Dict[str, Any]) -> str:
    return (
        ev.get("url")
        or ev.get("verify_url")
        or ev.get("store_url")
        or ev.get("host")
        or ev.get("render_url")
        or ""
    )


def finding_signature(vuln: Vulnerability) -> str:
    """Stable dedup signature: vuln class + normalized endpoint path + injection point.
    Identical bugs at the same location collapse to the same signature."""
    ev = (vuln.evidence or [{}])[0]
    endpoint = _primary_endpoint(ev)
    parsed = urlparse(endpoint) if "://" in endpoint else urlparse("//" + endpoint)
    path = (parsed.netloc + parsed.path).rstrip("/").lower()
    inj = str(
        ev.get("injection")
        or ev.get("parameter")
        or ev.get("store_field")
        or ev.get("provider")
        or ev.get("service")
        or ""
    )
    raw = f"{_vt(vuln)}|{path}|{inj.lower()}"
    return "OSOP-" + hashlib.sha1(raw.encode()).hexdigest()[:12]


def _repro_steps(vuln: Vulnerability) -> List[str]:
    vt = _vt(vuln)
    ev = (vuln.evidence or [{}])[0]
    ep = _primary_endpoint(ev)
    if vt == "ssrf":
        it = ev.get("interaction", {})
        return [
            f"Send a request to `{ep}` with the `{ev.get('injection')}` field set to an "
            f"attacker-controlled URL (an OAST/Collaborator callback).",
            f"Observe an out-of-band callback at the collaborator "
            f"(`{it.get('method','GET')} {it.get('path','')}`), proving the server fetched it.",
        ]
    if vt == "sqli":
        payloads = ev.get("payloads") or []
        pl = payloads[0] if payloads else "<sqlmap payload>"
        return [
            f"Target parameter `{ev.get('parameter')}` at `{ep}`.",
            f"Inject the payload: `{pl}`.",
            f"sqlmap confirms injection (DBMS: {ev.get('dbms','unknown')}).",
        ]
    if vt == "xss":
        return [
            f"Submit the payload into `{ev.get('store_field') or ev.get('parameter') or 'the field'}` "
            f"at `{ev.get('store_url') or ep}`.",
            f"Load `{ev.get('render_url') or ep}` — the injected script executes "
            f"(method: {ev.get('method','execution')}).",
        ]
    if vt == "jwt_abuse" or vt == "broken_access_control":
        return [
            f"Take a valid JWT and apply the `{ev.get('technique','forgery')}` technique.",
            f"Replay against `{ep}` — the server accepts the forged identity "
            f"(`{ev.get('victim') or ev.get('sentinel','forged user')}`).",
        ]
    if vt == "mass_assignment":
        return [
            f"Send the create/update request to `{ep}` adding the privileged field(s) "
            f"{ev.get('accepted_fields')}.",
            "Confirm the privileged value is persisted/reflected.",
        ]
    if vt == "subdomain_takeover":
        return [
            f"Resolve `{ev.get('host')}` — it points at an unclaimed {ev.get('service')} resource "
            f"(signature: '{ev.get('signature')}').",
            f"Claim the resource on {ev.get('service')} to serve content under the domain.",
        ]
    if vt == "exposed_secret":
        return [
            f"Extract the {ev.get('provider')} secret ({ev.get('secret_redacted')}).",
            f"Call the provider's read-only identity endpoint — it authenticates "
            f"(HTTP {ev.get('verify_status')}), proving the credential is live.",
        ]
    if vt == "race_condition":
        return [
            f"Send {ev.get('concurrency')} synchronized single-packet requests to `{ep}`.",
            f"Observe {ev.get('success_count')} successes on a once-only action "
            f"(limit {ev.get('expected_max')}) - double-spend confirmed.",
        ]
    return [f"Reproduce the confirmed condition at `{ep}` using the evidence below."]


def render_bounty_report(vuln: Vulnerability, program: str = "") -> str:
    """Render a submission-ready Markdown report for a single validated finding."""
    vt = _vt(vuln)
    sev = _sev(vuln)
    ev = (vuln.evidence or [{}])[0]
    sig = finding_signature(vuln)
    impact = _IMPACT.get(vt, "Demonstrated security impact on the target application.")
    remediation = _REMEDIATION.get(vt, "Apply input validation and least-privilege controls.")
    steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(_repro_steps(vuln)))
    poc = render_poc_markdown(vuln)
    evidence_json = json.dumps(ev, indent=2, default=str)

    header = f"# {vuln.title}\n\n"
    if program:
        header += f"**Program:** {program}  \n"
    header += (
        f"**Severity:** {vuln.severity if not hasattr(vuln.severity,'value') else vuln.severity.value} "
        f"(CVSS ~{_CVSS.get(sev,'N/A')})  \n"
        f"**Weakness:** {vuln.cwe or 'N/A'}  \n"
        f"**Dedup signature:** `{sig}`  \n"
        f"**Status:** {'Validated (active confirmation)' if vuln.validated else 'Unconfirmed'}\n\n"
    )
    body = (
        f"## Summary\n{vuln.description}\n\n"
        f"## Steps to Reproduce\n{steps}\n\n"
        f"## Proof of Concept\n{poc}\n"
        f"## Impact\n{impact}\n\n"
        f"## Evidence\n```json\n{evidence_json}\n```\n\n"
        f"## Remediation\n{remediation}\n"
    )
    return header + body
