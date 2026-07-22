"""Triager-grade bug-bounty report rendering + duplicate signatures.

The platform now CONFIRMS findings; this is the last mile to income — turning a
validated Vulnerability into a report a triager can reproduce in seconds and a
signature that flags likely duplicates before submission (duplicates are the #1
reason good bugs pay $0).
"""

import hashlib
import json
from typing import Any, Dict, List, Union
from urllib.parse import urlparse

from ai_osop.core.finding_view import FindingView, to_finding_view
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
    "dom_xss": "An attacker can execute arbitrary JavaScript in a victim's browser "
    "by sending a link with a crafted URL parameter or fragment. No server-side "
    "reflection is needed — the payload runs purely in client-side code.",
    "ssti": "An attacker can execute arbitrary code on the server by injecting "
    "template directives, leading to full server compromise, data exfiltration, or "
    "lateral movement.",
    "xxe": "An attacker can read arbitrary files on the server, perform SSRF to "
    "internal services, or trigger denial of service via XML entity expansion.",
    "command_injection": "An attacker can execute arbitrary operating system commands "
    "on the server, leading to full server compromise and data exfiltration.",
    "open_redirect": "An attacker can redirect victims to phishing pages that appear "
    "to be part of the legitimate application, enabling credential theft and malware "
    "distribution.",
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
    "dom_xss": "Avoid writing untrusted data to DOM sinks (innerHTML, document.write, eval). "
    "Use textContent, safe framework APIs, and a strict CSP with nonce-based script hashes.",
    "ssti": "Use sandboxed template engines that disable arbitrary code execution; never "
    "allow users to control template content; apply contextual output encoding.",
    "xxe": "Disable external entity resolution in XML parsers; use less complex data "
    "formats (JSON); apply input validation on XML content type endpoints.",
    "command_injection": "Use parameterized APIs instead of shell execution; validate and "
    "sanitize all input against an allow-list; apply strict input length limits.",
    "open_redirect": "Validate redirect URLs against an allow-list of approved domains; "
    "use relative redirects when possible; require cryptographic signatures on redirect targets.",
}
_CVSS = {  # rough representative vectors for the report header
    "critical": "9.8 (Critical)",
    "high": "8.1 (High)",
    "medium": "5.4 (Medium)",
    "low": "3.1 (Low)",
    "info": "0.0 (Informational)",
}

# MIN-2: Placeholder returned when a simulated finding reaches the report layer.
_SIMULATED_PLACEHOLDER = (
    "# [SIMULATED FINDING — NOT SUBMITTED]\n\n"
    "This finding was generated by a simulated/mock detector and has been "
    "suppressed by the report layer's defense-in-depth guard. It will never "
    "be submitted to a real program.\n"
)


def _as_dict(vuln: Union[Vulnerability, Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize a Vulnerability model or a raw graph dict into a plain dict."""
    if isinstance(vuln, Vulnerability):
        return vuln.model_dump()
    if hasattr(vuln, "model_dump"):
        return vuln.model_dump()
    return dict(vuln)


def _vt(view: FindingView) -> str:
    vt = view.get("category")
    return vt.value if hasattr(vt, "value") else str(vt)


def _sev(view: FindingView) -> str:
    s = view.get("severity")
    return (s.value if hasattr(s, "value") else str(s)).lower()


def _mitre_line(view: FindingView) -> str:
    """Render a MITRE ATT&CK reference line, if available."""
    mid = view.get("mitre_technique_id")
    if not mid:
        return ""
    label = f"MITRE ATT&CK: [{mid}](https://attack.mitre.org/techniques/{mid.replace('.', '/')}/)"
    tactic = view.get("mitre_tactic")
    if tactic:
        label += f" — {tactic}"
    return f"{label}  \n"


def finding_signature(vuln: Union[Vulnerability, Dict[str, Any]]) -> str:
    """Stable dedup signature: vuln class + normalized endpoint path + injection point.
    Identical bugs at the same location collapse to the same signature.

    MAJ-3 (2026-07-21): url-less vuln classes (e.g. ``exposed_secret``) all
    collapse to ``class||`` because path and param are empty. Include the
    provider / secret_type / title discriminator so distinct live credentials
    (e.g. AWS key vs Stripe key vs GitHub token) produce distinct signatures."""
    view = to_finding_view(_as_dict(vuln))
    endpoint = view.get("url") or ""
    parsed = urlparse(endpoint) if "://" in endpoint else urlparse("//" + endpoint)
    path = (parsed.netloc + parsed.path).rstrip("/").lower()
    inj = str(view.get("param") or "")
    vt = _vt(view)
    raw = f"{vt}|{path}|{inj.lower()}"

    # MAJ-3: For url-less vuln classes, add discriminating fields so distinct
    # findings don't collapse to the same signature.
    url_less_classes = {"exposed_secret", "secret_leak", "credential_leak", "osint_leak"}
    if vt in url_less_classes or (not endpoint and not path):
        title = str(view.get("title") or "").lower().strip()
        provider = ""
        ev = view.get("evidence")
        if ev and isinstance(ev, list) and ev:
            provider = str(ev[0].get("provider") or ev[0].get("service") or "").lower().strip()
        # Tie-break by path + provider + title so AWS key != Stripe key != GitHub token in same main.js
        raw = f"{vt}|{path}|{provider}|{title}"
    return "OSOP-" + hashlib.sha1(raw.encode()).hexdigest()[:12]


def _repro_steps(view: FindingView) -> List[str]:
    vt = _vt(view)
    ev = view["evidence"][0] if view.get("evidence") else {}
    ep = view.get("url") or ""
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
    if vt == "dom_xss":
        return [
            f"Navigate to `{ev.get('injection_mechanism') == 'fragment' and ep.split('#')[0] or ep}` "
            f"with a URL parameter `{ev.get('injection_point')}` set to a JavaScript probe.",
            f"Observe the probe executes in the browser DOM — the page contains client-side "
            f"JavaScript that reads unsanitized data from the URL and writes it to a DOM sink "
            f"(innerHTML, document.write, eval, etc.).",
        ]
    if vt == "ssti":
        return [
            f"Submit the template injection payload `{ev.get('payload') or '{{7*7}}'}` to `{ep}` "
            f"via parameter `{ev.get('parameter') or 'the vulnerable input'}`.",
            f"Observe the server evaluates the expression — the result (e.g. '49' for {{7*7}})"
            f"appears in the response, confirming server-side template injection.",
        ]
    if vt == "xxe":
        return [
            f"Send a request to `{ep}` with an XML body containing an external entity "
            f"that reads `/etc/passwd` or makes a server-side request.",
            f"Observe the entity content reflected in the response, proving the parser "
            f"resolved the external entity.",
        ]
    if vt == "command_injection":
        return [
            f"Inject the command `{ev.get('payload') or ';id'}` into the vulnerable parameter "
            f"at `{ev.get('parameter') or ep}`.",
            f"Observe the command output in the response, confirming arbitrary command execution.",
        ]
    if vt == "open_redirect":
        return [
            f"Send a GET request to `{ep}` with the redirect parameter set to "
            f"`https://attacker-controlled.com/`.",
            f"Observe the server redirects to the attacker-controlled domain without validation.",
        ]
    return [f"Reproduce the confirmed condition at `{ep}` using the evidence below."]


def render_bounty_report(vuln: Union[Vulnerability, Dict[str, Any]], program: str = "") -> str:
    """Render a submission-ready Markdown report for a single validated finding.

    MIN-2 (2026-07-21): Skip simulated/mock findings at render time as a
    defense-in-depth layer. The persistence funnel already blocks simulated
    findings when ``OSOP_ALLOW_SIMULATED_FINDINGS`` is False, but if that flag
    is ever set (self-test) or a future writer skips the funnel, the report
    layer must still refuse to render them."""
    view = to_finding_view(_as_dict(vuln))
    vt = _vt(view)
    sev = _sev(view)

    # MIN-2: Redundant report-layer is_simulated check.
    if isinstance(vuln, Vulnerability) and vuln.is_simulated():
        return _SIMULATED_PLACEHOLDER
    # Also check the raw dict form.
    raw = _as_dict(vuln)
    if raw.get("simulated") or raw.get("is_simulated"):
        return _SIMULATED_PLACEHOLDER

    ev = view["evidence"][0] if view.get("evidence") else {}
    sig = finding_signature(vuln)
    impact = _IMPACT.get(vt, "Demonstrated security impact on the target application.")
    remediation = _REMEDIATION.get(vt, "Apply input validation and least-privilege controls.")
    steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(_repro_steps(view)))
    poc = render_poc_markdown(vuln)
    evidence_json = json.dumps(ev, indent=2, default=str)

    severity = view.get("severity")
    header = f"# {view.get('title')}\n\n"
    if program:
        header += f"**Program:** {program}  \n"
    header += (
        f"**Severity:** {severity if not hasattr(severity,'value') else severity.value} "
        f"(CVSS ~{_CVSS.get(sev,'N/A')})  \n"
        f"**Weakness:** {view.get('cwe') or 'N/A'}  \n"
        f"**Dedup signature:** `{sig}`  \n"
        f"{_mitre_line(view)}"
        f"**Status:** {'Validated (active confirmation)' if view.get('validated') else 'Unconfirmed'}\n"
    )

    # MANUAL-CONFIRM-001: Prominent warning when a finding is not validated
    # (reflection-only XSS, echoed-only mass assignment, etc.). These findings
    # are strong leads, not confirmed vulnerabilities, and must be clearly
    # labelled so a triager does not mistake them for validated reports.
    # Using ``validated`` instead of ``manual_confirm_required`` (which lives
    # only in evidence dicts) covers ALL unvalidated findings regardless of
    # how they signal manual confirmation, and is future-proof for any new
    # scanners producing unvalidated results.
    if not view.get("validated"):
        header += (
            "> ⚠️ **MANUAL CONFIRMATION REQUIRED**  \n"
            "> This finding was detected as a **strong lead** but was not "
            "fully validated by an automated probe (e.g. XSS reflection "
            "was observed but browser DOM execution was not confirmed, or "
            "a mass-assignment field was echoed but not independently "
            "read-back). A human operator must manually verify this before "
            "submission.  \n"
        )
    header += "\n"
    body = (
        f"## Summary\n{view.get('description')}\n\n"
        f"## Steps to Reproduce\n{steps}\n\n"
        f"## Proof of Concept\n{poc}\n"
        f"## Impact\n{impact}\n\n"
        f"## Evidence\n```json\n{evidence_json}\n```\n\n"
        f"## Remediation\n{remediation}\n"
    )
    return header + body
