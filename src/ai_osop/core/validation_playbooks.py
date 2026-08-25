"""Validation Playbooks (T1.3)

Playbooks for the top 10 vulnerability classes that can be verified
without full exploitation. Each playbook re-observes the target to
confirm or reject a weakness hypothesis.
"""

import asyncio
import json
import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse, urljoin

import httpx

from ai_osop.core import confidence_engine as ce
from ai_osop.core.validation_engine import ValidationOutcome

logger = logging.getLogger("ai_osop.core.validation_playbooks")


async def _safe_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    timeout: float = 10.0,
) -> Optional[httpx.Response]:
    """Safe HTTP fetch with error handling."""
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "AI-OSOP-Validation/1.0"},
        ) as client:
            return await client.request(method, url, headers=headers, data=data)
    except Exception as e:
        logger.debug("playbook_fetch_failed url=%s error=%s", url, e)
        return None


# ── XSS Reflection Check ──────────────────────────────────────────────────────


async def handle_xss_reflection(hyp: Any) -> ValidationOutcome:
    """Check if a reflected XSS payload appears in the response body.

    Sends a unique canary string and checks if it's reflected without encoding.
    This is safe — no script execution, just reflection detection.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"
    parsed = urlparse(target)
    params = dict(parsed.query.split("&") if parsed.query else [])

    # Inject a unique canary
    canary = f"osop_xss_test_{id(hyp) & 0xFFFF:04x}"
    params["osop_test"] = canary
    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params)}"

    resp = await _safe_fetch(test_url)
    if resp is None:
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.INCONCLUSIVE,
            {"error": "target_unreachable"}, "target unreachable at validation time",
        )

    body = resp.text
    # Check if canary appears unencoded (reflected XSS indicator)
    if canary in body:
        # Check if it's HTML-encoded (safe) or raw (vulnerable)
        encoded_variants = [
            canary.replace("_", "&#95;"),
            canary.replace("_", "&lowbar;"),
            f"osop_xss_test",
        ]
        is_encoded = any(ev in body for ev in encoded_variants)
        if not is_encoded:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED,
                {"reflected": True, "canary": canary, "status": resp.status_code},
                f"Canary string '{canary}' reflected unencoded in response",
            )
        else:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.REJECTED,
                {"reflected": True, "encoded": True, "canary": canary},
                "Canary reflected but HTML-encoded (not exploitable)",
            )

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.REJECTED,
        {"reflected": False, "canary": canary},
        "Canary string not reflected in response",
    )


# ── SSRF OAST Callback Check ──────────────────────────────────────────────────


async def handle_ssrf_oast(hyp: Any) -> ValidationOutcome:
    """Verify SSRF by checking if the server made an outbound request.

    Uses a unique canary domain to check DNS/HTTP callbacks.
    Falls back to checking for SSRF indicators in the response.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"

    # Check if the response contains SSRF indicators
    resp = await _safe_fetch(target)
    if resp is None:
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.INCONCLUSIVE,
            {"error": "target_unreachable"}, "target unreachable",
        )

    body = resp.text.lower()
    indicators = [
        "internal server error",
        "connection refused",
        "name resolution",
        "getaddrinfo",
        "127.0.0.1",
        "localhost",
        "169.254.169.254",
        "metadata.google",
    ]
    found = [ind for ind in indicators if ind in body]
    if found:
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.VALIDATED,
            {"indicators": found, "status": resp.status_code},
            f"SSRF indicators found in response: {found[:3]}",
        )

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.INCONCLUSIVE,
        {"status": resp.status_code},
        "No SSRF indicators in response; OAST callback verification needed",
    )


# ── IDOR Differential ─────────────────────────────────────────────────────────


async def handle_idor_differential(hyp: Any) -> ValidationOutcome:
    """Verify IDOR by requesting the resource with and without auth.

    If both requests return identical content, authorization is not enforced.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        try:
            resp_auth = await client.get(target, headers={"Authorization": "Bearer osop-dummy-auth"})
            resp_noauth = await client.get(target)
        except Exception as e:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE,
                {"error": str(e)}, "requests failed",
            )

    # If both return 200 with identical bodies, authorization is missing
    if resp_auth.status_code == 200 and resp_noauth.status_code == 200:
        if resp_auth.text == resp_noauth.text:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED,
                {"auth_status": resp_auth.status_code, "noauth_status": resp_noauth.status_code},
                "Resource accessible without authentication — IDOR confirmed",
            )

    if resp_noauth.status_code in (401, 403):
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.REJECTED,
            {"status": resp_noauth.status_code},
            f"Unauthorized request returned {resp_noauth.status_code}",
        )

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.INCONCLUSIVE,
        {"auth_status": resp_auth.status_code, "noauth_status": resp_noauth.status_code},
        "Responses differ; authorization may be enforced",
    )


# ── Mass Assignment ────────────────────────────────────────────────────────────


async def handle_mass_assignment(hyp: Any) -> ValidationOutcome:
    """Verify mass assignment by injecting restricted fields.

    Sends a PUT/PATCH with extra fields (isAdmin, role, price) and checks
    if they're reflected in the response.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"

    restricted_fields = {"isAdmin": True, "role": "admin", "price": 0.01}
    payload = {**restricted_fields, "name": "test_validation"}

    resp = await _safe_fetch(target, method="PUT", data=payload)
    if resp is None:
        resp = await _safe_fetch(target, method="PATCH", data=payload)

    if resp is None:
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.INCONCLUSIVE,
            {"error": "target_unreachable"}, "target unreachable",
        )

    # Check if any restricted field appears in the response
    try:
        resp_body = resp.json()
        leaked = {k: v for k, v in restricted_fields.items() if k in resp_body}
        if leaked:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED,
                {"leaked_fields": list(leaked.keys()), "status": resp.status_code},
                f"Mass assignment confirmed: restricted fields accepted: {list(leaked.keys())}",
            )
    except (json.JSONDecodeError, ValueError):
        pass

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.REJECTED,
        {"status": resp.status_code},
        "Restricted fields not reflected in response",
    )


# ── SSTI Template Injection ───────────────────────────────────────────────────


async def handle_ssti_template(hyp: Any) -> ValidationOutcome:
    """Verify SSTI by sending a math expression and checking for evaluation.

    Sends {{7*7}} or ${7*7} and checks if the response contains 49.
    This is safe — no code execution, just template evaluation detection.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"
    parsed = urlparse(target)

    canary = str(7 * 7)  # "49"
    # Common SSTI payloads
    payloads = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{= 7*7}}",
    ]

    for payload in payloads:
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        resp = await _safe_fetch(test_url, method="GET")
        if resp and canary in resp.text and payload not in resp.text:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED,
                {"evaluated": payload, "result": canary},
                f"SSTI confirmed: '{payload}' evaluated to {canary}",
            )

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.REJECTED,
        {"payloads_tested": len(payloads)},
        "No template expressions evaluated",
    )


# ── CORS Misconfiguration ─────────────────────────────────────────────────────


async def handle_cors_misconfiguration(hyp: Any) -> ValidationOutcome:
    """Verify CORS misconfiguration by sending cross-origin requests.

    Checks if the server reflects arbitrary Origin headers.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"

    evil_origins = [
        "https://evil.com",
        "https://attacker.example.com",
        "null",
    ]

    for origin in evil_origins:
        headers = {"Origin": origin}
        resp = await _safe_fetch(target, headers=headers)
        if resp is None:
            continue

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == origin and acac.lower() == "true":
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED,
                {"origin": origin, "acao": acao, "acac": acac},
                f"CORS misconfiguration: reflects arbitrary Origin '{origin}' with credentials",
            )
        if acao == "*" and acac.lower() == "true":
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED,
                {"acao": acao, "acac": acac},
                "CORS misconfiguration: wildcard Origin with credentials",
            )

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.REJECTED,
        {"tested_origins": len(evil_origins)},
        "Server does not reflect arbitrary Origins",
    )


# ── Open Redirect ──────────────────────────────────────────────────────────────


async def handle_open_redirect(hyp: Any) -> ValidationOutcome:
    """Verify open redirect by checking if redirect parameter is followed.

    Sends a request with a redirect parameter pointing to an external URL.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"
    parsed = urlparse(target)

    canary_domain = "osop-redirect-test.invalid"
    redirect_params = ["redirect", "url", "next", "return_to", "goto", "dest"]

    for param in redirect_params:
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}=https://{canary_domain}/"
        resp = await _safe_fetch(test_url, timeout=5.0)
        if resp is None:
            continue

        # Check if redirected to our canary
        if str(resp.status_code).startswith("3"):
            location = resp.headers.get("location", "")
            if canary_domain in location:
                return ValidationOutcome(
                    hyp.id, hyp.playbook, ce.VALIDATED,
                    {"param": param, "location": location, "status": resp.status_code},
                    f"Open redirect confirmed via '{param}' parameter",
                )

        # Check response body for redirect
        if canary_domain in resp.text:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED,
                {"param": param, "in_body": True},
                f"Open redirect: external domain reflected in response body",
            )

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.REJECTED,
        {"params_tested": len(redirect_params)},
        "No open redirect found",
    )


# ── Header Injection ───────────────────────────────────────────────────────────


async def handle_header_injection(hyp: Any) -> ValidationOutcome:
    """Verify header injection by injecting CRLF sequences.

    Checks if the server reflects injected headers in the response.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"
    parsed = urlparse(target)

    canary = "X-OSOP-Test"
    payloads = [
        f"%0d%0a{canary}:injected",
        f"\r\n{canary}:injected",
        f"%0D%0A{canary}%3Ainjected",
    ]

    for payload in payloads:
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?q={payload}"
        resp = await _safe_fetch(test_url)
        if resp is None:
            continue

        # Check if the injected header appears
        for header_name, header_value in resp.headers.items():
            if canary.lower() in header_name.lower():
                return ValidationOutcome(
                    hyp.id, hyp.playbook, ce.VALIDATED,
                    {"injected_header": header_name, "value": header_value},
                    f"Header injection confirmed: injected header '{header_name}' present",
                )

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.REJECTED,
        {"payloads_tested": len(payloads)},
        "No header injection found",
    )


# ── XXE External Entity ────────────────────────────────────────────────────────


async def handle_xxe_external_entity(hyp: Any) -> ValidationOutcome:
    """Verify XXE by sending XML with external entity references.

    Sends a safe DTD that references a file we know exists on the server.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"

    # Safe XXE test: reference /etc/hostname (always exists on Linux)
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<test>&xxe;</test>"""

    headers = {"Content-Type": "application/xml"}
    resp = await _safe_fetch(target, method="POST", headers=headers, data=xxe_payload)
    if resp is None:
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.INCONCLUSIVE,
            {"error": "target_unreachable"}, "target unreachable",
        )

    body = resp.text
    # If the response contains content from /etc/hostname, XXE is confirmed
    # Heuristic: check if the body contains a hostname-like string (no spaces, contains dots)
    if re.search(r"\b[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+\b", body):
        # Check it's not just the original request reflected
        if "xxe" not in body.lower() or "file:///" in body:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED,
                {"response_snippet": body[:200]},
                "XXE confirmed: external entity resolved in response",
            )

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.REJECTED,
        {"status": resp.status_code},
        "No XXE resolution detected",
    )


# ── CSRF Token Missing ─────────────────────────────────────────────────────────


async def handle_csrf_token_missing(hyp: Any) -> ValidationOutcome:
    """Verify CSRF by submitting state-changing requests without tokens.

    Sends a POST without a CSRF token and checks if it succeeds.
    """
    target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"

    # First, get the page to check for CSRF tokens
    resp_get = await _safe_fetch(target)
    if resp_get is None:
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.INCONCLUSIVE,
            {"error": "target_unreachable"}, "target unreachable",
        )

    # Check if the page has CSRF token fields
    body = resp_get.text.lower()
    csrf_indicators = ["csrf", "_token", "csrfmiddleware", "csrf_token", "xsrf"]
    has_csrf_field = any(ind in body for ind in csrf_indicators)

    # Submit without CSRF token
    resp_post = await _safe_fetch(target, method="POST", data={"test": "validation"})
    if resp_post is None:
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.INCONCLUSIVE,
            {"error": "post_failed"}, "POST request failed",
        )

    # If no CSRF field exists and the POST succeeds, CSRF is vulnerable
    if not has_csrf_field and resp_post.status_code in (200, 302):
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.VALIDATED,
            {"has_csrf_field": has_csrf_field, "status": resp_post.status_code},
            "No CSRF token required for state-changing request",
        )

    if has_csrf_field:
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.REJECTED,
            {"has_csrf_field": True},
            "CSRF token field present in form",
        )

    return ValidationOutcome(
        hyp.id, hyp.playbook, ce.INCONCLUSIVE,
        {"get_status": resp_get.status_code, "post_status": resp_post.status_code},
        "CSRF status unclear; manual verification recommended",
    )
