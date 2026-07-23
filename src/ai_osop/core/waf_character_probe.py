"""WAF Character Probing Oracle.

The assessment's Immediate Priority 1: before injecting complex payloads,
systematically determine which characters the WAF filters. A human researcher
sends a probe containing `'"<script>&%` and observes which characters get
blocked. This oracle does the same — sends a character-group probe, observes
which characters return a WAF block (403/challenge), and passes the allowed/
blocked list as constraints to the payload engine so it only generates
payloads the target will accept.

This is the feedback loop the assessment identified as missing: "Send
payload → analyze response character by character → modify payload to
bypass the specific filter detected."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx


# Character groups to probe — grouped by injection context relevance.
# We send each group as a single parameter value and check if the response
# changes (status code, body length, or WAF challenge page).
_CHAR_GROUPS = [
    ("sql_basic", "'\";--"),           # SQL injection basics
    ("sql_operators", "()<>="),       # SQL operators
    ("sql_keywords", "UNION SELECT"),  # SQL keywords (case-sensitive test)
    ("xss_html", "<>\"'"),            # XSS HTML context
    ("xss_script", "<script>"),        # XSS script tag
    ("xss_event", "onerror=alert(1)"),  # XSS event handler
    ("xss_svg", "<svg onload=alert(1)>"),  # XSS SVG
    ("path_traversal", "../..\\"),    # Path traversal
    ("command_injection", ";|&`$()"),  # Command injection
    ("template_injection", "{{7*7}}"),  # SSTI
    ("nosql", "$ne $gt $where"),      # NoSQL operators
    ("xml", "<!ENTITY"),              # XXE
    ("special", "{}[]!@#%^*+=~?"),    # Special chars
]


@dataclass
class WAFCharacterProbeResult:
    """Result of probing a target for character filtering."""
    target_url: str
    waf_detected: Optional[str] = None
    blocked_groups: List[str] = field(default_factory=list)
    allowed_groups: List[str] = field(default_factory=list)
    baseline_status: int = 0
    baseline_length: int = 0
    evidence: Dict[str, Any] = field(default_factory=dict)


async def probe_waf_characters(
    client: httpx.AsyncClient,
    target_url: str,
    param: str = "q",
    method: str = "GET",
    timeout: float = 10.0,
) -> WAFCharacterProbeResult:
    """Probe a target endpoint to determine which character groups are WAF-filtered.

    Sends a baseline request (no special chars), then sends each character
    group as a parameter value. If the response changes to a WAF block (403,
    406, challenge page, or significantly different body length), that group
    is marked as "blocked".

    Returns a WAFCharacterProbeResult with the blocked/allowed lists, which
    the payload engine uses to select only payloads the target will accept.
    """
    result = WAFCharacterProbeResult(target_url=target_url)

    # 1. Baseline: send a benign value to establish the normal response
    try:
        if method.upper() == "GET":
            base_resp = await client.get(
                target_url, params={param: "osop_benign_probe"}, timeout=timeout
            )
        else:
            base_resp = await client.request(
                method, target_url, data={param: "osop_benign_probe"}, timeout=timeout
            )
        result.baseline_status = base_resp.status_code
        result.baseline_length = len(base_resp.text)
    except Exception:
        return result

    # Detect WAF from baseline response headers
    headers_lower = {k.lower(): v for k, v in base_resp.headers.items()}
    if "cf-ray" in headers_lower:
        result.waf_detected = "cloudflare"
    elif "x-amzn-waf" in headers_lower:
        result.waf_detected = "aws_waf"
    elif "x-sucuri-id" in headers_lower:
        result.waf_detected = "sucuri"
    elif "incap_ses" in base_resp.headers.get("set-cookie", "").lower():
        result.waf_detected = "imperva"

    # 2. Probe each character group
    for group_name, chars in _CHAR_GROUPS:
        try:
            if method.upper() == "GET":
                resp = await client.get(
                    target_url, params={param: chars}, timeout=timeout
                )
            else:
                resp = await client.request(
                    method, target_url, data={param: chars}, timeout=timeout
                )

            blocked = False

            # Check 1: WAF block status codes
            if resp.status_code in (403, 406, 429, 503):
                blocked = True

            # Check 2: WAF challenge page patterns
            body_lower = resp.text[:2000].lower()
            if any(p in body_lower for p in (
                "just a moment", "cf-browser-verification", "access denied",
                "request blocked", "security check", "captcha",
            )):
                blocked = True

            # Check 3: Significant body length change (>50% reduction = likely
            # a block page replacing the normal content)
            if result.baseline_length > 0:
                ratio = len(resp.text) / result.baseline_length
                if ratio < 0.5 and resp.status_code != result.baseline_status:
                    blocked = True

            # Check 4: Status changed from baseline to an error
            if resp.status_code != result.baseline_status and resp.status_code >= 400:
                blocked = True

            if blocked:
                result.blocked_groups.append(group_name)
            else:
                result.allowed_groups.append(group_name)

        except Exception:
            result.blocked_groups.append(group_name)  # assume blocked on error

    result.evidence = {
        "baseline_status": result.baseline_status,
        "baseline_length": result.baseline_length,
        "waf_detected": result.waf_detected,
        "blocked_count": len(result.blocked_groups),
        "allowed_count": len(result.allowed_groups),
        "blocked": result.blocked_groups,
        "allowed": result.allowed_groups,
    }

    return result


def filter_payloads_by_waf(
    payloads: List[str],
    probe_result: WAFCharacterProbeResult,
) -> List[str]:
    """Filter a list of payloads to only those compatible with the WAF probe.

    If a character group is blocked, any payload containing those characters
    is filtered out. This prevents wasting requests on payloads the WAF will
    block, and focuses the scan on payloads that can actually reach the backend.
    """
    if not probe_result.blocked_groups:
        return payloads  # nothing blocked, all payloads OK

    # Build a set of blocked characters
    blocked_chars = set()
    for group_name, chars in _CHAR_GROUPS:
        if group_name in probe_result.blocked_groups:
            for c in chars:
                if c.strip():  # skip spaces in keyword groups
                    blocked_chars.add(c)

    if not blocked_chars:
        return payloads

    return [p for p in payloads if not any(c in p for c in blocked_chars)]
