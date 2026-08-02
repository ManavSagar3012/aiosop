"""Secret-liveness verifier.

Finding a secret in JS/source-maps is only *informational* — and triagers routinely
reject "exposed key" reports without proof the key works. This verifier turns a found
secret into a CONFIRMED, valid credential by performing a single BENIGN, READ-ONLY
identity/status call against the provider. A successful authenticated response proves
the credential is live (and the report becomes a high-value access finding).

Liveness assessment produces one of three statuses (see :func:`assess_secret`):
  - ``confirmed_live``  — structurally valid AND a real read-only probe authenticated.
                          The ONLY status eligible to become a confirmed finding.
  - ``unverified``      — plausible but unproven (structurally valid but unprobed, a
                          provider key that failed structural validation, or a generic
                          high-entropy string with no known provider). Must be
                          downgraded so it does not create submission noise.
  - ``not_a_secret``    — a test/example/placeholder value or degenerate string that
                          should never be reported at all.

SAFETY: every provider probe is GET-only against an identity/status endpoint. We never
mutate, never list/dump data, never escalate — just confirm the credential authenticates.
Live probes are OPTIONAL and OFF by default (``allow_live_probe=False``); with probing
disabled, a structurally valid provider key can rise no higher than ``unverified``. A
`base_override` lets callers point checks at a controlled mock (for tests / to avoid
touching third parties).
"""

import math
import re
from typing import Any, Dict, Optional, Pattern

import httpx

# Liveness status vocabulary. Only CONFIRMED_LIVE is eligible for a confirmed finding.
STATUS_CONFIRMED_LIVE = "confirmed_live"
STATUS_UNVERIFIED = "unverified"
STATUS_NOT_A_SECRET = "not_a_secret"

# Provider table: prefix patterns -> a read-only identity endpoint plus a full-match
# structural `pattern`. `live_codes` are HTTP statuses that indicate the credential
# authenticated successfully. Providers WITH a `base`/`path` have a known safe verify
# endpoint and can be probed; structural-only providers (AWS/Google/SendGrid/Twilio/
# Mailgun) have no safe read-only whoami endpoint reachable with the key alone, so they
# can rise no higher than `unverified` (format-validated but unproven).
SECRET_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "github": {
        "prefixes": ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        "pattern": re.compile(r"(?:gh[opsur]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})$"),
        "base": "https://api.github.com",
        "path": "/user",
        "method": "GET",
        "auth": "bearer",
        "live_codes": [200],
    },
    "gitlab": {
        "prefixes": ["glpat-"],
        "pattern": re.compile(r"glpat-[A-Za-z0-9_\-]{20}$"),
        "base": "https://gitlab.com",
        "path": "/api/v4/user",
        "method": "GET",
        "auth": "bearer",
        "live_codes": [200],
    },
    "stripe": {
        "prefixes": ["sk_live_", "rk_live_"],
        "pattern": re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{24,}$"),
        "base": "https://api.stripe.com",
        "path": "/v1/account",
        "method": "GET",
        "auth": "bearer",
        "live_codes": [200],
    },
    "npm": {
        "prefixes": ["npm_"],
        "pattern": re.compile(r"npm_[A-Za-z0-9]{36}$"),
        "base": "https://registry.npmjs.org",
        "path": "/-/whoami",
        "method": "GET",
        "auth": "bearer",
        "live_codes": [200],
    },
    "slack": {
        "prefixes": ["xoxb-", "xoxp-", "xoxa-", "xoxr-"],
        "pattern": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}$"),
        "base": "https://slack.com",
        "path": "/api/auth.test",
        "method": "GET",
        "auth": "bearer",
        "live_codes": [200],
    },
    # Structural-only providers: strong format signal, but no safe key-only verify
    # endpoint, so probing is not available (they top out at `unverified`).
    # `method` is fixed GET to preserve the read-only safety invariant even though
    # these providers are never probed (no base/path => _can_probe is False).
    "aws": {
        "prefixes": ["AKIA", "ASIA"],
        "pattern": re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}$"),
        "method": "GET",
    },
    "google": {
        "prefixes": ["AIza"],
        "pattern": re.compile(r"AIza[0-9A-Za-z_\-]{35}$"),
        "method": "GET",
    },
    "sendgrid": {
        "prefixes": ["SG."],
        "pattern": re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}$"),
        "method": "GET",
    },
    "twilio": {
        "prefixes": ["SK", "AC"],
        "pattern": re.compile(r"(?:SK|AC)[0-9a-fA-F]{32}$"),
        "method": "GET",
    },
    "mailgun": {
        "prefixes": ["key-"],
        "pattern": re.compile(r"key-[0-9a-f]{32}$"),
        "method": "GET",
    },
}

# Values that are obviously not real credentials: vendor test keys, examples,
# placeholders, redactions. These classify as `not_a_secret` (never reported).
_TEST_PLACEHOLDER_TOKENS = (
    "sk_test_",
    "pk_test_",
    "rk_test_",
    "whsec_test",
    "_test_",
    "test_key",
    "your_",
    "example",
    "changeme",
    "change-me",
    "placeholder",
    "dummy",
    "sample",
    "redacted",
    "insert",
    "todo",
    "foobar",
    "xxxx",
    "<",
    "{{",
)

# Confidence scores per outcome. Only `confirmed_live` clears a reportable bar.
_CONF_CONFIRMED_LIVE = 0.98
_CONF_STRUCT_VALID_UNPROBED = 0.40
_CONF_PROBE_REJECTED = 0.15
_CONF_STRUCT_INVALID = 0.10
_CONF_GENERIC_ENTROPY = 0.25
_CONF_NOT_A_SECRET = 0.0

# Generic (no-provider) high-entropy heuristic thresholds.
_GENERIC_MIN_ENTROPY = 3.5
_GENERIC_MIN_LEN = 16


def classify_secret(value: str) -> Optional[str]:
    """Return the provider name a secret belongs to (by prefix), or None."""
    v = value or ""
    for name, p in SECRET_PROVIDERS.items():
        if any(v.startswith(prefix) for prefix in p["prefixes"]):
            return name
    return None


def _shannon_entropy(value: str) -> float:
    """Shannon entropy (bits/char). High-entropy strings are more likely secrets."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_test_or_placeholder(value: str) -> bool:
    """True for vendor test keys, placeholders, and degenerate (all-same-char) values."""
    v = value or ""
    low = v.lower()
    if any(tok in low for tok in _TEST_PLACEHOLDER_TOKENS):
        return True
    # Degenerate strings: all-zeros / a single repeated character (after any prefix)
    # carry no entropy and cannot be a real credential.
    stripped = re.sub(r"^[A-Za-z]+[_\-.]?", "", v) or v
    body = stripped[-24:] if len(stripped) >= 24 else stripped
    if body and len(set(body)) <= 1:
        return True
    return False


def structural_valid(value: str, provider_name: Optional[str] = None) -> bool:
    """True if `value` full-matches the provider's structural/format pattern."""
    if provider_name is None:
        provider_name = classify_secret(value)
    if not provider_name:
        return False
    pattern: Optional[Pattern[str]] = SECRET_PROVIDERS[provider_name].get("pattern")
    if pattern is None:
        return False
    return bool(pattern.match(value or ""))


def _can_probe(provider_name: str) -> bool:
    """True if the provider has a known safe read-only verify endpoint."""
    p = SECRET_PROVIDERS.get(provider_name) or {}
    return bool(p.get("base") and p.get("path"))


def is_reportable(verdict: Dict[str, Any]) -> bool:
    """A secret is eligible for a CONFIRMED finding only when confirmed live.

    Everything else (`unverified`, `not_a_secret`) is downgraded and must not be
    submitted as a confirmed finding — this is the anti-noise gate.
    """
    return verdict.get("status") == STATUS_CONFIRMED_LIVE


def _mask(value: str) -> str:
    """Mask a secret for safe logging/titles: keep a short prefix, redact the rest."""
    v = value or ""
    if len(v) <= 8:
        return (v[:2] + "***") if v else ""
    return f"{v[:6]}...{v[-2:]}"


def _verdict(
    *,
    value: str,
    provider: Optional[str],
    status: str,
    confidence: float,
    detail: str,
    structural: bool = False,
    live: bool = False,
    probed: bool = False,
    http_status: int = 0,
) -> Dict[str, Any]:
    return {
        "value_masked": _mask(value),
        "provider": provider,
        "status": status,
        "confidence": round(confidence, 3),
        "reportable": status == STATUS_CONFIRMED_LIVE,
        "structural_valid": structural,
        "live": live,
        "probed": probed,
        "http_status": http_status,
        "detail": detail,
    }


def _auth_headers(provider: Dict[str, Any], secret: str) -> Dict[str, str]:
    if provider["auth"] == "bearer":
        return {"Authorization": f"Bearer {secret}"}
    return {}


async def assess_secret(
    value: str,
    *,
    secret_type: Optional[str] = None,
    allow_live_probe: bool = False,
    client: Optional[httpx.AsyncClient] = None,
    base_override: Optional[str] = None,
    timeout: float = 12.0,
) -> Dict[str, Any]:
    """Assess a discovered secret's liveness and reportability.

    Pipeline (each stage can only *lower* the ceiling, never fabricate a positive):
      1. Test/placeholder/degenerate value            -> not_a_secret
      2. No known provider:
           high-entropy string                        -> unverified (low confidence)
           low-entropy string                         -> not_a_secret
      3. Known provider, structural validation fails   -> unverified (rejected format)
      4. Known provider, structurally valid:
           probing disabled or no safe endpoint        -> unverified (unproven)
           probe authenticates (real 2xx)              -> confirmed_live
           probe rejects the credential                -> unverified (rejected)

    Only ``confirmed_live`` is eligible for a confirmed finding (see :func:`is_reportable`).
    `secret_type` is an optional rule-name hint from the caller (currently advisory).
    """
    v = value or ""
    if not v or _is_test_or_placeholder(v):
        return _verdict(
            value=v,
            provider=None,
            status=STATUS_NOT_A_SECRET,
            confidence=_CONF_NOT_A_SECRET,
            detail="test/example/placeholder value",
        )

    provider_name = classify_secret(v)

    # --- No recognized provider: fall back to entropy heuristic only. ----------
    if not provider_name:
        entropy = _shannon_entropy(v)
        if len(v) >= _GENERIC_MIN_LEN and entropy >= _GENERIC_MIN_ENTROPY:
            return _verdict(
                value=v,
                provider=None,
                status=STATUS_UNVERIFIED,
                confidence=_CONF_GENERIC_ENTROPY,
                detail=f"generic high-entropy string (H={entropy:.2f}); no provider",
            )
        return _verdict(
            value=v,
            provider=None,
            status=STATUS_NOT_A_SECRET,
            confidence=_CONF_NOT_A_SECRET,
            detail=f"no provider and low entropy (H={entropy:.2f})",
        )

    # --- Recognized provider: structural validation gate. ----------------------
    if not structural_valid(v, provider_name):
        return _verdict(
            value=v,
            provider=provider_name,
            status=STATUS_UNVERIFIED,
            confidence=_CONF_STRUCT_INVALID,
            structural=False,
            detail=f"{provider_name} prefix but structurally invalid",
        )

    # Structurally valid. Without a real, positive probe we cannot claim liveness.
    if not allow_live_probe or not _can_probe(provider_name):
        reason = (
            "probing disabled" if not allow_live_probe else "no safe verify endpoint for provider"
        )
        return _verdict(
            value=v,
            provider=provider_name,
            status=STATUS_UNVERIFIED,
            confidence=_CONF_STRUCT_VALID_UNPROBED,
            structural=True,
            detail=f"{provider_name} format valid but unproven ({reason})",
        )

    # --- Real read-only liveness probe. ----------------------------------------
    probe = await verify_secret(v, client=client, base_override=base_override, timeout=timeout)
    http_status = int(probe.get("status") or 0)
    if probe.get("live"):
        return _verdict(
            value=v,
            provider=provider_name,
            status=STATUS_CONFIRMED_LIVE,
            confidence=_CONF_CONFIRMED_LIVE,
            structural=True,
            live=True,
            probed=True,
            http_status=http_status,
            detail=f"{provider_name} credential authenticated (read-only)",
        )
    return _verdict(
        value=v,
        provider=provider_name,
        status=STATUS_UNVERIFIED,
        confidence=_CONF_PROBE_REJECTED,
        structural=True,
        live=False,
        probed=True,
        http_status=http_status,
        detail=f"{provider_name} format valid but probe rejected: {probe.get('detail')}",
    )


async def verify_secret(
    secret: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    base_override: Optional[str] = None,
    timeout: float = 12.0,
) -> Dict[str, Any]:
    """Verify a single secret's liveness with one read-only call.

    Returns {provider, classified, live, status, detail}. `live` is True only when the
    provider's identity endpoint authenticated the credential. Providers without a safe
    verify endpoint (structural-only) return classified=True, live=False.
    """
    provider_name = classify_secret(secret)
    if not provider_name:
        return {
            "provider": None,
            "classified": False,
            "live": False,
            "status": 0,
            "detail": "unrecognized secret format",
        }

    provider = SECRET_PROVIDERS[provider_name]
    if not _can_probe(provider_name):
        return {
            "provider": provider_name,
            "classified": True,
            "live": False,
            "status": 0,
            "detail": "no safe verify endpoint for provider",
        }

    base = base_override or provider["base"]
    url = base.rstrip("/") + provider["path"]
    headers = _auth_headers(provider, secret)

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout)
    try:
        resp = await client.request(provider["method"], url, headers=headers)
        live = resp.status_code in provider["live_codes"]
        return {
            "provider": provider_name,
            "classified": True,
            "live": live,
            "status": resp.status_code,
            "detail": "authenticated" if live else f"rejected ({resp.status_code})",
        }
    except Exception as e:
        return {
            "provider": provider_name,
            "classified": True,
            "live": False,
            "status": 0,
            "detail": f"probe error: {e}",
        }
    finally:
        if own_client:
            await client.aclose()
