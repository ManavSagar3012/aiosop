"""Secret-liveness verifier.

Finding a secret in JS/source-maps is only *informational* — and triagers routinely
reject "exposed key" reports without proof the key works. This verifier turns a found
secret into a CONFIRMED, valid credential by performing a single BENIGN, READ-ONLY
identity/status call against the provider. A successful authenticated response proves
the credential is live (and the report becomes a high-value access finding).

SAFETY: every provider check is GET-only against an identity/status endpoint. We never
mutate, never list/dump data, never escalate — just confirm the credential authenticates.
A `base_override` lets callers point checks at a controlled mock (for tests / to avoid
touching third parties).
"""
from typing import Any, Dict, List, Optional

import httpx

# Provider table: prefix patterns -> a read-only identity endpoint. `live_codes` are
# HTTP statuses that indicate the credential authenticated successfully.
SECRET_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "github": {
        "prefixes": ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
        "base": "https://api.github.com", "path": "/user", "method": "GET",
        "auth": "bearer", "live_codes": [200],
    },
    "gitlab": {
        "prefixes": ["glpat-"],
        "base": "https://gitlab.com", "path": "/api/v4/user", "method": "GET",
        "auth": "bearer", "live_codes": [200],
    },
    "stripe": {
        "prefixes": ["sk_live_", "rk_live_"],
        "base": "https://api.stripe.com", "path": "/v1/account", "method": "GET",
        "auth": "bearer", "live_codes": [200],
    },
    "npm": {
        "prefixes": ["npm_"],
        "base": "https://registry.npmjs.org", "path": "/-/whoami", "method": "GET",
        "auth": "bearer", "live_codes": [200],
    },
    "slack": {
        "prefixes": ["xoxb-", "xoxp-", "xoxa-", "xoxr-"],
        "base": "https://slack.com", "path": "/api/auth.test", "method": "GET",
        "auth": "bearer", "live_codes": [200],
    },
}


def classify_secret(value: str) -> Optional[str]:
    """Return the provider name a secret belongs to (by prefix), or None."""
    v = value or ""
    for name, p in SECRET_PROVIDERS.items():
        if any(v.startswith(prefix) for prefix in p["prefixes"]):
            return name
    return None


def _auth_headers(provider: Dict[str, Any], secret: str) -> Dict[str, str]:
    if provider["auth"] == "bearer":
        return {"Authorization": f"Bearer {secret}"}
    return {}


async def verify_secret(
    secret: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    base_override: Optional[str] = None,
    timeout: float = 12.0,
) -> Dict[str, Any]:
    """Verify a single secret's liveness with one read-only call.

    Returns {provider, classified, live, status, detail}. `live` is True only when the
    provider's identity endpoint authenticated the credential.
    """
    provider_name = classify_secret(secret)
    if not provider_name:
        return {"provider": None, "classified": False, "live": False,
                "status": 0, "detail": "unrecognized secret format"}

    provider = SECRET_PROVIDERS[provider_name]
    base = base_override or provider["base"]
    url = base.rstrip("/") + provider["path"]
    headers = _auth_headers(provider, secret)

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout)
    try:
        resp = await client.request(provider["method"], url, headers=headers)
        live = resp.status_code in provider["live_codes"]
        return {"provider": provider_name, "classified": True, "live": live,
                "status": resp.status_code,
                "detail": "authenticated" if live else f"rejected ({resp.status_code})"}
    except Exception as e:
        return {"provider": provider_name, "classified": True, "live": False,
                "status": 0, "detail": f"probe error: {e}"}
    finally:
        if own_client:
            await client.aclose()
