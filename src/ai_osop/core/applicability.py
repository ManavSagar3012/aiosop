"""Applicability Engine — scanner preflight validation.

Before dispatching or executing a scanner against an endpoint, the Applicability Engine
determines if the vulnerability class is even possible/meaningful.
This reduces false positives, eliminates wasted compute, and keeps the attack graph clean.
"""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ai_osop.core.enums import VulnClass

logger = logging.getLogger("ai_osop.applicability")

# Static assets to exclude from active injection testing
STATIC_EXTENSIONS = {
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".webp",
    ".mp4",
    ".webm",
    ".js",
    ".pdf",
    ".txt",
    ".json",
    ".xml",
}

# Common read-only keywords in endpoint paths
READ_ONLY_PATH_PATTERNS = [
    "/search",
    "/find",
    "/query",
    "/filter",
    "/view",
    "/catalog",
    "/get",
    "/list",
    "/details",
    "/show",
    "/index",
    "/blog",
    "/posts",
    "/static",
    "/assets",
    "/docs",
    "/help",
    "/about",
    "/contact",
]


class ApplicabilityEngine:
    """Central registry and evaluator for scanner applicability rules."""

    @staticmethod
    def is_applicable(
        vuln_class: VulnClass, payload: Dict[str, Any], user_sessions: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        """Evaluate applicability. Returns {"applicable": bool, "reason": str}."""
        url = payload.get("url") or payload.get("target")
        if not url:
            return {"applicable": False, "reason": "No target URL provided in payload"}

        parsed = urlparse(url)
        path = parsed.path.lower()
        method = (payload.get("method") or "GET").upper()

        # 0. Global Check: Static Assets exclusion
        if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
            return {
                "applicable": False,
                "reason": f"Static asset endpoint ({path}); active scanning skipped.",
            }

        # 1. CSRF (Cross-Site Request Forgery)
        if vuln_class == VulnClass.CSRF:
            # Rule 1.1: Must be an unsafe HTTP method
            if method in ("GET", "HEAD", "OPTIONS", "TRACE"):
                return {
                    "applicable": False,
                    "reason": f"Read-only HTTP method ({method}); CSRF is not applicable.",
                }
            # Rule 1.2: Exclude read-only paths (search/catalog)
            if any(pattern in path for pattern in READ_ONLY_PATH_PATTERNS):
                return {
                    "applicable": False,
                    "reason": f"Endpoint path ({path}) is read-only; CSRF is not applicable.",
                }
            # Rule 1.3: Must have ambient cookies for exploitation context
            if user_sessions:
                has_cookies = any(getattr(s, "cookies", None) for s in user_sessions)
                if not has_cookies:
                    return {
                        "applicable": False,
                        "reason": "No authenticated browser-cookie sessions exist; CSRF is not applicable.",
                    }
            return {
                "applicable": True,
                "reason": "Endpoint accepts unsafe method and has active sessions",
            }

        # 2. SQLi (SQL Injection) and XSS (Cross-Site Scripting)
        elif vuln_class in (VulnClass.SQLI, VulnClass.XSS):
            # Rule 2.1: Must accept query parameters or post keys (including SPA hash-fragment query strings)
            has_fragment_query = False
            if parsed.fragment and "?" in parsed.fragment:
                has_fragment_query = True

            has_params = (
                bool(parsed.query)
                or has_fragment_query
                or bool(payload.get("body"))
                # `data` is the POST-body key the sqli_scan/run_sqlmap path actually
                # uses (e.g. a JSON/form login body). Without it a login SQLi scan
                # dispatched with a body but no explicit method defaulted to GET and
                # was wrongly skipped as "no input vectors" — the JS-001 false
                # negative. A present body is an injectable vector regardless of verb.
                or bool(payload.get("data"))
                or bool(payload.get("query_keys"))
            )
            if not has_params and method == "GET":
                return {
                    "applicable": False,
                    "reason": f"GET endpoint lacks input parameters/query string; SQLi/XSS skipped.",
                }
            return {"applicable": True, "reason": "Endpoint has input vectors (query/body)"}

        # 3. SSRF (Server-Side Request Forgery)
        elif vuln_class == VulnClass.SSRF:
            # Rule 3.1: Parameters must suggest URLs or resource redirection
            query_keys = payload.get("query_keys") or []
            if parsed.query:
                from urllib.parse import parse_qsl

                query_keys.extend([k for k, _ in parse_qsl(parsed.query)])

            ssrf_key_patterns = [
                "url",
                "target",
                "redirect",
                "src",
                "href",
                "host",
                "domain",
                "callback",
                "webhook",
                "file",
                "path",
                "uri",
                "destination",
            ]
            is_ssrf_key = any(
                any(pat in k.lower() for pat in ssrf_key_patterns) for k in query_keys
            )
            if not is_ssrf_key:
                return {
                    "applicable": False,
                    "reason": f"Input parameters {query_keys} do not contain URL/redirection hints; SSRF skipped.",
                }
            return {
                "applicable": True,
                "reason": "Endpoint accepts parameters with URL/redirection hints",
            }

        # 4. JWT Abuse
        elif vuln_class == VulnClass.JWT_ABUSE:
            # Rule 4.1: Must have a JWT token present in headers or session payload
            token = payload.get("token") or payload.get("bearer_token")
            if user_sessions and not token:
                token = any(
                    getattr(s, "bearer_token", None) or getattr(s, "has_bearer", False)
                    for s in user_sessions
                )
            if not token:
                return {
                    "applicable": False,
                    "reason": "No JWT token/bearer session available; JWT scanning is not applicable.",
                }
            return {"applicable": True, "reason": "JWT token is available for testing"}

        # 5. Race Conditions
        elif vuln_class == VulnClass.RACE_CONDITION:
            # Rule 5.1: Method must be state-changing (POST, PUT, PATCH, DELETE)
            if method in ("GET", "HEAD", "OPTIONS", "TRACE"):
                return {
                    "applicable": False,
                    "reason": f"Safe HTTP method ({method}) cannot trigger state-concurrency race conditions.",
                }
            # Rule 5.2: Path must suggest sensitive transactions (payment, voucher, likes)
            race_patterns = [
                "pay",
                "checkout",
                "transfer",
                "coupon",
                "voucher",
                "like",
                "add",
                "submit",
                "apply",
                "redeem",
                "join",
            ]
            if not any(pat in path for pat in race_patterns):
                return {
                    "applicable": False,
                    "reason": f"Endpoint path ({path}) does not suggest transactional state concurrency.",
                }
            return {
                "applicable": True,
                "reason": "Transactional endpoint accepting state-changing method",
            }

        # 6. GraphQL Abuse
        elif vuln_class == VulnClass.GRAPHQL:
            # Rule 6.1: Path must suggest a GraphQL endpoint
            if "graphql" not in path and "gql" not in path:
                return {
                    "applicable": False,
                    "reason": f"Endpoint path ({path}) is not a GraphQL endpoint.",
                }
            return {"applicable": True, "reason": "Endpoint path contains GraphQL identifier"}

        # Default fallback: allow if no specific rules matched
        return {"applicable": True, "reason": "No specific applicability constraints violated"}
