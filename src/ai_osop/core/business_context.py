"""Business Context Engine — semantic endpoint categorization.

The assessment identifies a critical gap: AI-OSOP treats all endpoints as
flat strings. A human researcher looks at /api/v2/tenant/billing/invoice
and immediately knows: "This handles billing for multi-tenant orgs —
test BOLA, price tampering, and step-skipping."

This module categorizes endpoints by business domain (payment, auth,
admin, file-processing, user-management) and assigns a criticality score
(1-10). The reasoning loop + value engine use this to prioritize
high-impact endpoints over static assets.

This is the "Orientation" phase the assessment says is missing: instead
of just observing raw endpoint strings, the system now builds a semantic
mental model of the target's business purpose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Business domain categories with their criticality score (1-10) and
# the path patterns that map to each category.
_BUSINESS_DOMAINS = [
    {
        "category": "payment",
        "criticality": 10,
        "patterns": ["payment", "checkout", "billing", "invoice", "pay", "stripe",
                      "transaction", "order", "cart", "purchase", "currency",
                      "wallet", "balance", "transfer", "deposit", "withdraw"],
        "description": "Payment/financial processing — highest impact (money flow)",
    },
    {
        "category": "authentication",
        "criticality": 9,
        "patterns": ["login", "signin", "signup", "register", "logout", "auth",
                      "oauth", "saml", "sso", "mfa", "2fa", "verify", "token",
                      "session", "password", "reset", "forgot"],
        "description": "Authentication — account takeover potential",
    },
    {
        "category": "admin",
        "criticality": 9,
        "patterns": ["admin", "administrator", "manage", "dashboard", "console",
                      "control", "panel", "root", "super", "operator", "staff",
                      "internal", "backoffice"],
        "description": "Administrative interface — privilege escalation target",
    },
    {
        "category": "user_management",
        "criticality": 8,
        "patterns": ["user", "account", "profile", "member", "customer", "tenant",
                      "organization", "employee", "contact", "address"],
        "description": "User data management — PII + IDOR surface",
    },
    {
        "category": "file_processing",
        "criticality": 7,
        "patterns": ["upload", "download", "file", "attachment", "import", "export",
                      "document", "media", "image", "avatar", "photo", "export",
                      "backup", "restore"],
        "description": "File processing — upload→RCE, stored XSS, path traversal",
    },
    {
        "category": "api_data",
        "criticality": 6,
        "patterns": ["api", "graphql", "rest", "v1", "v2", "v3", "data", "resource",
                      "object", "entity", "query", "search", "filter"],
        "description": "API data endpoints — injection + authorization surface",
    },
    {
        "category": "config_debug",
        "criticality": 8,
        "patterns": ["config", "setting", "env", "debug", "test", "dev", "staging",
                      "actuator", "health", "status", "info", "metrics", "env",
                      "swagger", "openapi", "api-docs", ".env", ".git"],
        "description": "Configuration/debug — information disclosure + RCE",
    },
    {
        "category": "redirect",
        "criticality": 5,
        "patterns": ["redirect", "return", "callback", "next", "goto", "dest",
                      "destination", "url", "to", "out", "link", "ref"],
        "description": "Redirect/SSRF surface — open redirect + OAuth chaining",
    },
    {
        "category": "static_asset",
        "criticality": 1,
        "patterns": [".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico",
                      ".woff", ".ttf", "static", "assets", "public", "dist"],
        "description": "Static asset — minimal attack surface",
    },
]


@dataclass
class EndpointContext:
    """Semantic business context for an endpoint."""
    url: str
    path: str
    category: str
    criticality: int  # 1-10
    description: str
    matched_patterns: List[str] = field(default_factory=list)
    recommended_tests: List[str] = field(default_factory=list)
    business_invariants: List[str] = field(default_factory=list)


def categorize_endpoint(url: str, path: str = "", params: Optional[List[str]] = None) -> EndpointContext:
    """Categorize an endpoint by its business domain.

    Analyzes the URL path + parameters against known business domain patterns
    and returns an EndpointContext with the category, criticality score,
    recommended tests, and business invariants to check.

    This is the "Orientation" step: the system builds a semantic understanding
    of what the endpoint DOES, not just what string it matches.
    """
    path_lower = (path or url).lower()
    params_lower = [p.lower() for p in (params or [])]
    full_text = path_lower + " " + " ".join(params_lower)

    best_category = "unknown"
    best_criticality = 3  # default: low-medium
    best_description = "Uncategorized endpoint — no business domain pattern matched."
    best_patterns: List[str] = []

    for domain in _BUSINESS_DOMAINS:
        matched = [p for p in domain["patterns"] if p in full_text]
        if matched:
            # If this domain matched more patterns or has higher criticality,
            # it wins.
            if len(matched) > len(best_patterns) or (
                len(matched) == len(best_patterns)
                and domain["criticality"] > best_criticality
            ):
                best_category = domain["category"]
                best_criticality = domain["criticality"]
                best_description = domain["description"]
                best_patterns = matched

    # Generate recommended tests based on the category
    recommended = _get_recommended_tests(best_category)

    # Generate business invariants to check
    invariants = _get_business_invariants(best_category, params or [])

    return EndpointContext(
        url=url,
        path=path or url,
        category=best_category,
        criticality=best_criticality,
        description=best_description,
        matched_patterns=best_patterns,
        recommended_tests=recommended,
        business_invariants=invariants,
    )


def _get_recommended_tests(category: str) -> List[str]:
    """Get recommended security tests for a business category."""
    _TESTS = {
        "payment": [
            "price_tampering", "negative_quantity", "currency_confusion",
            "coupon_reuse", "race_condition", "step_skipping",
            "idors", "mass_assignment",
        ],
        "authentication": [
            "jwt_abuse", "saml_bypass", "oauth_redirect", "mfa_bypass",
            "session_fixation", "password_reset_poisoning", "brute_force",
        ],
        "admin": [
            "idor", "mass_assignment", "authz_bypass", "privilege_escalation",
            "command_injection", "ssti", "path_traversal",
        ],
        "user_management": [
            "idor", "mass_assignment", "xss", "sqli", "authz_bypass",
            "user_enumeration", "pii_exposure",
        ],
        "file_processing": [
            "file_upload_rce", "stored_xss", "path_traversal", "xxe",
            "zip_slip", "ssrf",
        ],
        "api_data": [
            "sqli", "idor", "mass_assignment", "nosql_injection",
            "graphql_abuse", "rate_limit_bypass", "ssrf",
        ],
        "config_debug": [
            "info_disclosure", "actuator_abuse", "env_file_exposure",
            "debug_mode", "swagger_exposure",
        ],
        "redirect": [
            "open_redirect", "ssrf", "oauth_token_theft", "header_injection",
        ],
        "static_asset": [],
    }
    return _TESTS.get(category, [])


def _get_business_invariants(category: str, params: List[str]) -> List[str]:
    """Generate business invariants to verify for this category."""
    invariants: List[str] = []
    params_lower = [p.lower() for p in params]

    if category == "payment":
        invariants.append("Total price must be positive and match server-side calculation")
        invariants.append("Quantity must be a positive integer")
        if any("discount" in p or "coupon" in p for p in params_lower):
            invariants.append("Discount/coupon can only be applied once per transaction")
        if any("currency" in p for p in params_lower):
            invariants.append("Currency must match the merchant's accepted currencies")

    if category == "authentication":
        invariants.append("Authentication state must be verified before granting access")
        if any("mfa" in p or "2fa" in p for p in params_lower):
            invariants.append("MFA must be completed before session is fully authenticated")

    if category == "admin":
        invariants.append("Administrative actions must require admin-level authorization")
        invariants.append("Admin endpoints must not be accessible with user-level tokens")

    if category == "user_management":
        invariants.append("User must not access another user's resources without authorization")
        if any("role" in p or "admin" in p for p in params_lower):
            invariants.append("Role/admin flag must not be settable via mass assignment")

    return invariants


def batch_categorize(endpoints: List[Dict[str, Any]]) -> List[EndpointContext]:
    """Categorize a batch of endpoints from the graph.

    Each endpoint dict should have at least 'url' and optionally 'path',
    'query_keys', and 'parameters'.
    """
    results = []
    for ep in endpoints:
        url = ep.get("url", "")
        path = ep.get("path", "")
        params = list(ep.get("query_keys") or []) + list(ep.get("parameters") or [])
        ctx = categorize_endpoint(url, path, params)
        results.append(ctx)
    # Sort by criticality descending so the highest-value endpoints come first
    results.sort(key=lambda c: c.criticality, reverse=True)
    return results
