"""Shared vulnerability taxonomy for the calibration feedback loop (P2b).

The hypothesis engine reasons in broad *attack-class categories* (authz, graphql,
client_side, ssrf_redirect, workflow, cloud, session). Submission outcomes, however,
arrive keyed by concrete *finding types* (idor, xss, ssrf, ...) from the bug-bounty
adapters. If those two vocabularies are not reconciled, calibration lookups
(``get_historical_success_rate(category)``) never match recorded outcomes and the
learning loop silently degrades to a no-op.

This module is the single reconciliation point: outcome ingestion maps each concrete
finding type onto the hypothesis-category vocabulary before persisting to the corpus,
so a confirmed IDOR outcome informs the confidence of the *authz* hypothesis class.
"""

from __future__ import annotations

# Canonical categories the hypothesis engine emits and scores against.
HYPOTHESIS_CATEGORIES = frozenset(
    {"authz", "graphql", "client_side", "ssrf_redirect", "workflow", "cloud", "session"}
)

# Concrete finding type -> hypothesis category. Keys are lower-cased finding types
# as they appear on OutcomeRecord.finding_type / findings. The AUTHORITATIVE keys are
# the actual VulnClass enum *.value* strings the codebase emits (src/ai_osop/core/
# config.py) plus the raw DiffAuthFinding category labels — verified against every
# live emitter, not aspirational synonyms. A few common synonyms are kept too, since
# extra keys are harmless. Anything unlisted falls through to its own value (so
# unmapped types still accumulate under their own key rather than being dropped).
#
# Deliberately UNMAPPED: injection-family types (sqli, rce, lfi, xxe, deserialization,
# ssti) — there is no injection hypothesis category among the seven, so they pass
# through and simply do not participate in calibration until such a category exists.
_FINDING_TYPE_TO_CATEGORY = {
    # --- authorization / access control -> authz ---
    "idor": "authz",
    "bola": "authz",
    "bfla": "authz",
    "broken_access_control": "authz",
    "privilege_escalation": "authz",
    "mass_assignment": "authz",           # VulnClass.MASS_ASSIGNMENT (vuln_agent)
    "privesc": "authz",                    # HackerOne classifier shorthand
    "ato": "authz",                        # account takeover — fundamentally an auth/authz compromise
    "authz": "authz",
    "authorization": "authz",
    # diff-auth raw category labels (DiffAuthFinding.category)
    "horizontal_pe": "authz",
    "vertical_pe": "authz",
    "tenant_escape": "authz",
    # --- client-side -> client_side ---
    "xss": "client_side",
    "stored_xss": "client_side",
    "reflected_xss": "client_side",
    "dom_xss": "client_side",
    "csrf": "client_side",
    "request_smuggling": "client_side",   # VulnClass.REQUEST_SMUGGLING (vuln_agent)
    "sast_sink": "client_side",           # codeql_agent raw vuln_type
    "client_side": "client_side",
    # --- ssrf / redirect / url handling -> ssrf_redirect ---
    "ssrf": "ssrf_redirect",
    "open_redirect": "ssrf_redirect",
    "redirect": "ssrf_redirect",
    "ssrf_redirect": "ssrf_redirect",
    # --- graphql -> graphql ---
    "graphql": "graphql",
    "graphql_security": "graphql",        # VulnClass.GRAPHQL_SECURITY (graphql_agent — the real emitter)
    "graphql_batch": "graphql",
    "graphql_batch_abuse": "graphql",
    # --- business logic / workflow / race -> workflow ---
    "race_condition": "workflow",         # VulnClass.RACE_CONDITION (vuln_agent)
    "business_logic": "workflow",
    "workflow_bypass": "workflow",        # diff-auth raw category label
    "rate_limit": "workflow",
    "workflow": "workflow",
    # --- cloud / infra -> cloud ---
    "cloud_vuln": "cloud",                # VulnClass.CLOUD_VULN
    "container_vuln": "cloud",            # VulnClass.CONTAINER_VULN
    "kubernetes_security": "cloud",       # VulnClass.KUBERNETES_SECURITY
    "serverless_security": "cloud",       # VulnClass.SERVERLESS_SECURITY
    "cloud": "cloud",
    "s3": "cloud",
    "metadata_ssrf": "cloud",
    "iam": "cloud",
    # --- session / token / auth -> session ---
    "jwt_abuse": "session",               # VulnClass.JWT_ABUSE (the real emitted value)
    "oauth2": "session",                  # VulnClass.OAUTH2
    "authentication_weakness": "session",  # VulnClass.AUTHENTICATION_WEAKNESS
    "jwt": "session",
    "session": "session",
    "session_fixation": "session",
    "token": "session",
}


def category_for_finding_type(finding_type: str) -> str:
    """Map a concrete finding type onto the hypothesis-category vocabulary.

    Unknown/unmapped types (including the live-sync placeholder ``"unknown"``) pass
    through unchanged, so they still accumulate ground truth under their own key —
    they simply won't align with a hypothesis category until a mapping is added.
    """
    if not finding_type:
        return "unknown"
    return _FINDING_TYPE_TO_CATEGORY.get(finding_type.strip().lower(), finding_type.strip().lower())
