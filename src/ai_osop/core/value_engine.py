"""Attack Surface Value Engine (Sprint 15A).

Scores discovered assets and endpoints 0-100 so downstream scanning spends its
finite budget on the highest-value targets first, instead of treating `/` and
`/admin` identically.

Design goals:
- Pure, deterministic, dependency-free (easy to unit-test and reason about).
- Heuristic but explainable: every score comes with the signals that produced it.
- Tuned for the kinds of targets AI-OSOP runs against, including fintech
  (payment/transfer/wallet paths score high).

The score is intentionally a heuristic prior, NOT ground truth — Sprint 16
(acceptance learning) is meant to fold real outcomes back into these weights.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Path-substring signals → (score floor, label). Highest matching floor wins,
# then modifiers (method, params) are added. Ordered roughly by value.
_PATH_SIGNALS = [
    # Critical control / secrets exposure
    ("/.env", 96, "env-file"),
    ("/.git", 95, "git-exposure"),
    ("/actuator", 92, "spring-actuator"),
    ("/admin", 95, "admin"),
    ("/administrator", 95, "admin"),
    ("/internal", 90, "internal"),
    ("/manage", 88, "management"),
    ("/console", 88, "console"),
    ("/debug", 90, "debug"),
    ("/config", 88, "config"),
    ("/backup", 88, "backup"),
    ("/swagger", 80, "api-docs"),
    ("/openapi", 80, "api-docs"),
    ("/graphql", 80, "graphql"),
    # Fintech / money movement (high value for targets like Syfe)
    ("/payment", 88, "payment"),
    ("/transfer", 90, "transfer"),
    ("/withdraw", 90, "withdraw"),
    ("/wallet", 85, "wallet"),
    ("/balance", 82, "balance"),
    ("/transaction", 82, "transaction"),
    ("/invest", 80, "invest"),
    ("/order", 75, "order"),
    ("/kyc", 80, "kyc"),
    # File handling
    ("/upload", 78, "upload"),
    ("/import", 72, "import"),
    ("/export", 70, "export"),
    ("/download", 60, "download"),
    # User/account surface
    ("/user", 60, "user"),
    ("/account", 60, "account"),
    ("/profile", 58, "profile"),
    ("/settings", 55, "settings"),
    ("/me", 52, "self"),
    # Auth (interesting but typically hardened)
    ("/oauth", 60, "oauth"),
    ("/token", 60, "token"),
    ("/login", 50, "login"),
    ("/signin", 50, "login"),
    ("/auth", 52, "auth"),
    ("/register", 48, "register"),
    ("/signup", 48, "register"),
    ("/password", 55, "password"),
    ("/reset", 55, "reset"),
    # Generic API
    ("/api/", 62, "api"),
    ("/rest/", 60, "api"),
    ("/v1/", 55, "api-version"),
    ("/v2/", 55, "api-version"),
    ("/v3/", 55, "api-version"),
    # Search / query (injectable surface)
    ("/search", 45, "search"),
    ("/query", 45, "query"),
    ("/filter", 42, "filter"),
]

# Low-value static asset extensions.
_STATIC_EXT = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".map", ".webp", ".mp4", ".webm",
)

_STATE_CHANGING = {"POST", "PUT", "DELETE", "PATCH"}


def score_endpoint(
    url: str,
    method: str = "GET",
    status_code: Optional[int] = None,
    has_params: Optional[bool] = None,
    technologies: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Score a single endpoint 1-100. Returns {score, signals}.

    The score combines a base from the path signal, plus modifiers for
    state-changing methods, query/params (injectable surface), API-ness, and a
    penalty for obviously static assets.
    """
    signals: List[str] = []
    parsed = urlparse(url if "://" in url else f"http://{url}")
    path = (parsed.path or "/").lower()
    query = parsed.query or ""
    method = (method or "GET").upper()

    # Base from highest-floor path signal.
    base = 10
    for needle, floor, label in _PATH_SIGNALS:
        if needle in path and floor > base:
            base = floor
            best_label = label
    if base > 10:
        signals.append(best_label)
    elif path in ("", "/"):
        signals.append("root")
    else:
        signals.append("generic-path")

    score = base

    # Static asset penalty (overrides upward unless a strong path signal hit).
    if path.endswith(_STATIC_EXT) and base <= 25:
        score = 5
        signals.append("static-asset")
        return {"score": score, "signals": signals}

    # JS bundles: moderate — can leak routes/secrets (source-map territory).
    if path.endswith(".js") and base <= 25:
        score = max(score, 25)
        signals.append("js-bundle")

    # Modifiers
    if method in _STATE_CHANGING:
        score += 15
        signals.append(f"method:{method}")
    has_q = bool(query) if has_params is None else bool(has_params)
    if has_q:
        score += 12
        signals.append("has-params")
    if "/api/" in path or path.startswith("/api") or "/graphql" in path:
        score += 8
        signals.append("api-surface")
    if status_code is not None and status_code in (401, 403):
        # Protected resource → interesting (auth/authz testing).
        score += 10
        signals.append(f"protected:{status_code}")
    if technologies:
        tl = " ".join(technologies).lower()
        if any(t in tl for t in ("next.js", "react", "angular", "vue")):
            signals.append("spa")

    score = max(1, min(100, score))
    return {"score": score, "signals": signals}


def score_asset(value: str, asset_type: str = "domain") -> Dict[str, Any]:
    """Score an asset (host/domain) 1-100. Subdomains hinting at sensitive
    function (admin/api/internal/staging) score higher than the apex."""
    v = (value or "").lower()
    signals = [asset_type]
    score = 40
    for kw, s in (
        ("admin", 90), ("internal", 88), ("api", 70), ("staging", 65),
        ("dev", 60), ("test", 58), ("uat", 55), ("vpn", 75), ("git", 80),
        ("jenkins", 85), ("grafana", 75), ("kibana", 75),
    ):
        if kw in v:
            score = max(score, s)
            signals.append(kw)
    return {"score": min(100, score), "signals": signals}


def batch_endpoints_for_scan(
    endpoints: List[Dict[str, Any]],
    batch_size: int = 20,
    max_targets: int = 200,
    min_score: int = 0,
) -> List[List[str]]:
    """Value-order endpoints and split into bounded batches of URLs.

    This is the core of scan fan-out optimization (Sprint 15B): instead of one
    scan task per endpoint (which over-fans on 1,000+ endpoints), we take the
    top `max_targets` by value and chunk them into batches of `batch_size`,
    yielding a BOUNDED number of scan tasks that hit the highest-value targets
    first.

    Each endpoint dict needs at least {"url": ...}; optional method/status_code/
    has_params/technologies refine the score.
    """
    scored = []
    for ep in endpoints:
        url = ep.get("url")
        if not url:
            continue
        s = score_endpoint(
            url,
            method=ep.get("method", "GET"),
            status_code=ep.get("status_code"),
            has_params=ep.get("has_params"),
            technologies=ep.get("technologies"),
        )["score"]
        if s >= min_score:
            scored.append((s, url))

    # Highest value first; dedupe URLs preserving best score order.
    scored.sort(key=lambda x: x[0], reverse=True)
    seen = set()
    ordered_urls = []
    for _, url in scored:
        if url not in seen:
            seen.add(url)
            ordered_urls.append(url)

    ordered_urls = ordered_urls[:max_targets]
    return [ordered_urls[i : i + batch_size] for i in range(0, len(ordered_urls), batch_size)]
