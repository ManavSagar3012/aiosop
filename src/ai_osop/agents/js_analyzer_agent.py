"""
JS Analysis Agent
Analyzes client-side JavaScript bundles for secrets, endpoints, and routes
using REAL HTTP fetching and pattern detection.

No simulated/fabricated content: a JS bundle is fetched over the network
(scope-validated) before it is scanned, or pre-fetched content is supplied by
the caller. If neither a reachable URL nor content is available, the task
returns an honest empty result instead of inventing data.
"""

import hashlib
import math
import re
import uuid
from typing import Any, Dict, List, Optional, Pattern, Tuple

import httpx
import structlog

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
from ai_osop.core.models import Task, Vulnerability
from ai_osop.core.secret_verifier import STATUS_CONFIRMED_LIVE, STATUS_NOT_A_SECRET, assess_secret
from ai_osop.safety.scope import ScopeEnforcer

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Secret-detection ruleset.
#
# Each rule is (name, compiled-regex, severity, confidence). Patterns are drawn
# from well-known scanners (gitleaks / trufflehog) and tuned for low false
# positives. The capturing group (group 1 when present, else group 0) is the
# secret value used for evidence + masking. Generic / structural patterns carry
# lower confidence because they are noisier and need human triage.
# ---------------------------------------------------------------------------
SECRET_RULES: List[Tuple[str, Pattern[str], Severity, float]] = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), Severity.CRITICAL, 0.90),
    (
        "AWS Secret Access Key",
        re.compile(r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b"),
        Severity.CRITICAL,
        0.85,
    ),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), Severity.HIGH, 0.85),
    (
        "Google OAuth Client Secret",
        re.compile(r"\b(GOCSPX-[0-9A-Za-z_\-]{28})\b"),
        Severity.HIGH,
        0.85,
    ),
    (
        "GitHub Token",
        re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{36,251})\b"),
        Severity.CRITICAL,
        0.90,
    ),
    (
        "Slack Token",
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b"),
        Severity.HIGH,
        0.85,
    ),
    (
        "Stripe Live Secret Key",
        re.compile(r"\b(sk_live_[0-9A-Za-z]{24,})\b"),
        Severity.CRITICAL,
        0.90,
    ),
    (
        "Stripe Restricted Key",
        re.compile(r"\b(rk_live_[0-9A-Za-z]{24,})\b"),
        Severity.HIGH,
        0.85,
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----"),
        Severity.CRITICAL,
        0.95,
    ),
    (
        "JSON Web Token",
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
        Severity.MEDIUM,
        0.60,
    ),
    (
        "Mailgun API Key",
        re.compile(r"\b(key-[0-9a-f]{32})\b"),
        Severity.HIGH,
        0.70,
    ),
    (
        "Twilio API Key SID",
        re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
        Severity.HIGH,
        0.70,
    ),
    (
        "Generic Secret Assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|password|passwd)['\"]?\s*[:=]\s*"
            r"['\"]([0-9a-zA-Z\-_=+/.]{16,})['\"]"
        ),
        Severity.MEDIUM,
        0.50,
    ),
]

# Obvious placeholders that should never be reported as live secrets.
_PLACEHOLDER_TOKENS = (
    "your_",
    "example",
    "changeme",
    "change-me",
    "placeholder",
    "xxxxxx",
    "<",
    "{{",
    "test_key",
    "dummy",
    "sample",
    "redacted",
    "insert",
    "todo",
)

# Endpoint extraction: relative paths, absolute URLs, and template-literal routes.
_RELATIVE_PATH_RE = re.compile(r"['\"`](/[a-zA-Z0-9/_\-.]{2,})['\"`]")
_ABSOLUTE_URL_RE = re.compile(r"\b(https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[^\s'\"`<>)]*)?)")


def _shannon_entropy(value: str) -> float:
    """Shannon entropy (bits/char). High-entropy strings are more likely secrets."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    return any(tok in low for tok in _PLACEHOLDER_TOKENS)


# Markers indicating a value is intentionally public (analytics / client SDKs).
# Many providers ship a public, non-sensitive key in client JS by design
# (e.g. data-public-api-key, Stripe/Firebase publishable keys, public DSNs).
# Flagging these as "secrets" is a false positive — they grant no privileged
# access on their own and bounty programs treat them as informational.
_PUBLIC_KEY_MARKERS = (
    "public-api-key",
    "public_api_key",
    "publicapikey",
    "data-public",
    "publishable",
    "public-key",
    "public_key",
    "publickey",
    "client-id",
    "client_id",
    "clientid",
    "measurement-id",
    "measurement_id",
    "app-id",
)


def _in_public_context(context: str) -> bool:
    """True if the match context marks the value as an intentionally-public key."""
    low = context.lower()
    return any(m in low for m in _PUBLIC_KEY_MARKERS)


def _mask(secret: str) -> str:
    """Mask a secret for safe logging/titles: keep a short prefix, redact the rest."""
    if len(secret) <= 8:
        return secret[:2] + "***"
    return f"{secret[:6]}...{secret[-2:]}"


class JSAnalyzerAgent(BaseAgent):
    """
    JS Analysis Agent

    Extracts high-value information from client-side JavaScript bundles by
    fetching them over the network (scope-validated) and scanning for:
      - hardcoded secrets / API keys (multi-pattern, entropy-filtered)
      - API endpoints and routes (relative + absolute)

    Findings are real: every reported secret corresponds to a genuine pattern
    match in fetched (or caller-supplied) content, with the matched value and
    surrounding context captured as evidence.
    """

    # Maximum bytes to fetch per JS bundle (defensive against huge files).
    MAX_FETCH_BYTES = 8 * 1024 * 1024  # 8 MiB
    FETCH_TIMEOUT_SECONDS = 20.0

    @property
    def agent_type(self) -> AgentType:
        return AgentType.VULN_ANALYSIS

    def supports_task_type(self, task_type: str) -> bool:
        return task_type in (
            "analyze_js",
            "extract_endpoints_from_js",
            "detect_secrets_in_js",
        )

    async def _setup_resources(self) -> None:
        """Initialize JS resources."""
        self.discovered_endpoints: List[str] = []
        self._scope_manager: Optional[ScopeEnforcer] = None
        if self.ctx.scope is not None:
            try:
                self._scope_manager = ScopeEnforcer(self.ctx.scope)
            except Exception as e:  # noqa: BLE001 - scope optional for content-only tasks
                logger.warning("js_analyzer_scope_init_failed", error=str(e))

    # ------------------------------------------------------------------ routing
    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute JS analysis task."""
        task_type = task.type
        payload = task.payload or {}

        if task_type == "analyze_js":
            return await self._analyze_js(payload, do_endpoints=True, do_secrets=True)
        if task_type == "extract_endpoints_from_js":
            return await self._analyze_js(payload, do_endpoints=True, do_secrets=False)
        if task_type == "detect_secrets_in_js":
            return await self._analyze_js(payload, do_endpoints=False, do_secrets=True)
        return {"status": "error", "message": f"Unknown task type {task_type}"}

    # ------------------------------------------------------------------ fetching
    def _in_scope(self, url: str) -> bool:
        """Return True if url is in scope (or no scope is configured)."""
        if self._scope_manager is None:
            # No scope configured (e.g. content-only unit context): allow, but the
            # caller is responsible. Network fetches still go only to provided URLs.
            return True
        try:
            return self._scope_manager.validate_target(url)
        except (OutOfScopeError, ScopeValidationError) as e:
            logger.warning("js_analyzer_url_out_of_scope", url=url, error=str(e))
            return False

    async def _fetch_js(self, url: str) -> Optional[str]:
        """Fetch a JS bundle over HTTP. Returns text content or None on failure.

        Scope is validated before any network call so the agent never reaches
        out-of-scope hosts.
        """
        if not self._in_scope(url):
            return None
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.FETCH_TIMEOUT_SECONDS,
                headers={"User-Agent": "AI-OSOP-JSAnalyzer/1.0"},
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    logger.info("js_analyzer_fetch_non200", url=url, status=resp.status_code)
                    return None
                content = resp.text
                if len(content.encode("utf-8", "ignore")) > self.MAX_FETCH_BYTES:
                    content = content[: self.MAX_FETCH_BYTES]
                    logger.info("js_analyzer_fetch_truncated", url=url)
                return content
        except Exception as e:  # noqa: BLE001 - network errors are non-fatal
            logger.warning("js_analyzer_fetch_failed", url=url, error=str(e))
            return None

    async def _gather_sources(self, payload: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Resolve the set of (source_url, content) pairs to analyze.

        Accepts (in priority order): inline `content`, a single `url`, a list
        `urls`, or `targets`. Real content is fetched for any URL that lacks
        inline content. Never fabricates content.
        """
        sources: List[Tuple[str, str]] = []

        inline = payload.get("content")
        primary_url = payload.get("url") or payload.get("target") or payload.get("target_url")
        if inline:
            sources.append((primary_url or "inline://content", inline))

        urls: List[str] = []
        if primary_url and not inline:
            urls.append(primary_url)
        for u in payload.get("urls", []) or []:
            if u:
                urls.append(u)
        for u in payload.get("targets", []) or []:
            if u:
                urls.append(u)

        # De-dup while preserving order.
        seen = set()
        for u in urls:
            if u in seen:
                continue
            seen.add(u)
            content = await self._fetch_js(u)
            if content is not None:
                sources.append((u, content))
        return sources

    # ------------------------------------------------------------------ analysis
    def _extract_endpoints(self, content: str) -> List[str]:
        endpoints = set()
        for m in _RELATIVE_PATH_RE.finditer(content):
            endpoints.add(m.group(1))
        for m in _ABSOLUTE_URL_RE.finditer(content):
            endpoints.add(m.group(1))
        return sorted(endpoints)

    def _detect_secrets(self, content: str, source_url: str) -> List[Dict[str, Any]]:
        """Run the secret ruleset over content. Returns a list of finding dicts."""
        findings: List[Dict[str, Any]] = []
        seen_values = set()

        # SECRET_RULES are ordered specific-first, generic-last. Dedup by value
        # across all rules so each unique secret is reported once under its
        # most-specific matching rule (the generic assignment rule won't
        # re-report a value a specific rule already claimed).
        for name, regex, severity, confidence in SECRET_RULES:
            for m in regex.finditer(content):
                value = m.group(1) if m.groups() else m.group(0)
                if not value:
                    continue
                if value in seen_values:
                    continue
                seen_values.add(value)

                # Filter obvious placeholders and low-entropy noise for generic/
                # structural rules (private-key blocks and JWTs are exempt — their
                # structure is the signal).
                if _looks_like_placeholder(value):
                    continue
                if name in ("Generic Secret Assignment",) and _shannon_entropy(value) < 3.0:
                    continue

                start = max(0, m.start() - 60)
                end = min(len(content), m.end() + 60)
                context_snippet = content[start:end]

                # Suppress intentionally-public keys (e.g. data-public-api-key,
                # publishable keys, client IDs) for the generic rule — these are
                # public by design and are false positives as "secrets".
                if name == "Generic Secret Assignment" and _in_public_context(context_snippet):
                    continue

                findings.append(
                    {
                        "rule": name,
                        "value": value,
                        "masked": _mask(value),
                        "severity": severity,
                        "confidence": confidence,
                        "context": context_snippet,
                        "source_url": source_url,
                        "offset": m.start(),
                    }
                )
        return findings

    async def _persist_secret_finding(
        self, finding: Dict[str, Any], engagement_id: str
    ) -> Optional[str]:
        """Create + persist a Vulnerability for a detected secret. Returns vuln id."""
        value = finding["value"]
        value_hash = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()
        source_url = finding["source_url"]

        # LIVENESS GATE (2026-07-05): classify the candidate through the shared secret
        # verifier (structural only — NO live probe from static JS analysis; liveness
        # is the job of the separate secret_liveness_scan task). This (a) drops
        # placeholders/non-secrets that slipped past the regex heuristics — a real
        # false-positive cut — and (b) keeps js_analyzer honest: a hardcoded secret in
        # shipped JS is a genuine EXPOSURE, but it is NOT a confirmed live credential
        # until probed, so it is emitted as unvalidated with a capped confidence rather
        # than as a high-confidence "confirmed secret" that a triager would reject.
        verdict = await assess_secret(value, secret_type=finding["rule"], allow_live_probe=False)
        if verdict.get("status") == STATUS_NOT_A_SECRET:
            logger.info("js_secret_dropped_not_a_secret", rule=finding["rule"])
            return None
        confirmed_live = verdict.get("status") == STATUS_CONFIRMED_LIVE
        # Unverified static exposure: cap confidence so it can't masquerade as validated.
        effective_conf = (
            finding["confidence"] if confirmed_live else min(finding["confidence"], 0.5)
        )

        vuln = Vulnerability(
            id=f"vuln-js-{uuid.uuid4().hex[:8]}",
            title=f"Hardcoded secret in JavaScript: {finding['rule']}",
            description=(
                f"A {finding['rule']} ({finding['masked']}) was detected in "
                f"client-side JavaScript at {source_url}. Hardcoded secrets in "
                f"shipped JS are retrievable by any user and frequently grant "
                f"access to backend services. Liveness: {verdict.get('status')}"
                + (
                    ""
                    if confirmed_live
                    else " — run secret_liveness_scan to confirm the credential is live before reporting."
                )
            ),
            severity=finding["severity"],
            vuln_type=VulnClass.OSINT_LEAK,
            confidence=effective_conf,
            validated=confirmed_live,
            tool_source="js_analyzer",
            engagement_id=engagement_id,
            exploitability="high" if finding["severity"] == Severity.CRITICAL else "medium",
            evidence=[
                {
                    "type": "js_secret_match",
                    "provenance": "live",
                    "rule": finding["rule"],
                    "file": source_url,
                    "match_masked": finding["masked"],
                    "value_sha256": value_hash,
                    "context": finding["context"],
                    "offset": finding["offset"],
                    "liveness_status": verdict.get("status"),
                    "provider": verdict.get("provider"),
                    "structural_valid": verdict.get("structural_valid"),
                }
            ],
        )
        try:
            vid = await self.ctx.graph_memory.add_vulnerability(vuln)
            return vid or vuln.id
        except Exception as e:  # noqa: BLE001 - persistence failure shouldn't abort scan
            logger.error("js_analyzer_persist_failed", error=str(e), rule=finding["rule"])
            return None

    async def _analyze_js(
        self, payload: Dict[str, Any], do_endpoints: bool, do_secrets: bool
    ) -> Dict[str, Any]:
        """Fetch and analyze JS bundle(s) for endpoints and/or secrets."""
        engagement_id = payload.get("engagement_id") or self.ctx.session_id

        sources = await self._gather_sources(payload)
        if not sources:
            # Honest empty result — no content fetched, nothing fabricated.
            logger.info("js_analyzer_no_sources", payload_keys=list(payload.keys()))
            return {
                "status": "success",
                "sources_analyzed": 0,
                "endpoints_found": 0,
                "endpoints": [],
                "vulnerabilities_created": 0,
                "finding_ids": [],
                "note": "No reachable JS URL or inline content provided; nothing analyzed.",
            }

        all_endpoints: set = set()
        finding_ids: List[str] = []
        secret_summary: List[Dict[str, Any]] = []

        for source_url, content in sources:
            if do_endpoints:
                eps = self._extract_endpoints(content)
                all_endpoints.update(eps)

            if do_secrets:
                detected = self._detect_secrets(content, source_url)
                for finding in detected:
                    vid = await self._persist_secret_finding(finding, engagement_id)
                    if vid:
                        finding_ids.append(vid)
                        secret_summary.append(
                            {
                                "rule": finding["rule"],
                                "masked": finding["masked"],
                                "severity": (
                                    finding["severity"].value
                                    if hasattr(finding["severity"], "value")
                                    else str(finding["severity"])
                                ),
                                "source_url": source_url,
                            }
                        )

        # Best-effort reasoning (never blocks results). Secrets are masked.
        try:
            await self.think(
                f"Analyzed {len(sources)} JS source(s). "
                f"Endpoints discovered: {len(all_endpoints)}. "
                f"Secrets detected: {len(finding_ids)}.",
                ["js_analysis", "secret_discovery"],
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("js_analyzer_reasoning_skipped", error=str(e))

        self.discovered_endpoints = sorted(all_endpoints)
        return {
            "status": "success",
            "sources_analyzed": len(sources),
            "endpoints_found": len(all_endpoints),
            "endpoints": sorted(all_endpoints),
            "vulnerabilities_created": len(finding_ids),
            "finding_ids": finding_ids,
            "secrets": secret_summary,
        }

    async def _cleanup_resources(self) -> None:
        self.discovered_endpoints = []
