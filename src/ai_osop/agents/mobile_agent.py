"""
Mobile Analysis Agent
Specialized for mobile-BACKEND API security over HTTP, deep links, and
client-side logic.

Scope honesty (capability = "http_api_only"): this agent tests the mobile
backend API surface over HTTP. It does NOT decompile APK/IPA binaries or
perform on-device static analysis — anything that genuinely requires client
binary / device tooling (certificate pinning, root/jailbreak detection,
on-device secret storage) is reported as `not_tested` with a real reason
rather than a fabricated result.

What IS real here:
  * Deep-link analysis statically inspects the ACTUAL links supplied to the
    task: each link is parsed and its query/fragment parameters are checked
    for sensitive material (tokens, OTPs, credentials) carried in the URL — a
    real account-takeover / leakage vector.
  * Mobile-API testing sends REAL HTTP requests (async httpx) against the
    mobile backend and confirms every finding with an OBJECTIVE HTTP response
    oracle (status code / response body), never an LLM opinion:
      - a supposedly protected mobile endpoint served anonymously (2xx with no
        client/app auth header or session),
      - sensitive fields returned to an unauthenticated mobile client,
      - debug / version / actuator / .env endpoints exposed.
  * Traffic interception requires an out-of-band on-device MITM proxy this
    agent does not control, so that path reports its real (unavailable) status
    instead of claiming success.
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import structlog

from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task

logger = structlog.get_logger(__name__)

# Parameter names that should never travel inside a deep-link URL. Carrying
# these in a link exposes them via referrer leakage, history, logs, and
# inter-app intent interception.
SENSITIVE_PARAM_PATTERNS = re.compile(
    r"(?i)\b("
    r"token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"otp|one[_-]?time|code|auth|authorization|session|sid|"
    r"password|passwd|pwd|secret|api[_-]?key|apikey|key|"
    r"jwt|bearer|reset|activation|verify|verification|nonce|"
    r"credential|signature|sig"
    r")\b"
)

# Flows where a leaked parameter is especially dangerous (account takeover).
HIGH_RISK_FLOW_HINTS = ("reset", "verify", "activation", "login", "oauth", "magic", "confirm")

# Response-body field names that must never be returned to an UNAUTHENTICATED
# mobile client. Matched as JSON/dict keys (name followed by ':' or '=') so a
# passing mention in free text does not trip the oracle.
SENSITIVE_FIELD_PATTERNS = re.compile(
    r'(?i)["\']?\b('
    r"password|passwd|pwd|ssn|social[_-]?security|"
    r"credit[_-]?card|card[_-]?number|cardnumber|cvv|cvc|"
    r"api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|private[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|session[_-]?token|auth[_-]?token|"
    r"bank[_-]?account|account[_-]?number|routing[_-]?number|passport|"
    r"tax[_-]?id|date[_-]?of[_-]?birth|dob"
    r')\b["\']?\s*[:=]'
)

# Well-known debug / diagnostic / config endpoints that a mobile backend should
# never expose to anonymous clients. A 2xx here is an objective info-disclosure.
DEFAULT_DEBUG_PATHS = (
    "/actuator",
    "/actuator/env",
    "/actuator/heapdump",
    "/debug",
    "/api/debug",
    "/trace",
    "/.env",
    "/server-status",
    "/api/version",
    "/version",
)

# Debug paths whose exposure is high-severity (secrets / internals) vs merely
# informational (a plain version string).
_DEBUG_HIGH_RISK_TOKENS = ("actuator", "env", "heapdump", "debug", "trace", "server-status")


class MobileAnalysisAgent(BaseAgent):
    """
    Mobile Analysis Agent
    Focuses on: Deep Links (static parameter-leakage analysis) and mobile API
    traffic posture. Findings are derived only from the links actually supplied.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.VULN_ANALYSIS

    # Per-request HTTP timeout for mobile-API probing.
    HTTP_TIMEOUT_SECONDS = 15.0

    def supports_task_type(self, task_type: str) -> bool:
        return task_type in [
            "analyze_deep_links",
            "intercept_mobile_traffic",
            "test_mobile_api",
        ]

    async def _setup_resources(self) -> None:
        """Initialize mobile analysis resources."""
        self.analyzed_deep_links: List[str] = []

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute mobile analysis task."""
        task_type = task.type
        payload = task.payload or {}

        if task_type == "analyze_deep_links":
            return await self._analyze_deep_links(payload)
        elif task_type == "intercept_mobile_traffic":
            return await self._intercept_traffic(payload)
        elif task_type == "test_mobile_api":
            return await self._test_mobile_api(payload)
        else:
            return {"status": "error", "message": f"Unknown task type {task_type}"}

    def _analyze_link(self, link: str) -> Optional[Dict[str, Any]]:
        """Statically analyze a single deep link. Returns a finding dict or None.

        Real analysis: parse the link and flag any sensitive parameter actually
        present in its query string or fragment. Nothing is invented — the
        reported parameter and value-presence come from the supplied link.
        """
        try:
            parsed = urlparse(link)
        except Exception:  # noqa: BLE001 - malformed input is simply not a finding
            return None

        # Collect params from both query and fragment (deep links often use #).
        candidates: Dict[str, List[str]] = {}
        if parsed.query:
            candidates.update(parse_qs(parsed.query, keep_blank_values=True))
        if parsed.fragment and "=" in parsed.fragment:
            candidates.update(parse_qs(parsed.fragment, keep_blank_values=True))

        sensitive_params = [k for k in candidates if SENSITIVE_PARAM_PATTERNS.search(k)]
        if not sensitive_params:
            return None

        scheme_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower()
        flow = next(
            (h for h in HIGH_RISK_FLOW_HINTS if h in scheme_path or h in link.lower()), None
        )
        severity = "high" if flow else "medium"

        return {
            "type": "sensitive_param_in_deep_link",
            "link": link,
            "sensitive_params": sensitive_params,
            "flow": flow,
            "severity": severity,
            "risk": (
                "Sensitive value transmitted inside a deep-link URL. Such values "
                "leak via referrers, browser/app history, logs, and inter-app "
                "intent interception"
                + (f"; in a '{flow}' flow this enables account takeover." if flow else ".")
            ),
        }

    async def _analyze_deep_links(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Statically analyze the supplied Android/iOS deep links for leakage."""
        bundle_id = payload.get("bundle_id")
        links = payload.get("links", []) or []

        try:
            await self.think(
                f"Statically analyzing {len(links)} deep link(s)"
                + (f" for {bundle_id}" if bundle_id else "")
                + " for sensitive parameters carried in the URL.",
                ["mobile_security", "deep_link_analysis"],
            )
        except Exception as e:  # noqa: BLE001 - reasoning is best-effort
            logger.debug("mobile_reasoning_skipped", error=str(e))

        findings: List[Dict[str, Any]] = []
        for link in links:
            if not isinstance(link, str):
                continue
            self.analyzed_deep_links.append(link)
            finding = self._analyze_link(link)
            if finding:
                findings.append(finding)

        return {
            "status": "success",
            "analyzed_count": len([l for l in links if isinstance(l, str)]),
            "findings": findings,
            "findings_count": len(findings),
        }

    async def _intercept_traffic(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Report mobile API traffic-interception posture.

        Genuine interception of mobile traffic requires an on-device/proxy MITM
        setup (e.g. mitmproxy + a rooted/jailbroken device or emulator with the
        CA installed) that this agent does not control. Rather than claiming an
        active interception that isn't happening, report the real status so the
        operator can wire up a proxy out-of-band.
        """
        endpoint = payload.get("endpoint")
        proxy = payload.get("proxy")  # operator-supplied MITM proxy, if any

        try:
            await self.think(
                f"Assessing mobile API traffic posture for {endpoint}.",
                ["mobile_api_security", "traffic_interception"],
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("mobile_reasoning_skipped", error=str(e))

        return {
            "status": "success",
            "interception_active": bool(proxy),
            "endpoint": endpoint,
            "note": (
                "Interception is active via the supplied proxy."
                if proxy
                else "No interception proxy configured; mobile traffic capture "
                "requires an out-of-band on-device MITM setup. Reporting real "
                "status rather than a simulated capture."
            ),
        }

    # ─────────────────── real mobile-backend API testing ───────────────────

    def _make_client(self, headers: Optional[Dict[str, str]] = None) -> httpx.AsyncClient:
        """Build the async HTTP client used for mobile-API probing.

        Isolated into one method so tests can substitute an ``httpx.MockTransport``
        (offline, deterministic) without patching module internals — the real
        request/response path still runs.
        """
        base_headers = {"User-Agent": "AI-OSOP-Mobile/1.0 (okhttp/4.12.0)"}
        if headers:
            base_headers.update(headers)
        return httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.HTTP_TIMEOUT_SECONDS,
            headers=base_headers,
        )

    @staticmethod
    def _join(base: str, path: str) -> str:
        """Resolve an endpoint that may be a full URL or a path against base."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(base.rstrip("/") + "/", path.lstrip("/"))

    async def _probe(
        self, url: str, headers: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """GET ``url`` and return an objective response snapshot, or None on a
        network/transport error (which is inconclusive, never a finding)."""
        try:
            async with self._make_client(headers=headers) as client:
                resp = await client.get(url)
                return {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text,
                }
        except Exception as e:  # noqa: BLE001 - transport errors are inconclusive
            logger.warning("mobile_api_probe_failed", url=url, error=str(e))
            return None

    async def _test_mobile_api(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Test the mobile BACKEND API surface over HTTP with objective oracles.

        Payload:
            base_url   (required) mobile API origin, e.g. https://api.example.com
            endpoints  list of protected mobile endpoints (paths or full URLs)
                       that should require client/app auth or a user session.
            debug_paths  optional override for the default debug/version probe set.

        Every finding is confirmed by an HTTP response oracle:
          * unauthenticated 2xx on a protected endpoint  -> access-control gap,
          * sensitive field keys in that anonymous body   -> data exposure,
          * 2xx on a debug/version/actuator/.env path     -> info disclosure.
        Capabilities that genuinely require the client binary/device (e.g.
        certificate pinning) are reported as `not_tested`, not fabricated.
        """
        base_url = payload.get("base_url") or payload.get("url") or payload.get("target")
        if not base_url:
            return {"status": "failed", "error": "test_mobile_api requires 'base_url'"}

        endpoints: List[str] = [e for e in (payload.get("endpoints") or []) if isinstance(e, str)]
        debug_paths: List[str] = [
            p for p in (payload.get("debug_paths") or DEFAULT_DEBUG_PATHS) if isinstance(p, str)
        ]

        try:
            await self.think(
                f"Testing mobile backend API {base_url} over HTTP for anonymous "
                f"access, unauthenticated data exposure, and exposed debug endpoints.",
                ["mobile_api_security", "traffic_interception"],
            )
        except Exception as e:  # noqa: BLE001 - reasoning is best-effort
            logger.debug("mobile_reasoning_skipped", error=str(e))

        findings: List[Dict[str, Any]] = []
        checks_run: List[str] = []

        # ---- (a)/(c)/(d) protected endpoints reachable without client auth ----
        if endpoints:
            checks_run.append("unauthenticated_endpoint_access")
            for ep in endpoints:
                url = self._join(base_url, ep)
                # Deliberately send NO client/app auth header and NO session.
                snap = await self._probe(url, headers=None)
                if snap is None:
                    continue
                code = snap["status_code"]
                if 200 <= code < 300:
                    findings.append(
                        {
                            "type": "unauthenticated_mobile_endpoint_access",
                            "endpoint": url,
                            "status_code": code,
                            "severity": "high",
                            "oracle": "HTTP 2xx returned with no client/app auth header or session",
                            "risk": (
                                "Mobile backend served a protected endpoint to an "
                                "anonymous client. Missing enforcement of the "
                                "client/app auth header (or user session) allows any "
                                "party to call this mobile-only API directly."
                            ),
                        }
                    )
                    # (d) sensitive data returned to an unauthenticated client.
                    matched = sorted(
                        {
                            m.group(1).lower()
                            for m in SENSITIVE_FIELD_PATTERNS.finditer(snap["body"] or "")
                        }
                    )
                    if matched:
                        findings.append(
                            {
                                "type": "sensitive_data_to_unauthenticated_client",
                                "endpoint": url,
                                "status_code": code,
                                "sensitive_fields": matched,
                                "severity": "critical",
                                "oracle": "sensitive field keys present in an anonymous 2xx response body",
                                "risk": (
                                    "Sensitive fields were returned to an unauthenticated "
                                    "mobile client, disclosing regulated/credential data "
                                    "without any authorization."
                                ),
                            }
                        )
                # 401/403 (or other non-2xx) => endpoint is enforcing auth: no finding.

        # ---- (b) debug / version / actuator / .env endpoints exposed ----
        if debug_paths:
            checks_run.append("debug_endpoint_exposure")
            for path in debug_paths:
                url = self._join(base_url, path)
                snap = await self._probe(url, headers=None)
                if snap is None:
                    continue
                if 200 <= snap["status_code"] < 300:
                    low = url.lower()
                    high_risk = any(tok in low for tok in _DEBUG_HIGH_RISK_TOKENS)
                    findings.append(
                        {
                            "type": "debug_endpoint_exposed",
                            "endpoint": url,
                            "status_code": snap["status_code"],
                            "severity": "high" if high_risk else "low",
                            "oracle": "HTTP 2xx on a diagnostic/config path",
                            "risk": (
                                "Debug/diagnostic endpoint reachable anonymously; may "
                                "leak internals, configuration, secrets, or memory dumps."
                                if high_risk
                                else "Version/status endpoint exposed; leaks build/version "
                                "information useful for targeting known CVEs."
                            ),
                        }
                    )

        return {
            "status": "success",
            "capability": "http_api_only",
            "base_url": base_url,
            "checks_run": checks_run,
            "findings": findings,
            "findings_count": len(findings),
            "not_tested": [
                {
                    "check": "certificate_pinning",
                    "reason": "requires_apk_tooling",
                    "detail": (
                        "Certificate pinning is enforced in the client binary and can "
                        "only be verified with the APK/IPA or an on-device MITM setup; "
                        "it cannot be tested server-side over HTTP."
                    ),
                },
                {
                    "check": "apk_static_analysis",
                    "reason": "requires_apk_tooling",
                    "detail": (
                        "APK/IPA decompilation and static secret/permission analysis are "
                        "out of scope for this HTTP-only agent."
                    ),
                },
            ],
        }

    async def _cleanup_resources(self) -> None:
        self.analyzed_deep_links.clear()
