"""Graph-native hypothesis generation for AI-OSOP."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

import structlog

from ai_osop.core.models import Hypothesis
from ai_osop.memory.graph_memory import GraphMemory

logger = structlog.get_logger("ai_osop.hypothesis_engine")


class HypothesisEngine:
    """Infer testable security hypotheses from the engagement graph."""

    def __init__(
        self,
        graph_memory: GraphMemory,
        skill_engine: Optional[Any] = None,
        session_memory: Optional[Any] = None,
    ):
        self.graph_memory = graph_memory
        self.skill_engine = skill_engine
        # Optional: when session_memory is wired, hypothesis confidence is
        # recalibrated against the empirical success rate of each category (P2b
        # feedback loop), so categories that historically pan out rank higher and
        # get tested first. Left off in minimal setups so generation stays pure.
        self.session_memory = session_memory
        self._calibrator = None
        if session_memory is not None:
            try:
                from ai_osop.core.calibration_engine import ConfidenceCalibrationEngine

                self._calibrator = ConfidenceCalibrationEngine(
                    session_memory=session_memory, skill_engine=skill_engine
                )
            except Exception as e:  # noqa: BLE001 - calibration is advisory, never fatal
                logger.warning("calibration_engine_init_failed", error=str(e))
                self._calibrator = None

    async def generate_hypotheses(
        self, engagement_id: str, focus: str = "", limit: int = 8
    ) -> List[Hypothesis]:
        nodes = await self.graph_memory.get_all_nodes_for_engagement(engagement_id)
        edges = await self.graph_memory.get_all_edges_for_engagement(engagement_id)
        endpoints = await self.graph_memory.run_read_query(
            """
            MATCH (e:Endpoint {engagement_id: $engagement_id})
            RETURN e.id AS id, e.url AS url, e.path AS path, e.method AS method,
                   e.type AS type, e.technologies AS technologies, e.parameters AS parameters,
                   e.query_keys AS query_keys, e.body_schema_keys AS body_schema_keys,
                   e.auth_required AS auth_required, e.auth_class AS auth_class,
                   e.status_code AS status_code, e.workflow_id AS workflow_id
            """,
            {"engagement_id": engagement_id},
        )
        assets = await self.graph_memory.run_read_query(
            """
            MATCH (a:Asset {engagement_id: $engagement_id})
            RETURN a.id AS id, a.value AS value, a.type AS type, a.source AS source,
                   a.metadata AS metadata, a.confidence AS confidence
            """,
            {"engagement_id": engagement_id},
        )

        existing = await self.graph_memory.get_hypotheses_by_engagement(engagement_id)
        seen_titles = {str(item.get("title", "")).lower() for item in existing}

        tech_counter = Counter()
        for ep in endpoints:
            tech_counter.update(self._normalize_strings(ep.get("technologies", [])))
            tech_counter.update(self._normalize_strings(ep.get("query_keys", [])))
            tech_counter.update(self._normalize_strings(ep.get("body_schema_keys", [])))
            tech_counter.update(self._normalize_strings(ep.get("path", "")))

        hypotheses: List[Hypothesis] = []
        hypotheses.extend(self._authz_hypotheses(engagement_id, endpoints, seen_titles, focus))
        hypotheses.extend(self._graphql_hypotheses(engagement_id, endpoints, seen_titles, focus))
        hypotheses.extend(
            self._client_side_hypotheses(engagement_id, endpoints, seen_titles, focus)
        )
        hypotheses.extend(
            self._redirect_ssrf_hypotheses(engagement_id, endpoints, seen_titles, focus)
        )
        hypotheses.extend(self._workflow_hypotheses(engagement_id, endpoints, seen_titles, focus))
        hypotheses.extend(
            self._file_upload_hypotheses(engagement_id, endpoints, seen_titles, focus)
        )
        hypotheses.extend(self._saml_hypotheses(engagement_id, endpoints, seen_titles, focus))
        hypotheses.extend(self._websocket_hypotheses(engagement_id, endpoints, seen_titles, focus))
        hypotheses.extend(
            self._prototype_pollution_hypotheses(engagement_id, endpoints, seen_titles, focus)
        )
        hypotheses.extend(
            self._cloud_hypotheses(engagement_id, endpoints, assets, seen_titles, focus)
        )

        if tech_counter:
            hypotheses.extend(
                self._technology_summary_hypotheses(engagement_id, tech_counter, seen_titles, focus)
            )

        await self._calibrate(hypotheses)
        hypotheses.sort(key=lambda h: (-h.confidence, h.title.lower()))
        return hypotheses[:limit]

    async def _calibrate(self, hypotheses: List[Hypothesis]) -> None:
        """Recalibrate each hypothesis's confidence against empirical category
        success rates (P2b learning loop). In-place, best-effort — any failure
        leaves the raw heuristic confidence untouched so generation never breaks.

        The success rate is cached per category within a single generation pass to
        avoid redundant DB round-trips when several hypotheses share a category.
        """
        if self._calibrator is None or not hypotheses:
            return
        rate_cache: Dict[str, float] = {}
        for h in hypotheses:
            try:
                if h.category not in rate_cache:
                    rate_cache[h.category] = await self.session_memory.get_historical_success_rate(
                        h.category
                    )
                rate = rate_cache[h.category]
                # Only adjust when there is a real signal (rate != neutral 0.5);
                # otherwise keep the hand-tuned heuristic confidence. Reuse the
                # already-fetched rate (no second DB read, no TOCTOU gap).
                if rate != 0.5:
                    before = h.confidence
                    h.confidence = self._calibrator.calibrate_from_rate(
                        base_confidence=h.confidence, historical_rate=rate
                    )
                    logger.debug(
                        "hypothesis_confidence_calibrated",
                        category=h.category,
                        rate=round(rate, 4),
                        before=round(before, 4),
                        after=round(h.confidence, 4),
                    )
            except Exception as e:  # noqa: BLE001 - advisory; keep raw confidence
                logger.warning(
                    "hypothesis_calibration_failed",
                    category=getattr(h, "category", "?"),
                    error=str(e),
                )
                continue

    async def generate_and_persist(
        self, engagement_id: str, focus: str = "", limit: int = 8
    ) -> List[Hypothesis]:
        hypotheses = await self.generate_hypotheses(engagement_id, focus=focus, limit=limit)
        for hypothesis in hypotheses:
            await self.graph_memory.add_hypothesis(hypothesis)
        return hypotheses

    def _authz_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        for ep in endpoints:
            auth_required = bool(ep.get("auth_required"))
            auth_class = str(ep.get("auth_class") or "").lower()
            path = self._path(ep)
            if not (auth_required or auth_class in {"bearer", "cookie", "mixed"}):
                continue
            if not self._contains_any(
                path, ["admin", "account", "profile", "tenant", "billing", "role"]
            ):
                continue
            title = "Authorization bypass or IDOR across authenticated surface"
            if title.lower() in seen_titles:
                continue
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        f"Authenticated endpoint {self._url(ep)} may expose object-level or "
                        f"tenant-level authorization gaps. Cross-role replay and identifier "
                        f"swapping are likely to uncover BOLA/IDOR or privilege escalation."
                    ),
                    category="authz",
                    target_id=str(ep.get("id") or ""),
                    confidence=0.86,
                    supporting_entities=[str(ep.get("id") or ""), path, auth_class],
                    evidence=[{"signal": "authenticated_endpoint", "focus": focus}],
                    recommended_tests=[
                        "Replay the request as a lower-privilege identity",
                        "Swap object identifiers and tenant identifiers",
                        "Compare 200/403/404 behavior across roles",
                    ],
                    recommended_skills=["run_diff_auth_analysis", "capture_authenticated_surface"],
                    engagement_id=engagement_id,
                )
            )
            seen_titles.add(title.lower())
        return out

    def _graphql_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        for ep in endpoints:
            techs = self._normalize_strings(ep.get("technologies", []))
            path = self._path(ep)
            if "graphql" not in techs and "graphql" not in path:
                continue
            title = "GraphQL batching, alias abuse, or hidden mutation exposure"
            if title.lower() in seen_titles:
                continue
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        f"GraphQL surface at {self._url(ep)} can hide privileged operations "
                        f"and permit batch-based rate-limit bypass. Introspection, alias abuse, "
                        f"and authz replay should be prioritized."
                    ),
                    category="graphql",
                    target_id=str(ep.get("id") or ""),
                    confidence=0.9,
                    supporting_entities=[str(ep.get("id") or ""), path, "graphql"],
                    evidence=[{"signal": "graphql_surface", "focus": focus}],
                    recommended_tests=[
                        "Run schema introspection and compare against UI-observed operations",
                        "Probe for alias batching and per-request rate-limit bypass",
                        "Replay mutations under alternate identities",
                    ],
                    recommended_skills=[
                        "gql_discover_schema",
                        "gql_test_authorization",
                        "gql_batch_abuse",
                    ],
                    engagement_id=engagement_id,
                )
            )
            seen_titles.add(title.lower())
        return out

    def _client_side_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        for ep in endpoints:
            techs = self._normalize_strings(ep.get("technologies", []))
            path = self._path(ep)
            if not any(t in techs for t in ["react", "next.js", "nextjs", "webpack", "vite"]):
                continue
            title = "Client bundle or source-map leakage may expose hidden routes or secrets"
            if title.lower() in seen_titles:
                continue
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        f"Client-side delivery for {self._url(ep)} suggests the app may leak "
                        f"routes, internal APIs, or hardcoded secrets through bundles or source maps."
                    ),
                    category="client_side",
                    target_id=str(ep.get("id") or ""),
                    confidence=0.8,
                    supporting_entities=[str(ep.get("id") or ""), path] + techs[:4],
                    evidence=[{"signal": "client_bundle", "focus": focus}],
                    recommended_tests=[
                        "Fetch sourcemaps and inspect for internal API paths",
                        "Scan bundles for secrets and admin route references",
                        "Compare JS-discovered endpoints against graph inventory",
                    ],
                    recommended_skills=[
                        "extract_har_api_inventory",
                        "detect_secrets_in_js",
                        "extract_endpoints_from_js",
                    ],
                    engagement_id=engagement_id,
                )
            )
            seen_titles.add(title.lower())
        return out

    def _redirect_ssrf_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        keywords = ["url", "redirect", "callback", "return", "next", "dest", "continue", "webhook"]
        for ep in endpoints:
            path = self._path(ep)
            query_keys = self._normalize_strings(ep.get("query_keys", []))
            body_keys = self._normalize_strings(ep.get("body_schema_keys", []))
            signal_keys = set(query_keys + body_keys)
            if not any(self._contains_any(key, keywords) for key in signal_keys | {path}):
                continue
            title = "URL-bearing parameters may support SSRF, open redirect, or token leakage"
            if title.lower() in seen_titles:
                continue
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        f"Endpoint {self._url(ep)} accepts URL-like inputs or redirect-style "
                        f"parameters. That combination frequently enables SSRF, open redirect, "
                        f"or OAuth / token-handling abuse chains."
                    ),
                    category="ssrf_redirect",
                    target_id=str(ep.get("id") or ""),
                    confidence=0.78,
                    supporting_entities=[str(ep.get("id") or ""), path] + sorted(signal_keys)[:4],
                    evidence=[{"signal": "url_like_parameter", "focus": focus}],
                    recommended_tests=[
                        "Probe with internal and metadata URLs",
                        "Check redirect response handling and host normalization",
                        "Attempt callback and webhook-controlled destinations",
                    ],
                    recommended_skills=["ssrf_scan", "ssrf_metadata_chain", "oauth_audit"],
                    engagement_id=engagement_id,
                )
            )
            seen_titles.add(title.lower())
        return out

    def _workflow_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        for ep in endpoints:
            path = self._path(ep)
            if not self._contains_any(
                path,
                ["checkout", "cart", "order", "coupon", "pay", "invoice", "refund", "transfer"],
            ):
                continue
            title = "Business-logic or race-condition abuse may bypass workflow invariants"
            if title.lower() in seen_titles:
                continue
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        f"Workflow endpoint {self._url(ep)} implies stateful transitions and "
                        f"monetary or entitlement impact. Elite bounty workflows should test "
                        f"duplicate actions, replay, and state-machine skips."
                    ),
                    category="workflow",
                    target_id=str(ep.get("id") or ""),
                    confidence=0.83,
                    supporting_entities=[str(ep.get("id") or ""), path],
                    evidence=[{"signal": "business_flow", "focus": focus}],
                    recommended_tests=[
                        "Replay the same mutation or action concurrently",
                        "Skip intermediate workflow states",
                        "Check idempotency-key and coupon reuse handling",
                    ],
                    recommended_skills=[
                        "map_business_process",
                        "violate_invariant",
                        "test_race_condition",
                    ],
                    engagement_id=engagement_id,
                )
            )
            seen_titles.add(title.lower())
        return out

    def _file_upload_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        keywords = [
            "upload",
            "attachment",
            "avatar",
            "import",
            "media",
            "document",
            "photo",
            "profile-image",
        ]
        for ep in endpoints:
            path = self._path(ep)
            query_keys = self._normalize_strings(ep.get("query_keys", []))
            body_keys = self._normalize_strings(ep.get("body_schema_keys", []))
            signal_keys = set(query_keys + body_keys)
            if not any(self._contains_any(key, keywords) for key in signal_keys | {path}):
                continue
            title = "File-upload surface may permit unrestricted / dangerous file upload"
            if title.lower() in seen_titles:
                continue
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        f"Endpoint {self._url(ep)} accepts file uploads. Weak extension / "
                        f"content-type validation would let an attacker upload executable or "
                        f"active content and have it served back — a classic high-impact bug."
                    ),
                    category="file_upload",
                    target_id=str(ep.get("id") or ""),
                    confidence=0.79,
                    supporting_entities=[str(ep.get("id") or ""), path] + sorted(signal_keys)[:4],
                    evidence=[{"signal": "file_upload_endpoint", "focus": focus}],
                    recommended_tests=[
                        "Upload html/svg/php with a marker and retrieve it",
                        "Check served content-type and executable extension handling",
                        "Attempt double-extension and path-traversal filenames",
                    ],
                    recommended_skills=["file_upload_scan"],
                    engagement_id=engagement_id,
                )
            )
            seen_titles.add(title.lower())
        return out

    def _saml_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        keywords = [
            "saml",
            "samlresponse",
            "/acs",
            "acs",
            "sso",
            "assertion",
            "idp",
            "single-sign-on",
        ]
        for ep in endpoints:
            path = self._path(ep)
            query_keys = self._normalize_strings(ep.get("query_keys", []))
            body_keys = self._normalize_strings(ep.get("body_schema_keys", []))
            techs = self._normalize_strings(ep.get("technologies", []))
            signal_keys = set(query_keys + body_keys + techs)
            if not any(self._contains_any(key, keywords) for key in signal_keys | {path}):
                continue
            title = "SAML/SSO assertion consumer may accept forged or tampered assertions"
            if title.lower() in seen_titles:
                continue
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        f"Endpoint {self._url(ep)} exposes a SAML/SSO assertion-consumer surface. "
                        f"Missing or weak signature validation enables XML signature wrapping, "
                        f"unsigned-assertion acceptance, replay, or comment-injection impersonation."
                    ),
                    category="saml_sso",
                    target_id=str(ep.get("id") or ""),
                    confidence=0.8,
                    supporting_entities=[str(ep.get("id") or ""), path] + sorted(signal_keys)[:4],
                    evidence=[{"signal": "saml_acs_endpoint", "focus": focus}],
                    recommended_tests=[
                        "Replay a tampered SAMLResponse with a swapped NameID",
                        "Attempt XML signature wrapping and unsigned-assertion variants",
                        "Test assertion replay and comment-injection on the NameID",
                    ],
                    recommended_skills=["saml_scan"],
                    engagement_id=engagement_id,
                )
            )
            seen_titles.add(title.lower())
        return out

    def _websocket_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        keywords = ["ws://", "wss://", "socket.io", "websocket", "/ws", "/socket"]
        for ep in endpoints:
            path = self._path(ep)
            url = self._url(ep)
            ep_type = str(ep.get("type") or "").lower()
            techs = self._normalize_strings(ep.get("technologies", []))
            haystack = [url, path, ep_type] + techs
            if not any(self._contains_any(h, keywords) for h in haystack):
                continue
            title = "WebSocket endpoint may be vulnerable to CSWSH or missing origin/auth checks"
            if title.lower() in seen_titles:
                continue
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        f"WebSocket endpoint {url} was discovered. Sockets frequently skip "
                        f"Origin validation (Cross-Site WebSocket Hijacking), authenticate weakly, "
                        f"or run over cleartext ws:// — all confirmable with behavioural oracles."
                    ),
                    category="websocket",
                    target_id=str(ep.get("id") or ""),
                    confidence=0.78,
                    supporting_entities=[str(ep.get("id") or ""), path] + techs[:4],
                    evidence=[{"signal": "websocket_endpoint", "focus": focus}],
                    recommended_tests=[
                        "Attempt a handshake from a foreign Origin with victim cookies (CSWSH)",
                        "Send privileged messages on an unauthenticated socket",
                        "Check for cleartext ws:// transport of a wss:// site",
                    ],
                    recommended_skills=["websocket_scan"],
                    engagement_id=engagement_id,
                )
            )
            seen_titles.add(title.lower())
        return out

    def _prototype_pollution_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        node_stack = ["node", "nodejs", "node.js", "express", "koa", "hapi", "fastify", "nest"]
        merge_keywords = [
            "merge",
            "assign",
            "extend",
            "deepmerge",
            "clone",
            "__proto__",
            "constructor",
            "settings",
            "config",
            "options",
        ]
        for ep in endpoints:
            path = self._path(ep)
            query_keys = self._normalize_strings(ep.get("query_keys", []))
            body_keys = self._normalize_strings(ep.get("body_schema_keys", []))
            techs = self._normalize_strings(ep.get("technologies", []))
            signal_keys = set(query_keys + body_keys)
            node_stack_hit = any(t in techs for t in node_stack)
            merge_surface_hit = any(
                self._contains_any(key, merge_keywords) for key in signal_keys | {path}
            )
            # A JSON-merge/object-assign surface, or a Node/Express stack, warrants it.
            if not (node_stack_hit or merge_surface_hit):
                continue
            title = (
                "JSON-merge surface on a Node/JS stack may enable server-side prototype pollution"
            )
            if title.lower() in seen_titles:
                continue
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        f"Endpoint {self._url(ep)} ingests structured JSON on a JavaScript stack. "
                        f"Unsafe recursive merge/assign lets an attacker inject __proto__ / "
                        f"constructor.prototype properties, polluting the object prototype server-side."
                    ),
                    category="prototype_pollution",
                    target_id=str(ep.get("id") or ""),
                    confidence=0.75,
                    supporting_entities=[str(ep.get("id") or ""), path]
                    + (techs[:2] + sorted(signal_keys)[:2]),
                    evidence=[{"signal": "json_merge_surface", "focus": focus}],
                    recommended_tests=[
                        "Submit a __proto__ gadget then observe a payload-free probe",
                        "Try constructor.prototype status-override gadgets",
                        "Confirm the injected inherited property is reflected globally",
                    ],
                    recommended_skills=["prototype_pollution_scan"],
                    engagement_id=engagement_id,
                )
            )
            seen_titles.add(title.lower())
        return out

    def _cloud_hypotheses(
        self,
        engagement_id: str,
        endpoints: Sequence[Dict[str, Any]],
        assets: Sequence[Dict[str, Any]],
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        cloud_keywords = [
            "aws",
            "s3",
            "gcp",
            "azure",
            "cloudfront",
            "lambda",
            "k8s",
            "kubernetes",
            "bucket",
            "iam",
        ]
        asset_text = " ".join(
            " ".join(
                self._normalize_strings(
                    [a.get("value", ""), a.get("source", ""), a.get("type", "")]
                )
            )
            for a in assets
        ).lower()
        if not any(k in asset_text for k in cloud_keywords) and not any(
            any(
                k in " ".join(self._normalize_strings(ep.get("technologies", [])))
                for k in cloud_keywords
            )
            for ep in endpoints
        ):
            return out
        title = "Cloud exposure or trust-relationship abuse may be reachable from the discovered surface"
        if title.lower() not in seen_titles:
            target = str(
                endpoints[0].get("id") if endpoints else (assets[0].get("id") if assets else "")
            )
            out.append(
                Hypothesis(
                    title=title,
                    description=(
                        "The engagement graph already hints at cloud-adjacent infrastructure. "
                        "That makes metadata access, exposed buckets, and trust-policy abuse high-value."
                    ),
                    category="cloud",
                    target_id=target,
                    confidence=0.74,
                    supporting_entities=[a.get("id", "") for a in assets[:5]] or [target],
                    evidence=[{"signal": "cloud_keyword", "focus": focus}],
                    recommended_tests=[
                        "Enumerate metadata and credential exposure paths",
                        "Check bucket/object access controls and public-read posture",
                        "Review trust policies and cross-account assumptions",
                    ],
                    recommended_skills=["cloud_pentest", "probe_metadata", "analyze_iam"],
                    engagement_id=engagement_id,
                )
            )
        return out

    def _technology_summary_hypotheses(
        self,
        engagement_id: str,
        tech_counter: Counter,
        seen_titles: Set[str],
        focus: str,
    ) -> List[Hypothesis]:
        out: List[Hypothesis] = []
        if tech_counter.get("jwt") or tech_counter.get("authorization"):
            title = "JWT or session handling may enable impersonation or privilege escalation"
            if title.lower() not in seen_titles:
                out.append(
                    Hypothesis(
                        title=title,
                        description=(
                            "Repeated JWT / authorization signals in the graph justify explicit "
                            "token validation, audience checks, and replay / confusion testing."
                        ),
                        category="session",
                        target_id="graph",
                        confidence=0.72,
                        supporting_entities=["jwt", "authorization"],
                        evidence=[{"signal": "technology_summary", "focus": focus}],
                        recommended_tests=[
                            "Check alg/key confusion and token audience binding",
                            "Replay tokens across identities and tenants",
                        ],
                        recommended_skills=["jwt_scan", "run_diff_auth_analysis"],
                        engagement_id=engagement_id,
                    )
                )
        return out

    def _normalize_strings(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value.lower()]
        if isinstance(value, Iterable):
            out = []
            for item in value:
                if item is None:
                    continue
                out.append(str(item).lower())
            return out
        return [str(value).lower()]

    def _contains_any(self, text: str, needles: Sequence[str]) -> bool:
        lowered = str(text).lower()
        return any(needle in lowered for needle in needles)

    def _url(self, ep: Dict[str, Any]) -> str:
        return str(ep.get("url") or ep.get("path") or ep.get("id") or "")

    def _path(self, ep: Dict[str, Any]) -> str:
        return str(ep.get("path") or ep.get("url") or ep.get("id") or "")
