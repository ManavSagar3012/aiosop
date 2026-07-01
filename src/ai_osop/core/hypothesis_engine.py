"""Graph-native hypothesis generation for AI-OSOP."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from ai_osop.core.models import Hypothesis
from ai_osop.memory.graph_memory import GraphMemory


class HypothesisEngine:
    """Infer testable security hypotheses from the engagement graph."""

    def __init__(self, graph_memory: GraphMemory, skill_engine: Optional[Any] = None):
        self.graph_memory = graph_memory
        self.skill_engine = skill_engine

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
        hypotheses.extend(
            self._authz_hypotheses(engagement_id, endpoints, seen_titles, focus)
        )
        hypotheses.extend(
            self._graphql_hypotheses(engagement_id, endpoints, seen_titles, focus)
        )
        hypotheses.extend(
            self._client_side_hypotheses(engagement_id, endpoints, seen_titles, focus)
        )
        hypotheses.extend(
            self._redirect_ssrf_hypotheses(engagement_id, endpoints, seen_titles, focus)
        )
        hypotheses.extend(
            self._workflow_hypotheses(engagement_id, endpoints, seen_titles, focus)
        )
        hypotheses.extend(
            self._cloud_hypotheses(engagement_id, endpoints, assets, seen_titles, focus)
        )

        if tech_counter:
            hypotheses.extend(
                self._technology_summary_hypotheses(
                    engagement_id, tech_counter, seen_titles, focus
                )
            )

        hypotheses.sort(key=lambda h: (-h.confidence, h.title.lower()))
        return hypotheses[:limit]

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
            if not self._contains_any(path, ["admin", "account", "profile", "tenant", "billing", "role"]):
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
                    recommended_skills=["gql_discover_schema", "gql_test_authorization", "gql_batch_abuse"],
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
                    recommended_skills=["extract_har_api_inventory", "detect_secrets_in_js", "extract_endpoints_from_js"],
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
            if not self._contains_any(path, ["checkout", "cart", "order", "coupon", "pay", "invoice", "refund", "transfer"]):
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
                    recommended_skills=["map_business_process", "violate_invariant", "test_race_condition"],
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
        cloud_keywords = ["aws", "s3", "gcp", "azure", "cloudfront", "lambda", "k8s", "kubernetes", "bucket", "iam"]
        asset_text = " ".join(
            " ".join(self._normalize_strings([a.get("value", ""), a.get("source", ""), a.get("type", "")]))
            for a in assets
        ).lower()
        if not any(k in asset_text for k in cloud_keywords) and not any(
            any(k in " ".join(self._normalize_strings(ep.get("technologies", []))) for k in cloud_keywords)
            for ep in endpoints
        ):
            return out
        title = "Cloud exposure or trust-relationship abuse may be reachable from the discovered surface"
        if title.lower() not in seen_titles:
            target = str(endpoints[0].get("id") if endpoints else (assets[0].get("id") if assets else ""))
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
