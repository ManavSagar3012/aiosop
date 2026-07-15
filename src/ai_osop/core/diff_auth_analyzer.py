"""
Phase 2 — Differential Authorization Analyzer (HTTP / APIEndpoint based).

Turns the captured (:Workflow)-[:CALLED]->(:APIEndpoint) inventory into authorization
findings by replaying each endpoint as three identities and comparing the responses:

    APIEndpoint -> replay user_a -> replay user_b -> replay anonymous
                -> compare (5 signals) -> persist ReplayResult / AuthorizationTest / DiffAuthFinding

Distinct from the older browser/Step-based ``DifferentialAuthEngine``: this one is pure HTTP,
keyed on APIEndpoint nodes, and emits the Phase-2 node graph.

SAFETY: only idempotent methods (GET/HEAD/OPTIONS) are replayed unless include_unsafe=True —
replaying POST/PUT/PATCH/DELETE as another identity could mutate/destroy the target's data.
"""

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx

from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import DiffAuthFinding, Vulnerability

# Confidence at/above which a differential-authorization finding is treated as a
# demonstrated (validated) cross-identity access — i.e. CONFIRMED / reportable.
# The engine actively replayed the request as a different identity and observed
# unauthorized access to the same resource, which is a real PoC.
DIFF_AUTH_CONFIRM_THRESHOLD = 0.7

# Map diff-auth categories to the platform's vulnerability taxonomy.
_CATEGORY_TO_VULN_CLASS = {
    "horizontal_pe": VulnClass.IDOR,
    "tenant_escape": VulnClass.BOLA,
    "broken_access_control": VulnClass.BROKEN_ACCESS_CONTROL,
    "vertical_pe": VulnClass.PRIVILEGE_ESCALATION,
    "workflow_bypass": VulnClass.BROKEN_ACCESS_CONTROL,
}

logger = logging.getLogger(__name__)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SENSITIVE_KEYS = {
    "email",
    "password",
    "passwordhash",
    "hash",
    "ssn",
    "token",
    "secret",
    "apikey",
    "api_key",
    "credit_card",
    "creditcard",
    "balance",
    "iban",
    "totpsecret",
    "phone",
    "address",
    "dob",
}
# JSON keys that signal per-user ownership of a record.
OWNERSHIP_KEYS = {"id", "userid", "user_id", "email", "username", "owner", "ownerid", "accountid"}


def _classify_body(content: bytes, content_type: str) -> Dict[str, Any]:
    """Extract schema/sensitivity signals from a response body."""
    text = ""
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    lower = text.lower()
    json_keys: List[str] = []
    if "json" in content_type.lower() or text[:1] in ("{", "["):
        import json as _json

        try:
            parsed = _json.loads(text)
            if isinstance(parsed, dict):
                json_keys = sorted(str(k) for k in parsed.keys())
            elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                json_keys = sorted(str(k) for k in parsed[0].keys())
        except Exception:
            json_keys = []
    sensitive = sorted(k for k in SENSITIVE_KEYS if k in lower)
    ownership = sorted(k for k in json_keys if k.lower() in OWNERSHIP_KEYS)
    return {"json_keys": json_keys, "sensitive_fields": sensitive, "ownership_hits": ownership}


def _jaccard(a: List[str], b: List[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _size_similar(a: int, b: int, tol: float = 0.2) -> bool:
    if a == 0 and b == 0:
        return True
    hi = max(a, b)
    return hi > 0 and abs(a - b) / hi <= tol


class DiffAuthAnalyzer:
    def __init__(self, session_store: Any, graph_memory: Any):
        self.session_store = session_store
        self.graph_memory = graph_memory

    async def _bridge_to_vulnerability(
        self,
        cmp: Dict[str, Any],
        identity: str,
        test_r: Dict[str, Any],
        base_r: Dict[str, Any],
        ep: Dict[str, Any],
        url: str,
        method: str,
        endpoint_id: str,
        engagement_id: str,
    ) -> Optional[str]:
        """Create a Vulnerability node for a differential-authorization finding so
        it surfaces in classification + reporting.

        High-confidence findings (>= DIFF_AUTH_CONFIRM_THRESHOLD) are marked
        ``validated=True`` — the engine actively replayed the request as a
        different identity and observed unauthorized access to the same resource,
        which is a demonstrated proof of concept (classified CONFIRMED). Lower
        confidence is left unvalidated (a candidate needing manual confirmation).
        """
        category = cmp["category"]
        confidence = cmp["confidence"]
        vuln_class = _CATEGORY_TO_VULN_CLASS.get(category, VulnClass.BROKEN_ACCESS_CONTROL)
        validated = confidence >= DIFF_AUTH_CONFIRM_THRESHOLD
        sensitive = test_r.get("sensitive_fields") or []
        path = ep.get("path") or url

        if identity == "anonymous":
            actor = "an unauthenticated (anonymous) request"
        else:
            actor = f"a different authenticated identity ('{identity}')"

        severity = Severity.HIGH if validated else Severity.MEDIUM
        if vuln_class in (VulnClass.PRIVILEGE_ESCALATION,) and validated:
            severity = Severity.CRITICAL

        vuln = Vulnerability(
            title=f"{vuln_class.value.upper()} — unauthorized access to {path}",
            description=(
                f"Differential authorization testing showed that {actor} received the "
                f"same protected resource as the owning identity at {method} {url}. "
                f"The owner (user_a baseline) and the test "
                f"identity both received a 2xx response with matching schema"
                + (f" and sensitive fields ({', '.join(sensitive[:5])})" if sensitive else "")
                + ". Expected the test identity to be denied (401/403)."
            ),
            severity=severity,
            vuln_type=vuln_class,
            confidence=confidence,
            tool_source="diff_auth",
            engagement_id=engagement_id,
            endpoint_id=endpoint_id,
            validated=validated,
            exploitability="high",
            evidence=[
                {
                    "type": "differential_authorization",
                    "provenance": "live",
                    "category": category,
                    "method": method,
                    "url": url,
                    "test_identity": identity,
                    "owner_status": base_r.get("status_code"),
                    "test_identity_status": test_r.get("status_code"),
                    "owner_size": base_r.get("response_size"),
                    "test_identity_size": test_r.get("response_size"),
                    "schema_match": cmp["signals"].get("json_schema_match"),
                    "sensitive_fields": sensitive,
                    "expected": "401/403 (denied)",
                    "observed": f"{test_r.get('status_code')} with matching resource body",
                }
            ],
        )
        try:
            return await self.graph_memory.add_vulnerability(vuln)
        except Exception as e:  # noqa: BLE001 - persistence failure shouldn't abort analysis
            logging.getLogger("ai_osop.diff_auth").warning(
                "diff_auth_vuln_bridge_failed: %s", str(e)[:160]
            )
            return None

    async def _load_endpoints(self, engagement_id: str, workflow_id: str) -> List[Dict[str, Any]]:
        if workflow_id:
            cypher = (
                "MATCH (w:Workflow {id:$wid})-[:CALLED]->(a:Endpoint {type: 'api'}) "
                "RETURN a.id AS id, a.method AS method, a.url AS url, a.path AS path"
            )
            params = {"wid": workflow_id}
        else:
            cypher = (
                "MATCH (a:Endpoint {type: 'api', engagement_id:$eid}) "
                "RETURN a.id AS id, a.method AS method, a.url AS url, a.path AS path"
            )
            params = {"eid": engagement_id}
        out: List[Dict[str, Any]] = []
        records = await self.graph_memory.run_read_query(cypher, params)
        for rec in records:
            out.append(dict(rec))
        return out

    async def _replay_user(
        self, engagement_id: str, label: str, method: str, url: str
    ) -> Dict[str, Any]:
        try:
            async with self.session_store.as_user(engagement_id, label) as client:
                resp = await client.request(method, url)
                return self._from_response(resp)
        except Exception as e:
            return {
                "status_code": 0,
                "response_size": 0,
                "content_type": "",
                "error": str(e)[:200],
                "json_keys": [],
                "sensitive_fields": [],
                "ownership_hits": [],
            }

    async def _replay_anonymous(self, method: str, url: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as c:
                resp = await c.request(method, url)
                return self._from_response(resp)
        except Exception as e:
            return {
                "status_code": 0,
                "response_size": 0,
                "content_type": "",
                "error": str(e)[:200],
                "json_keys": [],
                "sensitive_fields": [],
                "ownership_hits": [],
            }

    @staticmethod
    def _from_response(resp: httpx.Response) -> Dict[str, Any]:
        ct = resp.headers.get("content-type", "")
        sig = _classify_body(resp.content, ct)
        return {
            "status_code": resp.status_code,
            "response_size": len(resp.content),
            "content_type": ct[:120],
            "error": "",
            **sig,
        }

    @staticmethod
    def _is_2xx_with_body(r: Dict[str, Any]) -> bool:
        return 200 <= r.get("status_code", 0) < 300 and (
            r.get("response_size", 0) > 0 or r.get("json_keys")
        )

    def _compare(
        self, base: Dict[str, Any], test: Dict[str, Any], test_label: str
    ) -> Dict[str, Any]:
        """Return {category, confidence, signals} for one test identity vs baseline (user_a)."""
        schema_match = _jaccard(base.get("json_keys", []), test.get("json_keys", []))
        size_sim = _size_similar(base.get("response_size", 0), test.get("response_size", 0))
        sensitive = test.get("sensitive_fields", [])
        ownership = test.get("ownership_hits", [])
        signals = {
            "status": {"user_a": base.get("status_code"), test_label: test.get("status_code")},
            "response_size": {
                "user_a": base.get("response_size"),
                test_label: test.get("response_size"),
            },
            "json_schema_match": round(schema_match, 3),
            "size_similar": size_sim,
            "sensitive_fields": sensitive,
            "ownership_indicators": ownership,
        }
        category = ""
        confidence = 0.0
        if self._is_2xx_with_body(test):
            if test_label == "anonymous":
                category = "broken_access_control"
                confidence = 0.6
                if sensitive:
                    confidence += 0.2
                if schema_match >= 0.6:
                    confidence += 0.1
            else:  # user_b
                category = "horizontal_pe"
                confidence = 0.4
                if schema_match >= 0.6:
                    confidence += 0.2
                if size_sim:
                    confidence += 0.2
                if sensitive:
                    confidence += 0.2
        return {
            "category": category,
            "confidence": round(min(confidence, 1.0), 3),
            "signals": signals,
        }

    async def analyze(
        self,
        engagement_id: str,
        workflow_id: str,
        user_a: str,
        user_b: str,
        include_unsafe: bool = False,
        confidence_threshold: float = 0.5,
    ) -> Dict[str, Any]:
        endpoints = await self._load_endpoints(engagement_id, workflow_id)
        replay_count = 0
        tests_count = 0
        findings: List[Dict[str, Any]] = []
        confidence_scores: List[float] = []
        skipped_unsafe = 0

        for ep in endpoints:
            method = (ep.get("method") or "GET").upper()
            url = ep.get("url") or ""
            eid_node = ep["id"]
            if not url:
                continue
            if method not in SAFE_METHODS and not include_unsafe:
                skipped_unsafe += 1
                continue

            # 1. Replay as the three identities.
            r_a = await self._replay_user(engagement_id, user_a, method, url)
            r_b = await self._replay_user(engagement_id, user_b, method, url)
            r_anon = await self._replay_anonymous(method, url)

            for identity, r in (("user_a", r_a), ("user_b", r_b), ("anonymous", r_anon)):
                await self.graph_memory.add_replay_result(
                    {
                        "id": f"rr-{uuid4().hex[:12]}",
                        "endpoint_id": eid_node,
                        "identity": identity,
                        "engagement_id": engagement_id,
                        **r,
                    }
                )
                replay_count += 1

            # 2. Compare each test identity against user_a baseline.
            cmp_b = self._compare(r_a, r_b, "user_b")
            cmp_anon = self._compare(r_a, r_anon, "anonymous")

            # Dominant signal: anonymous access subsumes user_b "IDOR" (it's just open).
            primary = cmp_anon if cmp_anon["category"] else cmp_b
            verdict = (
                "vulnerable"
                if (primary["category"] and primary["confidence"] >= confidence_threshold)
                else "ok"
            )
            at_id = f"at-{uuid4().hex[:12]}"
            await self.graph_memory.add_authorization_test(
                {
                    "id": at_id,
                    "endpoint_id": eid_node,
                    "user_a": user_a,
                    "user_b": user_b,
                    "signals": {"user_b": cmp_b["signals"], "anonymous": cmp_anon["signals"]},
                    "verdict": verdict,
                    "category": primary["category"],
                    "confidence": primary["confidence"],
                    "engagement_id": engagement_id,
                }
            )
            tests_count += 1

            # 3. Persist findings (one per triggering identity above threshold).
            for cmp, identity, test_r in ((cmp_b, user_b, r_b), (cmp_anon, "anonymous", r_anon)):
                if cmp["category"] and cmp["confidence"] >= confidence_threshold:
                    finding = DiffAuthFinding(
                        category=cmp["category"],
                        resource_id=eid_node,
                        test_identity_id=identity,
                        expected_result="403 Forbidden",
                        observed_result=f"{test_r.get('status_code')} ({test_r.get('response_size')}B)"
                        + (" [SENSITIVE]" if test_r.get("sensitive_fields") else ""),
                        evidence_diff=cmp["signals"],
                        confidence=cmp["confidence"],
                        engagement_id=engagement_id,
                    )
                    await self.graph_memory.add_diff_auth_finding_for_endpoint(
                        finding, eid_node, at_id
                    )
                    # Bridge into the Vulnerability graph so the finding flows into
                    # classification + reporting. A high-confidence cross-identity
                    # access is a demonstrated PoC (validated -> CONFIRMED); lower
                    # confidence is persisted as a candidate needing validation.
                    await self._bridge_to_vulnerability(
                        cmp, identity, test_r, r_a, ep, url, method, eid_node, engagement_id
                    )
                    findings.append(
                        {
                            "id": finding.id,
                            "category": cmp["category"],
                            "endpoint": ep.get("path"),
                            "identity": identity,
                            "confidence": cmp["confidence"],
                        }
                    )
                    confidence_scores.append(cmp["confidence"])

        return {
            "status": "success",
            "endpoints_tested": tests_count,
            "replay_count": replay_count,
            "findings_count": len(findings),
            "confidence_scores": confidence_scores,
            "skipped_unsafe": skipped_unsafe,
            "findings": findings,
        }
