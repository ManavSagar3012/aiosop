"""
V4.2A Differential Authorization Engine
Compares evidence across different identities to detect IDOR and privilege escalation.
"""

import json
from typing import Any, Dict, List, Optional

from ai_osop.core.models import DiffAuthFinding, Resource, Task
from ai_osop.memory.session_memory import SessionMemory


class DifferentialAuthEngine:
    """
    Compares evidence across identities to find authorization flaws.
    """

    def __init__(self, session_memory: SessionMemory):
        self.session_memory = session_memory

    async def compare(
        self,
        identity_a_evidence: Dict[str, Any],
        identity_b_evidence: Dict[str, Any],
        resource: Resource,
        expected_allowed: bool,
        anonymous_evidence: Optional[Dict[str, Any]] = None,
    ) -> Optional[DiffAuthFinding]:
        """
        Perform a differential analysis between two evidence artifacts.

        AIOSOP-AUDIT-2026-06-16 precision upgrade: a bare 2xx for identity B is NOT
        sufficient evidence of broken access control — that flags public resources,
        empty 200s, and static assets as IDOR (the #1 reason such reports are
        rejected at triage). This now requires *ownership proof* (B's response
        actually contains A's owned object) for high confidence, suppresses
        responses identical to an anonymous baseline (public resources), and emits a
        calibrated confidence with a manual-confirmation flag when proof is weak.
        Pass ``anonymous_evidence`` (the same endpoint fetched with no auth) to
        enable public-resource suppression.
        """
        # 1. Status and Basic Response Comparison
        status_a = identity_a_evidence.get("status_code", 200)
        status_b = identity_b_evidence.get("status_code", 200)

        # 2. JSON Body Comparison (Deep Diff)
        body_a = identity_a_evidence.get("body", {})
        body_b = identity_b_evidence.get("body", {})

        body_diff = self._diff_json(body_a, body_b)
        leakage_score = self._detect_leakage(body_b, resource)

        # 3. DOM / Semantic Comparison
        semantics_a = set(identity_a_evidence.get("semantics", []))
        semantics_b = set(identity_b_evidence.get("semantics", []))
        semantic_divergence = list(semantics_b - semantics_a)

        # 4. Precision signals
        ownership_proof = self._ownership_match(body_b, identity_a_evidence, resource)
        shared_with_anon = False
        if anonymous_evidence is not None:
            shared_with_anon = self._responses_equivalent(
                status_b,
                body_b,
                anonymous_evidence.get("status_code", 200),
                anonymous_evidence.get("body", {}),
            )

        category = "unknown"
        confidence = 0.0
        needs_manual = False

        # LOGIC 1: Unauthorized Success (Direct IDOR/PE)
        if not expected_allowed and status_b in [200, 201, 204]:
            # Suppress benign public resources: an anonymous client receives the same
            # response as B, and B shows no ownership of A's object and no extra
            # capability. That is a public endpoint, not broken access control.
            if shared_with_anon and not ownership_proof and not semantic_divergence:
                return None

            category = "horizontal_pe" if resource.owner_identity_id != "admin" else "vertical_pe"

            # Refine if cross-tenant
            if resource.metadata.get("tenant_id") and identity_b_evidence.get(
                "tenant_id"
            ) != resource.metadata.get("tenant_id"):
                category = "tenant_escape"

            # If semantic divergence also exists, it's a stronger indicator of PE
            if semantic_divergence:
                category = "unauthorized_action_visibility"
                confidence = max(confidence, 0.75)

            # Calibrate confidence by strength of evidence.
            if ownership_proof:
                confidence = max(confidence, 0.9)  # B demonstrably received A's owned object
            elif semantic_divergence:
                confidence = max(confidence, 0.75)  # B sees capability A's view lacks
            elif not confidence:
                confidence = 0.5  # bare 2xx, no ownership proof
                needs_manual = True
                category = f"{category}_unconfirmed"

        # LOGIC 2: Data Leakage (Even if allowed, check for sensitive fields)
        if leakage_score > 0.5:  # Lower threshold for better sensitivity
            if confidence < 0.8:  # Don't overwrite higher confidence direct access
                confidence = 0.8
                category = "pii_leakage"
            else:
                # Append to existing finding
                category = f"{category}_with_leakage"

        if confidence > 0:
            # R2 (2026-07-20): carry the raw request/response artifacts onto the
            # DiffAuthFinding so the downstream Vulnerability bridge and the
            # scorer can register a real 'request'/'response' pair. The evidence
            # dicts are the raw replay results; ``identity_b_evidence`` is the
            # test-identity's captured response (the unauthorized access proof).
            return DiffAuthFinding(
                category=category,
                resource_id=resource.id,
                test_identity_id=identity_b_evidence.get("user_label", "unknown"),
                expected_result="403 Forbidden" if not expected_allowed else "200 OK",
                observed_result=f"{status_b} {'(LEAK DETECTED)' if leakage_score > 0.5 else ''}",
                evidence_diff={
                    "status_diff": f"{status_a} vs {status_b}",
                    "json_diff": body_diff,
                    "semantic_divergence": semantic_divergence,
                    "leakage_score": leakage_score,
                    "ownership_proof": ownership_proof,
                    "compared_with_anonymous": anonymous_evidence is not None,
                    "shared_with_anonymous": shared_with_anon,
                    "needs_manual_confirmation": needs_manual,
                    # Raw replay evidence (request/response bytes when captured).
                    "request": identity_b_evidence.get("request") or identity_b_evidence.get(
                        "request_url"
                    ),
                    "response": identity_b_evidence.get("response", ""),
                },
                confidence=confidence,
                engagement_id=resource.engagement_id,
            )

        return None

    def _diff_json(self, a: Any, b: Any) -> Dict[str, Any]:
        """Simple JSON key diff."""
        if not isinstance(a, dict) or not isinstance(b, dict):
            return {"type_mismatch": True}

        keys_a = set(a.keys())
        keys_b = set(b.keys())

        return {
            "added": list(keys_b - keys_a),
            "removed": list(keys_a - keys_b),
            "changed_values": [k for k in keys_a & keys_b if a[k] != b[k]],
        }

    def _detect_leakage(self, body: Any, resource: Resource) -> float:
        """Detect if sensitive data related to the resource owner leaked."""
        if not isinstance(body, dict):
            return 0.0

        sensitive_keys = {
            "email",
            "password",
            "hash",
            "ssn",
            "token",
            "secret",
            "credit_card",
            "balance",
        }
        score = 0.0

        # 1. Key presence check
        body_str = str(body).lower()
        for key in sensitive_keys:
            if key in body_str:
                score += 0.2

        # 2. Resource value check (Reflection)
        if resource.value.lower() in body_str:
            score += 0.4

        return min(score, 1.0)

    def _ownership_match(
        self,
        body_b: Any,
        identity_a_evidence: Dict[str, Any],
        resource: Resource,
    ) -> bool:
        """True if B's response demonstrably contains data OWNED BY A.

        This is the triage-surviving signal that separates real cross-account access
        from a benign shared/public resource (AIOSOP-AUDIT-2026-06-16)."""
        body_str = str(body_b).lower()

        # 1. The object identifier A owns is reflected in B's response.
        #    PRECISION GUARD (benchmark 2026-07-04): a raw substring match on
        #    short/common values (a numeric id like "1", a path like "/") appears
        #    incidentally in almost any response, producing 0.9-confidence phantom
        #    IDORs — the #1 triage-rejection shape. Only treat a substring hit as
        #    ownership proof when the value is DISTINCTIVE enough that incidental
        #    collision is implausible; genuine numeric-id ownership is still caught
        #    structurally by signal 3 (equal id-like fields in both responses).
        val = str(getattr(resource, "value", "") or "")
        if val and self._is_distinctive(val) and val.lower() in body_str:
            return True

        # 2. A's owner identity id is reflected (ignore the generic 'admin' marker).
        oid = str(getattr(resource, "owner_identity_id", "") or "")
        if oid and oid != "admin" and self._is_distinctive(oid) and oid.lower() in body_str:
            return True

        # 3. Owner-private fields present AND equal in both A's and B's responses,
        #    at ANY nesting depth. Real APIs wrap the object under data/result/etc
        #    (Juice Shop basket => {"data": {"id": .., "UserId": ..}}); a top-level-
        #    only check under-scored genuine IDORs to 0.5 (benchmark 2026-07-04).
        a_ids = self._collect_id_fields(identity_a_evidence.get("body", {}))
        b_ids = self._collect_id_fields(body_b)
        for k, v in a_ids.items():
            if v not in (None, "", 0) and b_ids.get(k) == v:
                return True
        return False

    _ID_KEYS = frozenset(
        {
            "id",
            "email",
            "account_id",
            "user_id",
            "userid",
            "owner",
            "owner_id",
            "ownerid",
            "ref",
            "uuid",
            "bid",
            "basketid",
            "orderid",
            "order_id",
        }
    )

    @classmethod
    def _collect_id_fields(cls, body: Any, _depth: int = 0) -> Dict[str, Any]:
        """Collect owner-identifying id-like fields from a response body at any
        depth. Used as a structural ownership signal that survives API wrappers."""
        out: Dict[str, Any] = {}
        if _depth > 6:
            return out
        if isinstance(body, dict):
            for k, v in body.items():
                if isinstance(v, (dict, list)):
                    for kk, vv in cls._collect_id_fields(v, _depth + 1).items():
                        out.setdefault(kk, vv)
                elif str(k).lower() in cls._ID_KEYS and v not in (None, "", 0):
                    out.setdefault(str(k).lower(), v)
        elif isinstance(body, list):
            for item in body[:20]:
                for kk, vv in cls._collect_id_fields(item, _depth + 1).items():
                    out.setdefault(kk, vv)
        return out

    @staticmethod
    def _is_distinctive(value: str) -> bool:
        """A value whose incidental appearance in an unrelated body is implausible.

        Distinctive => long enough AND not a bare number (emails, UUIDs, opaque
        tokens qualify; ids like "1"/"42" and paths like "/" do not — those must be
        confirmed structurally via matching id-like fields, not raw substring).
        """
        v = value.strip()
        if len(v) < 8:
            return False
        if v.isdigit():
            return False
        return any(c.isalpha() for c in v)

    @staticmethod
    def _canonical(body: Any) -> str:
        """Stable serialization for response equivalence checks."""
        try:
            return json.dumps(body, sort_keys=True, default=str)
        except Exception:
            return str(body)

    def _responses_equivalent(self, status1: int, body1: Any, status2: int, body2: Any) -> bool:
        """True if two responses are effectively identical (same status + same body).
        Used to detect that B's response equals an anonymous client's — i.e. a public
        resource rather than broken access control."""
        if status1 != status2:
            return False
        return self._canonical(body1) == self._canonical(body2)

    # ---- AIOSOP-AUDIT-2026-06-16: verification stage + read-only safety ----

    # Replay/diff-auth must never send a state-changing request (program rules:
    # "read-only observation and replay", "no modification of data").
    SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

    def is_safe_method(self, method: Optional[str]) -> bool:
        """True if the HTTP method is read-only and therefore safe to replay."""
        return str(method or "GET").upper() in self.SAFE_METHODS

    def assert_distinct_identities(
        self,
        evidence_a: Dict[str, Any],
        evidence_b: Dict[str, Any],
        a_self: Optional[Dict[str, Any]] = None,
        b_self: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Confirm A and B are genuinely DIFFERENT accounts — so a 'cross-account'
        finding is not just one account tested against itself. Strong evidence: their
        own self-identity responses (/me) carry different identity markers. Weak
        fallback: different user labels. Returns False when distinctness can't be
        positively confirmed (conservative)."""
        if isinstance(a_self, dict) and isinstance(b_self, dict):
            ba = a_self.get("body") if isinstance(a_self.get("body"), dict) else {}
            bb = b_self.get("body") if isinstance(b_self.get("body"), dict) else {}
            for k in ("id", "user_id", "account_id", "email", "sub", "username"):
                if k in ba and k in bb and ba[k] and bb[k]:
                    return ba[k] != bb[k]
        la, lb = evidence_a.get("user_label"), evidence_b.get("user_label")
        if la and lb:
            return la != lb
        return False

    def verify_finding(
        self,
        finding: DiffAuthFinding,
        evidence_a: Dict[str, Any],
        evidence_b: Dict[str, Any],
        a_self: Optional[Dict[str, Any]] = None,
        b_self: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Independent second-opinion check on a candidate finding BEFORE it is
        reported. A finding is verified only when all hold:
          1. A and B are confirmed distinct accounts;
          2. B's access is backed by ownership proof OR a capability divergence;
          3. it is not merely a public resource (identical to anonymous w/o ownership).
        Returns a verdict dict; never mutates the finding."""
        diff = finding.evidence_diff or {}
        ownership = bool(diff.get("ownership_proof"))
        semantic = bool(diff.get("semantic_divergence"))
        public = bool(diff.get("shared_with_anonymous"))

        distinct = self.assert_distinct_identities(evidence_a, evidence_b, a_self, b_self)

        reasons = []
        if not distinct:
            reasons.append("identities_not_confirmed_distinct")
        if public and not ownership:
            reasons.append("identical_to_anonymous_public_resource")
        if not (ownership or semantic):
            reasons.append("no_ownership_or_capability_evidence")

        verified = distinct and (ownership or semantic) and not (public and not ownership)
        return {
            "verified": verified,
            "distinct_identities": distinct,
            "ownership_proof": ownership,
            "public_resource": public and not ownership,
            "reasons": reasons,
        }

    async def run_differential_test(
        self, workflow_id: str, test_identities: List[str], engagement_id: str, orchestrator: Any
    ) -> List[DiffAuthFinding]:
        """
        Orchestrate a multi-identity differential test across an entire workflow.
        """
        all_findings = []

        # 1. Fetch the baseline workflow and its steps from the graph
        # We sort by 'order' to ensure we replay the journey correctly
        cypher = """
        MATCH (w:Workflow {id: $wid})-[:HAS_STEP]->(s:Step)
        RETURN s ORDER BY s.order ASC
        """
        baseline_steps = []
        async with self.session_memory._pg_engine.connect():  # Error: Cypher is for Neo4j
            # Correcting: need graph_memory for Cypher
            pass

        # Real Logic: Using the orchestrator's graph memory
        records = await orchestrator.graph_memory.run_read_query(cypher, {"wid": workflow_id})
        for record in records:
            baseline_steps.append(dict(record.get("s", {})))

        if not baseline_steps:
            return []

        # AIOSOP-AUDIT-2026-06-16: capture an anonymous baseline per step so compare()
        # can suppress benign public resources (where an unauthenticated client gets
        # the same response as identity B). Guarded — if anon capture fails, compare()
        # simply runs without the baseline and behaves as before.
        anon_baseline: Dict[str, Dict[str, Any]] = {}
        for step in baseline_steps:
            # Read-only safety: never replay a state-changing request.
            if not self.is_safe_method(step.get("method")):
                continue
            try:
                anon_task = Task(
                    type="navigate",
                    agent_type="workflow",
                    payload={
                        "url": step["url"],
                        "user_label": "anonymous",
                        "capture_semantics": True,
                        "step_id": step["id"],
                    },
                    engagement_id=engagement_id,
                )
                anon_res = await orchestrator._execute_task_durable(anon_task)
                if anon_res.get("status") == "success":
                    a_state = anon_res.get("state", {})
                    anon_baseline[step["id"]] = {
                        "status_code": a_state.get("status_code", 200),
                        "body": a_state.get("body", {}),
                    }
            except Exception:
                pass

        # 2. For each test identity (e.g., 'user_b', 'guest')
        for identity in test_identities:
            # Identity-specific journey state

            for step in baseline_steps:
                # Read-only safety (AIOSOP-AUDIT-2026-06-16): never replay a
                # state-changing request (no POST/PUT/DELETE/PATCH).
                if not self.is_safe_method(step.get("method")):
                    continue
                # 2.1 Re-execute the step via PlaywrightAgent
                # We use the orchestrator to schedule a specific re-execution task
                task = Task(
                    type="navigate",  # Replay action
                    agent_type="workflow",
                    payload={
                        "url": step["url"],
                        "user_label": identity,
                        "capture_semantics": True,
                        "step_id": step["id"],
                    },
                    engagement_id=engagement_id,
                )

                # Execute and wait for result (durable path)
                # Note: In a real mission, this is a separate task in the queue.
                # Here we use the orchestrator's direct execution for the benchmark proof.
                exec_result = await orchestrator._execute_task_durable(task)

                if exec_result.get("status") == "success":
                    test_evidence = {
                        "status_code": exec_result.get("state", {}).get("status_code", 200),
                        "body": exec_result.get("state", {}).get("body", {}),
                        "semantics": exec_result.get("state", {}).get("semantics", []),
                        "user_label": identity,
                    }

                    # 2.2 Fetch original baseline evidence for comparison
                    # (In production, this would be stored in the graph/session memory)
                    baseline_evidence = step.get("baseline_evidence", {})

                    # 2.3 Perform Differential Analysis
                    finding = await self.compare(
                        baseline_evidence,
                        test_evidence,
                        Resource(
                            id=step["endpoint_id"],
                            type="endpoint",
                            value=step["url"],
                            owner_identity_id="user_a",
                            engagement_id=engagement_id,
                        ),
                        expected_allowed=False,  # The core hypothesis: Identity B should be forbidden
                        anonymous_evidence=anon_baseline.get(step["id"]),
                    )

                    if finding:
                        # AIOSOP-AUDIT-2026-06-16: independent verification before
                        # reporting. We attach the verdict (do not drop findings) so
                        # the report/triage layer can prioritise verified ones.
                        ev_a = dict(baseline_evidence)
                        ev_a.setdefault("user_label", "user_a")
                        verdict = self.verify_finding(finding, ev_a, test_evidence)
                        finding.evidence_diff["verification"] = verdict

                        # Learning loop (AIOSOP-AUDIT-2026-06-16): a VERIFIED finding
                        # credits the skills diff-auth relies on (stage="verification"),
                        # so reputation reflects effectiveness, not just usage. Durable
                        # via the SkillEngine persistence layer. Best-effort.
                        engine = getattr(orchestrator, "skill_engine", None)
                        if verdict.get("verified") and engine is not None:
                            try:
                                for sid in engine.resolve_ids(
                                    ["idor", "bola_testing", "auth_testing"]
                                ):
                                    engine.record_execution(
                                        sid,
                                        "diff-auth-engine",
                                        reason="verified diff-auth finding",
                                        stage="verification",
                                        finding_id=finding.id,
                                    )
                            except Exception:
                                pass

                        all_findings.append(finding)
                        # Persist finding to graph immediately
                        await orchestrator.graph_memory.add_diff_auth_finding(finding)

        return all_findings
