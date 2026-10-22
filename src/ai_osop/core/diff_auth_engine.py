"""
V4.2A Differential Authorization Engine
Compares evidence across different identities to detect IDOR and privilege escalation.
"""

from datetime import datetime
import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import DiffAuthFinding, EvidenceArtifact, Resource, Task
from ai_osop.memory.session_memory import SessionMemory, evidence_artifact_leaf_sha256
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets


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

        # Some applications return HTTP 200 for authorization failures. Treat an
        # explicit denial in the response body as a failed access attempt before
        # considering ownership, semantic, or sensitive-field signals.
        if self._is_denied_response(body_b):
            return None

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
                },
                confidence=confidence,
                engagement_id=resource.engagement_id,
            )

        return None

    TRANSIENT_KEYS = frozenset(
        {
            "_csrf",
            "csrf_token",
            "csrf",
            "nonce",
            "timestamp",
            "ts",
            "execution_time",
            "response_time",
            "request_id",
            "req_id",
            "trace_id",
            "span_id",
            "server_time",
            "date",
        }
    )

    @classmethod
    def _normalize_json(cls, val: Any) -> Any:
        if isinstance(val, dict):
            return {
                k: cls._normalize_json(v)
                for k, v in val.items()
                if k.lower() not in cls.TRANSIENT_KEYS
            }
        elif isinstance(val, list):
            return [cls._normalize_json(item) for item in val]
        return val

    @staticmethod
    def _is_denied_response(body: Any) -> bool:
        """Recognize explicit authorization failures hidden behind a 2xx status."""
        if isinstance(body, str):
            if re.search(
                r"<(?:title|h1|h2)[^>]*>[^<]*(?:access denied|forbidden|unauthorized)[^<]*</",
                body,
                re.IGNORECASE,
            ):
                return True
            return False
        if not isinstance(body, dict):
            return False
        if body.get("success") is False or body.get("status") in {"error", "denied", "forbidden"}:
            return True
        denial = re.compile(
            r"\b(?:access denied|permission denied|forbidden|unauthorized|"
            r"unauthenticated|not authorized|not allowed|login required)\b",
            re.IGNORECASE,
        )
        for key in ("error", "message", "detail", "reason", "error_description"):
            value = body.get(key)
            if isinstance(value, str) and denial.search(value):
                return True
        return False

    def _diff_json(self, a: Any, b: Any) -> Dict[str, Any]:
        """Normalized JSON key diff."""
        norm_a = self._normalize_json(a)
        norm_b = self._normalize_json(b)
        if not isinstance(norm_a, dict) or not isinstance(norm_b, dict):
            return {"type_mismatch": True}

        keys_a = set(norm_a.keys())
        keys_b = set(norm_b.keys())

        return {
            "added": list(keys_b - keys_a),
            "removed": list(keys_a - keys_b),
            "changed_values": [k for k in keys_a & keys_b if norm_a[k] != norm_b[k]],
        }

    async def create_and_persist_evidence_artifact(
        self,
        finding_id: str,
        engagement_id: str,
        target_url: str,
        http_method: str = "GET",
        request_headers: Optional[Dict[str, Any]] = None,
        request_body: Any = None,
        response_status: int = 200,
        response_headers: Optional[Dict[str, Any]] = None,
        response_body: Any = None,
        source_tool: str = "diff_auth_engine",
        approval_id: Optional[str] = None,
        replay_recipe: Optional[Dict[str, Any]] = None,
        *,
        source_task_id: Optional[str] = None,
        artifact_id: Optional[str] = None,
    ) -> EvidenceArtifact:
        """Persist bounded, REDACTED candidate metadata for a signed source Task.

        Digest-bearing metadata is not independent target-owner verification,
        a replay capability, or a VERIFIED finding. Raw authentication headers,
        request bodies, and query values never enter the immutable JSON ledger.
        """
        if (
            not isinstance(self.session_memory, SessionMemory)
            or not callable(getattr(self.session_memory, "record_evidence_artifact", None))
            or not isinstance(source_task_id, str)
            or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,59}", source_task_id)
            or (
                artifact_id is not None
                and (
                    not isinstance(artifact_id, str)
                    or not re.fullmatch(r"ev-[0-9a-f]{32}", artifact_id)
                )
            )
            or not isinstance(engagement_id, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", engagement_id)
            or not isinstance(finding_id, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", finding_id)
            or not isinstance(source_tool, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", source_tool)
            or not isinstance(http_method, str)
            or not re.fullmatch(r"[A-Za-z]{3,16}", http_method)
            or type(response_status) is not int
            or response_status < 100
            or response_status > 599
            or (
                approval_id is not None
                and (
                    not isinstance(approval_id, str)
                    or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", approval_id)
                )
            )
            or not isinstance(target_url, str)
            or len(target_url) > 2048
            or not isinstance(request_headers, (dict, type(None)))
            or not isinstance(response_headers, (dict, type(None)))
            or (replay_recipe is not None and not isinstance(replay_recipe, dict))
        ):
            raise WorkflowException("Signed evidence source and bounded metadata required")
        parsed = urlsplit(target_url)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or any(ord(char) < 33 or ord(char) == 127 for char in target_url)
        ):
            raise WorkflowException("Evidence target URL is unsafe")
        # Reconstructing a URL without query values deliberately does not
        # create an executable replay. Bind the exact original URL by digest.
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
        if len(query) > 32 or any(len(k) > 128 for k, _ in query):
            raise WorkflowException("Evidence URL query is too large")
        safe_url = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode([(key, "REDACTED") for key, _ in query]),
                "",
            )
        )
        if len(safe_url) > 1024:
            raise WorkflowException("Redacted evidence URL exceeds storage bounds")
        if replay_recipe is not None and (
            "method" in replay_recipe
            and replay_recipe["method"] != http_method.upper()
            or "url" in replay_recipe
            and replay_recipe["url"] != target_url
        ):
            raise WorkflowException("Replay metadata conflicts with evidence source")
        for header_map in (request_headers or {}, response_headers or {}):
            if len(header_map) > 64 or any(
                not isinstance(k, str) or not isinstance(v, str) or len(k) > 128 or len(v) > 8192
                for k, v in header_map.items()
            ):
                raise WorkflowException("Evidence headers must be bounded text")
        req_h_bytes = json.dumps(request_headers or {}, sort_keys=True, default=str).encode("utf-8")
        req_b_bytes = (
            request_body
            if isinstance(request_body, bytes)
            else json.dumps(
                request_body if request_body is not None else {}, sort_keys=True, default=str
            ).encode("utf-8")
        )
        res_h_bytes = json.dumps(response_headers or {}, sort_keys=True, default=str).encode(
            "utf-8"
        )
        res_b_bytes = (
            response_body
            if isinstance(response_body, bytes)
            else json.dumps(
                response_body if response_body is not None else {}, sort_keys=True, default=str
            ).encode("utf-8")
        )

        req_h_hash = hashlib.sha256(req_h_bytes).hexdigest()
        req_b_hash = hashlib.sha256(req_b_bytes).hexdigest()
        res_h_hash = hashlib.sha256(res_h_bytes).hexdigest()
        res_b_hash = hashlib.sha256(res_b_bytes).hexdigest()

        if any(
            len(blob) > 1_048_576 for blob in (req_h_bytes, req_b_bytes, res_h_bytes, res_b_bytes)
        ):
            raise WorkflowException("Evidence digest input exceeds permitted size")

        captured_at = datetime.utcnow()

        artifact = EvidenceArtifact(
            **({"id": artifact_id} if artifact_id is not None else {}),
            engagement_id=engagement_id,
            finding_id=finding_id,
            source_tool=source_tool,
            source_tool_version="1.0.0",
            target_url=safe_url,
            http_method=http_method.upper(),
            request_headers_sha256=req_h_hash,
            request_body_sha256=req_b_hash,
            response_status=response_status,
            response_headers_sha256=res_h_hash,
            response_body_sha256=res_b_hash,
            raw_storage_uri="",
            approval_id=approval_id,
            replay_recipe={
                "schema": "ai-osop.redacted-evidence-reference.v1",
                "source_task_id": source_task_id,
                "method": http_method.upper(),
                "url": safe_url,
                "original_url_sha256": hashlib.sha256(target_url.encode("utf-8")).hexdigest(),
                "request_header_names": sorted(
                    name.lower()
                    for name in (request_headers or {})
                    if name.lower()
                    not in {"authorization", "cookie", "proxy-authorization", "x-api-key"}
                )[:64],
                "request_body_sha256": req_b_hash,
                "replayable": False,
                "finding_verified": False,
                "target_effect_verified": False,
            },
            merkle_leaf_hash="0" * 64,
            captured_at=captured_at,
        )
        artifact.merkle_leaf_hash = evidence_artifact_leaf_sha256(artifact)
        persisted_id = await self.session_memory.record_evidence_artifact(
            artifact,
            source_task_id=source_task_id,
        )
        if persisted_id != artifact.id:
            raise WorkflowException("Evidence artifact durable admission is UNKNOWN")
        return artifact

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
        val = getattr(resource, "value", "") or ""
        if val and val.lower() in body_str:
            return True

        # 2. A's owner identity id is reflected (ignore the generic 'admin' marker).
        oid = getattr(resource, "owner_identity_id", "") or ""
        if oid and oid != "admin" and oid.lower() in body_str:
            return True

        # 3. Owner-private fields present AND equal in both A's and B's responses
        #    (B is seeing the same owned record A sees).
        body_a = identity_a_evidence.get("body", {})
        if isinstance(body_a, dict) and isinstance(body_b, dict):
            for k in ("id", "email", "account_id", "user_id", "owner", "ref", "uuid"):
                if k in body_a and k in body_b and body_a[k] and body_a[k] == body_b[k]:
                    return True
        return False

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
            body_a = a_self.get("body")
            ba = body_a if isinstance(body_a, dict) else {}
            body_b = b_self.get("body")
            bb = body_b if isinstance(body_b, dict) else {}
            for k in ("id", "user_id", "account_id", "email", "sub", "username"):
                if k in ba and k in bb and ba[k] and bb[k]:
                    return bool(ba[k] != bb[k])
        la, lb = evidence_a.get("user_label"), evidence_b.get("user_label")
        if la and lb:
            return bool(la != lb)
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
        self,
        workflow_id: str,
        test_identities: List[str],
        engagement_id: str,
        orchestrator: Any,
        *,
        parent_task: Optional[Task] = None,
        source_user_label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Admit distinct *approved* durable replays; never execute nested tools.

        A Neo4j workflow and a task executor are not admission authorities.
        The caller must supply the running PG-authoritative signed parent and
        trusted scheduler. One-shot child IDs are deterministic; an existing
        child (including UNKNOWN) is never enqueued or replayed again here.

        This returns QUEUED approval requests, not observations or findings.
        Analysis requires later independently verified terminal evidence; the
        old direct _execute_task_durable path fabricated neither admission nor
        approval and is intentionally removed.
        """
        from ai_osop.auth.session_store import SessionStore

        denied = WorkflowException("Signed differential replay admission unavailable")
        if (
            not isinstance(self.session_memory, SessionMemory)
            or orchestrator is None
            or getattr(orchestrator, "session_memory", None) is not self.session_memory
            or not callable(getattr(orchestrator, "schedule_task", None))
            or getattr(getattr(orchestrator, "graph_memory", None), "_driver", None) is None
            or not isinstance(parent_task, Task)
            or not isinstance(parent_task.payload, dict)
            or parent_task.id == ""
            or parent_task.engagement_id != engagement_id
            or parent_task.type != "replay_for_diff_auth"
            or parent_task.status != "running"
            or not parent_task.flow_id
            or not isinstance(parent_task.parent_task_id, str)
            or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,78}", parent_task.parent_task_id)
            or parent_task.payload.get("workflow_id") != workflow_id
            or not isinstance(workflow_id, str)
            or not re.fullmatch(r"wf-[A-Za-z0-9._-]{1,80}", workflow_id)
            or not isinstance(engagement_id, str)
            or not re.fullmatch(r"eng-[A-Za-z0-9._-]{1,80}", engagement_id)
            or type(parent_task.payload.get("_authorization_version")) is not int
            or parent_task.payload["_authorization_version"] < 1
            or type(parent_task.payload.get("_flow_revision")) is not int
            or parent_task.payload["_flow_revision"] < 0
            or not isinstance(test_identities, list)
            or len(test_identities) != 1
            or not isinstance(test_identities[0], str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", test_identities[0])
            or test_identities[0] in {"guest", "anonymous"}
            or parent_task.payload.get("target_user_label") != test_identities[0]
        ):
            raise denied

        version = parent_task.payload["_authorization_version"]
        assert parent_task.parent_task_id is not None
        assert parent_task.flow_id is not None
        parent_id = parent_task.parent_task_id
        flow_id = parent_task.flow_id

        async def assert_current() -> Any:
            """Read original signed map_workflow source, never the graph as origin."""
            try:
                current = await self.session_memory.load_task_authoritative(parent_task.id)
                original = await self.session_memory.load_task_authoritative(
                    parent_id,
                )
                signed = await self.session_memory.assert_signed_authorization(
                    engagement_id,
                    expected_version=version,
                )
                flow = await self.session_memory.load_flow(flow_id)
                engagement = await self.session_memory.load_session_state(engagement_id)
                approval_id = parent_task.payload.get("approval_id")
                if (
                    not isinstance(current, Task)
                    or current.id != parent_task.id
                    or current.engagement_id != engagement_id
                    or current.flow_id != parent_task.flow_id
                    or current.type != parent_task.type
                    or current.agent_type != parent_task.agent_type
                    or current.parent_task_id != parent_task.parent_task_id
                    or current.status != "running"
                    or current.payload != parent_task.payload
                    or not current.approval_required
                    or current.payload.get("operator_approved") is not True
                    or not isinstance(approval_id, str)
                    or not 1 <= len(approval_id) <= 80
                    or not await self.session_memory.is_task_approved(
                        parent_task.id,
                        engagement_id,
                        approval_id,
                    )
                    or signed.version != version
                    or flow is None
                    or flow.id != parent_task.flow_id
                    or flow.engagement_id != engagement_id
                    or flow.status not in {"pending", "running"}
                    or flow.revision != parent_task.payload["_flow_revision"]
                    or engagement is None
                    or engagement.session_id != engagement_id
                    or engagement.phase in {"halted", "completed"}
                    or engagement.scope.engagement_id != engagement_id
                    or not engagement.scope.authorization_ref
                    or not (engagement.scope.domains or engagement.scope.ips)
                    or not isinstance(original, Task)
                    or original.id != parent_task.parent_task_id
                    or original.type != "map_workflow"
                    or original.engagement_id != engagement_id
                    # Engagement-level signed auto-discovery predates Flow
                    # assignment; the explicitly approved replay parent is
                    # the durable bridge to its operator-confirmed Flow.
                    or original.flow_id not in {None, parent_task.flow_id}
                    or original.status != "completed"
                    or not isinstance(original.payload, dict)
                    or original.payload.get("_authorization_version") != version
                    or not isinstance(original.payload.get("user_label"), str)
                    or not re.fullmatch(
                        r"[A-Za-z0-9_.-]{1,64}",
                        original.payload["user_label"],
                    )
                    or not isinstance(original.result, dict)
                    or original.result.get("status") not in {"success", "workflow_recorded"}
                    or original.result.get("workflow_id") != workflow_id
                ):
                    raise denied
                enforcer = ScopeEnforcer(engagement.scope)
                enforcer.validate_time_window()
                validate_payload_targets(
                    enforcer,
                    {"url": original.payload.get("url")},
                    require_target=True,
                )
                return enforcer, original.payload["user_label"]
            except Exception as exc:
                raise WorkflowException(
                    "Signed differential replay scope, Flow or parent approval unverified"
                ) from exc

        scope, original_role = await assert_current()
        # Neo4j is an untrusted read model. Require all three entities to be
        # tenant-bound, linked through the original producer's HAS_STEP and
        # TARGETS_ENDPOINT relationships, not a global workflow-ID match.
        cypher = """
        MATCH (w:Workflow {id:$wid, engagement_id:$sid})
              -[:HAS_STEP]->(s:Step {engagement_id:$sid})
              -[:TARGETS_ENDPOINT]->(e:Endpoint {engagement_id:$sid})
        WHERE s.workflow_id = $wid AND s.endpoint_id = e.id
        RETURN w.role AS source_role, s.id AS step_id,
               s.order AS step_order, s.action_type AS action_type,
               e.id AS endpoint_id, e.method AS method, e.url AS url
        ORDER BY s.order ASC, s.id ASC LIMIT 34
        """
        try:
            async with orchestrator.graph_memory._driver.session() as graph:
                result = await graph.run(
                    cypher,
                    {"wid": workflow_id, "sid": engagement_id},
                )
                rows = [dict(record) async for record in result]
        except Exception as exc:
            raise WorkflowException("Tenant-bound workflow graph unavailable") from exc
        if not rows or len(rows) > 32:
            raise denied

        role = rows[0].get("source_role")
        identity = test_identities[0]
        if (
            not isinstance(role, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", role)
            or role in {"anonymous", "guest", identity}
            or (source_user_label is not None and source_user_label != role)
            or parent_task.payload.get("source_user_label", role) != role
            or role != original_role
            or any(row.get("source_role") != role for row in rows)
        ):
            raise denied
        # No anonymous fallback or cached identity substitution in signed
        # mode. Both actor sessions must be present in PostgreSQL and current.
        try:
            store = SessionStore(self.session_memory)
            imported_sessions: Dict[str, Any] = {}
            for label in (role, identity):
                existing = await store.get_session_authoritative(engagement_id, label)
                if existing is None or existing.is_expired():
                    raise denied
                imported_sessions[label] = existing
        except Exception as exc:
            raise WorkflowException("Signed replay identity evidence unavailable") from exc

        approved_steps: List[Dict[str, str]] = []
        seen: set[str] = set()
        for row in rows:
            step_id, endpoint_id, method, action, url = (
                row.get("step_id"),
                row.get("endpoint_id"),
                row.get("method"),
                row.get("action_type"),
                row.get("url"),
            )
            if (
                not isinstance(step_id, str)
                or not re.fullmatch(r"step-[A-Za-z0-9._-]{1,80}", step_id)
                or step_id in seen
                or not isinstance(endpoint_id, str)
                or not re.fullmatch(r"(?:ep|endpoint)-[A-Za-z0-9._-]{1,80}", endpoint_id)
                or type(row.get("step_order")) is not int
                or row["step_order"] < 0
            ):
                raise denied
            seen.add(step_id)
            # The shipped WorkflowAgent records browser GET navigations with
            # Step.action_type='NAVIGATE', while Endpoint.method='GET'. These
            # are two descriptions of the same read-only operation. Preserve
            # exact GET-only safety: a NAVIGATE label must NEVER disguise a
            # POST/PUT/DELETE endpoint, and missing method is not assumed GET.
            if (
                not isinstance(method, str)
                or not isinstance(action, str)
                or action.upper() not in {method.upper(), "NAVIGATE"}
                # Playwright "navigate" is always an HTTP GET, even when
                # the graph originally described HEAD/OPTIONS.
                or method.upper() != "GET"
            ):
                continue
            if not isinstance(url, str) or not 1 <= len(url) <= 2048:
                raise denied
            try:
                parsed = urlsplit(url)
                if (
                    parsed.scheme not in {"http", "https"}
                    or not parsed.hostname
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.fragment
                    or any(ord(char) < 33 for char in url)
                ):
                    raise ValueError()
                validate_payload_targets(scope, {"url": url}, require_target=True)
            except Exception as exc:
                raise WorkflowException("Replay destination is not within signed scope") from exc
            approved_steps.append(
                {
                    "id": step_id,
                    "endpoint_id": endpoint_id,
                    "method": method.upper(),
                    "url": url,
                }
            )

        if not approved_steps:
            return {
                "status": "no_replayable_steps",
                "queued_task_ids": [],
                "findings": [],
                "findings_count": 0,
            }

        queued: List[str] = []
        from ai_osop.core.signed_replay_comparison import (
            observation_subtask_id,
            observation_task_id,
        )
        from ai_osop.core.authority_session_binding import bound_replay_fingerprints

        # Admission of source AND target is a single signed PostgreSQL
        # transaction. Queue/graph hints follow durable commit and are never
        # authority for a browser call. NEVER execute nested actions here.
        for step in approved_steps:
            fresh_scope, fresh_role = await assert_current()
            if fresh_role != original_role:
                raise WorkflowException("Original replay source identity changed")
            validate_payload_targets(fresh_scope, {"url": step["url"]}, require_target=True)
            pair: List[Task] = []
            for observation_role, observation_label in (
                ("source", original_role),
                ("target", identity),
            ):
                # Original map_workflow is an inventory, not a comparable
                # independently approved HTTP response.
                replay_id = observation_task_id(
                    engagement_id,
                    parent_task.id,
                    parent_task.flow_id,
                    workflow_id,
                    step["id"],
                    observation_label,
                    version,
                )
                pair.append(
                    Task(
                        id=replay_id,
                        engagement_id=engagement_id,
                        type="navigate",
                        agent_type=AgentType.WORKFLOW,
                        status="pending",
                        approval_required=True,
                        parent_task_id=parent_task.id,
                        flow_id=parent_task.flow_id,
                        subtask_id=observation_subtask_id(replay_id),
                        dependencies=[parent_task.id],
                        priority=5,
                        max_retries=0,
                        payload={
                            "url": step["url"],
                            "method": step["method"],
                            "user_label": observation_label,
                            "_comparison_role": observation_role,
                            "target_user_label": identity,
                            "step_id": step["id"],
                            "workflow_id": workflow_id,
                            "source_user_label": role,
                            "capture_semantics": True,
                            "_authorization_version": version,
                            "_flow_revision": parent_task.payload["_flow_revision"],
                            **(
                                bound_replay_fingerprints(
                                    imported_sessions[observation_label],
                                    engagement_id=engagement_id,
                                    user_label=observation_label,
                                    method=step["method"],
                                    url=step["url"],
                                    task_id=replay_id,
                                    parent_task_id=parent_task.id,
                                )
                                if step["url"].startswith("https://")
                                else {}
                            ),
                        },
                    )
                )
            try:
                admitted_ids = await self.session_memory.admit_signed_replay_observation_pair(
                    parent_task,
                    pair,
                )
            except Exception as exc:
                # PostgreSQL rollback is atomic. An ambiguous COMMIT may have
                # persisted BOTH; recheck only, never blindly resubmit.
                raise WorkflowException("Signed replay pair admission is UNKNOWN") from exc
            if not admitted_ids:
                continue
            if admitted_ids != [child.id for child in pair]:
                raise WorkflowException("Signed replay pair returned incomplete admission")
            for child in pair:
                # The generic scheduler may be called only *after* both rows
                # commit. Its signed readback checks exact immutable identity.
                # Loss of queue delivery is UNKNOWN; no remote replay follows.
                try:
                    await orchestrator.schedule_task(child)
                    prior = await self.session_memory.load_task_authoritative(child.id)
                except Exception as exc:
                    raise WorkflowException("Signed replay queue delivery is UNKNOWN") from exc
                if (
                    not isinstance(prior, Task)
                    or prior.id != child.id
                    or prior.engagement_id != engagement_id
                    or prior.flow_id != child.flow_id
                    or prior.parent_task_id != child.parent_task_id
                    or prior.subtask_id != child.subtask_id
                    or prior.payload != child.payload
                    or not prior.approval_required
                    or prior.status not in {"pending", "awaiting_approval"}
                ):
                    raise WorkflowException("Replay child was not durably admitted")
                queued.append(child.id)
        return {
            "status": "pending_execution_approval" if queued else "already_admitted",
            "queued_task_ids": queued,
            "findings": [],
            "findings_count": 0,
        }
