"""
Attack Chain Agent
Multi-step exploitation reasoning, privilege escalation mapping,
and attack graph path discovery.
"""

import uuid
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.agents.base import BaseAgent
from ai_osop.core.chain_composer import ChainComposer
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.exceptions import AgentException, OutOfScopeError, ScopeValidationError
from ai_osop.core.goal_planner import GoalAction, GoalPlanner, GoalState
from ai_osop.core.knowledge_engine import get_knowledge_engine
from ai_osop.core.models import (
    AttackPath,
    PrimitiveLedger,
    PrimitiveType,
    Task,
    Vulnerability,
)
from ai_osop.safety.scope import ScopeEnforcer

logger = structlog.get_logger(__name__)


class AttackChainAgent(BaseAgent):
    """
    Attack Chain Intelligence Agent

    Responsibilities:
    - Attack graph construction and maintenance
    - Multi-step exploit path discovery
    - Privilege escalation mapping
    - Vulnerability correlation
    - Risk propagation analysis

    Planning Methodology:
    - Graph construction: Add nodes/edges as findings arrive
    - Path discovery: Background job searching for paths
    - Chain validation: Prioritize high-confidence, low-detection paths
    """

    # Pre-defined attack chain templates
    CHAIN_TEMPLATES = [
        {
            "name": "web_to_admin",
            "description": "Unauthenticated web vulnerability to admin access",
            "steps": [
                {"phase": 1, "vuln_types": ["sqli", "xss", "ssrf", "idor"], "entry_point": True},
                {"phase": 2, "vuln_types": ["auth_bypass", "session_hijacking", "jwt_abuse"]},
                {"phase": 3, "vuln_types": ["privilege_escalation", "idor"]},
                {"phase": 4, "vuln_types": ["rce", "file_upload", "deserialization"], "goal": True},
            ],
        },
        {
            "name": "recon_to_rce",
            "description": "Information disclosure to remote code execution",
            "steps": [
                {"phase": 1, "vuln_types": ["ssrf", "lfi", "idor"], "entry_point": True},
                {"phase": 2, "vuln_types": ["credential_exposure"]},
                {"phase": 3, "vuln_types": ["rce", "deserialization"], "goal": True},
            ],
        },
        {
            "name": "jwt_to_account_takeover",
            "description": "JWT weakness to account takeover",
            "steps": [
                {"phase": 1, "vuln_types": ["jwt_abuse"], "entry_point": True},
                {"phase": 2, "vuln_types": ["idor", "auth_bypass"]},
                {"phase": 3, "vuln_types": ["privilege_escalation"], "goal": True},
            ],
        },
    ]

    @property
    def agent_type(self) -> AgentType:
        return AgentType.ATTACK_CHAIN

    async def _setup_resources(self) -> None:
        """Initialize attack chain resources."""
        self.discovered_paths: List[AttackPath] = []
        self.validated_chains: List[Dict[str, Any]] = []
        # Defense-in-depth: scope-gate any payload-controlled URL this agent
        # dereferences (verify_url / idor_url in account_takeover). The signed
        # scope check at the scheduler is the primary gate; this stops an
        # otherwise in-scope task from being abused to reach an attacker host.
        self._scope_manager: Optional[ScopeEnforcer] = None
        if getattr(self.ctx, "scope", None) is not None:
            try:
                self._scope_manager = ScopeEnforcer(self.ctx.scope)
            except Exception as e:  # noqa: BLE001 - scope optional
                logger.warning("attack_chain_scope_init_failed", error=str(e))

    def _in_scope(self, url: str) -> bool:
        """Return True if the URL is in scope (or no scope is configured)."""
        if not url or self._scope_manager is None:
            return True
        try:
            return self._scope_manager.validate_target(url)
        except (OutOfScopeError, ScopeValidationError) as e:
            logger.warning("attack_chain_url_out_of_scope", url=url, error=str(e))
            return False

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute attack chain task."""
        task_type = task.type
        payload = task.payload

        if task_type == "discover_paths":
            return await self._discover_paths(payload)
        elif task_type == "account_takeover":
            return await self._account_takeover(payload)
        elif task_type == "validate_chain":
            return await self._validate_chain(payload)
        elif task_type == "propagate_risk":
            return await self._propagate_risk(payload)
        elif task_type == "find_lateral_movement":
            return await self._find_lateral_movement(payload)
        else:
            raise AgentException(f"Unknown attack chain task: {task_type}")

    async def _account_takeover(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Actively DEMONSTRATE account takeover by chaining real primitives.

        This does not merely score a graph path — it forges access as a chosen
        victim and confirms the server honours it. Today's confirmed primitive is
        JWT forgery (impersonate the victim's identity); an optional IDOR primitive
        (read the victim's object with the attacker's own token) is attempted when
        an idor_url is supplied. Any confirmed primitive yields a CRITICAL,
        validated Account-Takeover finding linked to its enabling weakness.

        Payload:
            verify_url     identity-reflecting endpoint (e.g. /rest/user/whoami)
            token          attacker's own valid JWT (to mutate)
            victim_email   identity to take over (forged into the token)
            idor_url       optional: a victim-resource URL to read with attacker token
            idor_marker    optional: string proving victim data was returned
            engagement_id  injected by _execute
        """
        engagement_id = payload.get("engagement_id") or (
            self.ctx.current_task.engagement_id if self.ctx.current_task else None
        )
        if not engagement_id:
            raise AgentException("account_takeover: cannot determine engagement_id")
        verify_url = payload.get("verify_url")
        token = payload.get("token")
        victim_email = payload.get("victim_email")
        if not (verify_url and token and victim_email):
            return {
                "status": "error",
                "error": "account_takeover requires verify_url, token, and victim_email",
            }
        if not self._in_scope(verify_url):
            return {
                "status": "out_of_scope",
                "error": f"verify_url {verify_url} is out of scope; account_takeover not attempted",
            }

        chain: List[Dict[str, Any]] = []
        primitive_vulns: List[Vulnerability] = []

        # --- Primitive 1: JWT forgery -> impersonate the victim identity ----------
        from ai_osop.core.jwt_tester import JWTTester

        tester = JWTTester(
            verify_url, token, sentinel=victim_email, method=payload.get("method", "GET")
        )
        try:
            jwt_findings = [f for f in await tester.run() if f.confirmed]
        except Exception as e:
            logger.warning("ato_jwt_primitive_failed", error=str(e))
            jwt_findings = []

        for f in jwt_findings:
            primitive_vulns.append(
                Vulnerability(
                    cwe="CWE-347",
                    vuln_type=VulnClass.JWT_ABUSE,
                    severity=Severity.CRITICAL,
                    title=f"JWT forgery enabling impersonation ({f.technique})",
                    description=f"{f.detail} Used as the takeover primitive for {victim_email}.",
                    evidence=[
                        {
                            "type": "jwt_forgery",
                            "provenance": "jwt_tester",
                            "technique": f.technique,
                            "verify_url": verify_url,
                            "victim": victim_email,
                            **f.evidence,
                        }
                    ],
                    tool_source="jwt_tester",
                    confidence=0.98,
                    validated=True,
                    exploitability="high",
                    impact="high",
                    engagement_id=engagement_id,
                )
            )
            chain.append({"primitive": "jwt_forgery", "technique": f.technique})

        # --- Primitive 2 (optional): IDOR read of the victim's object -------------
        idor_url = payload.get("idor_url")
        idor_marker = payload.get("idor_marker") or victim_email
        if idor_url and not self._in_scope(idor_url):
            logger.warning("ato_idor_out_of_scope", url=idor_url)
            idor_url = None
        if idor_url:
            import httpx

            try:
                async with self.get_governed_client(tool="attack_chain", timeout=15) as c:
                    r = await c.get(
                        idor_url,
                        headers={"Authorization": f"Bearer {token}", "Cookie": f"token={token}"},
                    )
                    if r.status_code == 200 and idor_marker in r.text:
                        primitive_vulns.append(
                            Vulnerability(
                                cwe="CWE-639",
                                vuln_type=VulnClass.IDOR,
                                severity=Severity.HIGH,
                                title="IDOR exposing victim account object",
                                description=f"Attacker token read {victim_email}'s object at {idor_url}.",
                                evidence=[
                                    {
                                        "type": "idor_read",
                                        "provenance": "http",
                                        "url": idor_url,
                                        "victim": victim_email,
                                        "status": r.status_code,
                                    }
                                ],
                                tool_source="ato_orchestrator",
                                confidence=0.93,
                                validated=True,
                                exploitability="high",
                                impact="high",
                                engagement_id=engagement_id,
                            )
                        )
                        chain.append({"primitive": "idor", "url": idor_url})
            except Exception as e:
                logger.warning("ato_idor_primitive_failed", error=str(e))

        if not primitive_vulns:
            logger.info("ato_not_confirmed", verify_url=verify_url, victim=victim_email)
            return {
                "status": "success",
                "tool": "ato_orchestrator",
                "account_takeover": False,
                "victim": victim_email,
                "findings_count": 0,
            }

        # Persist the enabling primitives in one batch transaction, then the chained ATO outcome.
        if primitive_vulns:
            try:
                await self.ctx.graph_memory.add_vulnerabilities_batch(primitive_vulns)
            except Exception as e:
                logger.error("ato_primitives_batch_persist_failed", error=str(e))

        ato = Vulnerability(
            cwe="CWE-287",  # Improper Authentication
            vuln_type=VulnClass.BROKEN_ACCESS_CONTROL,
            severity=Severity.CRITICAL,
            title=f"Account Takeover of {victim_email}",
            description=(
                f"Account takeover of {victim_email} was demonstrated by chaining "
                f"{len(primitive_vulns)} confirmed primitive(s): "
                f"{', '.join(c['primitive'] for c in chain)}. The server granted access "
                f"under the victim's identity."
            ),
            evidence=[
                {
                    "type": "account_takeover_chain",
                    "provenance": "ato_orchestrator",
                    "victim": victim_email,
                    "verify_url": verify_url,
                    "chain": chain,
                    "primitive_vuln_ids": [pv.id for pv in primitive_vulns],
                }
            ],
            tool_source="ato_orchestrator",
            confidence=0.97,
            validated=True,
            exploitability="high",
            impact="high",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_vulnerability(ato)
        except Exception as e:
            logger.error("ato_persist_failed", error=str(e))

        # Best-effort: record the chain as an AttackPath (primitive -> ATO goal).
        try:
            path = AttackPath(
                node_ids=[pv.id for pv in primitive_vulns] + [ato.id],
                edge_ids=[],
                confidence=0.97,
                risk_score=9.5,
                detection_risk=0.3,
                validated=True,
                entry_node_id=primitive_vulns[0].id,
                goal_node_id=ato.id,
                engagement_id=engagement_id,
            )
            await self.ctx.graph_memory.add_attack_path(path)
        except Exception as e:
            logger.warning("ato_attack_path_persist_failed", error=str(e))

        logger.info(
            "ato_confirmed",
            victim=victim_email,
            primitives=[c["primitive"] for c in chain],
        )
        return {
            "status": "success",
            "tool": "ato_orchestrator",
            "account_takeover": True,
            "victim": victim_email,
            "chain": chain,
            "findings_count": len(primitive_vulns) + 1,
            "ato_finding": ato.model_dump(),
        }

    async def _discover_paths(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Discover attack paths from entry points to goals."""
        engagement_id = payload["engagement_id"]
        entry_node_id = payload.get("entry_node_id")
        goal_types = payload.get("goal_types", ["rce", "admin_access", "data_exfiltration"])
        payload.get("max_depth", 5)

        # If no entry node specified, find all entry points
        if not entry_node_id:
            entry_nodes = await self._find_entry_points(engagement_id)
        else:
            entry_nodes = [entry_node_id]

        # Use SecurityKnowledgeEngine & GoalPlanner
        ske = get_knowledge_engine()
        planner = GoalPlanner()

        # Query session information from Neo4j for the initial state
        role = "anonymous"
        has_token = False
        if self.ctx.graph_memory:
            try:
                # Query active sessions
                cypher_session = """
                MATCH (s:Session {engagement_id: $eid, status: 'active'})-[:AUTHENTICATED_AS]->(i:Identity)-[:HAS_ROLE]->(r:Role)
                RETURN r.name as role_name LIMIT 1
                """
                records_session = await self.ctx.graph_memory.run_read_query(
                    cypher_session, {"eid": engagement_id}
                )
                if records_session:
                    role = records_session[0].get("role_name", "standard")

                # Query if there are any active credentials synced
                cypher_cred = """
                MATCH (c:Credential {engagement_id: $eid})
                RETURN c.type as cred_type LIMIT 1
                """
                records_cred = await self.ctx.graph_memory.run_read_query(
                    cypher_cred, {"eid": engagement_id}
                )
                if records_cred:
                    has_token = True
            except Exception as e:
                logger.warning("failed_to_query_session_for_planner", error=str(e))

        # Query existing vulnerabilities to establish known vulnerabilities
        known_vulns: List[str] = []
        if self.ctx.graph_memory:
            try:
                vulns = await self.ctx.graph_memory.get_vulnerabilities_by_engagement(engagement_id)
                for v in vulns:
                    if v:
                        v_type = v.get("vuln_type")
                        if v_type:
                            if hasattr(v_type, "value"):
                                known_vulns.append(str(v_type.value))
                            else:
                                known_vulns.append(str(v_type))
            except Exception as e:
                logger.warning("failed_to_query_vulnerabilities_for_planner", error=str(e))

        # 1. Map current engagement state into GoalState
        initial_state = GoalState(
            properties={
                "role": role,
                "has_token": has_token,
                "vuln_discovered": known_vulns,
                "network_zone": "external" if role == "anonymous" else "internal",
            }
        )

        # 2. Build the set of possible actions from SecurityKnowledgeEngine recommendation mappings
        actions = []

        # Build actions from recommendation chains in knowledge engine
        # E.g. sqli -> rce implies if sqli is discovered, we can perform sqli_to_rce to discover rce
        recommendation_chains = ske._data.get("recommendation_chains", {})
        for vuln_key, next_steps in recommendation_chains.items():
            for step in next_steps:
                actions.append(
                    GoalAction(
                        name=f"{vuln_key}_to_{step}",
                        preconditions={"vuln_discovered": vuln_key},
                        effects={"vuln_discovered": step},
                        cost=1.5,
                    )
                )

        # Add initial discovery actions (e.g. scanning or exploiting to find entry points)
        # Vulnerability scanning discovers basic vulns
        actions.append(
            GoalAction(
                name="vuln_scan_discover_sqli",
                preconditions={"role": "anonymous"},
                effects={"vuln_discovered": "sqli"},
                cost=2.0,
            )
        )
        actions.append(
            GoalAction(
                name="vuln_scan_discover_xss",
                preconditions={"role": "anonymous"},
                effects={"vuln_discovered": "xss"},
                cost=1.0,
            )
        )
        actions.append(
            GoalAction(
                name="vuln_scan_discover_ssrf",
                preconditions={"role": "anonymous"},
                effects={"vuln_discovered": "ssrf"},
                cost=1.5,
            )
        )
        actions.append(
            GoalAction(
                name="vuln_scan_discover_ssti",
                preconditions={"role": "anonymous"},
                effects={"vuln_discovered": "ssti"},
                cost=2.0,
            )
        )
        actions.append(
            GoalAction(
                name="vuln_scan_discover_idor",
                preconditions={"role": "anonymous"},
                effects={"vuln_discovered": "idor"},
                cost=1.0,
            )
        )

        # Actions for role escalation / privilege escalation
        actions.append(
            GoalAction(
                name="exploit_sqli_takeover",
                preconditions={"vuln_discovered": "sqli"},
                effects={"role": "admin", "network_zone": "internal"},
                cost=3.0,
            )
        )
        actions.append(
            GoalAction(
                name="exploit_idor_vertical_pe",
                preconditions={"vuln_discovered": "idor"},
                effects={"role": "admin", "network_zone": "internal"},
                cost=2.0,
            )
        )
        actions.append(
            GoalAction(
                name="token_abuse_privilege_escalation",
                preconditions={"vuln_discovered": "exposed_secret"},
                effects={"role": "admin", "network_zone": "internal", "has_token": True},
                cost=1.5,
            )
        )
        actions.append(
            GoalAction(
                name="rce_privilege_escalation",
                preconditions={"vuln_discovered": "rce"},
                effects={"role": "admin", "network_zone": "internal"},
                cost=1.0,
            )
        )
        actions.append(
            GoalAction(
                name="jwt_bypass_admin",
                preconditions={"vuln_discovered": "jwt_abuse"},
                effects={"role": "admin"},
                cost=1.0,
            )
        )

        # Action for exfiltration goal
        actions.append(
            GoalAction(
                name="data_exfiltration_from_sqli",
                preconditions={"vuln_discovered": "sqli"},
                effects={"data_exfiltrated": True},
                cost=1.5,
            )
        )
        actions.append(
            GoalAction(
                name="data_exfiltration_from_admin",
                preconditions={"role": "admin"},
                effects={"data_exfiltrated": True},
                cost=0.5,
            )
        )

        # 3. Solve for paths for each goal type
        all_paths = []
        for entry in entry_nodes:
            for goal_type in goal_types:
                # Setup goal state based on the requested goal type
                goal_props: Dict[str, Any] = {}
                if goal_type == "rce":
                    goal_props = {"vuln_discovered": "rce"}
                elif goal_type == "admin_access":
                    goal_props = {"role": "admin"}
                elif goal_type == "data_exfiltration":
                    goal_props = {"data_exfiltrated": True}
                else:
                    # Generic target properties based on string matching
                    goal_props = {"vuln_discovered": goal_type}
                goal_state = GoalState(properties=goal_props)

                planned_actions = planner.plan(initial_state, goal_state, actions)
                if planned_actions:
                    # Construct AttackPath
                    node_ids = [entry]
                    for idx, act in enumerate(planned_actions):
                        # Generate or find matching node ID for the transition state
                        effect_keys = list(act.effects.keys())
                        if effect_keys:
                            main_effect = act.effects[effect_keys[0]]
                            node_ids.append(f"node-{main_effect}-{idx}-{uuid.uuid4().hex[:6]}")
                        else:
                            node_ids.append(f"node-step-{idx}-{uuid.uuid4().hex[:6]}")

                    edge_ids = [f"LEADS_TO-{i}" for i in range(len(node_ids) - 1)]

                    # Estimate confidence and risk based on cost
                    total_cost = sum(act.cost for act in planned_actions)
                    confidence = max(1.0 - (total_cost * 0.1), 0.1)
                    risk_score = min(total_cost, 10.0)

                    path = AttackPath(
                        node_ids=node_ids,
                        edge_ids=edge_ids,
                        confidence=confidence,
                        risk_score=risk_score,
                        total_time_estimate=int(total_cost * 60),
                        detection_risk=min(total_cost * 0.05, 1.0),
                        validated=False,
                        entry_node_id=entry,
                        goal_node_id=node_ids[-1],
                        engagement_id=engagement_id,
                    )
                    all_paths.append(path)

        # Score and rank paths
        scored_paths = []
        for path in all_paths:
            score = self._score_path(path)
            scored_paths.append((path, score))

        scored_paths.sort(key=lambda x: x[1], reverse=True)

        # Store top paths
        self.discovered_paths = [p for p, _ in scored_paths[:10]]

        return {
            "status": "success",
            "paths_discovered": len(all_paths),
            "top_paths": [
                {
                    "path_id": p.id,
                    "confidence": p.confidence,
                    "risk_score": p.risk_score,
                    "time_estimate": p.total_time_estimate,
                    "detection_risk": p.detection_risk,
                    "node_count": len(p.node_ids),
                }
                for p, _ in scored_paths[:10]
            ],
        }

    async def _validate_chain(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a specific attack chain end-to-end."""
        if not self.ctx.current_task:
            return {"status": "error", "error": "No active task context"}

        path_id = payload["path_id"]

        # Retrieve path from graph
        path = next((p for p in self.discovered_paths if p.id == path_id), None)
        if not path:
            return {"status": "error", "error": f"Path {path_id} not discovered"}

        # Validate each step
        validation_results = []
        for node_id in path.node_ids:
            # Query node details
            node = await self.ctx.graph_memory.get_node_details(node_id)
            if node and node.get("type") == "Vulnerability":
                if not node.get("props", {}).get("validated", False):
                    # Fetch endpoint URL
                    endpoint_url = await self.ctx.graph_memory.get_endpoint_url_for_vulnerability(
                        node_id
                    )

                    # Build a real PoC from vulnerability node data via ChainComposer.
                    # Map the vulnerability to a PrimitiveLedger so ChainComposer can
                    # select the appropriate PoC builder for its type.
                    node_props = node.get("props", {})
                    vuln_type_raw = node_props.get("vuln_type", "generic")
                    # Map VulnClass string → PrimitiveType (best-effort; falls back to GENERIC)
                    _VULN_TO_PRIM = {
                        "ssrf": PrimitiveType.SSRF_HINT,
                        "idor": PrimitiveType.IDOR_HINT,
                        "bola": PrimitiveType.IDOR_HINT,
                        "xss": PrimitiveType.ENDPOINT_OBSERVED,
                        "sqli": PrimitiveType.ENDPOINT_OBSERVED,
                        "rce": PrimitiveType.NUCLEI_SIGNAL,
                        "race_condition": PrimitiveType.RATE_LIMIT_MISS,
                        "js_secret": PrimitiveType.JS_SECRET,
                    }
                    prim_type = _VULN_TO_PRIM.get(str(vuln_type_raw).lower(), PrimitiveType.GENERIC)
                    synthetic_prim = PrimitiveLedger(
                        primitive_type=prim_type,
                        engagement_id=self.ctx.current_task.engagement_id,
                        source="attack_chain_agent",
                        dedup_key=f"chain-validate-{node_id}",
                        target=endpoint_url or "",
                        raw={
                            "method": node_props.get("method", "GET"),
                            "headers": node_props.get("request_headers", {}),
                            "body": node_props.get("request_body", ""),
                            "template_id": node_props.get("template_id", ""),
                            "victim_cookie": node_props.get("victim_cookie", ""),
                            "attacker_cookie": node_props.get("attacker_cookie", ""),
                        },
                        confidence=node_props.get("confidence", 0.7),
                        severity_hint=str(node_props.get("severity", "medium")).lower(),
                    )
                    composer = ChainComposer()
                    tmp_chain = composer.compose([synthetic_prim])
                    tmp_chain = composer.generate_poc(tmp_chain, [synthetic_prim])
                    exploit_payload = tmp_chain.poc_script  # concrete argv list, never "TBD"

                    # Schedule validation task for the exploit agent
                    task = Task(
                        type="validate_exploit",
                        priority=8,
                        agent_type=AgentType.EXPLOIT_VALIDATION,
                        payload={
                            "target": endpoint_url,
                            "vulnerability_id": node_id,
                            "payload": exploit_payload,  # real PoC argv, not "TBD"
                            "poc_source": "chain_composer",
                        },
                        engagement_id=self.ctx.current_task.engagement_id,
                    )
                    # Push to orchestrator task queue
                    await self.ctx.session_memory.push_task_queue(
                        f"tasks:{self.ctx.current_task.engagement_id}", task.model_dump()
                    )
                    validation_results.append(
                        {"node_id": node_id, "status": "validation_scheduled", "task_id": task.id}
                    )
                else:
                    validation_results.append({"node_id": node_id, "status": "already_validated"})

        return {"status": "success", "path_id": path_id, "validation_results": validation_results}

    async def _propagate_risk(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Propagate risk from validated exploit."""
        exploit_id = payload["exploit_id"]
        impact_score = payload.get("impact_score", 5.0)

        await self.ctx.graph_memory.propagate_risk(exploit_id, impact_score)

        return {
            "status": "success",
            "exploit_id": exploit_id,
            "impact_score": impact_score,
            "propagated": True,
        }

    async def _find_lateral_movement(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Find lateral movement opportunities."""
        engagement_id = payload["engagement_id"]

        # Query graph for credential reuse, trust relationships
        # This would use Neo4j graph queries

        return {"status": "success", "lateral_vectors": [], "engagement_id": engagement_id}

    async def _find_entry_points(self, engagement_id: str) -> List[str]:
        """Find all entry point nodes in the graph."""
        if not self.ctx.graph_memory:
            return []
        ids: List[str] = []
        records = await self.ctx.graph_memory.run_read_query(
            "MATCH (a:Asset {engagement_id: $sid}) RETURN a.id as id",
            {"sid": engagement_id},
        )
        for record in records:
            r_id = record.get("id")
            if isinstance(r_id, str):
                ids.append(r_id)
        return ids

    def _score_path(self, path: AttackPath) -> float:
        """
        Score attack path quality.

        Factors:
        - Confidence (40%)
        - Inverse time (20%)
        - Inverse detection risk (20%)
        - Goal value (20%)
        """
        confidence_weight = path.confidence * 0.4
        time_weight = (1.0 / (1 + path.total_time_estimate / 3600)) * 0.2
        stealth_weight = (1.0 - path.detection_risk) * 0.2
        goal_weight = 0.2  # Simplified

        return confidence_weight + time_weight + stealth_weight + goal_weight

    async def _cleanup_resources(self) -> None:
        self.discovered_paths.clear()
        self.validated_chains.clear()
