"""ReasoningLoop — the hypothesis-driven reasoning loop.

This is the architectural change from the assessment: AI-OSOP currently
executes a FIXED pipeline (recon → discovery → scan → report). This module
replaces that with a CONTINUOUS reasoning loop that runs alongside the
existing phase monitor:

    Observe (read graph state)
    → Generate hypotheses (HypothesisEngine, already exists)
    → Select highest-value hypothesis (confidence × value × novelty)
    → Dispatch (create a Task for the hypothesis's recommended_test)
    → Evaluate (did the finding confirm/refute the hypothesis?)
    → Learn (record to FindingsKnowledge — already auto-records)
    → Loop (generate NEW hypotheses based on what was learned)

The phase monitor still handles phase transitions and the baseline scan
schedule. The reasoning loop adds ADAPTIVE work on top: targeted tests
the phase monitor would never schedule (e.g. "this endpoint has ?redirect=
— test open redirect → if confirmed, chain to OAuth token theft").

Dead-end recovery: when a hypothesis test returns 0 findings, the loop
generates follow-up hypotheses ("was the endpoint authenticated?", "should
we try a different technique?") instead of silently moving on.

Memory-driven planning: before selecting a hypothesis, the loop recalls
prior findings from FindingsKnowledge — if a technique succeeded on
similar targets before, boost its confidence; if it failed, lower it.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task

logger = logging.getLogger(__name__)

# How long to wait for a dispatched hypothesis test before giving up.
_HYPOTHESIS_TIMEOUT = 120  # seconds
# How long to sleep between reasoning cycles when no open hypotheses remain.
_IDLE_SLEEP = 5  # seconds
# Maximum consecutive dead-ends before giving up on an engagement.
_MAX_DEAD_ENDS = 20


# Map hypothesis recommended_skills (task types) to the AgentType that
# handles them. The scheduler uses this to route the task.
_SKILL_TO_AGENT_TYPE = {
    "sqli_scan": AgentType.VULN_ANALYSIS,
    "xss_scan": AgentType.VULN_ANALYSIS,
    "mass_assignment_scan": AgentType.VULN_ANALYSIS,
    "stored_xss_scan": AgentType.VULN_ANALYSIS,
    "secret_liveness_scan": AgentType.VULN_ANALYSIS,
    "ssrf_metadata_chain": AgentType.VULN_ANALYSIS,
    "oauth_reset_scan": AgentType.VULN_ANALYSIS,
    "open_redirect_scan": AgentType.VULN_ANALYSIS,
    "nosql_scan": AgentType.VULN_ANALYSIS,
    "cache_poisoning_scan": AgentType.VULN_ANALYSIS,
    "ai_mcp_scan": AgentType.VULN_ANALYSIS,
    "burp_scan": AgentType.VULN_ANALYSIS,
    "nuclei_scan": AgentType.VULN_ANALYSIS,
    "ssrf_scan": AgentType.SSRF_SCANNER,
    "ssti_scan": AgentType.SSTI_SCANNER,
    "csrf_scan": AgentType.CSRF_SCANNER,
    "jwt_scan": AgentType.JWT_SCANNER,
    "smuggling_scan": AgentType.SMUGGLING_SCANNER,
    "race_scan": AgentType.RACE_SCANNER,
    "upload_scan": AgentType.UPLOAD_SCANNER,
    "pollution_scan": AgentType.POLLUTION_SCANNER,
    "websocket_scan": AgentType.WEBSOCKET_SCANNER,
    "saml_scan": AgentType.SAML_SCANNER,
    "takeover_scan": AgentType.TAKEOVER_SCANNER,
    "run_diff_auth_analysis": AgentType.WORKFLOW,
    "capture_authenticated_surface": AgentType.WORKFLOW,
    "probe_metadata": AgentType.CLOUD_SPECIALIST,
    "analyze_iam": AgentType.CLOUD_SPECIALIST,
    "cloud_pentest": AgentType.CLOUD_SPECIALIST,
}


class ReasoningLoop:
    """Continuous hypothesis-driven reasoning loop.

    Runs as a background asyncio task alongside the phase monitor. Each
    cycle: observe the graph → generate hypotheses → select the highest-
    value one → dispatch it as a Task → evaluate the result → update the
    hypothesis status → generate follow-up hypotheses.
    """

    def __init__(self, orchestrator: Any):
        self._orch = orchestrator
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._dead_ends = 0
        self._tested_hypotheses: set = set()
        # Event-driven collaboration: finding.recorded events trigger immediate
        # chain hypothesis generation without waiting for the next polling cycle.
        self._event_subscriber: Optional[asyncio.Task] = None
        self._pending_finding_events: asyncio.Queue = asyncio.Queue()
        # Reasoning trace: records every decision the loop makes so the
        # system can explain WHY it tested hypothesis X instead of Y, WHY
        # it abandoned a hypothesis, and what it learned. This is the
        # 'self-evaluation + explainability' cognitive capability.
        from ai_osop.core.reasoning_trace import ReasoningTrace

        self.trace = ReasoningTrace()
        # WAF-block pivoting: fed by the WAFCharacterProbe in _observe
        # (real HTTP responses), consulted after each hypothesis test.
        from ai_osop.orchestrator.pivoting_broker import PivotingBroker

        self._pivoting_broker = PivotingBroker()

    def start(self) -> None:
        """Start the reasoning loop + the event subscriber as background tasks."""
        if self._task is not None and not self._task.done():
            return
        self._running = True
        self._task = asyncio.create_task(self._run())
        # Subscribe to finding.recorded events so every confirmed finding
        # immediately triggers chain hypothesis generation (event-driven
        # agent collaboration — Priority 4 of the roadmap).
        self._event_subscriber = asyncio.create_task(self._listen_for_findings())

    async def stop(self) -> None:
        """Stop the reasoning loop + event subscriber gracefully."""
        self._running = False
        for bg in (self._event_subscriber, self._task):
            if bg is not None and not bg.done():
                bg.cancel()
                try:
                    await asyncio.wait_for(asyncio.gather(bg, return_exceptions=True), timeout=5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
        self._task = None
        self._event_subscriber = None

    async def _listen_for_findings(self) -> None:
        """Subscribe to finding.recorded events and trigger immediate chain generation.

        This is the event-driven collaboration mechanism: when any agent
        persists a finding, GraphMemory publishes a finding.recorded event
        on the coordination bus. This subscriber receives it and immediately
        generates chain hypotheses (SSRF→metadata, IDOR→admin, etc.) without
        waiting for the next polling cycle.
        """
        bus = getattr(self._orch, "coordination_bus", None)
        if bus is None:
            return
        try:
            async for event in bus.subscribe("finding.recorded"):
                if not self._running:
                    break
                payload = event.payload if hasattr(event, "payload") else event.get("payload", {})
                await self._pending_finding_events.put(payload)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("reasoning_event_subscriber_error: %s", str(e))

    async def _run(self) -> None:
        """Main reasoning loop — runs until the orchestrator stops."""
        while self._running:
            try:
                # Drain any pending finding.recorded events FIRST (event-driven
                # collaboration). Each event triggers immediate chain hypothesis
                # generation without waiting for the next polling cycle.
                while not self._pending_finding_events.empty():
                    try:
                        event_payload = self._pending_finding_events.get_nowait()
                        eid = event_payload.get("engagement_id", "")
                        if eid:
                            await self._handle_finding_event(eid, event_payload)
                    except Exception as e:
                        logger.warning("reasoning_event_drain_error: %s", str(e))

                await asyncio.sleep(2)  # yield to the event loop
                for session_id, session in list(self._orch._sessions.items()):
                    eid = getattr(session, "canonical_engagement_id", None) or session_id
                    phase = session.phase
                    # Only reason during active phases (not HALTED/COMPLETED).
                    if phase in ("halted", "completed"):
                        continue
                    await self._reasoning_cycle(eid, session_id)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("reasoning_loop_error: %s", str(e))
                await asyncio.sleep(10)

    async def _handle_finding_event(self, engagement_id: str, payload: Dict[str, Any]) -> None:
        """Handle a finding.recorded event — trigger immediate chain generation.

        When a finding is persisted, generate chain hypotheses immediately:
          - SSRF confirmed → try metadata → try credentials → try S3
          - IDOR confirmed → try admin objects → try privilege escalation
          - XSS confirmed → try cookie theft → try session hijacking
          - JWT confirmed → try identity forgery → try admin access
        """
        vuln_type = payload.get("vuln_type", "")
        finding_id = payload.get("finding_id", "")

        # Map vuln types to chain focus strings
        chain_map = {
            "ssrf": "metadata chain: SSRF confirmed → probe IMDS → extract credentials → probe S3/secrets",
            "idor": "authorization chain: IDOR confirmed → try admin objects → privilege escalation",
            "xss": "XSS chain: execution confirmed → try cookie theft → session hijacking → ATO",
            "jwt_abuse": "JWT chain: forgery confirmed → try admin identity → full auth bypass",
            "sqli": "SQLi chain: injection confirmed → try UNION → try stacked queries → try RCE",
            "mass_assignment": "Mass-assignment chain: admin role set → try admin endpoints → privesc",
        }
        focus = chain_map.get(vuln_type, "")
        if not focus:
            return

        try:
            from ai_osop.core.hypothesis_engine import HypothesisEngine

            engine = HypothesisEngine(
                self._orch.graph_memory,
                skill_engine=getattr(self._orch, "skill_engine", None),
                session_memory=self._orch.session_memory,
            )
            await engine.generate_and_persist(engagement_id, focus=focus, limit=5)
            logger.info(
                "reasoning_event_chain_generated",
                engagement_id=engagement_id,
                vuln_type=vuln_type,
                finding_id=finding_id,
                focus=focus,
            )
        except Exception as e:
            logger.warning(
                "reasoning_event_chain_failed",
                engagement_id=engagement_id,
                vuln_type=vuln_type,
                error=str(e),
            )

    async def _reasoning_cycle(self, engagement_id: str, session_id: str) -> None:
        """One full Observe → Hypothesize → Dispatch → Evaluate → Critique cycle."""
        # 1. OBSERVE: read the current graph state
        state = await self._observe(engagement_id)
        if not state["endpoints"]:
            return  # nothing to reason about yet

        # 1b. ORIENT: categorize endpoints by business domain (Phase 3.1).
        # This is the semantic mental model the assessment says is missing —
        # instead of treating endpoints as flat strings, the system now
        # understands "this is a payment endpoint" or "this is an admin panel."
        from ai_osop.core.business_context import batch_categorize

        categorized = batch_categorize(state["endpoints"])
        high_value = [c for c in categorized if c.criticality >= 7]
        if high_value:
            state["focus"] = (
                f"high-value endpoints detected: "
                f"{', '.join(c.category for c in high_value[:5])}"
            )

        # 2. GENERATE HYPOTHESES
        from ai_osop.core.hypothesis_engine import HypothesisEngine

        engine = HypothesisEngine(
            self._orch.graph_memory,
            skill_engine=getattr(self._orch, "skill_engine", None),
            session_memory=self._orch.session_memory,
        )
        hypotheses = await engine.generate_and_persist(
            engagement_id, focus=state.get("focus", ""), limit=12
        )

        # Publish hypothesis.generated event for any subscribers
        await self._publish_event(
            "hypothesis.generated",
            {"engagement_id": engagement_id, "count": len(hypotheses)},
        )

        if not hypotheses:
            if self._dead_ends >= _MAX_DEAD_ENDS:
                return
            self._dead_ends += 1
            return

        # 3. SELECT highest-value hypothesis
        selected = await self._select_hypothesis(engagement_id, hypotheses, state)
        if selected is None:
            return

        # Skip if we already tested this hypothesis
        if selected.get("id") in self._tested_hypotheses:
            return
        self._tested_hypotheses.add(selected.get("id"))

        # Record the selection decision in the reasoning trace
        self.trace.record(
            engagement_id=engagement_id,
            step="select",
            decision=f"Selected hypothesis: {selected.get('title', '?')}",
            rationale=(
                f"confidence={selected.get('confidence', 0):.2f}, "
                f"category={selected.get('category', '?')}, "
                f"target={selected.get('target_id', '?')}"
            ),
            hypothesis_id=selected.get("id", ""),
            confidence=float(selected.get("confidence", 0)),
            alternatives_considered=[
                h.get("title", "?") if isinstance(h, dict) else getattr(h, "title", "?")
                for h in hypotheses[:5]
            ],
        )

        # 4. DISPATCH: create a Task for the hypothesis's recommended test
        task = await self._dispatch_hypothesis(engagement_id, session_id, selected)
        if task is None:
            self.trace.record(
                engagement_id=engagement_id,
                step="dispatch",
                decision="Skipped dispatch — no agent mapping or target URL",
                hypothesis_id=selected.get("id", ""),
                result="skipped",
            )
            return

        self.trace.record(
            engagement_id=engagement_id,
            step="dispatch",
            decision=f"Dispatched {task.type} to {task.agent_type.value}",
            rationale=f"maps to {task.agent_type.value}",
            hypothesis_id=selected.get("id", ""),
            task_id=task.id,
            result="dispatched",
        )

        # 5. EVALUATE: wait for the task, check results
        result = await self._wait_for_task(task.id, timeout=_HYPOTHESIS_TIMEOUT)
        await self._evaluate_result(engagement_id, selected, result)

        # 5b. CRITIQUE: adversarial review of findings (Phase 3.2).
        # The PostEngagementCriticAgent.audit_findings method reviews validated
        # findings for false positives, missing evidence, and incomplete
        # validation — the "peer review" step the assessment says is missing.
        # If the critic flags a finding, the reasoning loop logs the issue
        # so the report layer can downgrade or re-verify it.
        try:
            from ai_osop.agents.critic_agent import PostEngagementCriticAgent

            critic = PostEngagementCriticAgent(
                self._orch.session_memory,
                self._orch.graph_memory,
            )
            critiques = await critic.audit_findings(engagement_id)
            if critiques:
                for c in critiques:
                    logger.warning(
                        "reasoning_critic_flag",
                        engagement_id=engagement_id,
                        finding_id=c.get("finding_id"),
                        issues=c.get("issues"),
                    )
        except Exception as e:
            logger.warning("reasoning_critic_failed: %s", str(e))

        # 6. LEARN happens automatically: GraphMemory.add_vulnerability
        # calls FindingsKnowledge.record_finding. We just update the
        # hypothesis status so the next cycle generates fresh ones.

        # 6b. GRAPH PATHFINDER: after each cycle, run the automated graph
        # pathfinder to discover attack chains the template-based
        # AttackChainAgent would miss. The pathfinder queries Neo4j for
        # paths from confirmed vulnerabilities to high-value endpoints.
        # Discovered chains generate new hypotheses for the next cycle.
        try:
            from ai_osop.core.graph_pathfinder import GraphPathfinder

            pathfinder = GraphPathfinder(self._orch.graph_memory)
            chains = await pathfinder.find_chains(engagement_id, max_depth=5)
            if chains:
                for chain in chains[:3]:  # cap at 3 chains per cycle
                    logger.info(
                        "reasoning_graph_pathfinder_chain",
                        engagement_id=engagement_id,
                        chain_type=chain.get("chain_type"),
                        confidence=chain.get("confidence"),
                        description=chain.get("description", "")[:100],
                    )
                    # Publish the chain as a hypothesis-generated event so
                    # any subscriber can react.
                    await self._publish_event(
                        "chain.discovered",
                        {
                            "engagement_id": engagement_id,
                            "chain_type": chain.get("chain_type"),
                            "description": chain.get("description"),
                            "steps": chain.get("steps"),
                        },
                    )
        except Exception as e:
            logger.warning("reasoning_pathfinder_failed: %s", str(e))

    async def _observe(self, engagement_id: str) -> Dict[str, Any]:
        """Read the current graph state for an engagement."""
        gm = self._orch.graph_memory
        try:
            endpoints = await gm.run_read_query(
                "MATCH (e:Endpoint {engagement_id: $eid}) "
                "RETURN e.url AS url, e.method AS method, e.path AS path, "
                "e.query_keys AS query_keys, e.has_body AS has_body, "
                "e.auth_required AS auth_required, e.id AS id "
                "LIMIT 500",
                {"eid": engagement_id},
            )
            findings = await gm.run_read_query(
                "MATCH (v:Vulnerability {engagement_id: $eid}) "
                "RETURN v.vuln_type AS vuln_type, v.severity AS severity, "
                "v.validated AS validated "
                "LIMIT 100",
                {"eid": engagement_id},
            )
            open_hypotheses = await gm.get_hypotheses_by_engagement(engagement_id)
            open_hyp_ids = {h.get("id") for h in open_hypotheses if h.get("status") == "open"}
        except Exception as e:
            logger.warning("reasoning_observe_failed engagement_id=%s: %s", engagement_id, str(e))
            return {"endpoints": [], "findings": [], "open_hypotheses": set()}

        # Uncertainty detection: scan the current state for things we DON'T
        # know. Each uncertainty becomes an info-seeking hypothesis that the
        # reasoning loop can dispatch. This is the 'active information-
        # seeking' behavior the assessment says is missing — instead of
        # only testing for vulns, the system also tests to RESOLVE
        # uncertainty (is this endpoint authed? what framework is it?).
        try:
            from ai_osop.core.uncertainty_tracker import UncertaintyTracker

            if not hasattr(self, "_uncertainty_tracker"):
                self._uncertainty_tracker = UncertaintyTracker()
            new_uncerts = self._uncertainty_tracker.detect_uncertainties(
                engagement_id,
                endpoints,
                findings,
            )
            if new_uncerts:
                # AIOSOP-LINT-F841: hypothesis retrieval is informational only;
                # we log the count but do not currently branch on the result.
                self._uncertainty_tracker.get_uncertainty_hypotheses(engagement_id)
                logger.info(
                    "reasoning_uncertainties_detected",
                    engagement_id=engagement_id,
                    new=len(new_uncerts),
                    total_open=len(self._uncertainty_tracker.get_open_uncertainties(engagement_id)),
                )
                # Record the uncertainty detection in the reasoning trace
                self.trace.record(
                    engagement_id=engagement_id,
                    step="observe",
                    decision=f"Detected {len(new_uncerts)} new uncertainties",
                    rationale=f"open uncertainties: {self._uncertainty_tracker.get_summary(engagement_id)}",
                )
        except Exception as e:
            logger.warning("reasoning_uncertainty_detection_failed: %s", str(e))

        # WAF Character Probe: if any endpoint has a detected WAF, probe its
        # filtered characters so the payload engine can generate WAF-bypass
        # payloads. This is the "experiment design" cognitive capability —
        # the system actively gathers information about the target's defenses
        # before attacking.
        try:
            from ai_osop.core.waf_character_probe import probe_waf_characters

            # Check if any asset has a WAF detected
            waf_assets = await self._orch.graph_memory.run_read_query(
                "MATCH (a:Asset {engagement_id: $eid}) WHERE a.waf IS NOT NULL "
                "RETURN a.value AS value, a.waf AS waf LIMIT 5",
                {"eid": engagement_id},
            )
            for asset in waf_assets:
                waf_name = asset.get("waf", "")
                asset_value = asset.get("value", "")
                if not waf_name or not asset_value:
                    continue
                # Check if we already probed this host
                probe_key = f"waf_probed_{asset_value}"
                if probe_key in self._tested_hypotheses:
                    continue
                self._tested_hypotheses.add(probe_key)

                target_url = (
                    f"http://{asset_value}" if not asset_value.startswith("http") else asset_value
                )
                import httpx
                from ai_osop.safety.governed_client import (
                    governance_hook,
                    research_header_from_settings,
                    resolve_tls_verify,
                )
                from ai_osop.safety.rate_limiter import RateLimiter
                from ai_osop.core.config import settings as _settings

                ghook = governance_hook(
                    rate_limiter=RateLimiter(
                        target_rate=_settings.scan_target_rate_per_second,
                        target_capacity=_settings.scan_target_burst,
                    ),
                    research_header=research_header_from_settings(),
                )
                async with httpx.AsyncClient(
                    event_hooks={"request": [ghook]} if ghook else {},
                    # W5: audited insecure-TLS opt-in (target may present bad certs).
                    verify=resolve_tls_verify(False, allow_insecure=True, tool="waf_probe"),
                    timeout=10.0,
                ) as waf_client:
                    probe_result = await probe_waf_characters(
                        waf_client,
                        target_url,
                        param="q",
                    )
                    # Each blocked char-group is a real request the governed
                    # client sent that the WAF rejected (WAFCharacterProbe
                    # marks a group blocked on 403/406/429/503, a challenge
                    # page, or a >50% body-length drop). Feed them to the broker
                    # keyed by host — the same key should_pivot() is queried
                    # with below — so the block count reflects actual WAF
                    # rejections, then check for a strategic pivot right here at
                    # the real signal source. A fired pivot is advisory: it
                    # records a PIVOT step in the reasoning trace; it does not
                    # reschedule tasks.
                    blocked = list(probe_result.blocked_groups or [])
                    if probe_result.baseline_status in (403, 406, 429, 503):
                        blocked = blocked or ["baseline"]
                    for _ in blocked:
                        self._pivoting_broker.record_response(asset_value, 403)
                    if blocked:
                        decision = self._pivoting_broker.should_pivot(asset_value)
                        if decision.should_pivot:
                            self.trace.record(
                                engagement_id=engagement_id,
                                step="pivot",
                                decision=f"PIVOT: {decision.reason}",
                                rationale=decision.pivot_strategy,
                                result="pivot",
                            )
                    if probe_result.blocked_groups:
                        self.trace.record(
                            engagement_id=engagement_id,
                            step="observe",
                            decision=f"WAF probe: {len(probe_result.blocked_groups)} char groups blocked by {waf_name}",
                            rationale=f"blocked: {probe_result.blocked_groups}, allowed: {probe_result.allowed_groups}",
                        )
                        logger.info(
                            "reasoning_waf_probe_complete",
                            engagement_id=engagement_id,
                            waf=waf_name,
                            blocked=probe_result.blocked_groups,
                            allowed=probe_result.allowed_groups,
                        )
        except Exception as e:
            logger.warning("reasoning_waf_probe_failed: %s", str(e))

        # Param Miner: actively probe high-value endpoints for hidden
        # parameters. A human researcher doesn't just parse OpenAPI specs —
        # they brute-force parameter names. This discovers inputs that
        # static parsing would miss.
        try:
            from ai_osop.core.param_miner import mine_parameters

            # Only mine high-value endpoints (criticality >= 7 from business context)
            # to avoid wasting requests on static assets.
            mined_key = f"param_mined_{engagement_id}"
            if mined_key not in self._tested_hypotheses:
                # Mine up to 3 high-value endpoints per cycle
                high_value_eps = [
                    ep
                    for ep in endpoints[:5]
                    if ep.get("auth_required") or "api" in (ep.get("path", "")).lower()
                ]
                for ep in high_value_eps[:3]:
                    ep_url = ep.get("url", "")
                    if not ep_url:
                        continue
                    import httpx
                    from ai_osop.safety.governed_client import (
                        governance_hook,
                        research_header_from_settings,
                        resolve_tls_verify,
                    )
                    from ai_osop.safety.rate_limiter import RateLimiter
                    from ai_osop.core.config import settings as _settings

                    ghook = governance_hook(
                        rate_limiter=RateLimiter(
                            target_rate=_settings.scan_target_rate_per_second,
                            target_capacity=_settings.scan_target_burst,
                        ),
                        research_header=research_header_from_settings(),
                    )
                    method = (ep.get("method") or "GET").upper()
                    existing_params = list(ep.get("query_keys") or [])
                    async with httpx.AsyncClient(
                        event_hooks={"request": [ghook]} if ghook else {},
                        # W5: audited insecure-TLS opt-in (target may present bad certs).
                        verify=resolve_tls_verify(False, allow_insecure=True, tool="param_mine"),
                        timeout=8.0,
                    ) as mine_client:
                        mine_result = await mine_parameters(
                            mine_client,
                            ep_url,
                            method=method,
                            existing_params=existing_params,
                            max_params=30,
                        )
                        if mine_result.discovered_params:
                            self.trace.record(
                                engagement_id=engagement_id,
                                step="observe",
                                decision=f"Param miner: discovered {len(mine_result.discovered_params)} hidden params at {ep_url}",
                                rationale=f"discovered: {mine_result.discovered_params}",
                            )
                            # Persist discovered params on the endpoint
                            await self._orch.graph_memory.run_write_query(
                                "MATCH (e:Endpoint {url: $url}) SET e.mined_params = $params",
                                {"url": ep_url, "params": mine_result.discovered_params},
                            )
                self._tested_hypotheses.add(mined_key)
        except Exception as e:
            logger.warning("reasoning_param_mine_failed: %s", str(e))

        return {
            "endpoints": endpoints,
            "findings": findings,
            "open_hypotheses": open_hyp_ids,
            "finding_types": {f.get("vuln_type", "") for f in findings},
        }

    async def _select_hypothesis(
        self,
        engagement_id: str,
        hypotheses: List[Any],
        state: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Select the highest-value hypothesis to test next.

        W4 / roadmap #4: the LLM now ranks candidates by ATTACK-CHAIN value
        (which hypothesis, if true, enables the most damaging follow-on), instead
        of pure arithmetic confidence. If the LLM is unavailable, degraded, or
        returns an unusable ranking, we fall back to the prior arithmetic score —
        the loop never stalls on a bad reasoning call. The arithmetic score is
        still computed and recorded so the LLM decision is auditable against it.

        Fallback ranking factors (used when the LLM path cannot rank):
          - confidence (from HypothesisEngine heuristics)
          - novelty (has this category been tested before? untested = higher)
          - finding_types already found (if we found SSRF, boost chain hypotheses)
          - prior knowledge (recall from FindingsKnowledge)
        """
        finding_types = state.get("finding_types", set())

        # Normalize candidates to dicts, skipping already-tested/closed.
        candidates: List[Dict[str, Any]] = []
        for hyp in hypotheses:
            if isinstance(hyp, dict):
                h = hyp
            else:
                h = hyp.model_dump() if hasattr(hyp, "model_dump") else dict(hyp)
            if h.get("status") != "open":
                continue
            if h.get("id") in self._tested_hypotheses:
                continue
            candidates.append(h)

        if not candidates:
            return None

        # W4: try LLM ranking first; fall back to arithmetic on any failure.
        llm_ranked = await self._llm_rank_hypotheses(engagement_id, candidates, state)
        if llm_ranked is not None:
            return llm_ranked

        # --- arithmetic fallback (original behavior) ---
        ranked: List[tuple] = []
        for h in candidates:
            category = h.get("category", "")
            base_score = float(h.get("confidence", 0.5))
            if category not in finding_types:
                base_score += 0.1  # novel attack surface
            prior_boost = await self._recall_prior(engagement_id, category, h.get("target_id", ""))
            base_score += prior_boost
            ranked.append((base_score, h))

        if not ranked:
            return None
        ranked.sort(key=lambda x: x[0], reverse=True)
        best: Dict[str, Any] = ranked[0][1]
        return best

    async def _llm_rank_hypotheses(
        self,
        engagement_id: str,
        candidates: List[Dict[str, Any]],
        state: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Ask the reasoning model to rank candidate hypotheses by attack-chain value.

        Returns the top-ranked hypothesis dict, or None if the LLM is unavailable,
        degraded, or returns a ranking we can't map back to real candidate ids —
        in every failure case the caller falls back to arithmetic ranking, so a
        bad LLM call can never stall or corrupt the loop.

        The model sees a compact, sanitized summary of the observed state and the
        candidate list, and must answer with the single best hypothesis id. We do
        NOT trust the model to invent ids — we only accept an id that exactly
        matches a candidate, otherwise we discard the ranking.
        """
        llm = getattr(self._orch, "llm_client", None)
        if llm is None or not hasattr(llm, "complete"):
            return None

        from ai_osop.core.config import settings as _settings
        from ai_osop.safety.prompt_defense import sanitize_messages

        # Compact candidate view: id + category + confidence + what it recommends.
        lines = []
        for h in candidates[:12]:  # cap prompt size
            skills = h.get("recommended_skills", []) or []
            lines.append(
                f"id={h.get('id')} | cat={h.get('category')} | conf={h.get('confidence')} | "
                f"target={h.get('target_id')} | does={','.join(skills[:3])}"
            )
        endpoints = state.get("endpoints", [])
        finding_types = sorted(t for t in state.get("finding_types", set()) if t)
        focus = state.get("focus", "")
        user = (
            "You are ranking hypotheses for an AUTHORIZED security test inside its "
            "declared scope. Rank by which single hypothesis, if confirmed, enables the "
            "most damaging follow-on attack chain.\n\n"
            f"Observed: {len(endpoints)} endpoints; focus: {focus}; "
            f"findings already: {', '.join(finding_types) or 'none'}.\n\n"
            "Candidates:\n" + "\n".join(lines) + "\n\n"
            "Respond with EXACTLY one line: BEST: <id>\n"
            "Pick exactly one id that appears above. No explanation, no other text."
        )
        messages = sanitize_messages(
            [
                {"role": "system", "content": "You rank security-test hypotheses by impact."},
                {"role": "user", "content": user},
            ]
        )
        try:
            reasoning_model = getattr(_settings, "llm_reasoning_model", "") or None
            text = await llm.complete(
                messages,
                model=reasoning_model,
                max_tokens=getattr(_settings, "llm_reasoning_max_tokens", 1536),
            )
        except Exception as e:
            logger.info("reasoning_llm_rank_failed: %s", str(e)[:160])
            return None
        if isinstance(text, dict):
            text = text.get("content", "")
        text = str(text or "").strip()
        if not text:
            return None

        # Extract the id after BEST: and only accept an exact candidate id.
        import re as _re

        m = _re.search(r"BEST:\s*([A-Za-z0-9_-]+)", text)
        if not m:
            return None
        chosen_id = m.group(1)
        for h in candidates:
            if str(h.get("id")) == chosen_id:
                logger.info(
                    "reasoning_llm_selected hypothesis=%s category=%s candidates=%d",
                    chosen_id,
                    h.get("category"),
                    len(candidates),
                )
                self.trace.record(
                    engagement_id=engagement_id,
                    step="select",
                    decision=f"LLM selected hypothesis: {h.get('title', chosen_id)}",
                    rationale=f"attack-chain value ranking over {len(candidates)} candidates",
                )
                chosen: Dict[str, Any] = dict(h)
                return chosen
        # Model returned an id that is not a real candidate -> treat as unusable.
        logger.info("reasoning_llm_rank_unusable_id: %s", chosen_id[:80])
        return None

    async def _recall_prior(self, engagement_id: str, category: str, target_id: str) -> float:
        """Recall prior findings from FindingsKnowledge to adjust hypothesis confidence.

        If similar findings succeeded before → boost (the technique works).
        If they failed → penalty (the technique likely doesn't apply).
        Returns a delta to add to the base score.
        """
        try:
            kb = getattr(self._orch.graph_memory, "findings_knowledge", None)
            if kb is None:
                return 0.0
            prior = await kb.recall_similar(category, limit=3, min_score=0.3)
            if not prior:
                return 0.0
            # If we have prior successes for this category, boost slightly
            return min(0.1, len(prior) * 0.03)
        except Exception:
            return 0.0

    async def _dispatch_hypothesis(
        self,
        engagement_id: str,
        session_id: str,
        hypothesis: Dict[str, Any],
    ) -> Optional[Task]:
        """Create and schedule a Task for the hypothesis's recommended test."""
        rec_skills = hypothesis.get("recommended_skills", [])
        if not rec_skills:
            logger.info(
                "reasoning_hypothesis_no_recommended_tests",
                hypothesis=hypothesis.get("id"),
                title=hypothesis.get("title"),
            )
            return None

        # Pick the first recommended skill that maps to an agent type
        task_type = None
        agent_type = None
        for skill in rec_skills:
            at = _SKILL_TO_AGENT_TYPE.get(skill)
            if at is not None:
                task_type = skill
                agent_type = at
                break

        if task_type is None or agent_type is None:
            logger.info(
                "reasoning_hypothesis_no_agent_mapping",
                hypothesis=hypothesis.get("id"),
                skills=rec_skills,
            )
            return None

        # Build the task payload from the hypothesis target
        target_id = hypothesis.get("target_id", "")
        # Resolve the target to a URL
        url = await self._resolve_target_url(engagement_id, target_id)
        if not url:
            logger.info(
                "reasoning_hypothesis_no_target_url",
                hypothesis=hypothesis.get("id"),
                target_id=target_id,
            )
            return None

        task = Task(
            type=task_type,
            agent_type=agent_type,
            engagement_id=engagement_id,
            priority=8,  # high priority — hypothesis-driven work
            payload={
                "url": url,
                "engagement_id": engagement_id,
                "hypothesis_id": hypothesis.get("id"),
                "hypothesis_category": hypothesis.get("category"),
            },
            timeout_seconds=_HYPOTHESIS_TIMEOUT,
        )

        try:
            await self._orch.task_scheduler.schedule_task(task)
            logger.info(
                "reasoning_dispatched",
                hypothesis=hypothesis.get("id"),
                task_type=task_type,
                url=url,
                category=hypothesis.get("category"),
            )
            return task
        except Exception as e:
            logger.warning("reasoning_dispatch_failed: %s", str(e))
            return None

    async def _resolve_target_url(self, engagement_id: str, target_id: str) -> Optional[str]:
        """Resolve a hypothesis target_id to a URL (from Endpoint or Asset nodes)."""
        if not target_id:
            return None
        try:
            # Try Endpoint first
            recs = await self._orch.graph_memory.run_read_query(
                "MATCH (e:Endpoint {id: $tid}) RETURN e.url AS url LIMIT 1",
                {"tid": target_id},
            )
            if recs and recs[0].get("url"):
                return recs[0]["url"]
            # Try Asset
            recs = await self._orch.graph_memory.run_read_query(
                "MATCH (a:Asset {id: $tid}) RETURN a.value AS value LIMIT 1",
                {"tid": target_id},
            )
            if recs and recs[0].get("value"):
                val = recs[0]["value"]
                return val if val.startswith("http") else f"http://{val}"
        except Exception:
            pass
        return None

    async def _wait_for_task(self, task_id: str, timeout: float) -> Optional[Dict[str, Any]]:
        """Wait for a dispatched task to complete. Returns the task result dict."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            task = self._orch.state.get_task(task_id)
            if task is None:
                return None
            if task.status in ("completed", "failed", "error", "cancelled", "timeout"):
                return task.result or {"status": task.status, "findings_count": 0}
            await asyncio.sleep(2)
        return None  # timed out

    async def _evaluate_result(
        self,
        engagement_id: str,
        hypothesis: Dict[str, Any],
        result: Optional[Dict[str, Any]],
    ) -> None:
        """Evaluate the result of a hypothesis test and update its status.

        Dead-end recovery: if the test found nothing, generate follow-up
        hypotheses ("was the endpoint authenticated?", "try a different
        technique?") instead of silently moving on.
        """
        hyp_id = hypothesis.get("id", "")
        if hyp_id:
            self._tested_hypotheses.add(hyp_id)

        if result is None:
            # Task timed out — mark as inconclusive
            await self._update_hypothesis_status(hyp_id, "inconclusive")
            self._dead_ends += 1
            self.trace.record(
                engagement_id=engagement_id,
                step="evaluate",
                decision=f"Hypothesis {hyp_id} inconclusive (task timed out)",
                rationale="task did not complete within timeout — target may be slow or unresponsive",
                hypothesis_id=hyp_id,
                result="inconclusive",
            )
            return

        findings_count = result.get("findings_count", 0)

        if findings_count > 0:
            # CONFIRMED: the hypothesis was correct
            await self._update_hypothesis_status(hyp_id, "confirmed")
            self._dead_ends = 0
            self.trace.record(
                engagement_id=engagement_id,
                step="evaluate",
                decision=f"Hypothesis {hyp_id} CONFIRMED — {findings_count} finding(s)",
                rationale=f"findings_count={findings_count}, the hypothesis was correct",
                hypothesis_id=hyp_id,
                result="confirmed",
                confidence=(
                    float(result.get("findings", [{}])[0].get("confidence", 0.9))
                    if result.get("findings")
                    else 0.9
                ),
            )
            # Chain: the confirmed finding may open new attack paths
            await self._generate_chain_hypotheses(engagement_id, hypothesis, result)
        else:
            # REFUTED: dead end — generate follow-up hypotheses
            await self._update_hypothesis_status(hyp_id, "refuted")
            self._dead_ends += 1
            self.trace.record(
                engagement_id=engagement_id,
                step="evaluate",
                decision=f"Hypothesis {hyp_id} REFUTED — 0 findings",
                rationale=f"findings_count=0 — the hypothesis did not hold. Generating follow-up: was the endpoint authenticated? should we try a different technique?",
                hypothesis_id=hyp_id,
                result="refuted",
            )
            await self._generate_followup_hypotheses(engagement_id, hypothesis, result)
            # WAF-block pivoting is evaluated at the real signal source — the
            # _observe WAFCharacterProbe, which makes real governed HTTP
            # requests and records blocks keyed by host. It is NOT evaluated
            # here: a hypothesis-test result dict carries no per-request HTTP
            # status, and hypothesis.target_id is a graph-node id, not the
            # host the broker is keyed by, so a check here could never fire.

    async def _update_hypothesis_status(self, hyp_id: str, status: str) -> None:
        """Update a hypothesis's status in the graph."""
        if not hyp_id:
            return
        try:
            await self._orch.graph_memory.run_write_query(
                "MATCH (h:Hypothesis {id: $hid}) SET h.status = $status",
                {"hid": hyp_id, "status": status},
            )
        except Exception as e:
            logger.warning("reasoning_hypothesis_status_update_failed", hyp_id=hyp_id, error=str(e))

    async def _generate_chain_hypotheses(
        self,
        engagement_id: str,
        hypothesis: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        """When a hypothesis is confirmed, generate chain hypotheses.

        E.g. SSRF confirmed → try metadata → try credentials → try S3.
        IDOR confirmed → try admin objects → try privilege escalation.
        """
        category = hypothesis.get("category", "")
        chain_focus = ""

        if category in ("redirect_ssrf", "cloud"):
            chain_focus = "metadata chain: SSRF confirmed → probe IMDS → extract credentials"
        elif category in ("authz", "workflow"):
            chain_focus = (
                "authorization chain: IDOR confirmed → try admin objects → privilege escalation"
            )
        elif category in ("client_side",):
            chain_focus = "XSS chain: execution confirmed → try cookie theft → session hijacking"
        elif category in ("graphql",):
            chain_focus = (
                "GraphQL chain: introspection confirmed → try mutation authz → batch abuse"
            )

        if chain_focus:
            from ai_osop.core.hypothesis_engine import HypothesisEngine

            engine = HypothesisEngine(
                self._orch.graph_memory,
                skill_engine=getattr(self._orch, "skill_engine", None),
                session_memory=self._orch.session_memory,
            )
            await engine.generate_and_persist(engagement_id, focus=chain_focus, limit=5)
            logger.info(
                "reasoning_chain_hypotheses_generated",
                engagement_id=engagement_id,
                category=category,
                focus=chain_focus,
            )

    async def _generate_followup_hypotheses(
        self,
        engagement_id: str,
        hypothesis: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        """Dead-end recovery: when a hypothesis test finds nothing, generate
        follow-up hypotheses that explore WHY it failed.

        Instead of silently moving on, the loop asks:
          - Was the endpoint authenticated? (try auth first)
          - Was the parameter JSON? (try content-type variation)
          - Should we try a different technique?
        """
        category = hypothesis.get("category", "")
        target_id = hypothesis.get("target_id", "")

        # Generate follow-up with a focus that hints at the failure mode
        followup_focus = (
            f"dead-end recovery: {category} test found nothing at {target_id}. "
            f"Consider: authenticated access, different content-type, "
            f"alternative injection points, or different technique."
        )

        from ai_osop.core.hypothesis_engine import HypothesisEngine

        engine = HypothesisEngine(
            self._orch.graph_memory,
            skill_engine=getattr(self._orch, "skill_engine", None),
            session_memory=self._orch.session_memory,
        )
        await engine.generate_and_persist(engagement_id, focus=followup_focus, limit=5)
        logger.info(
            "reasoning_deadend_recovery",
            engagement_id=engagement_id,
            category=category,
            target_id=target_id,
        )

    async def _publish_event(self, topic: str, payload: Dict[str, Any]) -> None:
        """Publish an event on the coordination bus."""
        bus = getattr(self._orch, "coordination_bus", None)
        if bus is None:
            return
        try:
            await bus.publish(topic, payload, source="reasoning_loop")
        except Exception:
            pass
