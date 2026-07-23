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
from datetime import datetime
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
            logger.warning("reasoning_event_subscriber_error", error=str(e))

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
                        logger.warning("reasoning_event_drain_error", error=str(e))

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
                logger.warning("reasoning_loop_error", error=str(e))
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

        # 4. DISPATCH: create a Task for the hypothesis's recommended test
        task = await self._dispatch_hypothesis(engagement_id, session_id, selected)
        if task is None:
            return

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
                self._orch.session_memory, self._orch.graph_memory,
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
            logger.warning("reasoning_critic_failed", error=str(e))

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
            logger.warning("reasoning_pathfinder_failed", error=str(e))

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
            open_hyp_ids = {
                h.get("id") for h in open_hypotheses
                if h.get("status") == "open"
            }
        except Exception as e:
            logger.warning("reasoning_observe_failed", engagement_id=engagement_id, error=str(e))
            return {"endpoints": [], "findings": [], "open_hypotheses": set()}

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

        Ranking factors:
          - confidence (from HypothesisEngine heuristics)
          - novelty (has this category been tested before? untested = higher)
          - finding_types already found (if we found SSRF, boost chain hypotheses)
          - prior knowledge (recall from FindingsKnowledge)
        """
        finding_types = state.get("finding_types", set())

        ranked = []
        for hyp in hypotheses:
            if isinstance(hyp, dict):
                h = hyp
            else:
                h = hyp.model_dump() if hasattr(hyp, "model_dump") else dict(hyp)

            if h.get("status") != "open":
                continue
            if h.get("id") in self._tested_hypotheses:
                continue

            base_score = float(h.get("confidence", 0.5))

            # Novelty boost: untested categories rank higher
            category = h.get("category", "")
            if category not in finding_types:
                base_score += 0.1  # novel attack surface

            # Chain boost: if we already found something in a related category,
            # chain hypotheses are high-value
            rec_tests = h.get("recommended_tests", [])
            rec_skills = h.get("recommended_skills", [])

            # Memory-driven planning: recall prior findings for this category
            prior_boost = await self._recall_prior(engagement_id, category, h.get("target_id", ""))
            base_score += prior_boost

            ranked.append((base_score, h))

        if not ranked:
            return None

        ranked.sort(key=lambda x: x[0], reverse=True)
        return ranked[0][1]

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
            logger.warning("reasoning_dispatch_failed", error=str(e))
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
            return

        findings_count = result.get("findings_count", 0)

        if findings_count > 0:
            # CONFIRMED: the hypothesis was correct
            await self._update_hypothesis_status(hyp_id, "confirmed")
            self._dead_ends = 0
            # Chain: the confirmed finding may open new attack paths
            await self._generate_chain_hypotheses(engagement_id, hypothesis, result)
        else:
            # REFUTED: dead end — generate follow-up hypotheses
            await self._update_hypothesis_status(hyp_id, "refuted")
            self._dead_ends += 1
            await self._generate_followup_hypotheses(engagement_id, hypothesis, result)

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
            chain_focus = "authorization chain: IDOR confirmed → try admin objects → privilege escalation"
        elif category in ("client_side",):
            chain_focus = "XSS chain: execution confirmed → try cookie theft → session hijacking"
        elif category in ("graphql",):
            chain_focus = "GraphQL chain: introspection confirmed → try mutation authz → batch abuse"

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
        followup_focus = f"dead-end recovery: {category} test found nothing at {target_id}. " \
                          f"Consider: authenticated access, different content-type, " \
                          f"alternative injection points, or different technique."

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
