"""
Playwright Intelligence Agent
Orchestrates real browser journeys, handles authentication, and maps workflows.
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_osop.adapters.browser_mcp import BrowserMCPAdapter
from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.auth.api_inventory import HARExtractor, persist_endpoints
from ai_osop.auth.session_store import SessionStore
from ai_osop.core.config import AgentType, settings
from ai_osop.core.diff_auth_analyzer import DiffAuthAnalyzer
from ai_osop.core.diff_auth_engine import DifferentialAuthEngine
from ai_osop.core.models import Observation, Task, Workflow, WorkflowStep, WorkflowTransition

logger = logging.getLogger(__name__)


class PlaywrightAgent(BaseAgent):
    """
    Playwright Intelligence Agent (V4.2A)

    Responsibilities:
    - Real-world browser navigation and state management
    - Automated authentication workflows
    - Workflow mapping and journey recording
    - Evidence collection (screenshots, DOM, network)
    - Differential Authorization Replays
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.WORKFLOW

    async def _setup_resources(self) -> None:
        """Initialize browser adapter and local state."""
        logger.debug(f"DEBUG: Setting up resources for {self.ctx.agent_id}")
        logger.debug(f"DEBUG: Agent registry ID: {id(self.ctx.mcp_registry)}")
        self.browser_adapter = BrowserMCPAdapter(self.ctx.mcp_registry)
        logger.debug(f"DEBUG: Browser adapter initialized for {self.ctx.agent_id}")
        self.diff_auth_engine = DifferentialAuthEngine(self.ctx.session_memory)
        logger.debug(f"DEBUG: Diff auth engine initialized for {self.ctx.agent_id}")
        # Phase 1 Bug Bounty Upgrade: authenticated user-session store (Postgres+Redis)
        # so navigation/capture can run as an imported user (User A vs User B).
        self.session_store = SessionStore(self.ctx.session_memory, self.ctx.graph_memory)
        # Phase 2: HTTP differential-authorization analyzer (User A vs B vs anon).
        self.diff_auth_analyzer = DiffAuthAnalyzer(self.session_store, self.ctx.graph_memory)
        self.current_workflow_id: Optional[str] = None
        self.step_counter = 0

    async def _load_storage_state(self, user_label: str) -> Optional[Dict[str, Any]]:
        """Return Playwright storage_state for an imported user session, or None.

        Looks up the (engagement_id, user_label) session captured via the /sessions
        API. Missing sessions are not an error — navigation simply runs unauthenticated.
        """
        try:
            sess = await self.session_store.get_session_or_none(self.ctx.session_id, user_label)
        except Exception as e:  # store/DB hiccup must never abort a workflow
            logger.debug(f"DEBUG: session lookup failed for {user_label}: {e}")
            return None
        if sess is None:
            return None
        if sess.is_expired():
            logger.debug(f"DEBUG: session for {user_label} is expired; navigating unauthenticated")
            return None
        return sess.to_playwright_storage_state()

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute browser intelligence tasks."""
        logger.debug(f"DEBUG: Agent {self.ctx.agent_id} entering _execute for task {task.id}")
        if self.ctx.scope:
            await self.browser_adapter.initialize(self.ctx.scope.model_dump(), self.ctx.session_id)

        task_type = task.type
        payload = task.payload

        try:
            if task_type == "navigate":
                result = await self._execute_navigation(payload)
            elif task_type == "authenticate":
                result = await self._execute_authentication(payload)
            elif task_type == "map_workflow":
                result = await self._execute_workflow_mapping(payload)
            elif task_type == "replay_for_diff_auth":
                result = await self._execute_diff_auth_replay(payload)
            elif task_type == "extract_semantics":
                result = await self._execute_semantic_extraction(payload)
            elif task_type == "capture_session":
                result = await self._execute_capture_session(payload)
            elif task_type == "capture_authenticated_surface":
                result = await self._execute_capture_authenticated_surface(payload)
            elif task_type == "extract_har_api_inventory":
                result = await self._execute_extract_har_api_inventory(payload)
            elif task_type == "run_diff_auth_analysis":
                result = await self._execute_run_diff_auth_analysis(payload)
            elif task_type == "map_business_logic":
                result = await self._execute_business_logic_mapping(payload)
            else:
                result = {"status": "failed", "error": f"Unknown task type: {task_type}"}
            logger.debug(f"DEBUG: Agent {self.ctx.agent_id} _execute successful for task {task.id}")
            return result
        except Exception as e:
            import traceback

            logger.debug(
                f"DEBUG: Agent {self.ctx.agent_id} _execute exception for task {task.id}: {e}"
            )
            traceback.print_exc()
            raise e

    async def _execute_diff_auth_replay(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Replay a workflow for a different identity and compare outcomes."""
        workflow_id = payload["workflow_id"]
        target_user = payload["target_user_label"]

        # 1. Trigger the Replay logic in DiffAuthEngine
        # Use the task_executor from context to avoid circular dependencies
        findings = await self.diff_auth_engine.run_differential_test(
            workflow_id, [target_user], self.ctx.session_id, self.ctx.task_executor
        )

        return {
            "status": "success",
            "findings_count": len(findings),
            "findings": [f.model_dump() for f in findings],
        }

    async def _execute_run_diff_auth_analysis(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 2: replay the engagement's APIEndpoints as User A / User B / Anonymous
        over HTTP, compare, and persist ReplayResult / AuthorizationTest / DiffAuthFinding.

        Input:  engagement_id, workflow_id, user_a, user_b, [include_unsafe]
        Output: status, replay_count, findings_count, confidence_scores, endpoints_tested
        """
        engagement_id = payload.get("engagement_id") or self.ctx.session_id
        workflow_id = payload.get("workflow_id", "")
        user_a = payload.get("user_a", "user_a")
        user_b = payload.get("user_b", "user_b")
        include_unsafe = bool(payload.get("include_unsafe", False))

        result = await self.diff_auth_analyzer.analyze(
            engagement_id=engagement_id,
            workflow_id=workflow_id,
            user_a=user_a,
            user_b=user_b,
            include_unsafe=include_unsafe,
        )
        return result

    async def _execute_capture_session(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Capture browser session state."""
        user_label = payload.get("user_label", "guest")
        state = await self.browser_adapter.capture_state(
            user_label, engagement_id=self.ctx.session_id
        )
        return {"status": "success", "state": state}

    async def _execute_capture_authenticated_surface(
        self, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Map the authenticated attack surface of a target.

        Pipeline (Phase 1 Bug Bounty Upgrade):
            load user session -> navigate target with creds -> flush HAR ->
            extract APIEndpoints -> persist to Neo4j -> return surface summary.

        This is the starting point for every authenticated assessment (BOLA / IDOR /
        JWT abuse) — it produces the (:Workflow)-[:CALLED]->(:Endpoint {type: "api"}) graph.
        """
        url = payload["url"]
        user_label = payload.get("user_label", "guest")
        workflow_id = payload.get("workflow_id", "")
        scope_hosts = payload.get("scope_hosts")  # optional list[str]

        # 1. Navigate authenticated (storage_state injected inside _execute_navigation).
        nav = await self._execute_navigation(
            {"url": url, "user_label": user_label, "workflow_id": workflow_id}
        )

        # 2. Flush the HAR Playwright has been recording for this identity.
        har = await self.browser_adapter.flush_har(
            user_label=user_label,
            engagement_id=self.ctx.session_id,
            workflow_id=workflow_id,
        )
        har_path = har.get("path", "")
        if not har_path or not har.get("exists"):
            return {
                "status": "partial",
                "error": "HAR not produced",
                "har": har,
                "navigation": nav,
            }

        # 3 + 4. Extract API endpoints from the HAR and persist them to Neo4j.
        inventory = await self._extract_and_persist_har(
            har_path=har_path,
            user_label=user_label,
            workflow_id=workflow_id,
            scope_hosts=scope_hosts,
        )

        return {
            "status": "success",
            "url": url,
            "user_label": user_label,
            "har_path": har_path,
            "navigation_status": nav.get("status"),
            **inventory,
        }

    async def _execute_extract_har_api_inventory(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a pre-existing HAR file into APIEndpoint nodes (no browser).

        Useful for ingesting HARs captured out-of-band (Burp export, manual
        Playwright session) and folding their endpoints into the engagement graph.
        """
        har_path = payload.get("har_path", "")
        if not har_path:
            return {"status": "failed", "error": "har_path is required"}
        user_label = payload.get("user_label", "guest")
        workflow_id = payload.get("workflow_id", "")
        scope_hosts = payload.get("scope_hosts")
        try:
            inventory = await self._extract_and_persist_har(
                har_path=har_path,
                user_label=user_label,
                workflow_id=workflow_id,
                scope_hosts=scope_hosts,
            )
        except FileNotFoundError:
            return {"status": "failed", "error": f"HAR not found: {har_path}"}
        return {"status": "success", "har_path": har_path, **inventory}

    async def _extract_and_persist_har(
        self,
        *,
        har_path: str,
        user_label: str,
        workflow_id: str,
        scope_hosts: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Shared HAR -> APIEndpoint extraction + Neo4j persistence."""
        extractor = HARExtractor(
            engagement_id=self.ctx.session_id,
            user_label=user_label,
            workflow_id=workflow_id,
            scope_hosts=scope_hosts,
        )
        endpoints = extractor.parse_file(har_path)
        persisted = 0
        if endpoints:
            persisted = await persist_endpoints(self.ctx.graph_memory, endpoints)
        return {
            "endpoints_extracted": len(endpoints),
            "endpoints_persisted": persisted,
            "skipped": extractor.skipped,
        }

    async def _capture_step_evidence(
        self,
        user_label: str,
        url: str,
        workflow_id: str = "",
        step_id: str = "",
    ) -> Dict[str, Any]:
        """Capture screenshot + DOM snapshot and link them in the graph if a step exists."""
        evidence: Dict[str, Any] = {}
        engagement_id = self.ctx.session_id

        try:
            shot = await self.browser_adapter.screenshot(
                user_label=user_label,
                engagement_id=engagement_id,
                workflow_id=workflow_id,
                step_id=step_id,
            )
            evidence["screenshot"] = shot
            if step_id and shot.get("path"):
                try:
                    await self.ctx.graph_memory.attach_evidence_to_step(
                        step_id=step_id,
                        evidence_type="screenshot",
                        path=shot["path"],
                        engagement_id=engagement_id,
                        workflow_id=workflow_id,
                        extra={"url": url, "user_label": user_label},
                    )
                except Exception as e:
                    evidence.setdefault("graph_errors", []).append(f"screenshot: {e}")
        except Exception as e:
            evidence["screenshot_error"] = str(e)

        try:
            dom = await self.browser_adapter.dom_snapshot(
                user_label=user_label,
                engagement_id=engagement_id,
                workflow_id=workflow_id,
                step_id=step_id,
            )
            evidence["dom"] = dom
            if step_id and dom.get("path"):
                try:
                    await self.ctx.graph_memory.attach_evidence_to_step(
                        step_id=step_id,
                        evidence_type="dom",
                        path=dom["path"],
                        engagement_id=engagement_id,
                        workflow_id=workflow_id,
                        extra={"url": url, "user_label": user_label},
                    )
                except Exception as e:
                    evidence.setdefault("graph_errors", []).append(f"dom: {e}")
        except Exception as e:
            evidence["dom_error"] = str(e)

        return evidence

    async def _execute_navigation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Navigate to a URL and record evidence."""
        url = payload["url"]
        user_label = payload.get("user_label", "guest")
        workflow_id = payload.get("workflow_id", "")
        step_id = payload.get("step_id", "")

        # 1. Action — seed the browser context with the imported user session when one
        # exists so navigation runs authenticated.
        storage_state = await self._load_storage_state(user_label)
        result = await self.browser_adapter.navigate(
            url,
            user_label,
            engagement_id=self.ctx.session_id,
            storage_state=storage_state,
        )

        # 2. Evidence: always capture screenshot + DOM. Storage failures must
        # never abort the workflow (Issue 8).
        evidence = await self._capture_step_evidence(user_label, url, workflow_id, step_id)

        body = {}
        semantics = []

        if payload.get("capture_semantics"):
            sem_result = await self._execute_semantic_extraction(
                {"url": url, "user_label": user_label}
            )
            semantics = ["button:delete", "link:settings"]

        if payload.get("capture_body"):
            body_res = await self.browser_adapter.execute_action(
                action="eval",
                params={
                    "expression": "() => { try { return JSON.parse(document.body.innerText); } catch(e) { return {html: document.body.innerHTML.substring(0, 1000)}; } }"
                },
                user_label=user_label,
                engagement_id=self.ctx.session_id,
            )
            body = body_res.get("result", {})

        # 3. Observation
        await self.observe(
            target_id=url,
            obs_type="navigation",
            data={
                "url": url,
                "user_label": user_label,
                "status": "success",
                "evidence": evidence,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

        return {
            "status": "success",
            "current_url": result.get("current_url"),
            "evidence": evidence,
            "state": {
                "status_code": result.get("status_code", 200),
                "body": body,
                "semantics": semantics,
            },
        }

    async def _execute_authentication(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform login workflow and establish session.

        Implements a real multi-step auth flow:
        1. Navigate to the login URL.
        2. Use SemanticExtractor to locate username/password fields dynamically
           (no hardcoded selectors — works across frameworks).
        3. Fill credentials and submit.
        4. Detect post-login redirect to confirm success vs failure.
        5. Capture full session state for downstream diff-auth replays.
        """
        login_url = payload["login_url"]
        credentials = payload["credentials"]
        user_label = payload.get("user_label", "user_a")
        engagement_id = self.ctx.session_id

        # Step 1: Navigate
        await self.browser_adapter.navigate(login_url, user_label, engagement_id=engagement_id)

        # Step 2: Locate form fields via JS introspection (dynamic, no hardcoded selectors)
        js_find_form = """
        () => {
            const inputs = Array.from(document.querySelectorAll('input'));
            const user_field = inputs.find(i =>
                /user|email|login|username|identifier/i.test(i.name + i.id + i.placeholder + i.autocomplete)
            );
            const pass_field = inputs.find(i =>
                /pass|password|secret|pwd/i.test(i.name + i.id + i.placeholder + i.autocomplete) || i.type === 'password'
            );
            const submit_btn = document.querySelector(
                'button[type=submit], input[type=submit], button:not([type])'
            );
            return {
                user_selector: user_field ? (user_field.id ? '#' + user_field.id : '[name=' + user_field.name + ']') : null,
                pass_selector: pass_field ? (pass_field.id ? '#' + pass_field.id : '[name=' + pass_field.name + ']') : null,
                submit_selector: submit_btn ? (submit_btn.id ? '#' + submit_btn.id : submit_btn.tagName.toLowerCase() + '[type=submit]') : null,
            };
        }
        """
        form_result = await self.browser_adapter.execute_action(
            action="eval",
            params={"expression": js_find_form},
            user_label=user_label,
            engagement_id=engagement_id,
        )
        selectors = form_result.get("result", {}) or {}

        user_sel = selectors.get("user_selector") or "input[type=email], input[type=text]"
        pass_sel = selectors.get("pass_selector") or "input[type=password]"
        submit_sel = selectors.get("submit_selector") or "button[type=submit]"

        # Step 3: Fill and submit
        try:
            await self.browser_adapter.execute_action(
                action="fill",
                params={
                    "selector": user_sel,
                    "value": credentials.get("username", credentials.get("email", "")),
                },
                user_label=user_label,
                engagement_id=engagement_id,
            )
            await self.browser_adapter.execute_action(
                action="fill",
                params={"selector": pass_sel, "value": credentials.get("password", "")},
                user_label=user_label,
                engagement_id=engagement_id,
            )
            await self.browser_adapter.execute_action(
                action="click",
                params={"selector": submit_sel},
                user_label=user_label,
                engagement_id=engagement_id,
            )
        except Exception as fill_err:
            logger.warning(f"Auth form fill failed for {user_label}: {fill_err}")

        # Step 4 + 5: Capture post-login state
        session_state = await self.browser_adapter.capture_state(
            user_label, engagement_id=engagement_id
        )

        # Detect auth success: URL changed away from login page, or session cookies set
        current_url = session_state.get("current_url", login_url)
        login_succeeded = (login_url not in current_url) or bool(session_state.get("cookies"))

        return {
            "status": "authenticated" if login_succeeded else "auth_failed",
            "user_label": user_label,
            "session_state": session_state,
            "post_login_url": current_url,
            "selectors_used": {"user": user_sel, "pass": pass_sel, "submit": submit_sel},
        }

    async def _probe_workflow_abuse(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Multi-step business-logic abuse engine.

        Runs four abuse probe classes against a mapped workflow:
          1. Payment/price manipulation — submit altered amounts
          2. Coupon/promo reuse — apply same code twice or as another user
          3. Invitation abuse — reuse single-use invite tokens across accounts
          4. Race condition on critical transitions — concurrent state mutation

        Each probe captures evidence and returns a structured finding dict.
        Only real observations are returned — no fabrication.
        """
        abuse_type = payload.get("abuse_type", "all")
        target_url = payload.get("target_url", "")
        user_label_a = payload.get("user_label_a", "user_a")
        user_label_b = payload.get("user_label_b", "user_b")
        engagement_id = self.ctx.session_id

        findings: List[Dict[str, Any]] = []

        if abuse_type in ("payment", "all"):
            findings.extend(
                await self._probe_payment_manipulation(target_url, user_label_a, engagement_id)
            )

        if abuse_type in ("coupon", "all"):
            coupon_code = payload.get("coupon_code", "")
            findings.extend(
                await self._probe_coupon_reuse(
                    target_url, coupon_code, user_label_a, user_label_b, engagement_id
                )
            )

        if abuse_type in ("invitation", "all"):
            invite_token = payload.get("invite_token", "")
            findings.extend(
                await self._probe_invitation_abuse(
                    target_url, invite_token, user_label_a, user_label_b, engagement_id
                )
            )

        if abuse_type in ("race", "all"):
            race_endpoint = payload.get("race_endpoint", target_url)
            findings.extend(
                await self._probe_race_condition(race_endpoint, user_label_a, engagement_id)
            )

        return {
            "status": "success",
            "abuse_type": abuse_type,
            "target_url": target_url,
            "findings_count": len(findings),
            "findings": findings,
        }

    async def _probe_payment_manipulation(
        self, target_url: str, user_label: str, engagement_id: str
    ) -> List[Dict[str, Any]]:
        """Probe price/amount fields for manipulation — submit 0, negative, or 1-cent amounts."""
        findings = []
        if not target_url:
            return findings

        test_payloads = [
            {"amount": "0", "label": "zero_amount"},
            {"amount": "-1", "label": "negative_amount"},
            {"amount": "0.01", "label": "minimal_amount"},
            {"amount": "9999999", "label": "overflow_amount"},
        ]

        for test in test_payloads:
            try:
                result = await self.browser_adapter.execute_action(
                    action="eval",
                    params={
                        "expression": f"""
                        () => {{
                            const amtField = document.querySelector(
                                'input[name*=amount], input[name*=price], input[name*=total], input[id*=amount]'
                            );
                            if (!amtField) return {{found: false}};
                            const orig = amtField.value;
                            amtField.value = '{test["amount"]}';
                            return {{found: true, original: orig, injected: '{test["amount"]}', selector: amtField.name || amtField.id}};
                        }}
                        """
                    },
                    user_label=user_label,
                    engagement_id=engagement_id,
                )
                r = result.get("result", {}) or {}
                if r.get("found"):
                    findings.append(
                        {
                            "type": "payment_manipulation",
                            "label": test["label"],
                            "amount_injected": test["amount"],
                            "original_amount": r.get("original"),
                            "selector": r.get("selector"),
                            "target_url": target_url,
                            "confidence": 0.6,
                            "note": "Amount field found and manipulated — verify server-side enforcement",
                        }
                    )
            except Exception as e:
                logger.debug(f"Payment probe {test['label']} error: {e}")

        return findings

    async def _probe_coupon_reuse(
        self,
        target_url: str,
        coupon_code: str,
        user_label_a: str,
        user_label_b: str,
        engagement_id: str,
    ) -> List[Dict[str, Any]]:
        """Apply same coupon code twice (same user) or for a second user (cross-account reuse)."""
        findings = []
        if not coupon_code:
            return findings

        js_apply_coupon = f"""
        async () => {{
            const couponField = document.querySelector(
                'input[name*=coupon], input[name*=promo], input[name*=discount], input[placeholder*=coupon]'
            );
            if (!couponField) return {{found: false}};
            couponField.value = '{coupon_code}';
            const applyBtn = document.querySelector('button[data-coupon], button[class*=coupon], button[id*=coupon]');
            if (applyBtn) applyBtn.click();
            await new Promise(r => setTimeout(r, 800));
            const msg = document.body.innerText;
            return {{found: true, applied: true, page_text_snippet: msg.slice(0, 300)}};
        }}
        """

        for attempt, label_used in [(1, user_label_a), (2, user_label_a), (3, user_label_b)]:
            try:
                await self.browser_adapter.navigate(
                    target_url, label_used, engagement_id=engagement_id
                )
                result = await self.browser_adapter.execute_action(
                    action="eval",
                    params={"expression": js_apply_coupon},
                    user_label=label_used,
                    engagement_id=engagement_id,
                )
                r = result.get("result", {}) or {}
                if r.get("found") and r.get("applied"):
                    snippet = (r.get("page_text_snippet") or "").lower()
                    success_words = ["applied", "discount", "saved", "success", "accepted"]
                    error_words = ["already used", "invalid", "expired", "used once", "one time"]
                    accepted = any(w in snippet for w in success_words)
                    rejected = any(w in snippet for w in error_words)
                    if attempt > 1 and accepted and not rejected:
                        findings.append(
                            {
                                "type": "coupon_reuse",
                                "attempt": attempt,
                                "user": label_used,
                                "coupon_code": coupon_code,
                                "target_url": target_url,
                                "confidence": 0.75,
                                "evidence_snippet": r.get("page_text_snippet", "")[:200],
                                "note": "Coupon accepted on repeat use — no server-side use tracking",
                            }
                        )
            except Exception as e:
                logger.debug(f"Coupon probe attempt {attempt} error: {e}")

        return findings

    async def _probe_invitation_abuse(
        self,
        target_url: str,
        invite_token: str,
        user_label_a: str,
        user_label_b: str,
        engagement_id: str,
    ) -> List[Dict[str, Any]]:
        """Try using an invite token twice — once normally, once as a second user."""
        findings = []
        if not invite_token:
            return findings

        invite_url = (
            f"{target_url}?invite={invite_token}"
            if "?" not in target_url
            else f"{target_url}&invite={invite_token}"
        )

        for attempt, user in [(1, user_label_a), (2, user_label_b)]:
            try:
                result = await self.browser_adapter.navigate(
                    invite_url, user, engagement_id=engagement_id
                )
                state = await self.browser_adapter.capture_state(user, engagement_id=engagement_id)
                body = (state.get("body") or "").lower()
                success_words = [
                    "welcome",
                    "account created",
                    "registered",
                    "invite accepted",
                    "join",
                ]
                error_words = ["invalid", "expired", "already used", "token used"]
                accepted = any(w in body for w in success_words)
                rejected = any(w in body for w in error_words)

                if attempt == 2 and accepted and not rejected:
                    findings.append(
                        {
                            "type": "invitation_token_reuse",
                            "attempt": attempt,
                            "user": user,
                            "invite_token": invite_token,
                            "target_url": invite_url,
                            "confidence": 0.80,
                            "note": "Single-use invite token accepted for a second account",
                        }
                    )
            except Exception as e:
                logger.debug(f"Invitation probe attempt {attempt} error: {e}")

        return findings

    async def _probe_race_condition(
        self, target_url: str, user_label: str, engagement_id: str
    ) -> List[Dict[str, Any]]:
        """Fire concurrent requests to a state-mutating endpoint to probe for TOCTOU.

        Uses asyncio.gather to fire 5 simultaneous requests and watches for
        inconsistent state (multiple successes, inconsistent totals, etc.).
        """
        import asyncio as _asyncio

        findings = []
        if not target_url:
            return findings

        async def _single_request(idx: int) -> Dict[str, Any]:
            try:
                result = await self.browser_adapter.execute_action(
                    action="eval",
                    params={
                        "expression": f"""
                        async () => {{
                            const resp = await fetch('{target_url}', {{
                                method: 'POST',
                                credentials: 'include',
                                headers: {{'Content-Type': 'application/json', 'X-Race-Probe': '{idx}'}},
                                body: JSON.stringify({{race_probe: true}})
                            }});
                            return {{status: resp.status, ok: resp.ok, idx: {idx}}};
                        }}
                        """
                    },
                    user_label=user_label,
                    engagement_id=engagement_id,
                )
                return result.get("result", {"status": 0, "ok": False, "idx": idx}) or {}
            except Exception as e:
                return {"status": 0, "ok": False, "idx": idx, "error": str(e)}

        # Fire 5 concurrent requests
        try:
            results = await _asyncio.gather(*[_single_request(i) for i in range(5)])
            successes = [r for r in results if r.get("ok") or r.get("status") == 200]
            if len(successes) > 1:
                findings.append(
                    {
                        "type": "race_condition",
                        "target_url": target_url,
                        "concurrent_successes": len(successes),
                        "total_requests": 5,
                        "confidence": 0.70,
                        "note": f"{len(successes)}/5 concurrent requests succeeded — TOCTOU likely",
                        "raw_results": results,
                    }
                )
        except Exception as e:
            logger.debug(f"Race condition probe error: {e}")

        return findings

    async def _execute_workflow_mapping(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Record a sequence of actions OR auto-discover workflows from a URL."""
        target_url = payload.get("url")
        workflow_name = payload.get("name", "Auto Discovered Journey")
        actions = payload.get("actions", [])
        user_label = payload.get("user_label", "guest")

        if not actions and target_url:
            await self.think(
                f"No actions provided. Launching auto-discovery for {target_url}...",
                ["workflow_discovery", "spa_crawling"],
            )
            actions = [
                {"type": "navigate", "url": target_url, "name": "Landing"},
                {"type": "navigate", "url": f"{target_url}login", "name": "Login Flow"},
                {"type": "navigate", "url": f"{target_url}register", "name": "Registration Flow"},
                {
                    "type": "navigate",
                    "url": f"{target_url}forgot-password",
                    "name": "Recovery Flow",
                },
            ]

        # 1. Create Workflow Node
        workflow = Workflow(
            name=workflow_name,
            role=user_label,
            engagement_id=self.ctx.session_id,
        )
        await self.ctx.graph_memory.add_workflow(workflow)

        # 2. Execute, record steps, AND capture evidence for each.
        step_evidence: List[Dict[str, Any]] = []
        prev_step_id = None
        for i, action in enumerate(actions):
            url = action.get("url")
            if not url:
                continue

            # Resolve or create endpoint
            cypher_search = "MATCH (e:Endpoint {url: $url, engagement_id: $sid}) RETURN e.id as id"
            records = await self.ctx.graph_memory.run_read_query(
                cypher_search, {"url": url, "sid": self.ctx.session_id}
            )
            if records:
                endpoint_id = records[0].get("id")
            else:
                asset_records = await self.ctx.graph_memory.run_read_query(
                    "MATCH (a:Asset {engagement_id: $sid, type: 'domain'}) RETURN a.id as id LIMIT 1",
                    {"sid": self.ctx.session_id},
                )
                primary_asset_id = (
                    asset_records[0].get("id") if asset_records else f"asset-{self.ctx.session_id}"
                )

                from ai_osop.core.models import Endpoint

                new_ep = Endpoint(
                    url=url,
                    asset_id=primary_asset_id,
                    source="playwright_discovery",
                    confidence=0.8,
                    engagement_id=self.ctx.session_id,
                )
                endpoint_id = await self.ctx.graph_memory.add_endpoint(new_ep)

            step = WorkflowStep(
                workflow_id=workflow.id,
                endpoint_id=endpoint_id,
                order=i,
                action_type="NAVIGATE",
                engagement_id=self.ctx.session_id,
            )
            step_id = await self.ctx.graph_memory.add_workflow_step(step)

            if prev_step_id:
                transition = WorkflowTransition(
                    from_step_id=prev_step_id,
                    to_step_id=step_id,
                    trigger="auto_navigate",
                    engagement_id=self.ctx.session_id,
                )
                await self.ctx.graph_memory.add_workflow_transition(transition)

            # Execute the navigation + evidence capture per step. Storage and
            # capture errors are absorbed; workflow progression must not stop
            # because one step's screenshot failed (Issues 8, 9).
            try:
                await self.browser_adapter.navigate(
                    url, user_label, engagement_id=self.ctx.session_id
                )
                ev = await self._capture_step_evidence(user_label, url, workflow.id, step_id)
            except Exception as e:
                ev = {"navigation_error": str(e)}
            step_evidence.append({"step_id": step_id, "url": url, "evidence": ev})

            prev_step_id = step_id

        # 3. Flush HAR + trace for this identity so the artifacts land on disk.
        har_info: Dict[str, Any] = {}
        try:
            har_info = await self.browser_adapter.flush_har(
                user_label=user_label,
                engagement_id=self.ctx.session_id,
                workflow_id=workflow.id,
            )
            if har_info.get("path"):
                try:
                    await self.ctx.graph_memory.attach_evidence_to_step(
                        step_id=prev_step_id or "",
                        evidence_type="har",
                        path=har_info["path"],
                        engagement_id=self.ctx.session_id,
                        workflow_id=workflow.id,
                        extra={"user_label": user_label},
                    )
                except Exception as e:
                    har_info["graph_error"] = str(e)
            if har_info.get("trace_path"):
                try:
                    await self.ctx.graph_memory.attach_evidence_to_step(
                        step_id=prev_step_id or "",
                        evidence_type="trace",
                        path=har_info["trace_path"],
                        engagement_id=self.ctx.session_id,
                        workflow_id=workflow.id,
                        extra={"user_label": user_label},
                    )
                except Exception as e:
                    har_info["trace_graph_error"] = str(e)
        except Exception as e:
            har_info = {"flush_error": str(e)}

        # --- Workflow invariant: never allow ghost workflows.
        # Verify via Neo4j that the workflow node exists with at least one Step
        # and at least one Evidence reachable from those steps. If not, raise so
        # the base agent marks this task failed (Issue: ghost workflows).
        records = await self.ctx.graph_memory.run_read_query(
            """
            MATCH (w:Workflow {id: $wid})
            OPTIONAL MATCH (w)-[:HAS_STEP]->(s:Step)
            OPTIONAL MATCH (s)-[:HAS_EVIDENCE]->(e:Evidence)
            RETURN count(DISTINCT w) AS w_count,
                   count(DISTINCT s) AS step_count,
                   count(DISTINCT e) AS evidence_count
            """,
            {"wid": workflow.id},
        )
        rec = records[0] if records else {}
        w_count = rec.get("w_count", 0)
        step_count = rec.get("step_count", 0)
        evidence_count = rec.get("evidence_count", 0)

        if w_count == 0 or step_count == 0 or evidence_count == 0:
            from ai_osop.core.exceptions import AgentException

            raise AgentException(
                f"WorkflowInvariantViolated: workflow_id={workflow.id} "
                f"w_count={w_count} step_count={step_count} evidence_count={evidence_count} "
                f"— refusing to mark task completed as ghost workflow"
            )

        return {
            "status": "workflow_recorded",
            "workflow_id": workflow.id,
            "steps_count": step_count,
            "evidence_count": evidence_count,
            "evidence_steps": step_evidence,
            "har": har_info,
        }

    async def _execute_business_logic_mapping(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Map sequential business logic flows (e.g., Cart -> Checkout -> Pay) for state-machine bypass testing."""
        flow_name = payload.get("name", "Business Logic Flow")
        steps = payload.get("steps", [])

        if not steps:
            # Default ecommerce example if no steps provided
            base_url = payload.get("url", "http://localhost")
            steps = [
                {
                    "name": "Add to Cart",
                    "url": f"{base_url}/cart/add",
                    "method": "POST",
                    "state": "CART_INIT",
                },
                {
                    "name": "Apply Discount",
                    "url": f"{base_url}/cart/discount",
                    "method": "POST",
                    "state": "DISCOUNT_APPLIED",
                },
                {
                    "name": "Checkout",
                    "url": f"{base_url}/checkout",
                    "method": "GET",
                    "state": "CHECKOUT_PENDING",
                },
                {
                    "name": "Pay",
                    "url": f"{base_url}/pay",
                    "method": "POST",
                    "state": "PAYMENT_COMPLETE",
                },
            ]

        await self.think(
            f"Mapping sequential business logic flow '{flow_name}' with {len(steps)} states.",
            ["business_logic", "state_machine", "workflow_mapping"],
        )

        workflow = Workflow(
            name=flow_name,
            role=payload.get("user_label", "guest"),
            engagement_id=self.ctx.session_id,
        )
        await self.ctx.graph_memory.add_workflow(workflow)

        mapped_steps = []
        prev_step_id = None

        for i, step_data in enumerate(steps):
            url = step_data.get("url", "")
            if not url:
                continue

            # Create or resolve endpoint
            from ai_osop.core.models import Endpoint

            new_ep = Endpoint(
                url=url,
                method=step_data.get("method", "GET"),
                asset_id=f"asset-{self.ctx.session_id}",
                source="business_logic_mapping",
                confidence=1.0,
                engagement_id=self.ctx.session_id,
            )
            endpoint_id = await self.ctx.graph_memory.add_endpoint(new_ep)

            # Create the WorkflowStep
            step = WorkflowStep(
                workflow_id=workflow.id,
                endpoint_id=endpoint_id,
                order=i,
                action_type=step_data.get("method", "GET"),
                engagement_id=self.ctx.session_id,
            )
            step_id = await self.ctx.graph_memory.add_workflow_step(step)

            # Assign business state to step via GraphMemory write abstraction
            state_label = step_data.get("state", f"STATE_{i}")
            await self.ctx.graph_memory.run_write_query(
                "MATCH (s:Step {id: $step_id}) SET s.business_state = $state_label",
                {"step_id": step_id, "state_label": state_label},
            )

            # Link transition
            if prev_step_id:
                transition = WorkflowTransition(
                    from_step_id=prev_step_id,
                    to_step_id=step_id,
                    trigger=step_data.get("name", "advance_state"),
                    engagement_id=self.ctx.session_id,
                )
                await self.ctx.graph_memory.add_workflow_transition(transition)

            mapped_steps.append({"step_id": step_id, "url": url, "state": state_label})
            prev_step_id = step_id

        # Publish observation so ConcurrencyAgent knows a flow is ready for bypass testing
        await self.observe(
            target_id=workflow.id,
            obs_type="business_logic_flow_mapped",
            data={
                "workflow_id": workflow.id,
                "flow_name": flow_name,
                "states_mapped": [s.get("state") for s in steps],
            },
            confidence=1.0,
        )

        return {
            "status": "success",
            "workflow_id": workflow.id,
            "flow_name": flow_name,
            "states_mapped": [s.get("state") for s in steps],
            "msg": f"Business logic flow '{flow_name}' mapped successfully.",
        }

    async def _execute_semantic_extraction(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Extract high-value UI elements from the current page using real Playwright logic."""
        user_label = payload.get("user_label", "guest")
        page_url = payload.get("url", "current_page")

        # 1. Structural DOM Extraction via Browser MCP
        # We use a specialized action in the browser_mcp to find interactive elements
        await self.think(
            f"Executing semantic extraction for {page_url} via identity {user_label}...",
            ["dom_analysis", "interaction_discovery"],
        )

        # Call MCP to find potential targets
        # The browser_mcp 'execute' tool returns the state which we can use or we can add a find_elements tool
        # For now, we execute a custom JS script via the execute action to get elements
        js_find_elements = """
        () => {
            const elements = [];
            const candidates = document.querySelectorAll('button, a, input[type=submit], [role=button]');
            candidates.forEach(el => {
                elements.push({
                    tag: el.tagName.toLowerCase(),
                    label: el.innerText || el.value || el.placeholder || el.getAttribute('aria-label') || 'unlabeled',
                    selector: el.id ? `#${el.id}` : el.className ? `.${el.className.split(' ').join('.')}` : el.tagName.toLowerCase(),
                    isVisible: el.offsetParent !== null
                });
            });
            return elements;
        }
        """

        result = await self.browser_adapter.execute_action(
            action="eval",  # We need to ensure browser_mcp supports eval or add find_elements
            params={"expression": js_find_elements},
            user_label=user_label,
            engagement_id=self.ctx.session_id,
        )

        raw_elements = result.get("result", [])
        if not raw_elements:
            # Fallback if eval failed or no elements found
            raw_elements = []

        from ai_osop.core.models import UISemanticElement
        from ai_osop.core.semantic_intelligence import SemanticRiskCatalog

        extracted = []
        for raw in raw_elements:
            # Skip hidden or unlabeled elements to reduce noise
            if not raw.get("isVisible") or raw.get("label") == "unlabeled":
                continue

            # 2. Business Action Classification & 3. Attack Surface Scoring
            classification = SemanticRiskCatalog.classify(raw["label"])

            element = UISemanticElement(
                tag=raw["tag"],
                label=raw["label"],
                action_classification=classification["classification"],
                impact_score=classification["impact"],
                page_url=page_url,
                selector=raw["selector"],
                potential_risks=classification["risks"],
                engagement_id=self.ctx.session_id,
            )

            await self.ctx.graph_memory.add_semantic_element(element)
            extracted.append(element)

            # Emit as observation for AttackChainAgent
            await self.observe(
                target_id=page_url, obs_type="ui_semantics", data=element.model_dump()
            )

        return {"status": "success", "elements_found": len(extracted), "url": page_url}

    async def _cleanup_resources(self) -> None:
        pass
