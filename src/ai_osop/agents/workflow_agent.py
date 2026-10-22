"""
Playwright Intelligence Agent
Orchestrates real browser journeys, handles authentication, and maps workflows.
"""

import asyncio
import hashlib
import json
import re
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ai_osop.adapters.browser_mcp import BrowserMCPAdapter
from ai_osop.agents.base import AgentContext, BaseAgent
from ai_osop.auth.api_inventory import HARExtractor, persist_endpoints
from ai_osop.auth.session_store import SessionStore
from ai_osop.core.config import AgentType, settings
from ai_osop.core.diff_auth_analyzer import DiffAuthAnalyzer
from ai_osop.core.diff_auth_engine import DifferentialAuthEngine
from ai_osop.core.models import Observation, Task, Workflow, WorkflowStep, WorkflowTransition
from ai_osop.memory.authenticated_resource_paths import (
    ResourcePathDenied,
    signed_har_mount_attestation,
    snapshot_local_har,
)

logger = logging.getLogger(__name__)


def _same_capture_origin(expected: Any, observed: Any) -> bool:
    """Compare a signed navigation's final origin, excluding private URL data.

    Unlike an allowlisted-host-only check, scheme and effective port must
    remain exactly the same. Never return either URL in denial diagnostics.
    """
    if (
        type(expected) is not str or type(observed) is not str
        or not expected or not observed or len(expected) > 2048
        or len(observed) > 2048
    ):
        return False
    try:
        left, right = urlsplit(expected), urlsplit(observed)
        if any(
            part.scheme not in {"http", "https"}
            or not part.hostname
            or part.username is not None
            or part.password is not None
            or part.fragment
            for part in (left, right)
        ):
            return False
        def origin(part: Any) -> tuple[str, str, int]:
            port = part.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError("Invalid capture URL port")
            return (
                part.scheme,
                part.hostname.lower(),
                port if port is not None else (443 if part.scheme == "https" else 80),
            )
        return origin(left) == origin(right)
    except (ValueError, TypeError):
        return False


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
        self.browser_adapter = BrowserMCPAdapter(self.ctx.mcp_registry)
        self.diff_auth_engine = DifferentialAuthEngine(self.ctx.session_memory)
        # Phase 1 Bug Bounty Upgrade: authenticated user-session store (Postgres+Redis)
        # so navigation/capture can run as an imported user (User A vs User B).
        self.session_store = SessionStore(self.ctx.session_memory)
        # Phase 2: HTTP differential-authorization analyzer (User A vs B vs anon).
        self.diff_auth_analyzer = DiffAuthAnalyzer(self.session_store, self.ctx.graph_memory)
        self.current_workflow_id: Optional[str] = None
        self.step_counter = 0

    async def _load_storage_state(self, user_label: str) -> Optional[Dict[str, Any]]:
        """Return Playwright storage_state for an imported user session, or None.

        Looks up the (engagement_id, user_label) session captured via the /sessions
        API. Missing sessions are not an error — navigation simply runs unauthenticated.
        """
        current = self.ctx.current_task
        signed_auth_flow = (
            isinstance(current, Task)
            and isinstance(current.payload, dict)
            and type(current.payload.get("_authorization_version")) is int
            and (
                current.type == "capture_authenticated_surface"
                # Signed, approved differential-replay children are navigate
                # tasks. A deleted/expired identity must not fall back to a
                # stale Redis storage_state on a different worker replica.
                or current.type == "navigate"
                or (
                    current.type == "map_workflow"
                    and current.payload.get("name") == "Auto Authenticated Journey"
                )
            )
        )
        if signed_auth_flow:
            # Signed user identity is PG-authoritative on every navigation.
            # Cached Redis cookies can survive a remote operator deletion.
            try:
                sess = await self.session_store.get_session_authoritative(
                    self.ctx.session_id, user_label
                )
                if (
                    sess is None
                    or sess.engagement_id != self.ctx.session_id
                    or sess.user_label != user_label
                    or sess.is_expired(skew_seconds=0)
                    or not (sess.cookies or sess.local_storage)
                ):
                    raise ValueError("Signed authenticated browser identity is unavailable")
                return sess.to_playwright_storage_state()
            except Exception as exc:
                raise ResourcePathDenied(
                    "Signed authenticated browser session unavailable"
                ) from exc
        try:
            sess = await self.session_store.get_session_or_none(self.ctx.session_id, user_label)
        except Exception:
            # Explicit legacy/manual unauthenticated navigation remains
            # available without echoing DB errors or credential material.
            logger.warning("manual_browser_session_lookup_unavailable")
            return None
        if sess is None:
            return None
        if sess.is_expired():
            return None
        return sess.to_playwright_storage_state()

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute browser intelligence tasks."""
        if task.type == "navigate":
            # Guard the real worker entrypoint BEFORE even initializing the
            # browser provider. The navigation method repeats the check just
            # before the consequential remote GET, and MCP does a final
            # persisted scope/approval fence at dispatch.
            from ai_osop.core.signed_replay_execution import authorize_replay_step

            await authorize_replay_step(self.ctx, task.payload)
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
            return result
        except Exception:
            # The original debug traceback could disclose user cookie/storage
            # state, host paths, provider tokens or model input in production.
            logger.warning("browser_agent_task_failed", extra={"task_type": task_type})
            raise

    async def _execute_diff_auth_replay(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Stage bounded identity-replay children, never execute them inline.

        Only the real durable signed parent and PostgreSQL-owned orchestration
        adapter may request replay. Scheduling a child is not vulnerability
        evidence and cannot be returned to reporting as successful analysis.
        """
        parent = self.ctx.current_task
        executor = self.ctx.task_executor
        if (
            parent is None
            or parent.type != "replay_for_diff_auth"
            or parent.engagement_id != self.ctx.session_id
            or parent.payload != payload
            or not isinstance(payload.get("workflow_id"), str)
            or not isinstance(payload.get("target_user_label"), str)
            or executor is None
            or getattr(executor, "session_memory", None) is not self.ctx.session_memory
        ):
            raise PermissionError("Signed differential replay orchestration unavailable")
        return await self.diff_auth_engine.run_differential_test(
            payload["workflow_id"],
            [payload["target_user_label"]],
            self.ctx.session_id,
            executor,
            parent_task=parent,
            source_user_label=payload.get("source_user_label"),
        )

    async def _execute_run_diff_auth_analysis(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 2: replay the engagement's APIEndpoints as User A / User B / Anonymous
        over HTTP, compare, and persist ReplayResult / AuthorizationTest / DiffAuthFinding.

        Input:  engagement_id, workflow_id, user_a, user_b, [include_unsafe]
        Output: status, replay_count, findings_count, confidence_scores, endpoints_tested
        """
        from ai_osop.memory.session_memory import SessionMemory

        if isinstance(self.ctx.session_memory, SessionMemory):
            # This older analyzer directly replays three HTTP identities
            # through SessionStore/httpx (including unsafe methods when a
            # caller sets include_unsafe), without a per-request TaskORM,
            # signed MCP dispatch, source receipt or independent approval.
            # A signed parent is not permission for anonymous nested HTTP.
            # Keep the path quarantined until it consumes independently
            # admitted/terminal evidence from the durable replay workflow.
            raise PermissionError(
                "HTTP differential analysis requires verified replay evidence; "
                "direct nested target requests are not authorized"
            )
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

        # A live browser navigation is a target effect. For an authenticated,
        # signed capture, reject an absent/unpinned shared container mount
        # BEFORE navigation; remote flush_har.exists alone is not a receipt.
        from ai_osop.memory.session_memory import SessionMemory

        current = self.ctx.current_task
        signed_capture = (
            isinstance(self.ctx.session_memory, SessionMemory)
            or current is not None
            and (
                bool(current.flow_id)
                or bool(current.parent_task_id)
                or type(current.payload.get("_authorization_version")) is int
            )
        )
        if signed_capture:
            try:
                if (
                    not isinstance(current, Task)
                    or not isinstance(current.payload, dict)
                    or current.payload.get("url") != url
                ):
                    raise ResourcePathDenied("Signed capture target changed")
                await self._verified_har_task_boundary(
                    "",
                    user_label,
                    workflow_id,
                    require_parent=False,
                )
                signed_har_mount_attestation(self.ctx.session_id)
            except ResourcePathDenied:
                return {
                    "status": "partial",
                    "error": "Authenticated HAR synchronization provenance unavailable",
                }

        # 1. Navigate authenticated (storage_state injected inside _execute_navigation).
        nav = await self._execute_navigation(
            {"url": url, "user_label": user_label, "workflow_id": workflow_id}
        )
        if not isinstance(nav, dict) or nav.get("status") != "success" or (
            isinstance(nav.get("current_url"), str)
            and not _same_capture_origin(url, nav["current_url"])
        ):
            # An MCP timeout, navigation failure or foreign-origin redirect
            # may have made a remote effect. Never flush a HAR or reclassify
            # that UNKNOWN dispatch as a successful authenticated capture.
            return {"status": "execution_unknown", "reason": "browser_navigation_unconfirmed"}

        # 2. Flush the HAR Playwright has been recording for this identity.
        har = await self.browser_adapter.flush_har(
            user_label=user_label,
            engagement_id=self.ctx.session_id,
            workflow_id=workflow_id,
        )
        har_path = har.get("path", "") if isinstance(har, dict) else ""
        if not isinstance(har_path, str) or not har_path or har.get("exists") is not True:
            return {
                "status": "partial",
                "error": "HAR not produced",
                "navigation": nav,
            }

        # 3 + 4. Extract API endpoints from the HAR and persist them to Neo4j.
        try:
            inventory = await self._extract_and_persist_har(
                har_path=har_path,
                user_label=user_label,
                workflow_id=workflow_id,
                scope_hosts=scope_hosts,
                from_flush=True,
                flush_receipt=har,
            )
        except ResourcePathDenied:
            # Browser MCP can be on a different host: its remote 'exists'
            # boolean is NOT evidence the file is readable under our trusted
            # local mount. Never persist or auto-chain an unbound HAR path.
            return {
                "status": "partial",
                "error": "Authenticated HAR shared resource unavailable",
                "navigation": nav,
            }

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
        if not isinstance(har_path, str) or not har_path:
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
        except ResourcePathDenied:
            # Do not echo potentially sensitive local/remote filesystem paths.
            return {"status": "failed", "error": "Authenticated HAR resource unavailable"}
        return {"status": "success", "har_path": har_path, **inventory}

    async def _verified_har_task_boundary(
        self,
        har_path: str,
        user_label: str,
        workflow_id: str,
        *,
        require_parent: bool,
    ) -> Optional[tuple[List[str], Optional[str], Optional[str], Optional[str]]]:
        """Return current signed ROE hosts, verifying the original durable link.

        This is a local file-origin eligibility check, NOT a remotely signed
        browser-MCP receipt. Durable Task results prove who recorded a path;
        an operator-controlled shared mount supplies local bytes.
        """
        from ai_osop.memory.session_memory import SessionMemory

        current = self.ctx.current_task
        memory = self.ctx.session_memory
        signed = (
            isinstance(memory, SessionMemory)
            or current is not None
            and (
                bool(current.flow_id)
                or bool(current.parent_task_id)
                or type(current.payload.get("_authorization_version")) is int
            )
        )
        if not signed:
            return None
        if (
            not isinstance(current, Task)
            or current.engagement_id != self.ctx.session_id
            or not isinstance(current.payload, dict)
            or type(current.payload.get("_authorization_version")) is not int
            or current.payload["_authorization_version"] < 1
            # Only the won, durable one-shot execution claim grants a signed
            # worker access to the recovered resource. A pending row is just
            # a queued intent, not an execution grant.
            or current.status != "running"
            or current.type
            != ("extract_har_api_inventory" if require_parent else "capture_authenticated_surface")
        ):
            raise ResourcePathDenied("Signed HAR task provenance unavailable")
        version = current.payload["_authorization_version"]
        try:
            durable = await memory.load_task_authoritative(current.id)
            signed_auth = await memory.assert_signed_authorization(
                self.ctx.session_id,
                expected_version=version,
            )
            session = await memory.load_session_state(self.ctx.session_id)
            if (
                not isinstance(durable, Task)
                or durable.id != current.id
                or durable.type != current.type
                or durable.engagement_id != self.ctx.session_id
                or durable.flow_id != current.flow_id
                or durable.parent_task_id != current.parent_task_id
                or durable.status != "running"
                or durable.payload != current.payload
                or signed_auth.version != version
                or session is None
                or session.session_id != self.ctx.session_id
                or session.phase in {"halted", "completed"}
                or not session.scope.authorization_ref
                or not (session.scope.domains or session.scope.ips)
                or current.payload.get("user_label", "guest") != user_label
                or current.payload.get("workflow_id", "") != workflow_id
            ):
                raise ValueError()
            if current.flow_id:
                flow = await memory.load_flow(current.flow_id)
                if (
                    flow is None
                    or flow.id != current.flow_id
                    or flow.engagement_id != self.ctx.session_id
                    or flow.status not in {"pending", "running"}
                ):
                    raise ValueError()
            recorded_sha256 = None
            mount_sha256 = None
            container_image_sha256 = None
            if require_parent:
                parent_id = durable.parent_task_id
                if (
                    not isinstance(parent_id, str)
                    or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,78}", parent_id)
                    or durable.dependencies != [parent_id]
                ):
                    raise ValueError()
                parent = await memory.load_task_authoritative(parent_id)
                if (
                    not isinstance(parent, Task)
                    or parent.id != parent_id
                    or parent.engagement_id != self.ctx.session_id
                    or parent.type != "capture_authenticated_surface"
                    or parent.status != "completed"
                    or not isinstance(parent.payload, dict)
                    or parent.payload.get("_authorization_version") != version
                    or parent.payload.get("user_label", "guest") != user_label
                    or parent.payload.get("workflow_id", "") != workflow_id
                    or not isinstance(parent.result, dict)
                    or parent.result.get("status") != "success"
                    or parent.result.get("har_path") != har_path
                    or not isinstance(parent.result.get("resource_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", parent.result["resource_sha256"])
                    or not isinstance(parent.result.get("mount_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", parent.result["mount_sha256"])
                    or not isinstance(parent.result.get("container_image_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", parent.result["container_image_sha256"])
                ):
                    raise ValueError()
                recorded_sha256 = parent.result["resource_sha256"]
                mount_sha256 = parent.result["mount_sha256"]
                container_image_sha256 = parent.result["container_image_sha256"]
            # Scope derived only from signed durable engagement, never from
            # caller-provided scope_hosts (which could widen it).
            hosts = list(session.scope.domains or []) + list(session.scope.ips or [])
            if not hosts or any(
                not isinstance(host, str) or not 1 <= len(host) <= 253 for host in hosts
            ):
                raise ValueError()
            return hosts, recorded_sha256, mount_sha256, container_image_sha256
        except ResourcePathDenied:
            raise
        except Exception as exc:
            raise ResourcePathDenied("Signed HAR task provenance unavailable") from exc

    async def _extract_and_persist_har(
        self,
        *,
        har_path: str,
        user_label: str,
        workflow_id: str,
        scope_hosts: Optional[List[str]] = None,
        from_flush: bool = False,
        flush_receipt: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Bound local HAR snapshot -> APIEndpoint extraction + persistence.

        No raw remote/provider path is ever handed to HARExtractor.parse_file:
        that method calls Path.open without tenancy, size or symlink checks.
        """
        if (
            not isinstance(user_label, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", user_label)
            or not isinstance(workflow_id, str)
            or (workflow_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", workflow_id))
        ):
            raise ResourcePathDenied("HAR identity binding invalid")
        signed_boundary = await self._verified_har_task_boundary(
            har_path,
            user_label,
            workflow_id,
            require_parent=not from_flush,
        )
        from ai_osop.memory.session_memory import SessionMemory

        task = self.ctx.current_task
        signed = (
            isinstance(self.ctx.session_memory, SessionMemory)
            or task is not None
            and (
                bool(task.flow_id)
                or bool(task.parent_task_id)
                or type(task.payload.get("_authorization_version")) is int
            )
        )
        if signed and signed_boundary is None:
            raise ResourcePathDenied("Signed HAR scope unavailable")
        # Declared scope_hosts may narrow a signed scope, never widen it.
        # A legacy/manual ingestion also remains under its own import root.
        if signed_boundary is not None:
            scope_hosts = signed_boundary[0]
        elif scope_hosts is not None and (
            not isinstance(scope_hosts, list)
            or len(scope_hosts) > 64
            or any(not isinstance(item, str) or len(item) > 253 for item in scope_hosts)
        ):
            raise ResourcePathDenied("Manual HAR scope invalid")
        mount_sha256 = None
        container_image_sha256 = None
        if signed:
            mount_sha256, container_image_sha256 = signed_har_mount_attestation(
                self.ctx.session_id,
                expected_sha256=signed_boundary[2] if signed_boundary is not None else None,
            )
            if (
                signed_boundary is None
                or signed_boundary[3] is not None
                and signed_boundary[3] != container_image_sha256
            ):
                raise ResourcePathDenied("Signed HAR shared mount provenance unavailable")
            if from_flush:
                current = self.ctx.current_task
                if (
                    not isinstance(flush_receipt, dict)
                    or not isinstance(current, Task)
                    or flush_receipt.get("engagement_id") != self.ctx.session_id
                    or flush_receipt.get("user_label") != user_label
                    or flush_receipt.get("workflow_id") != workflow_id
                    or flush_receipt.get("path") != har_path
                    or flush_receipt.get("exists") is not True
                    or flush_receipt.get("mount_sha256") != mount_sha256
                    or flush_receipt.get("container_image_sha256") != container_image_sha256
                    or not isinstance(flush_receipt.get("resource_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", flush_receipt["resource_sha256"])
                    or (
                        "capture_task_id" in flush_receipt
                        and flush_receipt["capture_task_id"] != current.id
                    )
                ):
                    raise ResourcePathDenied(
                        "Signed HAR producer synchronization receipt unavailable"
                    )
        document, local_sha256 = snapshot_local_har(
            self.ctx.session_id,
            har_path,
            signed=signed,
        )
        if signed_boundary is not None and signed_boundary[1] is not None:
            import hmac

            if not hmac.compare_digest(signed_boundary[1], local_sha256):
                raise ResourcePathDenied("Signed HAR resource changed after capture")
        if from_flush and signed:
            import hmac

            if not hmac.compare_digest(flush_receipt["resource_sha256"], local_sha256):
                raise ResourcePathDenied("Signed HAR producer/mount resource digests disagree")
        extractor = HARExtractor(
            engagement_id=self.ctx.session_id,
            user_label=user_label,
            workflow_id=workflow_id,
            scope_hosts=scope_hosts,
        )
        endpoints = extractor.parse_har(document)
        if len(endpoints) > 2000:
            raise ResourcePathDenied("HAR endpoint inventory exceeds safe capacity")
        if signed:
            renewed = await self._verified_har_task_boundary(
                har_path,
                user_label,
                workflow_id,
                require_parent=not from_flush,
            )
            if renewed is None or renewed != signed_boundary:
                raise ResourcePathDenied("Signed HAR authority changed before persistence")
            renewed_mount, renewed_container = signed_har_mount_attestation(
                self.ctx.session_id,
                expected_sha256=mount_sha256,
            )
            if renewed_container != container_image_sha256 or renewed_mount != mount_sha256:
                raise ResourcePathDenied("Signed HAR mount changed before persistence")
        persisted = 0
        if endpoints:
            persisted = await persist_endpoints(self.ctx.graph_memory, endpoints)
        return {
            "endpoints_extracted": len(endpoints),
            "endpoints_persisted": persisted,
            "skipped": extractor.skipped,
            "resource_sha256": local_sha256,
            **(
                {
                    "mount_sha256": mount_sha256,
                    "container_image_sha256": container_image_sha256,
                }
                if signed
                else {}
            ),
            "resource_origin": "operator_shared_tenant_mount" if signed else "manual_tenant_import",
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
        from ai_osop.core.signed_replay_execution import (
            authorize_replay_step,
            signed_replay_provider_evidence,
        )

        replay = await authorize_replay_step(self.ctx, payload)
        if replay is not None:
            # The immutable, human-approved child admits *one* GET browser
            # navigation. Additional screenshots/DOM/eval operations are NOT
            # silently included in that approval and must have their own
            # durable provenance/authorization before being scheduled.
            storage = await self._load_storage_state(replay["user_label"])
            # Independent target-owned proofs require the original imported
            # PostgreSQL identity to be byte-for-byte unchanged since both
            # human-approved TaskORMs were atomically admitted. Never infer a
            # new approval from a rotated browser cookie, cache or provider.
            from ai_osop.core.authority_session_binding import reverify_replay_fingerprints

            if any(key.startswith("_authority_") for key in payload):
                current_identity = await self.session_store.get_session_authoritative(
                    self.ctx.session_id, replay["user_label"]
                )
                reverify_replay_fingerprints(
                    payload,
                    current_identity,
                    engagement_id=self.ctx.session_id,
                    user_label=replay["user_label"],
                    method="GET",
                    url=replay["url"],
                    task_id=self.ctx.current_task.id,
                    parent_task_id=replay["replay_parent_task_id"],
                )
            await self.ctx.session_memory.assert_signed_authorization(
                self.ctx.session_id, expected_version=replay["version"]
            )
            try:
                remote = await self.browser_adapter.navigate(
                    replay["url"],
                    replay["user_label"],
                    engagement_id=self.ctx.session_id,
                    storage_state=storage,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                # Once a consequential MCP call was attempted, an exception
                # cannot prove that the remote browser did nothing. Keep the
                # one-shot Task in UNKNOWN rather than generic failed/retryable.
                return {"status": "execution_unknown", "reason": "browser_dispatch_unconfirmed"}
            # The browser's HTTP response is NOT independent target proof.
            # Only an originally bound signed MCP receipt committed to the
            # PostgreSQL dispatch/event ledger can validate provider origin.
            evidence = await signed_replay_provider_evidence(
                self.ctx,
                version=replay["version"],
                url=replay["url"],
                scope=replay["scope"],
            )
            if not evidence or not isinstance(remote, dict):
                return {"status": "execution_unknown", "reason": "provider_origin_unverified"}
            final_url = remote.get("current_url")
            code = remote.get("status_code")
            if not isinstance(final_url, str) or type(code) is not int or not 100 <= code <= 599:
                return {"status": "execution_unknown", "reason": "browser_result_unverified"}
            try:
                from ai_osop.safety.scope import validate_payload_targets

                validate_payload_targets(
                    replay["scope"],
                    {"url": final_url},
                    require_target=True,
                )
            except Exception:
                return {"status": "execution_unknown", "reason": "browser_redirect_unverified"}
            # Redacted comparison fingerprint: never persist raw responses,
            # authentication cookies, headers, HTML or account identifiers.
            # This is an agent-generated summary of provider testimony only;
            # it cannot independently prove ownership or an authorization bug.
            body_digest = None
            body = remote.get("body")
            if isinstance(body, (dict, list, str)):
                try:
                    canonical = json.dumps(
                        body,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=False,
                    ).encode("utf-8")
                    if len(canonical) <= 16384:
                        body_digest = hashlib.sha256(
                            b"osop-signed-replay-v1:"
                            + self.ctx.session_id.encode("utf-8")
                            + b":"
                            + replay["workflow_id"].encode("utf-8")
                            + b":"
                            + replay["step_id"].encode("utf-8")
                            + b":"
                            + canonical
                        ).hexdigest()
                except (TypeError, ValueError, OverflowError, RecursionError):
                    body_digest = None
            return {
                "status": "success",
                "workflow_id": replay["workflow_id"],
                "step_id": replay["step_id"],
                "source_task_id": replay["source_task_id"],
                "replay_parent_task_id": replay["replay_parent_task_id"],
                "comparison_role": replay["comparison_role"],
                "response_body_sha256": body_digest,
                "redirected": final_url != replay["url"],
                "http_status_code": code,
                "provider_evidence": evidence,
                "verification_status": "provider_testimony_only",
                "remote_effect_verified": False,
                "authorization_violation_verified": False,
                "findings": [],
                "findings_count": 0,
            }
        url = payload["url"]
        user_label = payload.get("user_label", "guest")
        workflow_id = payload.get("workflow_id", "")
        step_id = payload.get("step_id", "")

        # 1. Action — seed the browser context with the imported user session when one
        # exists so navigation runs authenticated.
        storage_state = await self._load_storage_state(user_label)
        current = self.ctx.current_task
        signed_capture = (
            isinstance(current, Task)
            and current.type == "capture_authenticated_surface"
            and isinstance(current.payload, dict)
            and type(current.payload.get("_authorization_version")) is int
        )
        try:
            result = await self.browser_adapter.navigate(
                url,
                user_label,
                engagement_id=self.ctx.session_id,
                storage_state=storage_state,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            if signed_capture:
                # A remote request might have executed before its ACK failed;
                # callers must reconcile UNKNOWN rather than auto-retry it.
                return {"status": "execution_unknown", "reason": "browser_dispatch_unconfirmed"}
            raise
        if signed_capture:
            # The provider's 'success' wrapper alone is not evidence that its
            # nested browser navigation succeeded. The signed capture must
            # have a 2xx HTTP receipt and remain at the *exact* scheme, host
            # and port of the persisted Task URL before writing observations,
            # capturing page content, or allowing a downstream HAR flush.
            if (
                current.engagement_id != self.ctx.session_id
                or current.payload.get("url") != url
                or current.payload.get("user_label", "guest") != user_label
                or not isinstance(result, dict)
                or type(result.get("status_code")) is not int
                or not 200 <= result["status_code"] < 300
                or not _same_capture_origin(url, result.get("current_url"))
            ):
                return {"status": "execution_unknown", "reason": "browser_navigation_unconfirmed"}

        # 2. Evidence: always capture screenshot + DOM. Storage failures must
        # never abort the workflow (Issue 8).
        # A signed HAR capture authorizes the navigation and separately
        # fenced HAR flush. Unreviewed screenshot and DOM requests could
        # disclose private page content or consume independent MCP effects.
        evidence = (
            {} if signed_capture
            else await self._capture_step_evidence(user_label, url, workflow_id, step_id)
        )

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
                "status_code": result.get("status_code") if signed_capture else result.get("status_code", 200),
                "body": body,
                "semantics": semantics,
            },
        }

    async def _execute_authentication(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform login workflow and establish session."""
        login_url = payload["login_url"]
        credentials = payload["credentials"]
        user_label = payload.get("user_label", "user_a")

        # Placeholder for complex multi-step auth
        # 1. Navigate to login
        await self.browser_adapter.navigate(
            login_url, user_label, engagement_id=self.ctx.session_id
        )

        # 2. Fill and submit (assuming simple selectors for now)
        # Note: In Step 5, we'll use the Semantic Extractor to find these dynamically.
        # await self.browser_adapter.execute_action("fill", {"selector": "#user", "value": credentials["user"]})
        # await self.browser_adapter.execute_action("click", {"selector": "#submit"})

        # 3. Capture State
        session_state = await self.browser_adapter.capture_state(
            user_label, engagement_id=self.ctx.session_id
        )

        return {"status": "authenticated", "user_label": user_label, "session_state": session_state}

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
            async with self.ctx.graph_memory._driver.session() as session:
                result = await session.run(cypher_search, {"url": url, "sid": self.ctx.session_id})
                record = await result.single()
                if record:
                    endpoint_id = record["id"]
                else:
                    asset_query = "MATCH (a:Asset {engagement_id: $sid, type: 'domain'}) RETURN a.id as id LIMIT 1"
                    asset_res = await session.run(asset_query, {"sid": self.ctx.session_id})
                    asset_rec = await asset_res.single()
                    primary_asset_id = (
                        asset_rec["id"] if asset_rec else f"asset-{self.ctx.session_id}"
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
        async with self.ctx.graph_memory._driver.session() as inv_sess:
            res = await inv_sess.run(
                """
                MATCH (w:Workflow {id: $wid, engagement_id: $eid})
                OPTIONAL MATCH (w)-[:HAS_STEP]->(s:Step {engagement_id: $eid,
                                                         workflow_id: $wid})
                OPTIONAL MATCH (s)-[:HAS_EVIDENCE]->(e:Evidence {engagement_id: $eid,
                                                                 workflow_id: $wid})
                RETURN count(DISTINCT w) AS w_count,
                       count(DISTINCT s) AS step_count,
                       count(DISTINCT e) AS evidence_count
                """,
                {"wid": workflow.id, "eid": self.ctx.session_id},
            )
            rec = await res.single()
            w_count = rec["w_count"] if rec else 0
            step_count = rec["step_count"] if rec else 0
            evidence_count = rec["evidence_count"] if rec else 0

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

            # Assign business state to step via raw Cypher, as model doesn't have it natively
            state_label = step_data.get("state", f"STATE_{i}")
            async with self.ctx.graph_memory._driver.session() as session:
                await session.run(
                    "MATCH (s:Step {id: $step_id, engagement_id: $eid, workflow_id: $wid}) "
                    "SET s.business_state = $state_label",
                    {
                        "step_id": step_id,
                        "state_label": state_label,
                        "eid": self.ctx.session_id,
                        "wid": workflow.id,
                    },
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
