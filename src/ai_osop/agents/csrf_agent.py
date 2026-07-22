"""
CSRF Scanner Agent
Specialized agent for Cross-Site Request Forgery detection.

B4 honesty fix: the prior implementation flagged "no CSRF token string in the
response" as a CONFIRMED potential vuln — with no working PoC, no check that the
endpoint is actually state-changing + cookie-authed, and no proof the request
succeeds cross-site. That is the textbook false-positive generator that gets
reports rejected on real programs (and would be out-of-policy noise).

The new agent requires a real cross-site forgery simulation:
  1. Applicability preflight (unsafe method, not read-only path, cookie auth).
  2. Replay the state-changing action with a FOREIGN Origin/Referer, the ambient
     cookie, and NO CSRF token in the request.
  3. Confirm CSRF ONLY when the foreign-Origin request is ACCEPTED (success status)
     — i.e. the action can actually be forged from an attacker page. A request
     that is rejected (403/401), or a cookie-less/bearer-only endpoint, is
     honestly reported as not-applicable.
  4. Emit a CONFIRMED finding only on that objective signal. If applicability
     fails, no finding is emitted — only a skipped-scan graph node.

This mirrors the cross-site PoC the vuln_agent's CSRF path already implements,
applied to the standalone agent so the two paths agree.
"""

from typing import Any, Dict

import httpx  # noqa: F401

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.enums import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability


class CSRFAgent(BaseVulnerabilityAgent):
    """CSRF scanner — cross-site forgery simulation, not token-string sniffing."""

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CSRF_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "csrf_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute CSRF scan task."""
        if task.type == "csrf_scan":
            return await self._execute_csrf_scan(task)
        raise Exception(f"Unknown task type: {task.type}")

    async def _execute_csrf_scan(self, task: Task) -> Dict[str, Any]:
        """CSRF detection via a real cross-site forgery simulation.

        A CSRF finding is emitted ONLY when a foreign-Origin request carrying the
        ambient cookie (and NO anti-CSRF token) is ACCEPTED by a state-changing
        endpoint. Bearer-only or cookie-less endpoints are honestly reported as
        not applicable (bearer tokens are not sent cross-site, so they cannot be
        forged this way)."""
        target_url = task.payload.get("url") or task.payload.get("target")
        if not target_url:
            raise Exception("csrf_scan requires 'url'")

        from ai_osop.auth.session_store import SessionStore
        from ai_osop.core.applicability import ApplicabilityEngine

        store = SessionStore(self.ctx.session_memory)
        sessions = await store.list_sessions(task.engagement_id)

        app_check = ApplicabilityEngine.is_applicable(
            VulnClass.CSRF, task.payload, user_sessions=sessions
        )
        if not app_check["applicable"]:
            self.logger.info(f"csrf_scan_skipped: reason={app_check['reason']} url={target_url}")
            await self.ctx.graph_memory.log_skipped_scan(
                task_id=task.id,
                vuln_class="csrf",
                endpoint_url=target_url,
                reason=app_check["reason"],
                confidence=0.99,
                evidence=[app_check["reason"]],
                engagement_id=task.engagement_id,
            )
            return {
                "status": "success",
                "confirmed": False,
                "reason": app_check["reason"],
                "findings_count": 0,
            }

        # Ambient auth: cookie (CSRF-relevant). Bearer tokens are NOT CSRF-able
        # (not sent cross-site); ApplicabilityEngine already gates on cookie
        # sessions, but we re-check the explicit payload-provided cookie too.
        cookie = task.payload.get("cookie")
        if not cookie:
            self.logger.info(f"csrf_not_applicable_bearer url={target_url}")
            await self.ctx.graph_memory.log_skipped_scan(
                task_id=task.id,
                vuln_class="csrf",
                endpoint_url=target_url,
                reason="auth is not cookie/ambient (bearer tokens are not sent cross-site); CSRF not exploitable",
                confidence=0.99,
                evidence=["no ambient cookie"],
                engagement_id=task.engagement_id,
            )
            return {
                "status": "success",
                "confirmed": False,
                "reason": "auth is not cookie/ambient (bearer tokens are not sent cross-site); CSRF not exploitable",
                "findings_count": 0,
            }

        method = (task.payload.get("method") or "POST").upper()
        body = task.payload.get("body")
        ok_statuses = set(task.payload.get("success_status", [200, 201, 204]))
        content_type = task.payload.get("content_type", "application/json")

        # Cross-site forgery simulation: foreign Origin + ambient cookie, NO CSRF
        # token. If this request SUCCEEDS, the state-changing action can be forged
        # from an attacker page — that's the working PoC.
        headers = {
            "Origin": "https://evil.attacker.test",
            "Referer": "https://evil.attacker.test/csrf.html",
            "Cookie": cookie,
            "Content-Type": content_type,
        }

        try:
            async with self.get_governed_client(
                tool="csrf", verify=False, follow_redirects=False, timeout=15.0
            ) as c:
                if isinstance(body, (dict, list)):
                    resp = await c.request(method, target_url, json=body, headers=headers)
                else:
                    resp = await c.request(method, target_url, content=body or b"", headers=headers)
        except Exception as e:
            self.logger.error(f"Error scanning {target_url}: {e}")
            return {"status": "error", "tool": "csrf_scan", "error": str(e)}
        accepted = resp.status_code in ok_statuses
        if not accepted:
            self.logger.info(
                f"csrf_not_confirmed url={target_url} status={resp.status_code}: "
                f"cross-site request rejected -> not exploitable"
            )
            return {
                "status": "success",
                "tool": "csrf_scan",
                "target": target_url,
                "confirmed": False,
                "reason": f"cross-site request rejected (status {resp.status_code}); not exploitable",
                "findings_count": 0,
            }

        # Working PoC: the foreign-Origin request was accepted. This is the
        # objective signal (state change succeeded cross-site) — emit a CONFIRMED
        # finding with the actual request/response as evidence so a triager can
        # reproduce it verbatim.
        vuln = Vulnerability(
            cwe="CWE-352",
            vuln_type=VulnClass.CSRF,
            severity=Severity.MEDIUM,
            title=f"Cross-Site Request Forgery on {target_url}",
            description=(
                f"{method} {target_url} accepted a cross-site request (foreign Origin, ambient "
                f"cookie, no anti-CSRF token) with status {resp.status_code}, indicating the "
                f"state-changing action can be forged from an attacker page. Confirmed via "
                f"cross-site forgery simulation, not token-string sniffing."
            ),
            evidence=[
                {
                    "type": "csrf",
                    "provenance": "http",
                    "url": target_url,
                    "method": method,
                    "status": resp.status_code,
                    "origin": headers["Origin"],
                    "cookie_used": True,
                    "csrf_token_in_request": False,
                    "accepted_cross_site": True,
                }
            ],
            tool_source="csrf_scanner",
            confidence=0.85,
            validated=True,
            exploitability="medium",
            impact="medium",
            engagement_id=task.engagement_id,
        )
        await self.persist_finding(vuln)
        return {
            "status": "success",
            "tool": "csrf_scan",
            "target": target_url,
            "confirmed": True,
            "findings_count": 1,
            "findings": [vuln.model_dump()],
        }
