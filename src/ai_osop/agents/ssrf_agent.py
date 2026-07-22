"""
SSRF Scanner Agent
Specialized agent for Server-Side Request Forgery detection.
"""

import asyncio
from typing import Any, Dict

from ai_osop.adapters.oast_mcp import OASTAdapter
from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.enums import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from ai_osop.payload_engine.engine import PayloadTemplateLibrary


class SSRFAgent(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for SSRF vulnerabilities using the platform's
    payload engine and OAST for verification.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.SSRF_SCANNER

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "ssrf_scan"

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute SSRF scan task."""
        if task.type == "ssrf_scan":
            return await self._execute_ssrf_scan(task)
        raise Exception(f"Unknown task type: {task.type}")

    async def _execute_ssrf_scan(self, task: Task) -> Dict[str, Any]:
        """
        Implement SSRF scanning logic.
        """
        target_url = task.payload.get("url")
        oast_adapter = OASTAdapter(self.ctx.mcp_registry)
        # OASTAdapter exposes register() -> (token, callback_url) and poll(token);
        # there is no generate_probe()/poll_callbacks(). Blind SSRF needs a live OAST
        # server — if it is unavailable, skip cleanly instead of crashing the task.
        try:
            token, callback_url = await oast_adapter.register(
                label="ssrf",
                context={"engagement_id": task.engagement_id, "url": target_url},
            )
        except Exception as e:  # OAST server down / not initialized
            self.logger.info("ssrf_scan_skipped: OAST unavailable (%s)", e)
            return {
                "status": "success",
                "message": "skipped: OAST unavailable",
                "findings_count": 0,
            }
        if not callback_url:
            return {
                "status": "success",
                "message": "skipped: no OAST callback URL",
                "findings_count": 0,
            }

        templates = PayloadTemplateLibrary.get_templates(VulnClass.SSRF)

        # BLK-2 (2026-07-21): use governed client for SSRF probe egress
        async with self.get_governed_client(tool="ssrf", timeout=10.0) as client:
            for template in templates:
                payload = template.replace("{{OAST_CALLBACK}}", callback_url)
                try:
                    # Simplistic injection: assuming SSRF via a 'url' param
                    params = {"url": payload}
                    await client.get(target_url, params=params)
                except Exception:
                    pass

        # Wait for callbacks with adaptive polling (LLM-API-2026-07-22).
        # Previously a hardcoded asyncio.sleep(5) that always waited 5s even if
        # the callback arrived in 500ms, and missed callbacks that took >5s.
        # Now uses exponential intervals (0.5s → 1s → 2s → 2s → 2s) with a
        # configurable total timeout (default 30s), returning as soon as any
        # callback is detected. The slow-path reconciler (OASTCorrelationRegistry)
        # catches any callbacks that land after the inline window closes.
        _callback_timeout = task.payload.get("oast_poll_timeout", 30.0)
        callbacks = await _poll_oast_with_timeout(oast_adapter, token, timeout=_callback_timeout)

        if callbacks:
            vuln = Vulnerability(
                vuln_type=VulnClass.SSRF,
                severity=Severity.HIGH,
                title=f"Server-Side Request Forgery on {target_url}",
                description=f"SSRF detected in {target_url} via OAST callback validation.",
                evidence=[
                    {
                        "type": "oast_callback",
                        "url": target_url,
                        "callbacks": callbacks,
                    }
                ],
                tool_source="ssrf_scanner",
                confidence=0.95,
                engagement_id=task.engagement_id,
                validated=True,
            )
            await self.persist_finding(vuln)

        return {"status": "success", "message": f"SSRF scan completed for {target_url}"}


async def _poll_oast_with_timeout(
    oast_adapter: OASTAdapter,
    token: str,
    *,
    timeout: float = 30.0,
    initial_interval: float = 0.5,
    max_interval: float = 2.0,
) -> list[dict[str, Any]]:
    """Poll an OAST token with exponential backoff, returning as soon as
    callbacks are detected or the timeout expires.

    Intervals: 0.5s, 1.0s, 2.0s, 2.0s, 2.0s, ... up to ``timeout`` total.
    The first probe sends immediately (no initial sleep), so a fast callback
    on a warm OAST server resolves in ~500ms instead of 5s.
    """
    deadline = asyncio.get_event_loop().time() + timeout
    interval = initial_interval
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            callbacks = await oast_adapter.poll(token)
        except Exception:
            callbacks = None
        if callbacks:
            return callbacks
        next_sleep = min(interval, remaining)
        if next_sleep > 0:
            await asyncio.sleep(next_sleep)
        interval = min(interval * 2, max_interval)
    # Final poll after timeout in case a callback arrived during the last sleep.
    try:
        return await oast_adapter.poll(token) or []
    except Exception:
        return []
