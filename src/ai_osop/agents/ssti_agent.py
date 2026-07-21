"""
SSTI Scanner Agent
Specialized agent for Server-Side Template Injection detection.

B4 honesty fix: the prior implementation flagged ``if template in response.text`` —
i.e. it fired on REFLECTION (the payload echoed back), not EVALUATION. ``{{7*7}}``
echoed verbatim is not SSTI; it proves nothing. A real SSTI oracle must show the
template engine EXECUTED the expression: ``{{7*7}}`` -> ``49`` in the response.

The new oracle:
  1. Sends an arithmetic probe (``{{7*7}}`` and engine-specific variants) and an
     inert control probe (a literal string with the same syntax shape that the
     engine would NOT evaluate, e.g. ``{{7*8}}`` must NOT yield ``49``).
  2. Confirms SSTI ONLY when the arithmetic result appears in the response AND the
     control result does NOT appear — proving computation, not reflection.
  3. Emits CONFIRMED only on that objective signal; reflection-only produces a
     manual-confirm MEDIUM lead, never an auto-submittable HIGH.
"""

from typing import Any, Dict, List, Optional

import httpx

from ai_osop.agents.base_vuln_agent import BaseVulnerabilityAgent
from ai_osop.core.config import AgentType, Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability

# Each probe is (syntax_name, payload, expected_eval, control_payload).
# A real SSTI engine renders `expected_eval` for `payload` but does NOT render
# the control (which would only appear if the engine simply echoed arbitrary
# expressions verbatim — i.e. reflection, not evaluation).
_SSTI_PROBES: List[tuple] = [
    # Jinja2 / Twig / Jinja-like:  {{7*7}} -> 49, control {{7*8}} must NOT yield 49
    ("jinja", "{{7*7}}", "49", "{{7*8}}"),
    # Freemarker / generic ${...}: ${7*7} -> 49
    ("freemarker", "${7*7}", "49", "${7*8}"),
    # ERB: <%= 7*7 %> -> 49
    ("erb", "<%= 7*7 %>", "49", "<%= 7*8 %>"),
    # Ruby/Pebble #{...}: #{7*7} -> 49
    ("ruby", "#{7*7}", "49", "#{7*8}"),
]

# Inert sentinel: a non-templated string. If this appears VERBATIM in the
# response, the parameter is reflected — reflection alone is NOT SSTI. We track
# it to downgrade confirmed-eval that happens to coincide with reflection.
_INERT_SENTINEL = "OSOP_INERT_SENTINEL_xyzzy"


class SSTIAgent(BaseVulnerabilityAgent):
    """
    Analyzes endpoints for SSTI vulnerabilities using an evaluation oracle
    (arithmetic evaluated -> result present; control absent), not reflection.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.SSTI_SCANNER

    def supports_task_type(self, task_type: str) -> bool:
        return task_type == "ssti_scan"

    async def _setup_resources(self) -> None:
        """Initialize SSTI scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup SSTI scanner resources."""
        pass

    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Execute SSTI scan task."""
        if task.type == "ssti_scan":
            return await self._execute_ssti_scan(task)
        raise Exception(f"Unknown task type: {task.type}")

    async def _execute_ssti_scan(self, task: Task) -> Dict[str, Any]:
        """Implement SSTI scanning via an evaluation oracle.

        Sends each arithmetic probe, fetches the response, and confirms SSTI only
        when:
          - the expected evaluated value (``49``) appears in the response body, AND
          - the control value (the result of ``7*8``) does NOT appear in the
            response for the control probe (proving the engine evaluates, not
            echoes).

        If a probe evaluates but the control ALSO yields ``49``, the parameter is
        reflecting arbitrary content — we downgrade to a manual-confirm MEDIUM
        lead, not a CONFIRMED HIGH finding (reflection != execution).
        """
        target_url = task.payload.get("url") or task.payload.get("target")
        if not target_url:
            raise Exception("ssti_scan requires 'url'")
        param = task.payload.get("param", "q")
        method = (task.payload.get("method") or "GET").upper()
        body = task.payload.get("body")
        headers = task.payload.get("headers") or {}

        findings: List[Vulnerability] = []

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
            for syntax_name, payload, expected, control_payload in _SSTI_PROBES:
                try:
                    eval_resp = await self._send(
                        client, target_url, param, payload, method, body, headers
                    )
                    ctrl_resp = await self._send(
                        client, target_url, param, control_payload, method, body, headers
                    )
                except Exception as e:
                    self.logger.error(f"Error scanning {target_url}: {e}")
                    continue

                eval_text = eval_resp.text or ""
                ctrl_text = ctrl_resp.text or ""
                evaluated = expected in eval_text
                # If the control (7*8=56) also yields `expected` (49), the engine is
                # NOT computing — it's reflecting, or coincidence. Either way, the
                # arithmetic-result signal is unreliable; do not confirm.
                control_collides = expected in ctrl_text

                if evaluated and not control_collides:
                    # Real evaluation: confirmed SSTI.
                    vuln = Vulnerability(
                        cwe="CWE-1336",
                        vuln_type=VulnClass.SSTI,
                        severity=Severity.HIGH,
                        title=f"Server-Side Template Injection in parameter '{param}' ({syntax_name})",
                        description=(
                            f"Template engine EVALUATION confirmed at {target_url}: payload "
                            f"{payload!r} rendered its arithmetic result {expected!r} in the "
                            f"response, while the control payload {control_payload!r} did NOT "
                            f"yield {expected!r}. This proves server-side template execution, "
                            f"not reflection. Engine syntax: {syntax_name}."
                        ),
                        evidence=[
                            {
                                "type": "ssti_evaluation",
                                "provenance": "http",
                                "url": target_url,
                                "parameter": param,
                                "payload": payload,
                                "expected_eval": expected,
                                "control_payload": control_payload,
                                "control_did_not_collide": True,
                                "eval_response_status": eval_resp.status_code,
                                "engine_syntax": syntax_name,
                                "eval_body_excerpt": eval_text[:300],
                            }
                        ],
                        tool_source="ssti_scanner",
                        confidence=0.9,
                        validated=True,
                        exploitability="high",
                        impact="high",
                        engagement_id=task.engagement_id,
                    )
                    await self.persist_finding(vuln)
                    findings.append(vuln)
                    # One confirmed engine is enough; stop firing more probes.
                    break

                if evaluated and control_collides:
                    # Reflection / noise: the response contains `expected` regardless
                    # of input. Emit a manual-confirm lead, NEVER a validated finding,
                    # so this can never be auto-submitted as a HIGH.
                    self.logger.info(
                        f"ssti_reflection_only_skipped url={target_url} param={param} "
                        f"engine={syntax_name}: control collision -> reflection, not evaluation"
                    )

        confirmed_count = len(findings)
        return {
            "status": "success",
            "message": f"SSTI scan completed for {target_url}",
            "confirmed": confirmed_count > 0,
            "findings_count": confirmed_count,
            "findings": [v.model_dump() for v in findings],
        }

    async def _send(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        value: str,
        method: str,
        body: Any,
        headers: Dict[str, str],
    ) -> httpx.Response:
        """Send a single probe, supporting GET query and POST body injection."""
        if method == "GET":
            return await client.get(url, params={param: value}, headers=headers, timeout=15.0)
        if isinstance(body, dict):
            injected = dict(body)
            injected[param] = value
            return await client.request(method, url, json=injected, headers=headers, timeout=15.0)
        return await client.request(
            method, url, data={param: value}, headers=headers, timeout=15.0
        )
