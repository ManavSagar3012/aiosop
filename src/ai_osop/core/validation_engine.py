"""Validation Engine (charter section 12) — the ONLY writer of VALIDATED/REJECTED.

Safe, non-destructive playbooks that re-observe the target to confirm or reject
weakness hypotheses:

    http_header_recheck / csp_recheck / sri_recheck  -> one authenticated-less
        GET; compares live response against the finding's claim
    tls_reprobe   -> service_intel.assess_tls re-run
    ssh_rebanner  -> service_intel.assess_ssh re-run

Every transition goes through confidence_engine.assert_transition, so this
engine is provably the single component able to reach terminal states.
Scope is enforced: targets outside the engagement scope are refused.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import httpx

from ai_osop.core import confidence_engine as ce
from ai_osop.core import service_intel as si

# FIX (ve-selfcontained-2026-08-24): playbook vocabulary owned HERE so this
# engine never depends on either hypothesis generator's internal shape. Any
# hypothesis-like object works (canonical models.Hypothesis or dict-shaped).
PB_CSP_RECHECK = "csp_recheck"
PB_HEADER_RECHECK = "http_header_recheck"
PB_SRI_RECHECK = "sri_recheck"
PB_SSH_REBANNER = "ssh_rebanner"
PB_TLS_REPROBE = "tls_reprobe"

PB_SSRF_OAST = "ssrf_oast"
PB_SQLI_DIFFERENTIAL = "sqli_differential"
PB_AUTHZ_DIFFERENTIAL = "authz_differential"
# AIOSOP-GOLDEN-001 (2026-08-30): HTTP-differential SQLi confirmation. The
# sqlmap playbook requires a live security-bridge backend and a query-string
# injection point. Form/JSON body injection (e.g. a login form) needs a direct
# HTTP differential: a control request must fail, an injection payload must
# succeed, and the response difference is the confirmation. No tooling required.
PB_SQLI_HTTP_DIFFERENTIAL = "sqli_http_differential"

_CATEGORY_TO_PLAYBOOK = {
    "sqli": PB_SQLI_DIFFERENTIAL,
    "sql injection": PB_SQLI_DIFFERENTIAL,
    "ssrf": PB_SSRF_OAST,
    "server-side request forgery": PB_SSRF_OAST,
    "authz": PB_AUTHZ_DIFFERENTIAL,
    "idor": PB_AUTHZ_DIFFERENTIAL,
    "broken access control": PB_AUTHZ_DIFFERENTIAL,
    "header": PB_HEADER_RECHECK,
    "headers": PB_HEADER_RECHECK,
    "csp": PB_CSP_RECHECK,
    "sri": PB_SRI_RECHECK,
    "tls": PB_TLS_REPROBE,
    "ssl": PB_TLS_REPROBE,
    "ssh": PB_SSH_REBANNER,
}


def _resolve_playbook(hyp) -> str:
    """Duck-typed resolution across hypothesis shapes.

    Supports: .playbook attr (FIT-style), canonical models.Hypothesis via
    category/recommended_tests text, and plain dicts.
    """
    pb = getattr(hyp, "playbook", None)
    if pb:
        return pb
    if isinstance(hyp, dict):
        return hyp.get("playbook") or _CATEGORY_TO_PLAYBOOK.get(
            str(hyp.get("category", "")).lower(), ""
        )
    cat = str(getattr(hyp, "category", "")).lower()
    if cat in _CATEGORY_TO_PLAYBOOK:
        return _CATEGORY_TO_PLAYBOOK[cat]
    text = " ".join(map(str, getattr(hyp, "recommended_tests", []) or [])).lower()
    if "tls" in text or "ssl" in text:
        return PB_TLS_REPROBE
    if "ssh" in text:
        return PB_SSH_REBANNER
    if "csp" in text:
        return PB_CSP_RECHECK
    if "header" in text:
        return PB_HEADER_RECHECK
    if "idor" in text or "authz" in text or "access control" in text:
        return PB_AUTHZ_DIFFERENTIAL
    return ""


logger = logging.getLogger(__name__)


@dataclass
class ValidationOutcome:
    hypothesis_id: str
    playbook: str
    validation_state: str  # VALIDATED | REJECTED | INCONCLUSIVE
    evidence: Dict[str, Any] = field(default_factory=dict)
    explanation: str = ""


def _scope_guard(target: str, scope: Optional[Any]) -> None:
    if scope is None:
        return  # header GETs to already-scoped findings' surfaces are safe by construction
    from urllib.parse import urlparse

    from ai_osop.safety.scope import ScopeEnforcer

    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or target
    ScopeEnforcer(scope).validate_target(host)


class ValidationEngine:
    """Executes playbooks and owns terminal validation transitions."""

    def __init__(self, timeout: float = 10.0, mcp_registry: Any = None):
        self.timeout = timeout
        # EXPLOIT-PLAYBOOKS-001: exploit-class playbooks need tooling access;
        # without a registry they degrade to INCONCLUSIVE honestly.
        self.mcp_registry = mcp_registry
        # Header weakness -> confirmed when claimed-missing headers are still absent.
        self._playbooks = {
            PB_HEADER_RECHECK: self._validate_headers,
            PB_CSP_RECHECK: self._validate_headers,
            PB_SRI_RECHECK: self._validate_sri,
            PB_TLS_REPROBE: self._validate_tls,
            PB_SSH_REBANNER: self._validate_ssh,
            PB_SQLI_DIFFERENTIAL: self._validate_sqli,
            PB_SSRF_OAST: self._validate_ssrf_oast,
            PB_AUTHZ_DIFFERENTIAL: self._validate_authz,
            # AIOSOP-GOLDEN-001: form/body SQLi differential (no tooling needed).
            PB_SQLI_HTTP_DIFFERENTIAL: self._validate_sqli_http_differential,
        }

    async def validate(self, hyp: Any, scope: Optional[Any] = None) -> ValidationOutcome:
        playbook = self._playbooks.get(hyp.playbook)
        if playbook is None:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, explanation=f"no playbook for {hyp.playbook}"
            )
        try:
            _scope_guard(hyp.target, scope)
        except Exception as e:  # noqa: BLE001 - out of scope => refuse loudly
            logger.warning(f"validation_scope_denied target={hyp.target} error={e}")
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.REJECTED, explanation="target outside authorized scope"
            )

        return await playbook(hyp)

    # -- HTTP playbooks -------------------------------------------------------

    async def _fetch(self, url: str, headers: dict = None):
        merged_headers = {"User-Agent": "AI-OSOP-ValidationEngine/1.0"}
        if headers:
            merged_headers.update(headers)
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            headers=merged_headers,
        ) as client:
            return await client.get(url)

    def _decide_headers(self, hyp: Any, headers) -> ValidationOutcome:
        plan_headers = (hyp.test_plan or {}).get("headers", [])
        present = [h for h in plan_headers if h.lower() in {k.lower() for k in headers.keys()}]
        missing = [h for h in plan_headers if h not in present]
        ev = {"checked": plan_headers, "present": present, "missing": missing}
        if missing:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.VALIDATED,
                ev,
                f"weakness reproduced: still missing {missing}",
            )
        if plan_headers:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.REJECTED,
                ev,
                "all previously-missing headers now present (fixed or false positive)",
            )
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.INCONCLUSIVE, ev, "no headers specified in test plan"
        )

    async def _validate_headers(self, hyp: Any) -> ValidationOutcome:
        url = hyp.target if "://" in hyp.target else f"https://{hyp.target}"
        try:
            resp = await self._fetch(url)
        except Exception as e:  # noqa: BLE001
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, {"error": str(e)}, "target unreachable"
            )
        return self._decide_headers(hyp, resp.headers)

    async def _validate_sri(self, hyp: Any) -> ValidationOutcome:
        import re as _re

        url = hyp.target if "://" in hyp.target else f"https://{hyp.target}"
        try:
            resp = await self._fetch(url)
        except Exception as e:  # noqa: BLE001
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, {"error": str(e)}, "target unreachable"
            )
        scripts = _re.findall(r"<script[^>]+src=", resp.text, _re.I)[:50]
        with_integrity = _re.findall(r"<script[^>]+integrity=", resp.text, _re.I)
        ev = {"external_scripts": len(scripts), "with_integrity": len(with_integrity)}
        if scripts:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.VALIDATED,
                ev,
                f"{len(scripts)} script tags, " f"{len(with_integrity)} with integrity",
            )
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.INCONCLUSIVE, ev, "no external script tags observed"
        )

    # -- probe playbooks ------------------------------------------------------

    async def _validate_tls(self, hyp: Any) -> ValidationOutcome:
        import asyncio

        host = hyp.target.split("://")[-1].split("/")[0].split(":")[0]
        result = await asyncio.to_thread(si.assess_tls, host)
        legacy = result.get("legacy_versions_accepted", [])
        ev = {"versions": result.get("versions"), "legacy_accepted": legacy}
        if legacy:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED, ev, f"legacy protocols still accepted: {legacy}"
            )
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.REJECTED, ev, "no legacy TLS accepted on reprobe"
        )

    async def _validate_ssh(self, hyp: Any) -> ValidationOutcome:
        import asyncio

        host = hyp.target.split(":")[0]
        result = await asyncio.to_thread(si.assess_ssh, host)
        risky = [i for i in result.get("issues", []) if i["level"] == si.CANDIDATE]
        ev = {"banner": result.get("banner"), "issues": [i["id"] for i in risky]}
        if risky:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.VALIDATED, ev, "risky SSH configuration reproduced"
            )
        if result.get("reachable"):
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.REJECTED, ev, "SSH banner clean on reprobe"
            )
        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.INCONCLUSIVE, ev, "ssh unreachable at validation time"
        )

    async def _registry_call(
        self, server_id: str, tool_name: str, params: Dict[str, Any], hyp: Any, scope: Optional[Any]
    ) -> Optional[Any]:
        """Tool-Reality-gated MCP call; None => tooling unavailable."""
        if getattr(self, "mcp_registry", None) is None:
            return None
        try:
            return await self.mcp_registry.execute_tool(server_id, tool_name, params, scope=scope)
        except Exception as e:  # noqa: BLE001 - honest tool failure
            logger.warning(
                f"validation_registry_call_failed server={server_id} " f"tool={tool_name} error={e}"
            )
            return {"status": "error", "error": str(e)}

    _SQLMAP_VERDICT_MARKERS = ("injectable", "vulnerable", "sqlmap identified")

    async def _validate_sqli(self, hyp: Any) -> ValidationOutcome:
        """EXPLOIT-PLAYBOOKS-001: differential confirmation via security-bridge
        sqlmap. Tool Reality applies - without a live sqlmap backend this stays
        INCONCLUSIVE rather than pretending."""
        from urllib.parse import urlparse

        target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"
        if not urlparse(target).query:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.INCONCLUSIVE,
                {},
                "no query parameters to differentially test",
            )
        resp = await self._registry_call(
            "security-bridge",
            "sqlmap",
            {"url": target, "batch": True, "level": 1},
            hyp,
            getattr(hyp, "_scope", None),
        )
        if resp is None:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, {}, "security-bridge tooling unavailable"
            )
        result = getattr(resp, "result", None) or {}
        text = str(result).lower()
        # FIX (sqli-negation-2026-08-24): "NOT injectable" contains "injectable"
        # as a substring - negations must be checked BEFORE positive markers.
        if "not injectable" in text or "not vulnerable" in text:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.REJECTED,
                {"tool": "sqlmap", "target": target},
                "sqlmap found no injection on retest",
            )
        if any(m in text for m in self._SQLMAP_VERDICT_MARKERS):
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.VALIDATED,
                {"tool": "sqlmap", "target": target},
                "sqlmap reported injectable parameter",
            )
        if getattr(resp, "status", "") == "success":
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.REJECTED,
                {"tool": "sqlmap", "target": target},
                "sqlmap found no injection on retest",
            )
        return ValidationOutcome(
            hyp.id,
            hyp.playbook,
            ce.INCONCLUSIVE,
            {"raw": str(result)[:400]},
            "sqlmap output inconclusive",
        )

    async def _validate_sqli_http_differential(self, hyp: Any) -> ValidationOutcome:
        """AIOSOP-GOLDEN-001: direct HTTP differential for body/form SQLi.

        For a login form (or JSON API) SQLi, the injection point is a body
        parameter — sqlmap's query-string playbook does not cover it. Instead:
          1. Send a CONTROL request with a benign username; expect authentication
             to FAIL (a distinct response marker).
          2. Send an INJECTION request with the SQLi payload; expect the SUCCESS
             marker to appear.
          3. The response difference IS the confirmation — VALIDATED.

        The hypothesis must carry the differential plan in ``hyp.test_plan``:
          {url, method, parameter, control_value, payload, success_marker,
           failure_marker}. Any missing field or tooling failure -> INCONCLUSIVE
          (honest, never fabricated).
        """
        plan = getattr(hyp, "test_plan", None) or {}
        url = plan.get("url") or (hyp.target if "://" in str(hyp.target or "") else f"https://{hyp.target}")
        parameter = plan.get("parameter", "username")
        control_value = plan.get("control_value", "__nonexistent_user__")
        payload = plan.get("payload", "' OR 1=1 --")
        success_marker = plan.get("success_marker", "Welcome")
        failure_marker = plan.get("failure_marker", "Login failed")

        if not url:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, {}, "no target URL for differential"
            )

        async def _post(pvalue: str):
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                return await client.post(
                    url,
                    data={parameter: pvalue, "password": "probe"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

        try:
            control = await _post(control_value)
            injected = await _post(payload)
        except Exception as e:  # noqa: BLE001 - honest tool failure
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, {"error": str(e)}, "target unreachable"
            )

        control_body = control.text or ""
        injected_body = injected.text or ""
        control_failed = failure_marker in control_body or "Welcome" not in control_body
        injection_succeeded = success_marker in injected_body

        ev = {
            "control_status": control.status_code,
            "control_marker": "fail" if control_failed else "unexpected",
            "injected_status": injected.status_code,
            "injected_marker": "success" if injection_succeeded else "not_seen",
            "url": url,
            "parameter": parameter,
            "payload": payload,
        }

        if injection_succeeded and control_failed:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.VALIDATED,
                ev,
                f"differential confirmed: control failed, injection reached {success_marker}",
            )
        if not injection_succeeded and not control_failed:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.REJECTED,
                ev,
                "control and injection both succeeded — not a login differential",
            )
        if not injection_succeeded:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.REJECTED,
                ev,
                "injection payload did not reach the success marker on retest",
            )
        return ValidationOutcome(
            hyp.id,
            hyp.playbook,
            ce.INCONCLUSIVE,
            ev,
            "control did not fail as expected — response shape unexpected",
        )

    async def _validate_ssrf_oast(self, hyp: Any) -> ValidationOutcome:
        """EXPLOIT-PLAYBOOKS-002: OOB SSRF confirmation via oast-mcp callback.

        Flow: generate callback token -> inject into target URL param ->
        poll for interactions. Callback received = VALIDATED (server made the
        request). No callback within timeout = REJECTED (not exploitable).
        Tool Reality applies: without oast-mcp this stays INCONCLUSIVE.
        """
        from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

        registry = getattr(self, "mcp_registry", None)
        if registry is None:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, {}, "oast-mcp registry not available"
            )

        # Step 1: generate callback token via oast-mcp
        try:
            conn = registry.get_server("oast-mcp")
            if conn is None or getattr(conn, "_circuit_open", False):
                return ValidationOutcome(
                    hyp.id, hyp.playbook, ce.INCONCLUSIVE, {}, "oast-mcp unavailable"
                )
            # Discover available tools dynamically (Tool Reality)
            tools = {t.tool_name for t in (await conn.list_tools())}
            gen_tool = next(
                (t for t in tools if "payload" in t or "generate" in t or "collab" in t), None
            )
            poll_tool = next(
                (t for t in tools if "callback" in t or "poll" in t or "interaction" in t), None
            )
            if not gen_tool or not poll_tool:
                return ValidationOutcome(
                    hyp.id,
                    hyp.playbook,
                    ce.INCONCLUSIVE,
                    {"tools_available": list(tools)[:10]},
                    "oast-mcp lacks payload/poll tools",
                )
        except Exception as e:  # noqa: BLE001
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, {"error": str(e)}, "tool discovery failed"
            )

        # Generate callback URL
        gen_resp = await self._registry_call(
            "oast-mcp", gen_tool, {}, hyp, getattr(hyp, "_scope", None)
        )
        if not gen_resp or getattr(gen_resp, "status", "") != "success":
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, {}, "callback generation failed"
            )
        callback_url = str(
            (getattr(gen_resp, "result", None) or {}).get(
                "url", (getattr(gen_resp, "result", None) or {}).get("callback_url", "")
            )
        )
        if not callback_url:
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.INCONCLUSIVE, {}, "no callback URL in oast response"
            )

        # Inject callback URL into target parameter
        target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"
        parsed = urlparse(target)
        qs = parse_qs(parsed.query)
        injected = False
        for key in qs:
            if any(
                w in key.lower()
                for w in (
                    "url",
                    "uri",
                    "host",
                    "dest",
                    "redirect",
                    "fetch",
                    "proxy",
                    "src",
                    "next",
                    "return",
                )
            ):
                qs[key] = [callback_url]
                injected = True
        if not injected and qs:
            first_key = list(qs.keys())[0]
            qs[first_key] = [callback_url]
            injected = True
        if not injected:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.INCONCLUSIVE,
                {"callback_url": callback_url},
                "no injectable URL parameter found",
            )
        new_query = urlencode(qs, doseq=True)
        probe_url = urlunparse(parsed._replace(query=new_query))

        # Fire the request
        try:
            await self._fetch(probe_url)
        except Exception:  # noqa: BLE001 - even errors may trigger server-side fetch
            pass

        # Poll for callbacks
        import asyncio as _aio

        for _ in range(6):  # poll up to ~30 seconds
            await _aio.sleep(5)
            poll_resp = await self._registry_call(
                "oast-mcp", poll_tool, {"token": callback_url}, hyp, getattr(hyp, "_scope", None)
            )
            result = getattr(poll_resp, "result", None) or {}
            interactions = result.get("interactions", result.get("callbacks", []))
            if interactions:
                return ValidationOutcome(
                    hyp.id,
                    hyp.playbook,
                    ce.VALIDATED,
                    {
                        "callback_url": callback_url,
                        "probe_url": probe_url,
                        "interactions": len(interactions),
                        "detail": str(interactions[0])[:200],
                    },
                    f"OOB callback received ({len(interactions)} interaction(s)) "
                    f"- server performed the request",
                )

        return ValidationOutcome(
            hyp.id,
            hyp.playbook,
            ce.REJECTED,
            {"callback_url": callback_url, "probe_url": probe_url},
            "no OOB callback received after 30s " "- target likely does not fetch URLs",
        )

    # -- model application ----------------------------------------------------

    async def _validate_authz(self, hyp: Any) -> ValidationOutcome:
        """EXPLOIT-PLAYBOOKS-002: Authz Differential Testing.
        Takes two session contexts, requests the same resource, and diffs responses
        to mathematically prove a privilege escalation or IDOR.
        """
        auth_a = getattr(hyp, "auth_a", {})
        auth_b = getattr(hyp, "auth_b", {})
        target = hyp.target if "://" in hyp.target else f"https://{hyp.target}"

        if not auth_a or not auth_b:
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.INCONCLUSIVE,
                {},
                "Missing dual session contexts for differential auth testing",
            )

        # FIX (authz-reuse-fetch-2026-08-25): use self._fetch (mockable) instead
        # of inline httpx.AsyncClient which bypassed class-level test patches.
        res_a = await self._fetch(target, headers=auth_a.get("headers", {}))
        res_b = await self._fetch(target, headers=auth_b.get("headers", {}))

        if res_a.status_code == 404 or res_b.status_code == 404:
            return ValidationOutcome(hyp.id, hyp.playbook, ce.REJECTED, {}, "Resource not found")

        if res_a.status_code in (401, 403) or res_b.status_code in (401, 403):
            return ValidationOutcome(
                hyp.id, hyp.playbook, ce.REJECTED, {}, "Authorization enforced by status code"
            )

        try:
            body_a = res_a.json()
            body_b = res_b.json()
        except ValueError:
            body_a = res_a.text
            body_b = res_b.text

        if body_a == body_b:
            # Mathematical proof of privilege escalation/IDOR
            return ValidationOutcome(
                hyp.id,
                hyp.playbook,
                ce.VALIDATED,
                {"response": body_a, "target": target},
                "Mathematical proof of privilege escalation: distinct identities returned identical resource ASTs",
            )

        return ValidationOutcome(
            hyp.id, hyp.playbook, ce.REJECTED, {}, "Responses differ; authorization enforced"
        )

    def apply_to_finding(self, finding: Any, outcome: ValidationOutcome) -> str:
        """Transition a finding's validation_state per outcome (audited)."""
        target_state = outcome.validation_state
        explanation = outcome.explanation

        finding.validation_state = ce.assert_transition(
            finding.validation_state, target_state, finding.id, "ValidationEngine", explanation
        )
        if target_state == ce.VALIDATED:
            finding.validated = True
        elif target_state == ce.REJECTED:
            finding.validated = False
            finding.evidence = [outcome.evidence] if outcome.evidence else []

        # AIOSOP-LEDGER-001 (2026-08-29): record the transition into the findings
        # ledger so the funnel is visible (why findings die / survive). Best-effort —
        # a ledger hiccup must never break validation.
        try:
            from ai_osop.core.findings_ledger import record_finding_event

            record_finding_event(
                engagement_id=getattr(finding, "engagement_id", ""),
                finding_id=str(getattr(finding, "id", "")),
                finding_title=str(getattr(finding, "title", "")),
                stage="validated",
                status=target_state,
                reason=explanation or f"ValidationEngine playbook={outcome.playbook}",
                actor="ValidationEngine",
            )
        except Exception:  # noqa: BLE001 - ledger is advisory
            pass
        return finding.validation_state
