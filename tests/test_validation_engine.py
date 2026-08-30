"""Validation Engine: sole writer of VALIDATED/REJECTED (charter 12)."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

import pytest

from ai_osop.core import confidence_engine as ce
from ai_osop.core import validation_engine as ve
from ai_osop.core.validation_engine import (
    PB_HEADER_RECHECK, PB_TLS_REPROBE)


def _hyp(playbook=PB_HEADER_RECHECK, target="https://t.example",
         plan=None):
    # duck-typed hypothesis compatible with both generator shapes
    return SimpleNamespace(id="hyp-x", title="t", playbook=playbook,
                      source_finding_id="v-1", fingerprint="fp", target=target,
                      reason="r", confidence=0.6, priority=0.7,
                      test_plan=plan or {"headers": ["X-Frame-Options",
                                                     "Content-Security-Policy"]})


def _resp(headers):
    r = MagicMock()
    r.headers = headers
    return r


class TestHeaderPlaybook:
    @pytest.mark.asyncio
    async def test_still_missing_validates(self):
        eng = ve.ValidationEngine()
        with patch.object(eng, "_fetch",
                          AsyncMock(return_value=_resp({"server": "nginx"}))):
            out = await eng.validate(_hyp())
        assert out.validation_state == ce.VALIDATED
        assert set(out.evidence["missing"]) == {"X-Frame-Options",
                                                "Content-Security-Policy"}

    @pytest.mark.asyncio
    async def test_headers_present_rejects(self):
        eng = ve.ValidationEngine()
        hdrs = {"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src"}
        with patch.object(eng, "_fetch", AsyncMock(return_value=_resp(hdrs))):
            out = await eng.validate(_hyp())
        assert out.validation_state == ce.REJECTED

    @pytest.mark.asyncio
    async def test_unreachable_inconclusive(self):
        eng = ve.ValidationEngine()
        with patch.object(eng, "_fetch", AsyncMock(side_effect=RuntimeError("boom"))):
            out = await eng.validate(_hyp())
        assert out.validation_state == ce.INCONCLUSIVE


class TestScopeGuard:
    @pytest.mark.asyncio
    async def test_out_of_scope_refused(self):
        eng = ve.ValidationEngine()
        scope = SimpleNamespace(domains=["safe.example"], ips=["10.0.0.0/8"],
                                engagement_id="e", exclusions=[])
        from ai_osop.core.models import ScopeDefinition
        sd = ScopeDefinition(engagement_id="e", domains=["safe.example"],
                             ips=["10.0.0.0/8"])
        out = await eng.validate(_hyp(target="https://evil.example/"), scope=sd)
        assert out.validation_state == ce.REJECTED
        assert "scope" in out.explanation.lower()


class TestTransitionOwnership:
    def test_apply_transitions_and_records(self):
        """Updated for audit-trail contract: assert_transition raises on illegal
        moves and returns target; provenance flows to the audit log."""
        f = SimpleNamespace(id="v1", validation_state=ce.UNTESTED,
                            validated=False, yield_metadata={})
        eng = ve.ValidationEngine()
        outcome = ve.ValidationOutcome("hyp-x", PB_HEADER_RECHECK, ce.VALIDATED,
                                       {"k": 1}, "reproduced")
        assert eng.apply_to_finding(f, outcome) == ce.VALIDATED
        assert f.validated is True

    def test_terminal_state_protected(self):
        """VALIDATED is terminal — illegal regression now raises LOUDLY via
        confidence_engine.assert_transition (no silent refusal)."""
        f = SimpleNamespace(id="v2", validation_state=ce.VALIDATED,
                            validated=True, yield_metadata={})
        eng = ve.ValidationEngine()
        outcome = ve.ValidationOutcome("hyp-y", PB_HEADER_RECHECK, ce.REJECTED,
                                       {}, "changed")
        with pytest.raises(ValueError, match="VALIDATED -> REJECTED"):
            eng.apply_to_finding(f, outcome)
        assert f.validation_state == ce.VALIDATED  # untouched on failure


class TestTlsReprobe:
    @pytest.mark.asyncio
    async def test_legacy_reproduces_validated(self):
        eng = ve.ValidationEngine()
        fake_tls = {"versions": ["TLSv1.2"], "legacy_versions_accepted": ["TLSv1"]}
        with patch("ai_osop.core.service_intel.assess_tls", return_value=fake_tls):
            with patch("asyncio.to_thread",
                       AsyncMock(return_value=fake_tls)):
                out = await eng.validate(
                    _hyp(PB_TLS_REPROBE, target="https://old.example"))
        assert out.validation_state == ce.VALIDATED


class TestSqliDifferential:
    """EXPLOIT-PLAYBOOKS-001: first CONFIRMED_VULNERABILITY path."""

    PB = "sqli_differential"

    def _hyp(self, target="https://t.example/item?id=7"):
        return SimpleNamespace(id="hyp-sqli", playbook=self.PB, target=target,
                               test_plan={})

    @pytest.mark.asyncio
    async def test_no_query_params_inconclusive(self):
        eng = ve.ValidationEngine(mcp_registry=None)
        out = await eng.validate(
            SimpleNamespace(id="h", playbook=self.PB,
                            target="https://t.example/no-params"))
        assert out.validation_state == ce.INCONCLUSIVE

    @pytest.mark.asyncio
    async def test_tooling_unavailable_honest_inconclusive(self):
        eng = ve.ValidationEngine(mcp_registry=None)
        out = await eng.validate(self._hyp())
        assert out.validation_state == ce.INCONCLUSIVE
        assert "unavailable" in out.explanation

    @pytest.mark.asyncio
    async def test_sqlmap_injectable_validates(self):
        reg = MagicMock()
        reg.execute_tool = AsyncMock(return_value=SimpleNamespace(
            status="success",
            result={"output": "parameter 'id' is INJECTABLE, dbms: MySQL"}))
        eng = ve.ValidationEngine(mcp_registry=reg)
        out = await eng.validate(self._hyp())
        assert out.validation_state == ce.VALIDATED
        assert out.evidence["tool"] == "sqlmap"

    @pytest.mark.asyncio
    async def test_sqlmap_clean_rejects(self):
        reg = MagicMock()
        reg.execute_tool = AsyncMock(return_value=SimpleNamespace(
            status="success", result={"output": "all tested parameters not injectable"}))
        eng = ve.ValidationEngine(mcp_registry=reg)
        out = await eng.validate(self._hyp())
        assert out.validation_state == ce.REJECTED

    @pytest.mark.asyncio
    async def test_scope_flows_to_registry_gate(self):
        reg = MagicMock()
        reg.execute_tool = AsyncMock(return_value=SimpleNamespace(
            status="success", result={"output": "not injectable"}))
        from ai_osop.core.models import ScopeDefinition

        sd = ScopeDefinition(engagement_id="e", domains=["safe.example"],
                             ips=["10.0.0.0/8"])
        eng = ve.ValidationEngine(mcp_registry=reg)
        h = self._hyp(target="https://evil.example/x?id=1")
        h._scope = sd
        out = await eng.validate(h, scope=sd)
        assert out.validation_state == ce.REJECTED  # scope refusal -> REJECTED
        reg.execute_tool.assert_not_called()


class TestSSRFOast:
    """EXPLOIT-PLAYBOOKS-002: OOB SSRF confirmation via oast-mcp."""

    PB = "ssrf_oast"

    def _hyp(self, target="https://t.example/fetch?url=https://internal.local"):
        return SimpleNamespace(id="hyp-ssrf", playbook=self.PB, target=target,
                               test_plan={})

    @pytest.mark.asyncio
    async def test_no_registry_inconclusive(self):
        eng = ve.ValidationEngine(mcp_registry=None)
        out = await eng.validate(self._hyp())
        assert out.validation_state == ce.INCONCLUSIVE

    @pytest.mark.asyncio
    async def test_callback_received_validates(self):
        reg = MagicMock()
        conn = MagicMock()
        conn._circuit_open = False
        tool_obj = SimpleNamespace(tool_name="generate_payload")
        poll_obj = SimpleNamespace(tool_name="poll_interactions")
        conn.list_tools = AsyncMock(return_value=[tool_obj, poll_obj])
        reg.get_server.return_value = conn

        call_count = [0]
        async def _execute_tool(sid, tool, params, **kw):
            call_count[0] += 1
            if "generate" in tool or "payload" in tool:
                return SimpleNamespace(status="success",
                                       result={"url": "https://oast.example/abc123"})
            # poll
            if call_count[0] >= 3:  # callback arrives on second poll
                return SimpleNamespace(status="success", result={
                    "interactions": [{"source": "target", "protocol": "http"}]})
            return SimpleNamespace(status="success", result={"interactions": []})
        reg.execute_tool = _execute_tool

        eng = ve.ValidationEngine(mcp_registry=reg)
        with patch.object(eng, "_fetch", AsyncMock(return_value=MagicMock())):
            out = await eng.validate(self._hyp())
        assert out.validation_state == ce.VALIDATED
        assert "callback received" in out.explanation.lower()
        assert out.evidence["interactions"] >= 1

    @pytest.mark.asyncio
    async def test_no_callback_rejects(self):
        reg = MagicMock()
        conn = MagicMock()
        conn._circuit_open = False
        conn.list_tools = AsyncMock(return_value=[
            SimpleNamespace(tool_name="generate_payload"),
            SimpleNamespace(tool_name="poll_interactions"),
        ])
        reg.get_server.return_value = conn

        async def _exec(sid, tool, params, **kw):
            if "generate" in tool:
                return SimpleNamespace(status="success",
                                       result={"url": "https://oast.example/xyz"})
            return SimpleNamespace(status="success", result={"interactions": []})
        reg.execute_tool = _exec

        # patch sleep to skip 30s wait
        import ai_osop.core.validation_engine as ve_mod
        with patch.object(eng_mod := ve, "ValidationEngine"):
            pass
        eng = ve.ValidationEngine(mcp_registry=reg)
        with patch.object(eng, "_fetch", AsyncMock(return_value=MagicMock())):
            with patch("asyncio.sleep", AsyncMock()):
                out = await eng.validate(self._hyp())
        assert out.validation_state == ce.REJECTED
        assert "no oob callback" in out.explanation.lower()

    @pytest.mark.asyncio
    async def test_no_url_param_inconclusive(self):
        reg = MagicMock()
        conn = MagicMock()
        conn._circuit_open = False
        conn.list_tools = AsyncMock(return_value=[
            SimpleNamespace(tool_name="generate_payload"),
            SimpleNamespace(tool_name="poll_interactions"),
        ])
        reg.get_server.return_value = conn
        gen_resp = SimpleNamespace(status="success",
                                   result={"url": "https://oast.example/tok"})
        reg.execute_tool = AsyncMock(return_value=gen_resp)

        eng = ve.ValidationEngine(mcp_registry=reg)
        # FIX: use a truly paramless URL so the fallback injector skips
        h = self._hyp(target="https://t.example/search")
        with patch.object(eng, "_fetch", AsyncMock()):
            out = await eng.validate(h)
        assert out.validation_state == ce.INCONCLUSIVE
        assert "no injectable" in out.explanation.lower()


class TestAuthzDifferential:
    """EXPLOIT-PLAYBOOKS-003: dual-session authorization differential."""

    PB = "authz_differential"

    def _hyp(self, target="https://t.example/admin/panel"):
        return SimpleNamespace(
            id="h", playbook=self.PB, target=target, test_plan={},
            auth_a={"headers": {"Cookie": "session=userA"}},
            auth_b={"headers": {"Cookie": "session=userB"}})

    def _resp(self, status=200, body=None, text=""):
        """SimpleNamespace response with deterministic .json()/.text."""
        r = SimpleNamespace(status_code=status, headers={},
                            json=lambda b=body: b or {},
                            text=text or str(body or ""),
                            content=(text or str(body or "")).encode())
        return r

    @pytest.mark.asyncio
    async def test_same_bodies_validates_broken_access(self):
        eng = ve.ValidationEngine()
        shared = {"users": ["admin", "user1"], "role": "admin"}
        eng._fetch = AsyncMock(side_effect=[
            self._resp(200, shared),   # session A sees admin data
            self._resp(200, shared),   # session B sees SAME admin data
        ])
        out = await eng.validate(self._hyp())
        assert out.validation_state == ce.VALIDATED
        assert "privilege escalation" in out.explanation.lower()

    @pytest.mark.asyncio
    async def test_403_rejects(self):
        eng = ve.ValidationEngine()
        eng._fetch = AsyncMock(side_effect=[
            self._resp(200, {"data": "ok"}),
            self._resp(403),
        ])
        out = await eng.validate(self._hyp())
        assert out.validation_state == ce.REJECTED

    @pytest.mark.asyncio
    async def test_different_bodies_rejects(self):
        eng = ve.ValidationEngine()
        eng._fetch = AsyncMock(side_effect=[
            self._resp(200, {"data": "admin_panel"}),
            self._resp(200, {"data": "user_home"}),
        ])
        out = await eng.validate(self._hyp())
        assert out.validation_state == ce.REJECTED
        assert "differ" in out.explanation.lower()

    @pytest.mark.asyncio
    async def test_404_rejects(self):
        eng = ve.ValidationEngine()
        eng._fetch = AsyncMock(side_effect=[
            self._resp(200, {}),
            self._resp(404),
        ])
        out = await eng.validate(self._hyp())
        assert out.validation_state == ce.REJECTED
