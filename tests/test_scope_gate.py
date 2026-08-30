"""Tests for the client-side MCP scope gate.

FIX (scope-gate-2026-08-24): the registry previously forwarded tool parameters
to remote servers without any client-side target validation. These tests pin
the fail-closed contract:
  * no target params          -> allowed
  * targets + valid scope     -> allowed
  * targets + out-of-scope    -> OutOfScopeError
  * targets + NO scope        -> OutOfScopeError for ACTIVE servers only
  * passive intel servers     -> never blocked, flagged when unscooped
  * malformed scope dict      -> refused (fail closed)
  * BaseAgent._validate_task  -> scope_check and dependency gates enforced
"""

from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.exceptions import AgentTaskFailed, OutOfScopeError
from ai_osop.core.models import ScopeDefinition, Task
from ai_osop.core.config import AgentType
from ai_osop.safety.scope_gate import (
    ScopeGate,
    ScopeDecision,
    check_tool_call,
    extract_targets,
)


def _scope(domains=None, ips=None) -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="eng-scope-test",
        domains=domains or ["target.example"],
        ips=ips or ["127.0.0.0/8"],
    )


@pytest.fixture
def gate():
    return ScopeGate()


class TestTargetExtraction:
    def test_extracts_url_values(self):
        params = {"url": "http://target.example/login", "depth": 2}
        assert extract_targets(params) == ["http://target.example/login"]

    def test_extracts_bare_domains_and_ips(self):
        params = {"domain": "target.example"}
        assert "target.example" in extract_targets(params)
        params2 = {"ip": "127.0.0.1"}
        assert "127.0.0.1" in extract_targets(params2)

    def test_deep_nested_and_lists(self):
        params = {
            "config": {"targets": ["target.example", "127.0.0.1"]},
            "meta": {"origin": "https://target.example/x"},
        }
        t = extract_targets(params)
        assert "target.example" in t and "127.0.0.1" in t
        assert "https://target.example/x" in t

    def test_urls_found_anywhere_in_tree(self):
        params = {"request": "GET http://evil.example/path HTTP/1.1"}
        assert any("evil.example" in t for t in extract_targets(params))

    def test_ignores_non_target_strings(self):
        # flags/wordlists must NOT be treated as attack targets
        params = {"wordlist": "/usr/share/words.txt", "flags": "-sV -p-"}
        assert extract_targets(params) == []

    def test_comma_separated_scalar(self):
        params = {"hosts": "a.target.example, b.target.example"}
        t = extract_targets(params)
        assert "a.target.example" in t and "b.target.example" in t


class TestScopeGateDecisions:
    def test_no_targets_allowed_without_scope(self, gate):
        d = gate.check("burp-mcp", "get_proxy_history", {"limit": 100}, None)
        assert d.allowed and d.reason == "no_target_parameters"

    def test_in_scope_target_allowed(self, gate):
        d = gate.check(
            "burp-mcp",
            "scan_target",
            {"url": "http://target.example/app"},
            _scope(),
        )
        assert d.allowed

    def test_out_of_scope_denied(self, gate):
        d = gate.check(
            "burp-mcp",
            "scan_target",
            {"url": "http://notinscope.example/"},
            _scope(),
        )
        assert not d.allowed
        assert "target_rejected" in d.reason

    def test_active_server_no_scope_fail_closed(self, gate):
        d = gate.check("recon-mcp", "nmap_scan", {"targets": ["10.9.9.9"]}, None)
        assert not d.allowed
        assert d.reason == "no_scope_bound_for_active_tool"

    def test_passive_server_unscooped_flagged_but_allowed(self, gate):
        d = gate.check("shodan-mcp", "shodan_lookup", {"domain": "anything.io"}, None)
        assert d.allowed
        assert d.unscooped_passive is True
        assert d.passive_server is True

    def test_malformed_scope_dict_fails_closed(self, gate):
        d = gate.check(
            "burp-mcp",
            "scan_target",
            {"url": "http://target.example/"},
            {"bogus_field": True},  # missing required engagement_id/domains
        )
        assert not d.allowed
        assert d.reason.startswith("scope_dict_invalid")

    def test_ip_outside_cidr_denied(self, gate):
        d = gate.check("recon-mcp", "nmap_scan", {"targets": ["8.8.8.8"]}, _scope())
        assert not d.allowed


class TestRegistryIntegration:
    @pytest.mark.asyncio
    async def test_execute_tool_raises_out_of_scope(self):
        """The registry funnel must raise OutOfScopeError (fail closed, loud)."""
        from ai_osop.mcp.protocol import MCPExecuteResponse, MCPRegistry

        registry = MCPRegistry()
        conn = MagicMock()
        conn.execute = AsyncMock(
            return_value=MCPExecuteResponse(request_id="r1", status="success", result={})
        )
        registry._servers["recon-mcp"] = conn

        with pytest.raises(OutOfScopeError) as exc:
            await registry.execute_tool(
                "recon-mcp", "nmap_scan", {"targets": ["203.0.113.5"]}, scope=None
            )
        assert "scope-gate" in str(exc.value)
        # The remote server must NEVER have been contacted.
        conn.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_execute_tool_passes_with_valid_scope(self):
        from ai_osop.mcp.protocol import MCPExecuteResponse, MCPRegistry

        registry = MCPRegistry()
        conn = MagicMock()
        conn.execute = AsyncMock(
            return_value=MCPExecuteResponse(request_id="r1", status="success", result={})
        )
        registry._servers["recon-mcp"] = conn

        resp = await registry.execute_tool(
            "recon-mcp",
            "nmap_scan",
            {"targets": ["127.0.0.1"]},
            scope=_scope().model_dump(),
        )
        assert resp.status == "success"
        conn.execute.assert_awaited_once()


def _make_agent_ctx(scope=None):
    """ctx whose SESSION STORE carries the engagement scope (authoritative source)."""
    ctx = MagicMock()
    ctx.session_memory = MagicMock()
    ctx.session_memory.load_task = AsyncMock(side_effect=lambda tid: None)
    if scope is None:
        ctx.session_memory.load_session_state = AsyncMock(return_value=None)
    else:
        sess = SimpleNamespace(scope=scope)
        ctx.session_memory.load_session_state = AsyncMock(return_value=sess)
    return ctx


def _make_task(dep_ids=None, scope_check=True) -> Task:
    return Task(
        id="task-t",
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-x",
        payload={"domain": "target.example"},
        dependencies=dep_ids or [],
        scope_check=scope_check,
    )


class TestBaseAgentValidateTask:
    """Regression: _validate_task was a `pass` stub (fake enforcement)."""

    @pytest.fixture
    def agent(self):
        from ai_osop.agents.recon_agent import ReconAgent

        r = ReconAgent.__new__(ReconAgent)
        r.ctx = None
        return r

    @pytest.mark.asyncio
    async def test_scope_check_requires_bound_scope(self, agent):
        agent.ctx = _make_agent_ctx(scope=None)
        with pytest.raises(AgentTaskFailed) as exc:
            await type(agent)._validate_task(agent, _make_task())
        assert "scope_check" in str(exc.value)

    @pytest.mark.asyncio
    async def test_missing_dependency_rejected(self, agent):
        agent.ctx = _make_agent_ctx(scope=_scope())
        with pytest.raises(AgentTaskFailed) as exc:
            await type(agent)._validate_task(agent, _make_task(dep_ids=["task-gone"]))
        assert "does not exist" in str(exc.value)

    @pytest.mark.asyncio
    async def test_incomplete_dependency_rejected(self, agent):
        agent.ctx = _make_agent_ctx(scope=_scope())
        dep = _make_task(dep_ids=[])
        dep.id = "task-dep"
        dep.status = "failed"
        agent.ctx.session_memory.load_task = AsyncMock(return_value=dep)
        with pytest.raises(AgentTaskFailed) as exc:
            await type(agent)._validate_task(agent, _make_task(dep_ids=["task-dep"]))
        assert "'failed'" in str(exc.value)

    @pytest.mark.asyncio
    async def test_happy_path_passes(self, agent):
        agent.ctx = _make_agent_ctx(scope=_scope())
        dep = _make_task(dep_ids=[])
        dep.id = "task-dep"
        dep.status = "completed"
        agent.ctx.session_memory.load_task = AsyncMock(return_value=dep)
        await type(agent)._validate_task(agent, _make_task(dep_ids=["task-dep"]))
