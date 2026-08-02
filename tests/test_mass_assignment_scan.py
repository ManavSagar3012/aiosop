"""Mass-assignment scan hardening tests (roadmap Phase 2.1).

The scan previously treated *reflection* (the injected value echoed in the response) as
confirmation — a classic triager-rejected false positive, since many APIs echo the whole
request body or set fields by default. The hardened scan adds a baseline CONTROL request
and only counts a field as attacker-controlled when the value appears after injection but
was ABSENT in the control, and it distinguishes persisted (independent read-back →
validated) from merely reflected (create-response echo → manual-confirm lead, MEDIUM).

All hermetic: httpx.AsyncClient is monkeypatched with a fake that returns queued bodies
in call order — no network.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents import vuln_agent as va
from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.core.config import Severity


class _FakeResp:
    def __init__(self, text):
        self.text = text
        self.status_code = 200


def _fake_client_factory(bodies):
    """Return an httpx.AsyncClient stand-in that yields ``bodies`` in call order."""
    queue = list(bodies)

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, **kw):
            return _FakeResp(queue.pop(0))

        async def get(self, url, **kw):
            return _FakeResp(queue.pop(0))

    return _FakeClient


def _agent():
    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)  # skip heavy __init__
    agent.ctx = SimpleNamespace(
        graph_memory=SimpleNamespace(add_vulnerability=AsyncMock()),
        current_task=None,
    )
    agent.findings = {}
    return agent


@pytest.mark.asyncio
async def test_persisted_via_independent_readback_is_validated_high(monkeypatch):
    """Injected value absent in control read-back, present in injected read-back -> persisted."""
    # order: control request, control readback, injected request, injected readback
    monkeypatch.setattr(
        va.httpx,
        "AsyncClient",
        _fake_client_factory(['{"id":1}', '{"role":"user"}', '{"id":1}', '{"role":"admin"}']),
    )
    agent = _agent()
    res = await agent._execute_mass_assignment_scan(
        {
            "url": "https://x/api/users",
            "engagement_id": "e1",
            "base_body": {"name": "bob"},
            "inject": {"role": "admin"},
            "readback_url": "https://x/api/users/1",
        }
    )
    assert res["confirmed"] is True
    assert res["provenance"] == "persisted"
    assert res["manual_confirm_required"] is False
    vuln = next(iter(agent.findings.values()))
    assert vuln.validated is True
    assert vuln.severity == Severity.HIGH
    agent.ctx.graph_memory.add_vulnerability.assert_awaited_once()


@pytest.mark.asyncio
async def test_server_default_is_suppressed_by_baseline(monkeypatch):
    """Field present even in the control (server default / echo-all) -> NOT confirmed."""
    # control readback ALREADY has role=admin -> attacker did not control it.
    monkeypatch.setattr(
        va.httpx,
        "AsyncClient",
        _fake_client_factory(['{"id":1}', '{"role":"admin"}', '{"id":1}', '{"role":"admin"}']),
    )
    agent = _agent()
    res = await agent._execute_mass_assignment_scan(
        {
            "url": "https://x/api/users",
            "engagement_id": "e1",
            "base_body": {"name": "bob"},
            "inject": {"role": "admin"},
            "readback_url": "https://x/api/users/1",
        }
    )
    assert res["confirmed"] is False
    assert res["findings_count"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


@pytest.mark.asyncio
async def test_reflected_only_is_manual_confirm_medium(monkeypatch):
    """No independent read-back; create response echoes the field -> reflected lead."""
    # order (no readback_url): control request, injected request
    monkeypatch.setattr(
        va.httpx,
        "AsyncClient",
        _fake_client_factory(['{"id":1}', '{"id":1,"role":"admin"}']),
    )
    agent = _agent()
    res = await agent._execute_mass_assignment_scan(
        {
            "url": "https://x/api/users",
            "engagement_id": "e1",
            "base_body": {"name": "bob"},
            "inject": {"role": "admin"},
        }
    )
    assert res["confirmed"] is True
    assert res["provenance"] == "reflected"
    assert res["manual_confirm_required"] is True
    vuln = next(iter(agent.findings.values()))
    assert vuln.validated is False
    assert vuln.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_clean_endpoint_not_confirmed(monkeypatch):
    """Injected field neither reflected nor persisted -> clean."""
    monkeypatch.setattr(
        va.httpx,
        "AsyncClient",
        _fake_client_factory(['{"id":1}', '{"id":1}']),
    )
    agent = _agent()
    res = await agent._execute_mass_assignment_scan(
        {
            "url": "https://x/api/users",
            "engagement_id": "e1",
            "base_body": {"name": "bob"},
            "inject": {"role": "admin"},
        }
    )
    assert res["confirmed"] is False
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


@pytest.mark.asyncio
async def test_finding_carries_request_and_response_evidence(monkeypatch):
    """The persisted finding must embed real request + response artifacts so a
    triager can reproduce it without re-running the scan. Before this, findings
    carried only the semantic result (accepted_fields) and scored 0 evidence."""
    # order (no readback_url): control request, injected request (echoes role)
    monkeypatch.setattr(
        va.httpx,
        "AsyncClient",
        _fake_client_factory(['{"id":1}', '{"id":1,"role":"admin"}']),
    )
    agent = _agent()
    await agent._execute_mass_assignment_scan(
        {
            "url": "https://x/api/users",
            "engagement_id": "e1",
            "base_body": {"name": "bob"},
            "inject": {"role": "admin"},
        }
    )
    vuln = next(iter(agent.findings.values()))
    ev = vuln.evidence[0]
    assert ev["request"]["method"] == "POST"
    assert ev["request"]["url"] == "https://x/api/users"
    assert ev["request"]["body"]["role"] == "admin"  # the injected payload
    assert ev["response"]["status"] == 200
    assert "admin" in ev["response"]["body_snippet"]  # response demonstrates acceptance
    assert ev["response"]["source"] == "create_response"


@pytest.mark.asyncio
async def test_requires_url(monkeypatch):
    from ai_osop.core.exceptions import AgentException

    agent = _agent()
    with pytest.raises(AgentException):
        await agent._execute_mass_assignment_scan({"engagement_id": "e1"})
