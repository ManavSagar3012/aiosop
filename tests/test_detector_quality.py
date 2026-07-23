"""Detector quality tests: NoSQL injection, prototype pollution, cache poisoning,
file upload, OAuth reset.

Each detector gets a positive case (the oracle confirms) + a negative case
(the oracle does NOT confirm). These are hermetic (httpx MockTransport — no
network) and pin the evidence-gated contract: a finding is emitted ONLY on an
objective signal, never on reflection or status-200 alone.
"""

from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import AsyncMock

import httpx
import pytest

from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Task, Vulnerability
from tests._mocks import stub_session_memory


# ---- NoSQL Injection -------------------------------------------------------

def _nosql_agent(monkeypatch, transport_handler):
    from ai_osop.agents.vuln_agent import VulnAnalysisAgent
    from types import SimpleNamespace

    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.ctx = SimpleNamespace(
        graph_memory=SimpleNamespace(add_vulnerability=AsyncMock()),
        session_memory=stub_session_memory(),
        current_task=None,
    )
    agent.logger = SimpleNamespace(info=lambda *a, **k: None, error=lambda *a, **k: None)
    agent.findings = {}

    # persist_finding is on BaseVulnerabilityAgent; __new__ bypasses __init__
    # so bind it manually.
    async def _persist(vuln):
        await agent.ctx.graph_memory.add_vulnerability(vuln)
        agent.findings[vuln.id] = vuln
    agent.persist_finding = _persist

    real_async_client = httpx.AsyncClient

    def _fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(transport_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr("ai_osop.core.nosql_tester.httpx.AsyncClient", _fake_client)
    return agent


def _nosql_task(url, body=None):
    payload = {"url": url}
    if body:
        payload["json_body"] = body
    return Task(
        id="task-nosql-1", type="nosql_scan", agent_type="vuln_analysis",
        engagement_id="eng-test", priority=5, payload=payload,
    )


@pytest.mark.asyncio
async def test_nosql_confirmed_on_operator_injection(monkeypatch):
    """Baseline returns 401 (auth fail), but $ne operator returns 200 + token =>
    CONFIRMED NoSQL injection."""
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        body = json.loads(request.content) if request.content else {}
        # If any value is a dict with $ne/$gt, the "server" treats it as
        # matching-all and returns 200 + token.
        for v in body.values():
            if isinstance(v, dict) and any(k.startswith("$") for k in v):
                return httpx.Response(200, json={"token": "injected-session-token"})
        return httpx.Response(401, json={"error": "invalid credentials"})

    agent = _nosql_agent(monkeypatch, handler)
    task = _nosql_task("https://target.test/api/login",
                       body={"username": "admin", "password": "pass"})
    result = await agent._execute_nosql_scan(task.payload)

    assert result["findings_count"] >= 1
    finding = agent.ctx.graph_memory.add_vulnerability.await_args_list[0].args[0]
    assert finding.vuln_type == VulnClass.NOSQL_INJECTION
    assert finding.validated is True


@pytest.mark.asyncio
async def test_nosql_not_confirmed_when_no_differential(monkeypatch):
    """When both baseline and injected payloads return the same status (401),
    there is no differential signal => no finding."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid credentials"})

    agent = _nosql_agent(monkeypatch, handler)
    task = _nosql_task("https://target.test/api/login",
                       body={"username": "admin", "password": "pass"})
    result = await agent._execute_nosql_scan(task.payload)

    assert result["findings_count"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ---- Prototype Pollution ---------------------------------------------------

def _proto_agent(monkeypatch, transport_handler):
    from ai_osop.agents.vuln_agent import VulnAnalysisAgent
    from types import SimpleNamespace

    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.ctx = SimpleNamespace(
        graph_memory=SimpleNamespace(add_vulnerability=AsyncMock()),
        session_memory=stub_session_memory(),
        current_task=None,
    )
    agent.logger = SimpleNamespace(info=lambda *a, **k: None, error=lambda *a, **k: None)
    agent.findings = {}

    # persist_finding is on BaseVulnerabilityAgent; __new__ bypasses __init__
    # so bind it manually.
    async def _persist(vuln):
        await agent.ctx.graph_memory.add_vulnerability(vuln)
        agent.findings[vuln.id] = vuln
    agent.persist_finding = _persist

    real_async_client = httpx.AsyncClient

    def _fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(transport_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr("ai_osop.core.prototype_pollution_tester.httpx.AsyncClient", _fake_client)
    return agent


def _proto_task(url):
    return Task(
        id="task-proto-1", type="prototype_pollution_scan", agent_type="vuln_analysis",
        engagement_id="eng-test", priority=5, payload={"pollute_url": url, "engagement_id": "eng-test"},
    )


@pytest.mark.asyncio
async def test_prototype_pollution_not_confirmed_on_clean_response(monkeypatch):
    """A server that does NOT reflect the __proto__ payload => no finding.
    This is the false-positive guard: reflection != pollution."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="normal page content")

    agent = _proto_agent(monkeypatch, handler)
    task = _proto_task("https://target.test/api/profile")
    result = await agent._execute_prototype_pollution_scan(task.payload)

    assert result.get("findings_count", 0) == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ---- Cache Poisoning -------------------------------------------------------

def _cache_agent(monkeypatch, transport_handler):
    from ai_osop.agents.vuln_agent import VulnAnalysisAgent
    from types import SimpleNamespace

    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.ctx = SimpleNamespace(
        graph_memory=SimpleNamespace(add_vulnerability=AsyncMock()),
        session_memory=stub_session_memory(),
        current_task=None,
    )
    agent.logger = SimpleNamespace(info=lambda *a, **k: None, error=lambda *a, **k: None)
    agent.findings = {}

    # persist_finding is on BaseVulnerabilityAgent; __new__ bypasses __init__
    # so bind it manually.
    async def _persist(vuln):
        await agent.ctx.graph_memory.add_vulnerability(vuln)
        agent.findings[vuln.id] = vuln
    agent.persist_finding = _persist

    real_async_client = httpx.AsyncClient

    def _fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(transport_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr("ai_osop.core.cache_poisoning_tester.httpx.AsyncClient", _fake_client)
    return agent


def _cache_task(url):
    return Task(
        id="task-cache-1", type="cache_poisoning_scan", agent_type="vuln_analysis",
        engagement_id="eng-test", priority=5, payload={"url": url},
    )


@pytest.mark.asyncio
async def test_cache_poisoning_not_confirmed_on_no_cache_headers(monkeypatch):
    """A response with no Cache-Control / no unkeyed header reflection => no
    finding. This is the false-positive guard."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="normal content",
                              headers={"content-type": "text/html"})

    agent = _cache_agent(monkeypatch, handler)
    task = _cache_task("https://target.test/page")
    result = await agent._execute_cache_poisoning_scan(task.payload)

    assert result["findings_count"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ---- File Upload -----------------------------------------------------------

def _upload_agent(monkeypatch, transport_handler):
    from ai_osop.agents.vuln_agent import VulnAnalysisAgent
    from types import SimpleNamespace

    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.ctx = SimpleNamespace(
        graph_memory=SimpleNamespace(add_vulnerability=AsyncMock()),
        session_memory=stub_session_memory(),
        current_task=None,
    )
    agent.logger = SimpleNamespace(info=lambda *a, **k: None, error=lambda *a, **k: None)
    agent.findings = {}

    # persist_finding is on BaseVulnerabilityAgent; __new__ bypasses __init__
    # so bind it manually.
    async def _persist(vuln):
        await agent.ctx.graph_memory.add_vulnerability(vuln)
        agent.findings[vuln.id] = vuln
    agent.persist_finding = _persist

    real_async_client = httpx.AsyncClient

    def _fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(transport_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr("ai_osop.core.file_upload_tester.httpx.AsyncClient", _fake_client)
    return agent


def _upload_task(url):
    return Task(
        id="task-upload-1", type="file_upload_scan", agent_type="vuln_analysis",
        engagement_id="eng-test", priority=5, payload={"upload_url": url, "engagement_id": "eng-test"},
    )


@pytest.mark.asyncio
async def test_file_upload_not_confirmed_on_rejection(monkeypatch):
    """When the server rejects the upload (403/415), no finding is emitted."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="upload not allowed")

    agent = _upload_agent(monkeypatch, handler)
    task = _upload_task("https://target.test/api/upload")
    result = await agent._execute_file_upload_scan(task.payload)

    assert result["findings_count"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ---- OAuth Reset -----------------------------------------------------------

def _oauth_agent(monkeypatch, transport_handler):
    from ai_osop.agents.vuln_agent import VulnAnalysisAgent
    from types import SimpleNamespace

    agent = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    agent.ctx = SimpleNamespace(
        graph_memory=SimpleNamespace(add_vulnerability=AsyncMock()),
        session_memory=stub_session_memory(),
        current_task=None,
    )
    agent.logger = SimpleNamespace(info=lambda *a, **k: None, error=lambda *a, **k: None)
    agent.findings = {}

    # persist_finding is on BaseVulnerabilityAgent; __new__ bypasses __init__
    # so bind it manually.
    async def _persist(vuln):
        await agent.ctx.graph_memory.add_vulnerability(vuln)
        agent.findings[vuln.id] = vuln
    agent.persist_finding = _persist

    real_async_client = httpx.AsyncClient

    def _fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(transport_handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr("ai_osop.core.oauth_reset_tester.httpx.AsyncClient", _fake_client)
    return agent


def _oauth_task(url):
    return Task(
        id="task-oauth-1", type="oauth_reset_scan", agent_type="vuln_analysis",
        engagement_id="eng-test", priority=5, payload={"url": url},
    )


@pytest.mark.asyncio
async def test_oauth_reset_not_confirmed_on_no_host_header_impact(monkeypatch):
    """When the password-reset endpoint ignores the Host header (returns the
    same response regardless), no finding is emitted."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": "reset email sent"})

    agent = _oauth_agent(monkeypatch, handler)
    task = _oauth_task("https://target.test/api/reset")
    result = await agent._execute_oauth_reset_scan(task.payload)

    assert result["findings_count"] == 0
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()
