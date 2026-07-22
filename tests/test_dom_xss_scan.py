"""Unit tests for DOM-based XSS detection."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.agents.vuln_agent import _DOM_XSS_SCAN_JS, VulnAnalysisAgent
from ai_osop.core.models import Vulnerability

_PATCH_APP = "ai_osop.core.applicability.ApplicabilityEngine.is_applicable"


def test_dom_xss_scan_js_probe_is_valid():
    """Module-level probe constant contains sink patterns."""
    assert isinstance(_DOM_XSS_SCAN_JS, str) and len(_DOM_XSS_SCAN_JS) > 50
    assert "innerHTML" in _DOM_XSS_SCAN_JS
    assert "document\.write" in _DOM_XSS_SCAN_JS or "document.write" in _DOM_XSS_SCAN_JS
    assert "eval" in _DOM_XSS_SCAN_JS
    assert "location" in _DOM_XSS_SCAN_JS


def _make_agent():
    a = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    a.ctx = MagicMock()
    a.ctx.current_task = MagicMock()
    a.ctx.current_task.id = "task-test"
    a.ctx.graph_memory.log_skipped_scan = AsyncMock()
    a.ctx.graph_memory.add_vulnerability = AsyncMock(return_value="vuln-test")
    a.ctx.session_memory.get_session_state_by_engagement_id = AsyncMock(return_value=None)
    a.browser_adapter = AsyncMock()
    a.browser_adapter.navigate = AsyncMock()
    a.browser_adapter.execute_action = AsyncMock(return_value={"result": []})
    a.browser_adapter.initialize = AsyncMock()
    a._inject_payload = MagicMock(side_effect=lambda u, p, param: u)
    a._confirm_xss_execution = AsyncMock(return_value=False)
    a.findings = {}
    a.logger = MagicMock()
    return a


@pytest.mark.asyncio
async def test_dom_xss_scan_skipped_via_applicability():
    agent = _make_agent()
    with patch(_PATCH_APP, return_value={"applicable": False, "reason": "Skipped"}):
        result = await agent._execute_dom_xss_scan(
            {"url": "http://test.com/page", "engagement_id": "eng-test"}
        )
    assert result["status"] == "success" and result["confirmed"] is False
    assert result["findings_count"] == 0 and "Skipped" in result.get("reason", "")
    agent.ctx.graph_memory.log_skipped_scan.assert_awaited_once()


@pytest.mark.asyncio
async def test_dom_xss_scan_no_url_raises():
    agent = _make_agent()
    with patch(_PATCH_APP, return_value={"applicable": True, "reason": ""}):
        with pytest.raises(Exception, match="dom_xss_scan task requires"):
            await agent._execute_dom_xss_scan({"engagement_id": "eng-test"})


@pytest.mark.asyncio
async def test_dom_xss_scan_no_sinks_found():
    agent = _make_agent()
    agent.browser_adapter.execute_action = AsyncMock(return_value={"result": []})
    with patch(_PATCH_APP, return_value={"applicable": True, "reason": ""}):
        result = await agent._execute_dom_xss_scan(
            {"url": "http://test.com/page", "engagement_id": "eng-test"}
        )
    assert result["status"] == "success" and result["confirmed"] is False
    assert result["findings_count"] == 0
    assert "No DOM sinks detected" in result.get("reason", "")


@pytest.mark.asyncio
async def test_dom_xss_scan_confirmed_via_execution():
    agent = _make_agent()
    agent.browser_adapter.execute_action = AsyncMock(
        return_value={
            "result": [
                {"sink": "innerHTML", "line": 15, "preview": "el.innerHTML = params.q"},
                {"sink": "URL_source_available", "params": ["q"], "hash": "none"},
            ]
        }
    )
    agent._confirm_xss_execution = AsyncMock(return_value=True)
    with patch(_PATCH_APP, return_value={"applicable": True, "reason": ""}):
        result = await agent._execute_dom_xss_scan(
            {"url": "http://test.com/page?q=test", "engagement_id": "eng-test"}
        )
    assert result["status"] == "success" and result["confirmed"] is True
    assert result["findings_count"] == 1
    assert result.get("injection_point") is not None
    agent.ctx.graph_memory.add_vulnerability.assert_awaited_once()
    args = agent.ctx.graph_memory.add_vulnerability.await_args
    persisted = args[0][0] if args.args else args.kwargs.get("vuln")
    assert isinstance(persisted, Vulnerability)
    assert persisted.validated is True
    assert persisted.title.startswith("DOM-based Cross-Site Scripting")


@pytest.mark.asyncio
async def test_dom_xss_scan_browser_init_failure_continues():
    agent = _make_agent()
    agent.browser_adapter.initialize = AsyncMock(side_effect=Exception("Browser init timeout"))
    agent.browser_adapter.navigate = AsyncMock()
    agent.browser_adapter.execute_action = AsyncMock(
        return_value={
            "result": [{"sink": "innerHTML", "line": 15, "preview": "el.innerHTML = params.q"}]
        }
    )
    agent._confirm_xss_execution = AsyncMock(return_value=True)
    with patch(
        "ai_osop.core.applicability.ApplicabilityEngine.is_applicable",
        return_value={"applicable": True, "reason": ""},
    ):
        result = await agent._execute_dom_xss_scan(
            {"url": "http://test.com/page?q=test", "engagement_id": "eng-test"}
        )
    assert result["status"] == "success"
    assert result["confirmed"] is True
    assert result["findings_count"] == 1


@pytest.mark.asyncio
async def test_dom_xss_scan_sinks_unreachable():
    agent = _make_agent()
    agent.browser_adapter.execute_action = AsyncMock(
        return_value={
            "result": [
                {"sink": "innerHTML", "line": 42, "preview": "el.innerHTML = location.hash"},
                {"sink": "URL_source_available", "params": ["q"], "hash": "present"},
            ]
        }
    )
    agent._confirm_xss_execution = AsyncMock(return_value=False)
    with patch(
        "ai_osop.core.applicability.ApplicabilityEngine.is_applicable",
        return_value={"applicable": True, "reason": ""},
    ):
        result = await agent._execute_dom_xss_scan(
            {"url": "http://test.com/page?q=test", "engagement_id": "eng-test"}
        )
    assert result["status"] == "success"
    assert result["confirmed"] is False
    assert result["findings_count"] == 0
    assert result.get("sinks_found", 0) == 2
