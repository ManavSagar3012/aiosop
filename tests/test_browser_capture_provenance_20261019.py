"""Signed WorkflowAgent browser capture: no provider, browser or application DB.

The real navigation method and capture pipeline exercise the MCP result shape,
then original signed Task and pinned-mount HAR readback from existing fixtures.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.adapters.browser_mcp import BrowserMCPAdapter
from ai_osop.agents.workflow_agent import PlaywrightAgent, _same_capture_origin
from ai_osop.core.exceptions import MCPException
from tests.test_authenticated_resource_paths import resources, workflow  # noqa: F401 - fixtures
from tests.test_authenticated_resource_sync_boundary import (
    _capture,
    trusted_sync as upstream_trusted_sync,  # noqa: F401 - registered pytest fixture
)


URL = "https://example.test/"
PAYLOAD = {"url": URL, "workflow_id": "wf-1", "user_label": "user-a"}


@pytest.fixture
def signed_capture_fixture(request):
    return request.getfixturevalue("upstream_trusted_sync")


def configure_real_capture(fx, monkeypatch, nav):
    _capture(fx)
    fx.agent._execute_navigation = PlaywrightAgent._execute_navigation.__get__(fx.agent)
    fx.agent._load_storage_state = AsyncMock(return_value={"cookies": [{"name": "sid", "value": "private"}]})
    fx.agent._capture_step_evidence = AsyncMock(
        side_effect=AssertionError("Signed HAR capture has no independent screenshot authorization")
    )
    fx.agent.observe = AsyncMock()
    fx.agent.browser_adapter.navigate = AsyncMock(return_value=nav)
    monkeypatch.setattr(
        "ai_osop.core.signed_replay_execution.authorize_replay_step",
        AsyncMock(return_value=None),
    )
    return fx.agent.browser_adapter.navigate


@pytest.mark.asyncio
async def test_signed_capture_requires_authoritative_navigation_then_har_digest_readback(
    signed_capture_fixture, monkeypatch,
):
    fx = signed_capture_fixture
    navigate = configure_real_capture(fx, monkeypatch, {
        "current_url": "https://EXAMPLE.test:443/landing?private=secret",
        "status_code": 200,
        "body": {"private_account_body": "must-never-return"},
        "headers": {"Authorization": "must-never-return"},
    })
    result = await fx.agent._execute_capture_authenticated_surface(dict(PAYLOAD))
    assert result["status"] == "success"
    assert result["resource_sha256"] == fx.receipt["resource_sha256"]
    assert result["endpoints_persisted"] == 1
    assert result["resource_origin"] == "operator_shared_tenant_mount"
    assert result["navigation_status"] == "success"
    assert "must-never-return" not in str(result)
    navigate.assert_awaited_once()
    fx.agent.browser_adapter.flush_har.assert_awaited_once()
    fx.graph.add_endpoint.assert_awaited_once()
    fx.agent._capture_step_evidence.assert_not_awaited()
    fx.agent.observe.assert_awaited_once()
    assert "private" not in str(fx.agent.observe.await_args)
    assert "must-never-return" not in str(fx.agent.observe.await_args)


@pytest.mark.asyncio
@pytest.mark.parametrize("nav", [
    {},
    {"current_url": "https://example.test/", "status_code": None},
    {"current_url": "https://example.test/", "status_code": True},
    {"current_url": "https://example.test/", "status_code": 0},
    {"current_url": "https://example.test/", "status_code": 401},
    {"current_url": "https://example.test/", "status_code": 403},
    {"current_url": "https://example.test/", "status_code": 500},
    {"current_url": "https://foreign.test/private?token=secret", "status_code": 200},
    {"current_url": "http://example.test/", "status_code": 200},
    {"current_url": "https://example.test:8443/", "status_code": 200},
    {"current_url": "https://someone:password@example.test/", "status_code": 200},
    {"current_url": "https://example.test:invalid/", "status_code": 200},
    {"current_url": "https://example.test/", "status_code": "200"},
])
async def test_signed_capture_remote_failure_or_cross_origin_never_flushes_or_persists(
    signed_capture_fixture, monkeypatch, nav,
):
    fx = signed_capture_fixture
    configure_real_capture(fx, monkeypatch, nav)
    result = await fx.agent._execute_capture_authenticated_surface(dict(PAYLOAD))
    assert result == {"status": "execution_unknown", "reason": "browser_navigation_unconfirmed"}
    fx.agent.browser_adapter.flush_har.assert_not_awaited()
    fx.agent._capture_step_evidence.assert_not_awaited()
    fx.agent.observe.assert_not_awaited()
    fx.graph.add_endpoint.assert_not_awaited()
    assert "password" not in str(result) and "secret" not in str(result)


@pytest.mark.asyncio
async def test_lost_mcp_ack_is_unknown_not_success_or_retry(signed_capture_fixture, monkeypatch):
    fx = signed_capture_fixture
    navigate = configure_real_capture(fx, monkeypatch, {})
    navigate.side_effect = TimeoutError("cookie=do-not-leak")
    result = await fx.agent._execute_capture_authenticated_surface(dict(PAYLOAD))
    assert result["status"] == "execution_unknown"
    assert result["reason"] == "browser_navigation_unconfirmed"
    assert "cookie" not in str(result)
    navigate.assert_awaited_once()
    fx.agent.browser_adapter.flush_har.assert_not_awaited()
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_capture_cannot_change_original_task_url_before_remote_effect(
    signed_capture_fixture, monkeypatch,
):
    fx = signed_capture_fixture
    navigate = configure_real_capture(fx, monkeypatch, {
        "current_url": URL, "status_code": 200,
    })
    result = await fx.agent._execute_capture_authenticated_surface(
        {**PAYLOAD, "url": "https://foreign.test/private"}
    )
    assert result["status"] == "partial"
    navigate.assert_not_awaited()
    fx.agent.browser_adapter.flush_har.assert_not_awaited()
    fx.graph.add_endpoint.assert_not_awaited()


@pytest.mark.parametrize("final", [
    "https://example.test:8443/p", "http://example.test/", "https://attacker.test/",
    "https://example.test:bogus/", "https://user:secret@example.test/",
    "https://example.test/#fragment", "javascript:alert(1)", None,
])
def test_origin_check_rejects_cross_origin_and_malformed_targets(final):
    assert not _same_capture_origin(URL, final)


@pytest.mark.asyncio
@pytest.mark.parametrize("result,status", [
    ({"status": "failed", "error": "secret=never-reflect"}, "success"),
    ({"success": False, "body": "secret=never-reflect"}, "success"),
    ({"isError": True, "headers": {"Authorization": "secret"}}, "success"),
    ({"status": "execution_unknown"}, "success"),
    (None, "success"),
    ({"current_url": URL}, "error"),
])
async def test_mcp_nested_failure_and_transport_error_do_not_become_success(result, status):
    registry = SimpleNamespace(execute_tool=AsyncMock(return_value=SimpleNamespace(
        status=status, result=result, error="secret=never-reflect",
    )))
    adapter = BrowserMCPAdapter(registry)
    with pytest.raises(MCPException) as error:
        await adapter.navigate(URL, engagement_id="eng-har-a")
    assert "secret" not in str(error.value)
    registry.execute_tool.assert_awaited_once()
