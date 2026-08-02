"""Browser-interaction discovery: _execute_authentication surfaces the auth POST.

Driving a login submit fires the auth XHR (e.g. POST /rest/user/login) which the
recorded HAR captures with its body params; flush_har + extract then persists it
as a scannable Endpoint. These lock two review-hardened behaviours:
  * a real login form (password field) is required before filling+submitting, so
    the guest recon probe never submits an unrelated form on a non-login page;
  * discovery (flush_har -> _extract_and_persist_har) runs regardless.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.workflow_agent import PlaywrightAgent


def _agent(form_selectors):
    agent = PlaywrightAgent.__new__(PlaywrightAgent)
    agent.ctx = SimpleNamespace(session_id="eng-1", graph_memory=AsyncMock(), scope=None)

    async def fake_execute_action(action=None, params=None, **kw):
        expr = (params or {}).get("expression", "")
        if "querySelectorAll" in expr:  # the form-finder introspection
            return {"result": form_selectors}
        return {"result": True}

    agent.browser_adapter = SimpleNamespace(
        navigate=AsyncMock(),
        execute_action=AsyncMock(side_effect=fake_execute_action),
        capture_state=AsyncMock(return_value={"url": "http://x/#/login", "cookies": []}),
        flush_har=AsyncMock(return_value={"path": "/tmp/x.har", "exists": True}),
    )
    agent._extract_and_persist_har = AsyncMock(return_value={"endpoints_persisted": 1})
    return agent


def _payload():
    return {
        "login_url": "http://x/#/login",
        "credentials": {"email": "probe@example.invalid", "password": "probe"},
        "user_label": "recon_probe",
    }


def _actions(agent):
    return [c.kwargs.get("action") for c in agent.browser_adapter.execute_action.call_args_list]


@pytest.mark.asyncio
async def test_login_form_present_fills_submits_and_discovers():
    agent = _agent(
        {"user_selector": "#email", "pass_selector": "#password", "submit_selector": "#loginButton"}
    )
    res = await agent._execute_authentication(_payload())
    actions = _actions(agent)
    assert actions.count("fill") == 2  # email + password filled
    assert "eval" in actions  # JS submit fired
    agent._extract_and_persist_har.assert_awaited_once()  # discovery ran
    assert res["endpoints_persisted"] == 1


@pytest.mark.asyncio
async def test_no_password_field_skips_submit_but_still_discovers():
    # a non-login landing page: form-finder finds no password field
    agent = _agent({"user_selector": "#q", "pass_selector": None, "submit_selector": None})
    await agent._execute_authentication(_payload())
    actions = _actions(agent)
    assert "fill" not in actions  # never fills/submits a non-login form
    agent.browser_adapter.flush_har.assert_awaited_once()
    agent._extract_and_persist_har.assert_awaited_once()  # still extracts nav XHR
