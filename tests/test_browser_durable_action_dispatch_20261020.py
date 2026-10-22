"""Narrow production source of original Browser Action authority.

These contract tests do not claim actual Chromium or PostgreSQL execution.
"""

from types import SimpleNamespace

import pytest

from ai_osop.mcp.protocol import (
    MCPRegistry,
    MCPToolDefinition,
    MCPToolParameter,
    SideEffectClass,
)
from ai_osop.memory.flow_mcp_action_dispatch import (
    MCPActionDenied,
    _safe_parameters,
)
from ai_osop.orchestrator.flow_mcp_action_executor import (
    FlowMCPActionDenied,
    _bounded_params,
    _tool_definition,
)


_PARAMETERS = {
    "url": "https://in-scope.example/reviewed",
    "action": "navigate",
    "user_label": "guest",
}


def _browser(**changed):
    definition = MCPToolDefinition(
        name="execute",
        description="Scoped signed Browser action",
        parameters=[
            MCPToolParameter(name="url", type="string", description="Target URL", required=False),
            MCPToolParameter(name="action", type="string", description="Action", required=True),
            MCPToolParameter(
                name="user_label", type="string", description="Identity", required=True
            ),
            MCPToolParameter(
                name="evidence_mode",
                type="string",
                description="Reviewed capture consent",
                required=False,
            ),
        ],
        returns={"status": "string", "result": "object"},
        side_effect_class=SideEffectClass.RECON_ACTIVE,
        requires_approval=True,
        scope_check=True,
    )
    return definition.model_copy(update=changed)


def _registry(definition):
    registry = MCPRegistry()
    registry._servers["browser-mcp"] = SimpleNamespace(
        server_id="browser-mcp",
        _initialized=True,
        _tools={"execute": definition},
        get_circuit_state=lambda: "closed",
    )
    return registry


def test_only_exact_signed_browser_navigation_schema_admitted():
    declaration = _tool_definition(_registry(_browser()), "browser-mcp", "execute")
    params = _bounded_params(_PARAMETERS, declaration)
    assert _safe_parameters(params, declaration, server_id="browser-mcp") == params
    captured = {**params, "evidence_mode": "screenshot_dom_har"}
    assert _safe_parameters(captured, declaration, server_id="browser-mcp") == captured
    with pytest.raises(MCPActionDenied):
        _safe_parameters(params, declaration)  # No extra permissions for other services


@pytest.mark.parametrize(
    "changes",
    [
        {"action": "click"},
        {"action": "eval"},
        {"user_label": "../../private"},
        {"user_label": "private cookie"},
        {"url": "https://in-scope.example/?session=secret"},
        {"url": "https://other@in-scope.example/"},
        {"url": "https://in-scope.example/#secret"},
        {"url": "http://in-scope.example/\nInjected: header"},
        {"url": "file:///etc/passwd"},
        {"engagement_id": "eng-forged"},
        {"storage_state": {"cookies": []}},
        {"cookie": "session"},
        {"selector": "a"},
        {"expression": "document.cookie"},
        {"evidence_mode": "screenshot"},
        {"evidence_mode": "all"},
    ],
)
def test_all_non_navigation_or_unapproved_browser_parameters_denied(changes):
    with pytest.raises((FlowMCPActionDenied, MCPActionDenied)):
        _safe_parameters({**_PARAMETERS, **changes}, _browser(), server_id="browser-mcp")


@pytest.mark.parametrize(
    "changed",
    [
        {"requires_approval": False},
        {"scope_check": False},
        {"side_effect_class": SideEffectClass.READ_ONLY},
        {"side_effect_class": SideEffectClass.INVASIVE_EXPLOIT},
        {"parameters": [MCPToolParameter(name="url", type="string", description="Incomplete")]},
    ],
)
def test_browser_declaration_must_match_exact_current_scope_and_review(changed):
    with pytest.raises(FlowMCPActionDenied):
        _tool_definition(_registry(_browser(**changed)), "browser-mcp", "execute")


def test_browser_exception_does_not_enable_arbitrary_execute_on_other_services():
    registry = _registry(_browser())
    registry._servers["recon-mcp"] = SimpleNamespace(
        server_id="recon-mcp",
        _initialized=True,
        _tools={"execute": _browser()},
        get_circuit_state=lambda: "closed",
    )
    with pytest.raises(FlowMCPActionDenied):
        _tool_definition(registry, "recon-mcp", "execute")
