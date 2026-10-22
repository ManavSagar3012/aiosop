"""Read-only signed preflight is a distinct mounted operator route, not dispatch."""

from fastapi.testclient import TestClient


def test_real_app_mounts_immutable_action_preflight_separately_from_dispatch():
    from ai_osop.api.main import app

    routes = {
        (method, route.path) for route in app.routes for method in getattr(route, "methods", ())
    }
    assert ("GET", "/flows/{flow_id}/mcp-actions/{action_id}/preflight") in routes
    assert ("POST", "/flows/{flow_id}/mcp-actions/{action_id}/dispatch") in routes
    assert ("POST", "/flows/{flow_id}/tool-proposals") in routes


def test_anonymous_cannot_query_signed_action_eligibility():
    from ai_osop.api.main import app

    client = TestClient(app, raise_server_exceptions=False)
    result = client.get(
        "/flows/flow-eligibility/mcp-actions/action-" + "a" * 32 + "/preflight",
        params={
            "expected_engagement_id": "eng-eligibility",
            "expected_revision": 1,
            "expected_authorization_version": 1,
            "task_id": "task-eligibility",
            "subtask_id": "subtask-eligibility",
            "server_id": "browser_mcp",
            "tool_name": "inspect",
        },
    )
    assert result.status_code in {401, 403}


def test_action_preflight_is_get_only_and_does_not_mint_approval():
    from ai_osop.api.main import app

    paths = [
        route
        for route in app.routes
        if route.path == "/flows/{flow_id}/mcp-actions/{action_id}/preflight"
    ]
    assert len(paths) == 1
    assert paths[0].methods == {"GET"}
