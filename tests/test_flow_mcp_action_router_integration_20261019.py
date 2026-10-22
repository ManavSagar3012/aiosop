"""Separate signed action API must not weaken the inert MCP review route."""

from fastapi.testclient import TestClient


def test_real_app_mounts_distinct_inert_review_and_executable_action_routes():
    from ai_osop.api.main import app

    routes = {
        (method, route.path) for route in app.routes for method in getattr(route, "methods", ())
    }
    assert ("POST", "/flows/{flow_id}/tool-proposals") in routes
    assert ("POST", "/flows/{flow_id}/subtasks/{subtask_id}/dispatch") in routes
    for method, route in (
        ("GET", "/flows/{flow_id}/mcp-actions"),
        ("POST", "/flows/{flow_id}/mcp-actions"),
        ("GET", "/flows/{flow_id}/mcp-actions/{action_id}"),
        ("POST", "/flows/{flow_id}/mcp-actions/{action_id}/dispatch"),
    ):
        assert (method, route) in routes


def test_anonymous_cannot_prepare_list_read_or_dispatch_mcp_action():
    from ai_osop.api.main import app

    client = TestClient(app, raise_server_exceptions=False)
    root = "/flows/flow-anonymous-contract/mcp-actions"
    for method, path in (
        ("GET", root),
        ("POST", root),
        ("GET", f"{root}/action-{'a' * 32}"),
        ("POST", f"{root}/action-{'a' * 32}/dispatch"),
    ):
        response = client.request(method, path)
        assert response.status_code in {401, 403, 422}, response.text


def test_legacy_review_marker_remains_non_dispatchable():
    from inspect import getsource

    from ai_osop.api.routers.flows import dispatch_subtask

    source = getsource(dispatch_subtask)
    assert 'subtask.task_type == "operator_mcp_capability_review"' in source
    assert "cannot be dispatched" in source
