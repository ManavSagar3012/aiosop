"""Production mount and unauthenticated-denial contract for inert folder CRUD.

The metadata API must never replace immutable artifact admission, MCP approval,
or signed report final release. These checks start no app or test database.
"""

from fastapi.testclient import TestClient


FLOW = "flow-resource-folder-integration"
EXPECTED = {
    ("GET", "/flows/{flow_id}/resource-folders"),
    ("POST", "/flows/{flow_id}/resource-folders"),
}


def test_resource_folder_routes_are_registered_in_real_fastapi_app():
    from ai_osop.api.main import app

    routes = {
        (method, route.path) for route in app.routes for method in getattr(route, "methods", ())
    }
    assert EXPECTED <= routes
    # The newly persisted metadata catalog cannot replace the existing inert
    # SHA-verified manifest and signed Task eligibility preflight contracts.
    assert ("GET", "/flows/{flow_id}/resource-aliases") in routes
    assert ("POST", "/flows/{flow_id}/resource-aliases/task-preview") in routes
    assert ("POST", "/flows/{flow_id}/tool-proposals") in routes


def test_anonymous_operator_cannot_read_or_write_resource_folders():
    from ai_osop.api.main import app

    # No lifespan context: never initialize/connect the application databases.
    client = TestClient(app, raise_server_exceptions=False)
    for method in ("GET", "POST"):
        response = client.request(method, f"/flows/{FLOW}/resource-folders")
        assert response.status_code in {401, 403, 422}, response.text


def test_folder_routers_are_never_methods_on_task_dispatch_paths():
    from ai_osop.api.main import app

    folder_routes = [
        route for route in app.routes if route.path == "/flows/{flow_id}/resource-folders"
    ]
    assert folder_routes
    assert all("/dispatch" not in route.path for route in folder_routes)
    assert not any("DELETE" in getattr(route, "methods", ()) for route in folder_routes)
