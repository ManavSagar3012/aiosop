"""The deployed API mounts credential *references*, never provider activation.

These are anonymous boundary/route checks against the real FastAPI app; the
PostgreSQL lifecycle itself is tested separately without calling any provider.
"""

from fastapi.testclient import TestClient


PATH = "/flows/flow-provider-ref-check/provider-credential-profile-refs"
FENCE = {
    "expected_engagement_id": "eng-provider-ref-check",
    "expected_revision": 3,
    "expected_authorization_version": 2,
    "expected_authorization_id": "auth-provider-ref-check",
    "expected_authorization_sha256": "e" * 64,
}


def test_actual_app_mounts_reference_workflow_separately_from_policy_intent():
    from ai_osop.api.main import app

    registered = {
        (route.path, frozenset(route.methods))
        for route in app.routes
        if getattr(route, "methods", None)
    }
    assert ("/flows/{flow_id}/provider-credential-profile-refs", frozenset({"GET"})) in registered
    assert ("/flows/{flow_id}/provider-credential-profile-refs", frozenset({"POST"})) in registered
    assert (
        "/flows/{flow_id}/provider-credential-profile-refs/{ref_id}",
        frozenset({"GET"}),
    ) in registered
    assert (
        "/flows/{flow_id}/provider-route-policy-reviews",
        frozenset({"GET"}),
    ) in registered


def test_real_app_denies_anonymous_reference_reads_and_writes():
    from ai_osop.api.main import app

    client = TestClient(app, raise_server_exceptions=False)
    responses = (
        client.get(PATH, params=FENCE),
        client.get(PATH + "/pcref-" + "a" * 32, params=FENCE),
        client.post(
            PATH,
            params=FENCE,
            json={
                "operation": "register",
                "operation_id": "pcop-" + "f" * 32,
                "provider": "openai",
                "slot": "primary",
                "policy_review_id": "provider-review-" + "b" * 32,
                "policy_sha256": "c" * 64,
            },
        ),
    )
    assert all(response.status_code in {401, 403} for response in responses)


def test_reference_routes_do_not_offer_put_delete_or_dispatch():
    from ai_osop.api.main import app

    registered = [
        route
        for route in app.routes
        if route.path.startswith("/flows/{flow_id}/provider-credential-profile-refs")
    ]
    assert registered
    assert all(route.methods <= {"GET", "POST"} for route in registered)
    assert all(
        "dispatch" not in route.path and "activate" not in route.path for route in registered
    )
