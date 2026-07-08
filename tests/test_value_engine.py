import pytest

from ai_osop.core.value_engine import score_endpoint


def test_score_endpoint_prioritization():
    # 1. Admin/Auth sensitive paths should score higher
    admin_score = score_endpoint("/admin/users", method="GET")
    assert admin_score["score"] > 20
    assert "admin" in admin_score["signals"] or "sensitive" in str(admin_score["signals"])

    # 2. Static assets should be penalized
    static_score = score_endpoint("/assets/logo.png", method="GET")
    assert static_score["score"] <= 10
    assert "static-asset" in static_score["signals"]

    # 3. State changing methods (+15)
    post_score = score_endpoint("/api/v1/update", method="POST")
    get_score = score_endpoint("/api/v1/update", method="GET")
    assert post_score["score"] == get_score["score"] + 15
    assert "method:POST" in post_score["signals"]

    # 4. Parameters (+12)
    with_params = score_endpoint("/api/data", has_params=True)
    no_params = score_endpoint("/api/data", has_params=False)
    assert with_params["score"] == no_params["score"] + 12
    assert "has-params" in with_params["signals"]


def test_score_endpoint_api_premium():
    # API endpoints should be prioritized
    api_score = score_endpoint("/api/v1/resource", method="GET")
    generic_score = score_endpoint("/resources", method="GET")
    assert api_score["score"] > generic_score["score"]
    assert "api-surface" in api_score["signals"]


def test_protected_resource_premium():
    # Protected resources should be prioritized
    protected_score = score_endpoint("/private", status_code=401)
    public_score = score_endpoint("/private", status_code=200)
    assert protected_score["score"] > public_score["score"]
    assert "protected:401" in protected_score["signals"]
