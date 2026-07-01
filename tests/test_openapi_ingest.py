"""Tests for P1.3 OpenAPI/Swagger ingestion."""
from ai_osop.core.openapi_ingest import (
    is_spec,
    parse_spec,
    spec_candidate_urls,
)

OPENAPI3 = {
    "openapi": "3.0.1",
    "servers": [{"url": "https://api.shop.com/v1"}],
    "paths": {
        "/users/{id}": {
            "parameters": [{"name": "id", "in": "path"}],
            "get": {
                "operationId": "getUser",
                "parameters": [{"name": "expand", "in": "query"}],
            },
        },
        "/login": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"properties": {"email": {}, "password": {}}}
                        }
                    }
                }
            }
        },
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "host": "api.shop.com",
    "basePath": "/v2",
    "schemes": ["https"],
    "paths": {
        "/search": {
            "get": {"parameters": [{"name": "q", "in": "query"}, {"name": "sort", "in": "query"}]}
        }
    },
}


def test_is_spec():
    assert is_spec(OPENAPI3)
    assert is_spec(SWAGGER2)
    assert not is_spec({"random": "json"})
    assert not is_spec("not a dict")


def test_parse_openapi3_paths_params_and_body():
    eps = parse_spec(OPENAPI3)
    by_path = {(e["method"], e["path"]): e for e in eps}

    # path + operation params merge
    user = by_path[("GET", "/users/{id}")]
    assert user["url"] == "https://api.shop.com/v1/users/{id}"
    assert user["parameters"] == ["expand", "id"]
    assert user["operation_id"] == "getUser"

    # request body field names captured
    login = by_path[("POST", "/login")]
    assert login["body_keys"] == ["email", "password"]


def test_parse_swagger2_host_basepath():
    eps = parse_spec(SWAGGER2)
    assert len(eps) == 1
    e = eps[0]
    assert e["method"] == "GET"
    assert e["url"] == "https://api.shop.com/v2/search"
    assert e["parameters"] == ["q", "sort"]


def test_base_url_override():
    eps = parse_spec(OPENAPI3, base_url="http://localhost:3000")
    assert eps[0]["url"].startswith("http://localhost:3000/")


def test_spec_candidate_urls():
    urls = spec_candidate_urls("http://localhost:3000")
    assert "http://localhost:3000/openapi.json" in urls
    assert "http://localhost:3000/v3/api-docs" in urls
    assert all(u.startswith("http://localhost:3000/") for u in urls)


def test_parse_handles_garbage():
    assert parse_spec({}) == []
    assert parse_spec({"paths": "nope"}) == []
    assert parse_spec("not a dict") == []
