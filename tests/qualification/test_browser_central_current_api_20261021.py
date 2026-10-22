"""Real mounted Browser current-authority ASGI route qualification, 2026-10-21.

Uses the actual route, original signed 0034/native evidence and current signed
ROE verifier. Only the app's FlowMCPActionStore construction is redirected to
an in-process SELECT-only FakePG fixture. No application DB, Playwright, target,
provider, Docker, original navigation, external network or replay is used.
"""

from __future__ import annotations

import base64
import copy
import json
from types import SimpleNamespace
from typing import Any, Optional

import httpx
import pytest
from fastapi import FastAPI

from ai_osop.api.routers import native_browser_current_authority as route
from ai_osop.memory.browser_source_authority import DOMAIN as SOURCE_DOMAIN
from ai_osop.orchestrator.browser_current_authority_readback import (
    EVIDENCE_DOMAIN,
    verify_current_browser_authority,
)
from tests.qualification.test_browser_current_central_state_join_20261021 import (
    _proof,
    current_case as signed_current_case,
)


PATH = "/native-browser/current-authority/readback"
HOST_TOKEN = "central-current-host-service-token-20261021"
SOURCE_TOKEN = "browser-source-service-token-20261021"
NATIVE_TOKEN = "native-browser-provider-token-20261021"
SM_SOURCE_TOKEN = "sourcemap-original-source-token-20261021"
SM_STATUS_TOKEN = "sourcemap-original-status-token-20261021"
TOKEN_ENVS = {
    "OSOP_BROWSER_CURRENT_AUTHORITY_SERVICE_TOKEN": HOST_TOKEN,
    "OSOP_BROWSER_SOURCE_SERVICE_TOKEN": SOURCE_TOKEN,
    "OSOP_BROWSER_MCP_BEARER_TOKEN": NATIVE_TOKEN,
    "OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN": SM_SOURCE_TOKEN,
    "OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN": SM_STATUS_TOKEN,
}


@pytest.fixture
def api_case(monkeypatch: pytest.MonkeyPatch, signed_current_case: dict[str, Any]) -> dict[str, Any]:
    """Full route+real central cryptography, never an external DB or adapter."""
    for name, value in TOKEN_ENVS.items():
        monkeypatch.setenv(name, value)
    memory = object()
    registry = object()
    monkeypatch.setitem(route.state, "orchestrator", SimpleNamespace(
        session_memory=memory, mcp_registry=registry,
    ))
    calls: list[tuple[Any, Any]] = []

    def injected_action_store(got_memory: Any, got_registry: Any) -> Any:
        calls.append((got_memory, got_registry))
        if got_memory is not memory or got_registry is not registry:
            raise AssertionError("Incorrect central authority dependency")
        return signed_current_case["readback"]._actions

    monkeypatch.setattr(route, "FlowMCPActionStore", injected_action_store)
    app = FastAPI()
    app.include_router(route.router)
    matched = [r for r in app.routes if getattr(r, "path", "") == PATH]
    assert len(matched) == 1 and "POST" in matched[0].methods
    return {**signed_current_case, "app": app, "calls": calls,
            "memory": memory, "registry": registry}


def _body(case: dict[str, Any]) -> dict[str, Any]:
    return {"source_proof": case["source"], "provider_evidence": case["evidence"]}


async def _request(
    case: dict[str, Any], *, body: Optional[bytes] = None,
    token: Optional[str] = HOST_TOKEN, base_url: str = "http://authority.test",
    client_host: str = "127.0.0.1", method: str = "POST",
    path: str = PATH, headers: Optional[list[tuple[str | bytes, str | bytes]]] = None,
) -> httpx.Response:
    supplied_headers = list(headers) if headers is not None else [("content-type", "application/json")]
    if token is not None:
        supplied_headers.append(("authorization", "Bearer " + token))
    if body is None:
        body = json.dumps(_body(case), separators=(",", ":")).encode("utf-8")
    # ASGITransport runs the real FastAPI endpoint in-process without binding
    # any socket; its client identity is synthetic and explicit here.
    transport = httpx.ASGITransport(app=case["app"], client=(client_host, 14567))
    async with httpx.AsyncClient(transport=transport, base_url=base_url,
                                 follow_redirects=False) as client:
        return await client.request(method, path, headers=supplied_headers, content=body)


def _unchanged(case: dict[str, Any]) -> None:
    assert case["calls"] == []
    assert case["pg"].statements == []


def _constructed_without_db(case: dict[str, Any]) -> None:
    assert case["calls"] == [(case["memory"], case["registry"])]
    assert case["pg"].statements == []


def _fail_closed(response: httpx.Response, status: int) -> None:
    assert response.status_code == status, response.text[:400]
    payload = response.json()
    assert "authority_proof" not in payload
    assert "automatic_retry_authorized" not in payload
    assert "source_proof" not in response.text
    assert "provider_evidence" not in response.text
    for secret in TOKEN_ENVS.values():
        assert secret not in response.text


@pytest.mark.asyncio
async def test_real_route_current_read_only_signature_and_no_target_effect(api_case: dict[str, Any]) -> None:
    result = await _request(api_case)
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    assert result.headers["x-content-type-options"] == "nosniff"
    value = result.json()
    assert set(value) == {
        "status", "authority_proof", "original_browser_artifact_bytes_verified",
        "independent_target_effect_verified", "automatic_retry_authorized",
        "production_release_certified",
    }
    assert value["status"] == "current_central_authority_only"
    assert value["original_browser_artifact_bytes_verified"] is False
    assert value["independent_target_effect_verified"] is False
    assert value["automatic_retry_authorized"] is False
    assert value["production_release_certified"] is False
    expected = {name: api_case["source"]["claims"][name] for name in (
        "request_id", "engagement_id", "flow_id", "task_id",
        "subtask_id", "action_id", "owner_id", "preflight_id",
    )}
    receipt = verify_current_browser_authority(value["authority_proof"], expected)
    assert receipt["authority_current"] is True
    assert receipt["artifact_bytes_verified"] is False
    assert receipt["target_effect_verified"] is False
    assert receipt["expires_at"] - receipt["checked_at"] == 5
    assert api_case["calls"] == [(api_case["memory"], api_case["registry"])]
    assert api_case["pg"].statements[0] == (
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    )
    assert len(api_case["pg"].statements) > 10
    assert all(s.startswith("SELECT ") for s in api_case["pg"].statements[1:])


@pytest.mark.asyncio
@pytest.mark.parametrize("variant,expected", [
    ("missing", 401), ("bad", 403), ("native", 403), ("source", 403),
    ("sourcemap-source", 403), ("sourcemap-status", 403),
    ("short", 403), ("long", 403),
])
async def test_dedicated_host_only_identity_and_provider_bearer_rejected(
    api_case: dict[str, Any], variant: str, expected: int,
) -> None:
    token = {
        "missing": None, "bad": "no-authority-match-and-not-the-service-key",
        "native": NATIVE_TOKEN, "source": SOURCE_TOKEN,
        "sourcemap-source": SM_SOURCE_TOKEN, "sourcemap-status": SM_STATUS_TOKEN,
        "short": "short", "long": "x" * 513, "nonascii": "é" * 40,
    }[variant]
    response = await _request(api_case, token=token)
    _fail_closed(response, expected)
    _unchanged(api_case)


@pytest.mark.asyncio
async def test_raw_nonascii_authorization_octets_denied_by_real_route(
    api_case: dict[str, Any],
) -> None:
    # HTTPX rejects non-ASCII Python string headers before ASGI. Explicit
    # header octets model an untrusted remote client reaching Starlette.
    incoming = [(b"content-type", b"application/json"),
                (b"authorization", b"Bearer " + ("é" * 40).encode("utf-8"))]
    result = await _request(api_case, token=None, headers=incoming)
    _fail_closed(result, 403)
    _unchanged(api_case)


@pytest.mark.asyncio
@pytest.mark.parametrize("collision_key", [
    "OSOP_BROWSER_SOURCE_SERVICE_TOKEN", "OSOP_BROWSER_MCP_BEARER_TOKEN",
    "OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", "OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN",
])
async def test_exact_service_token_collision_denied(
    api_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch, collision_key: str,
) -> None:
    monkeypatch.setenv(collision_key, HOST_TOKEN)
    result = await _request(api_case)
    _fail_closed(result, 403)
    _unchanged(api_case)


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_env", [
    "OSOP_BROWSER_CURRENT_AUTHORITY_SERVICE_TOKEN", "OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "OSOP_BROWSER_CURRENT_AUTHORITY_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_BROWSER_CURRENT_AUTHORITY_SIGNING_KID", "OSOP_BROWSER_CURRENT_AUTHORITY_PRIVATE_KEY_B64",
])
async def test_missing_dedicated_identity_or_independent_enrolled_keys_denied(
    api_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch, missing_env: str,
) -> None:
    monkeypatch.delenv(missing_env)
    response = await _request(api_case)
    _fail_closed(response, 403 if missing_env.endswith("SERVICE_TOKEN") else 503)
    if missing_env.endswith("SERVICE_TOKEN"):
        _unchanged(api_case)
    else:
        _constructed_without_db(api_case)


@pytest.mark.asyncio
async def test_unavailable_or_failing_real_read_only_db_fails_closed(
    api_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = api_case
    monkeypatch.setitem(route.state, "orchestrator", None)
    _fail_closed(await _request(case), 503)
    _unchanged(case)
    monkeypatch.setitem(route.state, "orchestrator", SimpleNamespace(
        session_memory=case["memory"], mcp_registry=case["registry"],
    ))
    case["rows"]["action"] = None
    _fail_closed(await _request(case), 503)
    assert len(case["calls"]) == 1
    assert case["pg"].statements[0].endswith("READ ONLY")
    assert all(stmt.startswith("SELECT ") for stmt in case["pg"].statements[1:])
    assert len([s for s in case["pg"].statements if s.startswith("SELECT ")]) == 1


@pytest.mark.asyncio
async def test_database_session_exception_cannot_escape_or_trigger_retry(
    api_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    def disconnected() -> Any:
        raise RuntimeError("internal-db-connection-secret-20261021")

    monkeypatch.setattr(api_case["readback"]._actions, "_sessions", disconnected)
    response = await _request(api_case)
    _fail_closed(response, 503)
    assert "internal-db-connection-secret" not in response.text
    _constructed_without_db(api_case)


@pytest.mark.asyncio
@pytest.mark.parametrize("authority_key", ["source_key", "native_key"])
async def test_central_signing_root_cannot_alias_provider_or_source(
    api_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch, authority_key: str,
) -> None:
    duplicated = api_case[authority_key]
    monkeypatch.setenv("OSOP_BROWSER_CURRENT_AUTHORITY_PRIVATE_KEY_B64",
                       base64.b64encode(duplicated.private_bytes_raw()).decode("ascii"))
    trusted = base64.b64encode(duplicated.public_key().public_bytes_raw()).decode("ascii")
    monkeypatch.setenv("OSOP_BROWSER_CURRENT_AUTHORITY_TRUSTED_PUBLIC_KEYS_JSON",
                       json.dumps({"centralReadback": trusted}))
    _fail_closed(await _request(api_case), 503)
    _constructed_without_db(api_case)


@pytest.mark.asyncio
@pytest.mark.parametrize("base_url,host,status", [
    ("http://authority.test", "192.0.2.14", 403),
    ("http://authority.test", "authority.test", 403),
    ("https://authority.test", "192.0.2.14", 200),
    ("http://authority.test", "::1", 200),
])
async def test_plaintext_must_be_numeric_loopback_but_https_has_bearer_fence(
    api_case: dict[str, Any], base_url: str, host: str, status: int,
) -> None:
    response = await _request(api_case, base_url=base_url, client_host=host)
    if status == 200:
        assert response.status_code == 200, response.text
        assert response.json()["automatic_retry_authorized"] is False
    else:
        _fail_closed(response, status)
        _unchanged(api_case)


@pytest.mark.asyncio
async def test_query_credentials_duplicate_authorization_and_method_deny(
    api_case: dict[str, Any],
) -> None:
    _fail_closed(await _request(api_case, path=PATH + "?token=secret"), 403)
    _fail_closed(await _request(api_case, headers=[
        ("content-type", "application/json"),
        ("authorization", "Bearer " + HOST_TOKEN),
    ]), 401)
    _fail_closed(await _request(api_case, method="GET"), 405)
    _unchanged(api_case)


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_body,status", [
    (b"{}", 422),
    (b"[]", 422),
    (b"null", 422),
    (b"{", 422),
    (b'{"source_proof":{},"source_proof":{},"provider_evidence":{}}', 422),
    (b'{"source_proof":{"claims":{},"claims":{},"kid":"k","signature":"x"},"provider_evidence":{"claims":{},"kid":"k","signature":"x"}}', 422),
    (b'{"source_proof":{"claims":{"a":1,"a":2},"kid":"k","signature":"x"},"provider_evidence":{"claims":{},"kid":"k","signature":"x"}}', 422),
    (b'{"source_proof":{"claims":{},"kid":"k","signature":"x"},"provider_evidence":{"claims":{},"kid":"k","signature":"x","kid":"other"}}', 422),
    (b'{"source_proof":{"claims":{},"kid":"k","signature":"x"},"provider_evidence":{"claims":{"created_at":NaN},"kid":"k","signature":"x"}}', 422),
    (b'{"source_proof":{"claims":{},"kid":"k","signature":"x"},"provider_evidence":{"claims":{"created_at":Infinity},"kid":"k","signature":"x"}}', 422),
    (b'{"source_proof":{"claims":{},"kid":"k","signature":"x"},"provider_evidence":{"claims":{"created_at":1.5},"kid":"k","signature":"x"}}', 422),
    (b'{"source_proof":{"claims":{},"kid":"k","signature":"x","extra":"x"},"provider_evidence":{"claims":{},"kid":"k","signature":"x"}}', 422),
    (b'{"source_proof":{"claims":{},"kid":"k","signature":"x"},"provider_evidence":{"claims":{},"kid":"k","signature":"x"},"retry":true}', 422),
    (b" " * 12289, 413),
])
async def test_ambiguous_nonfinite_fractional_oversize_json_never_reaches_store(
    api_case: dict[str, Any], bad_body: bytes, status: int,
) -> None:
    response = await _request(api_case, body=bad_body)
    _fail_closed(response, status)
    _unchanged(api_case)


@pytest.mark.asyncio
async def test_media_type_and_body_boundary_rules(api_case: dict[str, Any]) -> None:
    for value in ("text/plain", "application/x-www-form-urlencoded", ""):
        response = await _request(api_case, headers=[("content-type", value)])
        _fail_closed(response, 415)
        _unchanged(api_case)
    # The exact limit is applied to raw streamed bytes, before signatures or DB.
    large = b" " * 12288
    _fail_closed(await _request(api_case, body=large), 422)
    _unchanged(api_case)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,change", [
    ("source_proof", "flow"), ("source_proof", "kid"),
    ("provider_evidence", "task"), ("provider_evidence", "signature"),
    ("provider_evidence", "effect_claim"),
])
async def test_tampered_signed_source_or_provider_evidence_cannot_promote(
    api_case: dict[str, Any], kind: str, change: str,
) -> None:
    body = copy.deepcopy(_body(api_case))
    if change == "flow":
        body[kind]["claims"]["flow_id"] = "flow-other-tenant"
    elif change == "kid":
        body[kind]["kid"] = "centralReadback"
    elif change == "task":
        body[kind]["claims"]["task_id"] = "task-other"
    elif change == "signature":
        body[kind]["signature"] = "A" * 86
    elif change == "effect_claim":
        body[kind]["claims"]["target_effect_verified"] = True
    response = await _request(api_case, body=json.dumps(body).encode())
    _fail_closed(response, 503)
    _constructed_without_db(api_case)


@pytest.mark.asyncio
async def test_even_valid_source_signature_for_wrong_flow_is_denied(
    api_case: dict[str, Any],
) -> None:
    forged = copy.deepcopy(_body(api_case))
    original = copy.deepcopy(api_case["source"]["claims"])
    original["flow_id"] = "flow-foreign-tenant"
    forged["source_proof"] = _proof(api_case["source_key"], "centralSource",
                                    SOURCE_DOMAIN, original)
    response = await _request(api_case, body=json.dumps(forged).encode())
    _fail_closed(response, 503)
    assert api_case["calls"] == [(api_case["memory"], api_case["registry"])]
    assert api_case["pg"].statements[0].endswith("READ ONLY")
    assert all(q.startswith("SELECT ") for q in api_case["pg"].statements[1:])


@pytest.mark.asyncio
async def test_valid_native_signature_for_other_task_not_central_authority(
    api_case: dict[str, Any],
) -> None:
    body = copy.deepcopy(_body(api_case))
    wrong = copy.deepcopy(api_case["evidence"]["claims"])
    wrong["task_id"] = "task-foreign"
    body["provider_evidence"] = _proof(api_case["native_key"], "nativeBrowser",
                                       EVIDENCE_DOMAIN, wrong)
    _fail_closed(await _request(api_case, body=json.dumps(body).encode()), 503)
    _constructed_without_db(api_case)


@pytest.mark.asyncio
async def test_current_reviewer_revoked_has_no_fallback_or_reissue(
    api_case: dict[str, Any],
) -> None:
    api_case["rows"]["reviewer_control"] = {"disabled": True}
    response = await _request(api_case)
    _fail_closed(response, 503)
    assert len(api_case["calls"]) == 1
    assert api_case["pg"].statements[0].endswith("READ ONLY")
    assert all(q.startswith("SELECT ") for q in api_case["pg"].statements[1:])
    # No second POST, no browser call, no original Action state mutation:
    # fail-closed UNKNOWN is the sole observable route result.
    assert api_case["rows"]["action"]["status"] == "unknown"
    assert api_case["rows"]["action"]["receipt_sha256"] is None
