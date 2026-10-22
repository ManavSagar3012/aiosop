"""Operator-mounted Browser host custody join with genuine offline signers.

Real production code: senior JWT dependency, operator ASGI router, native and
central ASGI routes, separate signed custody witness, screenshot/DOM/HAR byte
comparison and CURRENT ROE/revocation rechecks. FakePG and synthetic original
bytes are test-owned fixtures; no Chromium, network, application DB or target.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from jose import jwt

from ai_osop.api import deps
from ai_osop.api.browser_current_custody_readback import (
    BrowserCurrentCustodyReadback,
    OriginalBrowserHostRecord,
    create_browser_current_custody_router,
)
from tests.test_native_browser_current_original_bridge_20261021 import (
    _bridge,
    bridge_case,
)
from tests.qualification.test_browser_current_original_custody_join_20261021 import (
    _expected,
    custody_case,
)
from tests.qualification.test_browser_central_current_api_20261021 import api_case
from tests.qualification.test_browser_current_central_state_join_20261021 import (
    current_case as signed_current_case,
)

SECRET = "offline-browser-custody-senior-only-jwt-secret"
PATH = "/system/browser/custody/readback"


def _token(role: str = "senior_operator", *, expired: bool = False) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": "local-senior-operator",
            "iss": "test-local",
            "role": role,
            "iat": now - 20,
            "exp": now - 1 if expired else now + 300,
        },
        SECRET,
        algorithm="HS256",
    )


@pytest.fixture
def operator_case(
    bridge_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    case = bridge_case
    monkeypatch.setattr(deps.settings, "environment", "production")
    monkeypatch.setattr(deps.settings, "jwt_secret", SECRET)
    monkeypatch.setattr(deps.settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(deps.settings, "jwt_issuer", None)
    monkeypatch.setattr(deps.settings, "jwt_audience", None)
    monkeypatch.setattr(deps.settings, "operator_revocation_required", False)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)

    record = OriginalBrowserHostRecord(
        original_uri=case["rows"]["action"]["safe_parameters"]["url"],
        source_proof=case["source"],
        provider_evidence=case["attestation"],
        expected={
            **_expected(case),
            "authorization_sha256": case["source"]["claims"]["authorization_sha256"],
            "original_intent_sha256": case["rows"]["action"]["intent_sha256"],
            "url_sha256": case["source"]["claims"]["url_sha256"],
        },
    )
    loads: list[tuple[str, str, str]] = []

    async def load(engagement: str, request: str, actor: str) -> OriginalBrowserHostRecord:
        loads.append((engagement, request, actor))
        return record

    case["record"] = record
    case["loads"] = loads
    case["load"] = load
    case["service"] = BrowserCurrentCustodyReadback(
        enabled=True,
        independent_host_enrolled=True,
        bridge=_bridge(case),
        host_record_resolver=load,
    )
    return case


async def _post(
    case: dict[str, Any],
    *,
    service: Any = None,
    role: str = "senior_operator",
    expired: bool = False,
    token: Any = True,
    body: Any = None,
    raw: Any = None,
    headers: Any = None,
    client_host: str = "127.0.0.1",
    base_url: str = "http://127.0.0.1",
    path: str = PATH,
) -> httpx.Response:
    app = FastAPI()
    app.include_router(create_browser_current_custody_router(
        case["service"] if service is None else service
    ))
    if body is None:
        body = {
            "request_id": case["source"]["claims"]["request_id"],
            "engagement_id": case["source"]["claims"]["engagement_id"],
        }
    supplied = list(headers) if headers is not None else [("content-type", "application/json")]
    if token:
        supplied.append(("authorization", "Bearer " + (
            _token(role, expired=expired) if token is True else str(token)
        )))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(client_host, 8123)),
        base_url=base_url,
        follow_redirects=False,
    ) as client:
        return await client.post(
            path, headers=supplied,
            content=json.dumps(body).encode("utf-8") if raw is None else raw,
        )


def _denied(response: httpx.Response, code: int, reason: str) -> None:
    assert response.status_code == code, response.text
    result = response.json()["detail"]
    assert result["status"] == "UNVERIFIED"
    assert result["reason"] == reason
    assert result["current_original_artifact_bytes_verified"] is False
    assert result["independent_target_effect_verified"] is False
    assert result["automatic_retry_authorized"] is False
    assert result["production_release_certified"] is False
    assert "custody_proof" not in result
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_mounted_senior_current_original_bytes_are_signed_readonly_and_never_effect(
    operator_case: dict[str, Any],
) -> None:
    case = operator_case
    response = await _post(case)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "CURRENT_ORIGINAL_CUSTODY_VERIFIED"
    assert body["current_original_artifact_bytes_verified"] is True
    assert body["independent_target_effect_verified"] is False
    assert body["automatic_retry_authorized"] is False
    assert body["production_release_certified"] is False
    assert body["custody_proof"]["claims"]["original_bytes_read"] is True
    assert set(body["artifacts"]) == {"dom", "har", "screenshot"}
    assert body["artifacts"] == case["attestation"]["claims"]["artifacts"]
    assert "original_uri" not in json.dumps(body)
    assert case["loads"] == [(
        case["binding"]["engagement_id"], case["binding"]["request_id"],
        "local-senior-operator",
    )]
    assert case["central_transport"].calls == 2
    assert case["native_transport"].calls == 2
    assert len(case["read_events"]) == 1
    assert len(case["sign_events"]) == 1
    assert case["pg"].statements[0].endswith("READ ONLY")
    assert all(s.startswith("SELECT ") for s in case["pg"].statements[1:])
    assert case["rows"]["action"]["status"] == "unknown"
    assert case["journal"].reserve() is False
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["enabled", "enrolled", "bridge", "resolver", "reader", "signer", "roots"])
async def test_default_unconfigured_or_unenrolled_host_fails_before_io(
    operator_case: dict[str, Any], missing: str,
) -> None:
    case = operator_case
    values = {
        "enabled": True,
        "independent_host_enrolled": True,
        "bridge": _bridge(case),
        "host_record_resolver": case["load"],
    }
    if missing == "enabled":
        values["enabled"] = False
    elif missing == "enrolled":
        values["independent_host_enrolled"] = False
    elif missing == "bridge":
        values["bridge"] = None
    elif missing == "resolver":
        values["host_record_resolver"] = None
    else:
        rename = {"reader": "original_reader", "signer": "independent_signer", "roots": "independent_roots"}
        values["bridge"] = _bridge(case, **{rename[missing]: None})
    response = await _post(case, service=BrowserCurrentCustodyReadback(**values))
    _denied(response, 503, "INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED")
    assert case["loads"] == []
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0
    assert case["read_events"] == []
    assert case["sign_events"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("role,expired,token,code", [
    ("operator", False, True, 403),
    ("viewer", False, True, 403),
    ("senior_operator", True, True, 401),
    ("senior_operator", False, False, 403),
])
async def test_senior_signed_operator_required_before_host_lookup(
    operator_case: dict[str, Any], role: str, expired: bool, token: bool, code: int,
) -> None:
    response = await _post(operator_case, role=role, expired=expired, token=token)
    assert response.status_code == code
    assert operator_case["loads"] == []
    assert operator_case["central_transport"].calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("problem", [
    "foreign_flow", "foreign_owner", "different_authorization",
    "changed_uri", "changed_preflight", "different_request",
])
async def test_host_source_and_caller_identity_mismatches_fail_without_provider_or_byte_access(
    operator_case: dict[str, Any], problem: str,
) -> None:
    case = operator_case
    expected = dict(case["record"].expected)
    uri = case["record"].original_uri
    if problem == "foreign_flow":
        expected["flow_id"] = "flow-other"
    elif problem == "foreign_owner":
        expected["owner_id"] = "operator-other"
    elif problem == "different_authorization":
        expected["authorization_sha256"] = "0" * 64
    elif problem == "changed_uri":
        uri += "?privileged=1"
    elif problem == "changed_preflight":
        expected["preflight_id"] = "nbp-" + "a" * 32
    elif problem == "different_request":
        expected["request_id"] = "req-" + "c" * 48
    record = OriginalBrowserHostRecord(
        original_uri=uri, source_proof=case["source"],
        provider_evidence=case["attestation"], expected=expected,
    )

    async def changed(*_: Any) -> OriginalBrowserHostRecord:
        return record

    service = BrowserCurrentCustodyReadback(
        enabled=True, independent_host_enrolled=True,
        bridge=_bridge(case), host_record_resolver=changed,
    )
    _denied(await _post(case, service=service), 503, "ORIGINAL_HOST_IDENTITY_MISMATCH")
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_operator_cannot_supply_provider_screenshot_proof_paths_or_retry(
    operator_case: dict[str, Any],
) -> None:
    case = operator_case
    body = {
        "engagement_id": case["binding"]["engagement_id"],
        "request_id": case["binding"]["request_id"],
        "provider_evidence": {"provider_says_original": True},
        "original_path": "captures/caller.png",
        "target_effect_verified": True,
    }
    _denied(await _post(case, body=body), 422, "INVALID_OPERATOR_REQUEST")
    assert case["loads"] == []
    assert case["sign_events"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["screenshot", "dom", "har"])
async def test_tampered_original_bytes_deny_independent_witness(
    operator_case: dict[str, Any], kind: str,
) -> None:
    case = operator_case
    path = case["paths"][kind]
    path.write_bytes(path.read_bytes() + b"CHANGED_HOST_FILE")
    _denied(await _post(case), 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["read_events"] == []
    assert case["sign_events"] == []
    assert case["rows"]["action"]["status"] == "unknown"
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_current_roe_revoked_after_original_read_does_not_promote(
    operator_case: dict[str, Any],
) -> None:
    case = operator_case
    previous = case["reader"]

    async def revoke(binding: Any, artifacts: Any) -> Any:
        raw = await previous(binding, artifacts)
        case["rows"]["authorization"]["status"] = "revoked"
        return raw

    case["service"].bridge = _bridge(case, original_reader=revoke)
    _denied(await _post(case), 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["central_transport"].calls == 2
    assert case["native_transport"].calls == 2
    assert case["sign_events"] == []
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_revoked_current_signer_after_read_denies_before_custody_signature(
    operator_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = operator_case
    previous = case["reader"]

    async def revoke_key(binding: Any, artifacts: Any) -> Any:
        raw = await previous(binding, artifacts)
        monkeypatch.setenv("OSOP_BROWSER_CURRENT_AUTHORITY_TRUSTED_PUBLIC_KEYS_JSON", "{}")
        return raw

    case["service"].bridge = _bridge(case, original_reader=revoke_key)
    _denied(await _post(case), 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["sign_events"] == []
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_lost_central_ack_never_retries_or_signs_original_custody(
    operator_case: dict[str, Any],
) -> None:
    case = operator_case
    case["service"].bridge = _bridge(
        case, central_bearer="synthetic-wrong-central-readback-token",
    )
    _denied(await _post(case), 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["central_transport"].calls == 1
    assert case["native_transport"].calls == 0
    assert case["sign_events"] == []
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_absent_host_original_ledger_return_is_machine_unverified(
    operator_case: dict[str, Any],
) -> None:
    case = operator_case

    async def missing(*_: Any) -> OriginalBrowserHostRecord:
        raise TimeoutError("simulated independent owner lost ACK")

    service = BrowserCurrentCustodyReadback(
        enabled=True, independent_host_enrolled=True,
        bridge=_bridge(case), host_record_resolver=missing,
    )
    _denied(await _post(case, service=service), 503, "ORIGINAL_HOST_RECORD_UNAVAILABLE")
    assert case["central_transport"].calls == 0
    assert case["sign_events"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("extra", [
    b'{"request_id":"abc","engagement_id":"eng-abc","request_id":"abc"}',
    b'{"request_id":2,"engagement_id":"eng-abc"}',
    b'{"request_id":[],"engagement_id":"eng-abc"}',
])
async def test_ambiguous_operator_body_rejected_before_any_original_read(
    operator_case: dict[str, Any], extra: bytes,
) -> None:
    _denied(await _post(operator_case, raw=extra), 422, "INVALID_OPERATOR_REQUEST")
    assert operator_case["loads"] == []
    assert operator_case["read_events"] == []


@pytest.mark.asyncio
async def test_fail_closed_on_external_plaintext_or_query_credentials(
    operator_case: dict[str, Any],
) -> None:
    _denied(
        await _post(operator_case, base_url="http://operator.example", client_host="192.0.2.1"),
        403, "INDEPENDENT_TRANSPORT_UNVERIFIED",
    )
    _denied(
        await _post(operator_case, path=PATH + "?Bearer=secret"),
        403, "OPERATOR_QUERY_FORBIDDEN",
    )
    assert operator_case["loads"] == []
