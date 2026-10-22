"""Four-original host join: senior mounted API and independent CURRENT proofs.

All signers and original bytes are separately generated **test-only** fixtures,
never production roots, target actions, external providers or application DB.
"""

from __future__ import annotations

import asyncio
import copy
import json
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from ai_osop.api.browser_original_host_join_20261022 import (
    PATH,
    BrowserOriginalHostJoin,
    BrowserOriginalHostJoinDenied,
    create_browser_original_host_join_router,
    install_browser_original_host_join,
)
from ai_osop.api.browser_host_original_enrollment_20261022 import (
    BrowserHostOriginalEnrollment,
    EnrolledBrowserOriginal,
    ENROLLMENT_DOMAIN,
)
from tests.qualification.test_browser_custody_readback_join_20261021 import (
    _token,
    operator_case,
)
from tests.qualification.test_browser_host_original_enrollment_20261022 import enrolled
from tests.qualification.test_browser_central_current_api_20261021 import api_case
from tests.qualification.test_browser_current_original_custody_join_20261021 import custody_case
from tests.qualification.test_browser_current_central_state_join_20261021 import (
    _proof,
    current_case as signed_current_case,
)
from tests.test_native_browser_current_original_bridge_20261021 import bridge_case


def _join(case: dict[str, Any]) -> BrowserOriginalHostJoin:
    return BrowserOriginalHostJoin(BrowserHostOriginalEnrollment(**case["host_opts"]), enabled=True)


async def _post(
    case: dict[str, Any],
    *,
    join: BrowserOriginalHostJoin | None = None,
    role: str = "senior_operator",
    expired: bool = False,
    token: bool = True,
    body: Any = None,
    raw: bytes | None = None,
    path: str = PATH,
    headers: list[tuple[str, str]] | None = None,
    app: FastAPI | None = None,
) -> httpx.Response:
    if app is None:
        app = FastAPI()
        app.include_router(create_browser_original_host_join_router(join))
    if body is None:
        body = {
            "engagement_id": case["binding"]["engagement_id"],
            "request_id": case["binding"]["request_id"],
        }
    request_headers = [("content-type", "application/json")]
    if token:
        request_headers.append(("authorization", "Bearer " + _token(role, expired=expired)))
    if headers:
        request_headers.extend(headers)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 16220)),
        base_url="http://127.0.0.1",
        follow_redirects=False,
    ) as client:
        return await client.post(
            path,
            headers=request_headers,
            content=json.dumps(body).encode("utf-8") if raw is None else raw,
        )


def _unverified(response: httpx.Response, reason: str | None = None) -> None:
    assert response.status_code == 503, response.text
    obj = response.json()["detail"]
    assert obj["status"] == "UNVERIFIED"
    if reason is not None:
        assert obj["reason"] == reason
    assert obj["current_original_artifact_bytes_verified"] is False
    assert obj["raw_http_original_bytes_verified"] is False
    assert obj["independent_target_effect_verified"] is False
    assert obj["automatic_retry_authorized"] is False
    assert obj["production_release_certified"] is False
    assert "custody_proof" not in obj
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_real_mounted_senior_readonly_four_originals_three_current_central(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    reply = await _post(case, join=_join(case))
    assert reply.status_code == 200, reply.text
    data = reply.json()
    assert data["status"] == "CURRENT_HOST_ORIGINAL_FOUR_DIGEST_READBACK"
    assert data["engagement_id"] == case["binding"]["engagement_id"]
    assert data["request_id"] == case["binding"]["request_id"]
    assert data["current_original_artifact_bytes_verified"] is True
    assert data["raw_http_original_bytes_verified"] is True
    assert data["independent_target_effect_verified"] is False
    assert data["automatic_retry_authorized"] is False
    assert data["production_release_certified"] is False
    assert set(data["artifacts"]) == {"http_raw", "screenshot", "dom", "har"}
    for kind, path in case["host_paths"].items():
        assert data["artifacts"][kind]["size_bytes"] == path.stat().st_size
        assert len(data["artifacts"][kind]["sha256"]) == 64
    assert len(data["host_enrollment_sha256"]) == 64
    assert len(data["custody_claims_sha256"]) == 64
    assert case["central_transport"].calls == 3
    assert case["native_transport"].calls == 2
    assert len(case["sign_events"]) == 1
    assert case["rows"]["action"]["status"] == "unknown"
    assert case["journal"].reserve() is False
    assert reply.headers["cache-control"] == "no-store"
    assert reply.headers["x-content-type-options"] == "nosniff"
    for forbidden in (
        str(case["host_root"]),
        ".http",
        "captures/",
        "Host: example.invalid",
        case["host_paths"]["http_raw"].name,
        "central-current-host-service-token",
    ):
        assert forbidden not in reply.text
    assert all(s.startswith("SELECT ") or s.endswith("READ ONLY") for s in case["pg"].statements)


def _default_host_app() -> FastAPI:
    app = FastAPI()
    app.include_router(create_browser_original_host_join_router())
    assert sum(getattr(route, "path", None) == PATH for route in app.routes) == 1
    return app


@pytest.mark.asyncio
async def test_mounted_default_deny_then_host_only_late_install_and_safe_readback_replay(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    app = _default_host_app()
    _unverified(
        await _post(case, app=app),
        "INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED",
    )
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0
    assert not hasattr(app.state, "_osop_browser_original_host_join_20261022")

    enrolled_join = _join(case)
    install_browser_original_host_join(app, enrolled_join)
    assert app.state._osop_browser_original_host_join_20261022 is enrolled_join
    for index in (1, 2):
        response = await _post(case, app=app)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "CURRENT_HOST_ORIGINAL_FOUR_DIGEST_READBACK"
        assert response.json()["automatic_retry_authorized"] is False
        assert response.json()["independent_target_effect_verified"] is False
        assert case["central_transport"].calls == 3 * index
        assert case["native_transport"].calls == 2 * index
        assert case["journal"].reserve() is False
        assert case["rows"]["action"]["status"] == "unknown"

    for replacement in (enrolled_join, _join(case)):
        with pytest.raises(ValueError, match="already installed"):
            install_browser_original_host_join(app, replacement)
    assert app.state._osop_browser_original_host_join_20261022 is enrolled_join
    assert sum(getattr(route, "path", None) == PATH for route in app.routes) == 1


@pytest.mark.asyncio
async def test_host_installer_does_not_enroll_missing_keys_or_enable_false(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    app = _default_host_app()
    for invalid in (
        None,
        {},
        BrowserOriginalHostJoin(BrowserHostOriginalEnrollment(**case["host_opts"])),
        BrowserOriginalHostJoin(None, enabled=True),
    ):
        with pytest.raises(ValueError):
            install_browser_original_host_join(app, invalid)
    for field in ("enrollment_roots", "custody_roots", "custody_signer", "enabled"):
        opts = dict(case["host_opts"])
        opts[field] = False if field == "enabled" else {}
        with pytest.raises(ValueError, match="unavailable"):
            install_browser_original_host_join(
                app, BrowserOriginalHostJoin(BrowserHostOriginalEnrollment(**opts), enabled=True)
            )
    _unverified(await _post(case, app=app))
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0
    assert not hasattr(app.state, "_osop_browser_original_host_join_20261022")
    # Failed enrollment doesn't poison the original app: a separately
    # authenticated complete configuration can still install exactly once.
    install_browser_original_host_join(app, _join(case))
    assert (await _post(case, app=app)).status_code == 200


@pytest.mark.asyncio
async def test_forged_http_enrollment_request_cannot_install_reconfigure_or_replace_host(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    app = _default_host_app()
    original_body = {
        "engagement_id": case["binding"]["engagement_id"],
        "request_id": case["binding"]["request_id"],
    }
    payloads = (
        {"host_root": "C:\\private\\captures"},
        {"enabled": True, "independent_host_enrolled": True},
        {"custody_signer": "user-supplied-signer"},
        {"enrollment_roots": {"hostEnrollment": "AAAA"}},
        {"join": {"enabled": True}},
        {"source_proof": {"current": True}},
    )
    for extras in payloads:
        forged = await _post(case, app=app, body={**original_body, **extras})
        assert forged.status_code == 422
        assert not hasattr(app.state, "_osop_browser_original_host_join_20261022")
    assert case["central_transport"].calls == 0

    join = _join(case)
    install_browser_original_host_join(app, join)
    for extras in payloads:
        forged = await _post(case, app=app, body={**original_body, **extras})
        assert forged.status_code == 422
        assert app.state._osop_browser_original_host_join_20261022 is join
    assert (await _post(case, app=app)).status_code == 200


@pytest.mark.asyncio
async def test_host_state_forgery_cannot_bypass_one_time_install_identity(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    app = _default_host_app()
    forged = _join(case)
    app.state._osop_browser_original_host_join_20261022 = forged
    _unverified(await _post(case, app=app))
    with pytest.raises(ValueError, match="already installed"):
        install_browser_original_host_join(app, _join(case))
    del app.state._osop_browser_original_host_join_20261022
    original = _join(case)
    install_browser_original_host_join(app, original)
    assert (await _post(case, app=app)).status_code == 200

    # Even privileged Python setting app.state directly can't change the
    # module's installed identity; a different join is rejected per request.
    app.state._osop_browser_original_host_join_20261022 = forged
    _unverified(await _post(case, app=app))
    with pytest.raises(ValueError, match="already installed"):
        install_browser_original_host_join(app, forged)
    app.state._osop_browser_original_host_join_20261022 = original
    assert (await _post(case, app=app)).status_code == 200


def test_installer_rejects_absent_duplicate_and_prebound_route(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    join = _join(case)
    with pytest.raises(ValueError, match="unavailable"):
        install_browser_original_host_join(FastAPI(), join)
    already_bound = FastAPI()
    already_bound.include_router(create_browser_original_host_join_router(join))
    with pytest.raises(ValueError, match="unavailable"):
        install_browser_original_host_join(already_bound, join)
    duplicates = _default_host_app()
    duplicates.include_router(create_browser_original_host_join_router())
    with pytest.raises(ValueError, match="unavailable"):
        install_browser_original_host_join(duplicates, join)
    assert case["central_transport"].calls == 0


def test_parallel_host_install_attempts_are_atomic_single_winner(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    app = _default_host_app()
    options = [_join(case) for _ in range(8)]

    def attempt(candidate: BrowserOriginalHostJoin) -> bool:
        try:
            install_browser_original_host_join(app, candidate)
        except ValueError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        winners = list(pool.map(attempt, options))
    assert winners.count(True) == 1
    assert app.state._osop_browser_original_host_join_20261022 is options[winners.index(True)]
    assert case["central_transport"].calls == 0


@pytest.mark.asyncio
async def test_default_denied_and_only_senior_signed_operator_allowed(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    _unverified(await _post(case), "INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED")
    for role in ("operator", "viewer"):
        response = await _post(case, join=_join(case), role=role)
        assert response.status_code == 403
    response = await _post(case, join=_join(case), expired=True)
    assert response.status_code == 401
    response = await _post(case, join=_join(case), token=False)
    assert response.status_code in (401, 403)
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_no_operator_supplied_uri_private_path_source_or_effect(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    original = {
        "engagement_id": case["binding"]["engagement_id"],
        "request_id": case["binding"]["request_id"],
    }
    for extra in (
        {"original_uri": "http://127.0.0.1/private"},
        {"path": "../secrets.txt"},
        {"source_proof": {"fake": True}},
        {"http_raw": "GET /private HTTP/1.1"},
        {"independent_target_effect_verified": True},
    ):
        response = await _post(case, join=_join(case), body={**original, **extra})
        assert response.status_code == 422
    assert case["central_transport"].calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["http_raw", "screenshot", "dom", "har"])
async def test_mutated_original_bytes_deny_without_promotion(
    enrolled: dict[str, Any], kind: str
) -> None:
    case = enrolled
    path = case["host_paths"][kind]
    path.chmod(stat.S_IREAD | stat.S_IWRITE)
    path.write_bytes(path.read_bytes() + b"TAMPERED")
    path.chmod(stat.S_IREAD)
    _unverified(await _post(case, join=_join(case)))
    assert case["sign_events"] == []
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_expired_host_enrollment_denies_before_central_or_native(
    enrolled: dict[str, Any]
) -> None:
    case = enrolled
    claims = copy.deepcopy(case["host_claims"])
    claims["issued_at"] = int(time.time()) - 80
    claims["expires_at"] = int(time.time()) - 1
    signed = _proof(case["host_key"], "hostEnrollment", ENROLLMENT_DOMAIN, claims)
    key = next(iter(case["host_opts"]["records"]))
    opts = {
        **case["host_opts"],
        "records": {key: EnrolledBrowserOriginal(case["record"], signed)},
    }
    service = BrowserOriginalHostJoin(BrowserHostOriginalEnrollment(**opts), enabled=True)
    _unverified(await _post(case, join=service))
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0


@pytest.mark.asyncio
async def test_forged_independent_enrollment_signer_never_reaches_central(
    enrolled: dict[str, Any]
) -> None:
    case = enrolled
    forged = _proof(
        Ed25519PrivateKey.generate(),
        "hostEnrollment",
        ENROLLMENT_DOMAIN,
        copy.deepcopy(case["host_claims"]),
    )
    key = next(iter(case["host_opts"]["records"]))
    opts = {
        **case["host_opts"],
        "records": {key: EnrolledBrowserOriginal(case["record"], forged)},
    }
    _unverified(
        await _post(
            case, join=BrowserOriginalHostJoin(BrowserHostOriginalEnrollment(**opts), enabled=True)
        )
    )
    assert case["central_transport"].calls == 0
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_foreign_tenant_and_flow_reference_are_not_accepted(enrolled: dict[str, Any]) -> None:
    case = enrolled
    foreign = await _post(
        case,
        join=_join(case),
        body={
            "engagement_id": "eng-foreign-tenant",
            "request_id": case["binding"]["request_id"],
        },
    )
    _unverified(foreign)
    key = next(iter(case["host_opts"]["records"]))
    tampered_record = copy.deepcopy(case["record"])
    changed = {
        **case["host_opts"],
        "records": {key: EnrolledBrowserOriginal(tampered_record, case["host_proof"])},
    }
    changed["records"][key].original.expected["flow_id"] = "flow-foreign"
    response = await _post(
        case, join=BrowserOriginalHostJoin(BrowserHostOriginalEnrollment(**changed), enabled=True)
    )
    _unverified(response)
    assert case["central_transport"].calls == 0


@pytest.mark.asyncio
async def test_revoked_original_roe_denied_by_actual_mounted_central_state(
    enrolled: dict[str, Any]
) -> None:
    case = enrolled
    case["rows"]["authorization"]["status"] = "revoked"
    _unverified(await _post(case, join=_join(case)))
    assert case["central_transport"].calls == 1
    assert case["native_transport"].calls == 0
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_roe_revoked_after_first_success_before_final_current_recheck(
    enrolled: dict[str, Any]
) -> None:
    case = enrolled
    transport = case["central_transport"]
    original_handler = transport.handle_async_request

    async def change_before_final(request: httpx.Request) -> httpx.Response:
        if transport.calls == 2:
            case["rows"]["authorization"]["status"] = "revoked"
        return await original_handler(request)

    transport.handle_async_request = change_before_final
    _unverified(await _post(case, join=_join(case)))
    assert transport.calls == 3
    assert case["native_transport"].calls == 2
    assert case["rows"]["action"]["status"] == "unknown"
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_pre_and_post_cancellation_have_no_success_or_retry(enrolled: dict[str, Any]) -> None:
    case = enrolled
    join = _join(case)
    engagement = case["binding"]["engagement_id"]
    request = case["binding"]["request_id"]

    async def abort() -> bool:
        return True

    with pytest.raises(BrowserOriginalHostJoinDenied):
        await join.readback(engagement, request, "local-senior-operator", cancellation_check=abort)
    assert case["central_transport"].calls == 0
    assert case["sign_events"] == []

    attempts = 0

    async def late_abort() -> bool:
        nonlocal attempts
        attempts += 1
        return attempts >= 3

    with pytest.raises(BrowserOriginalHostJoinDenied):
        await join.readback(
            engagement, request, "local-senior-operator", cancellation_check=late_abort
        )
    assert case["central_transport"].calls == 2
    assert case["sign_events"]
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_cancelled_error_is_propagated_not_retried(enrolled: dict[str, Any]) -> None:
    case = enrolled

    async def cancelled() -> bool:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await _join(case).readback(
            case["binding"]["engagement_id"],
            case["binding"]["request_id"],
            "local-senior-operator",
            cancellation_check=cancelled,
        )
    assert case["central_transport"].calls == 0


@pytest.mark.asyncio
async def test_absent_independent_custody_roots_denied_before_network(
    enrolled: dict[str, Any]
) -> None:
    case = enrolled
    opts = {**case["host_opts"], "custody_roots": {}}
    _unverified(
        await _post(
            case,
            join=BrowserOriginalHostJoin(BrowserHostOriginalEnrollment(**opts), enabled=True),
        )
    )
    assert case["central_transport"].calls == 0
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_enrollment_root_rotation_during_final_current_denied(
    enrolled: dict[str, Any]
) -> None:
    case = enrolled
    enrollment = BrowserHostOriginalEnrollment(**case["host_opts"])
    transport = case["central_transport"]
    original_handler = transport.handle_async_request

    async def rotate_at_third_current(request: httpx.Request) -> httpx.Response:
        if transport.calls == 2:
            enrollment._enrollment_roots["nextIndependentSigner"] = (
                Ed25519PrivateKey.generate().public_key().public_bytes_raw()
            )
        return await original_handler(request)

    transport.handle_async_request = rotate_at_third_current
    join = BrowserOriginalHostJoin(enrollment, enabled=True)
    _unverified(await _post(case, join=join))
    assert transport.calls == 3
    assert len(case["sign_events"]) == 1


@pytest.mark.asyncio
async def test_raw_http_modified_after_external_signer_but_before_final_read(
    enrolled: dict[str, Any]
) -> None:
    case = enrolled
    opts = dict(case["host_opts"])
    signer = case["signer"]
    raw = case["host_paths"]["http_raw"]

    async def changed_after_signed(claims: Any) -> Any:
        valid_proof = await signer(claims)
        raw.chmod(stat.S_IREAD | stat.S_IWRITE)
        raw.write_bytes(raw.read_bytes() + b"UNWITNESSED_LATE_CHANGE")
        raw.chmod(stat.S_IREAD)
        return valid_proof

    opts["custody_signer"] = changed_after_signed
    joined = BrowserOriginalHostJoin(BrowserHostOriginalEnrollment(**opts), enabled=True)
    _unverified(await _post(case, join=joined))
    # The underlying three-file signer proof is genuine, but the fourth raw
    # original changed after that proof and must block the four-file join.
    assert len(case["sign_events"]) == 1
    assert case["central_transport"].calls == 2
    assert case["native_transport"].calls == 2
