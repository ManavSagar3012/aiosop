"""Offline independently pinned host enrollment into mounted Browser CURRENT.

Real: mounted FastAPI senior JWT, actual central/native ASGI, host-enrollment
Ed25519 verification, four local original file descriptor reads, independent
custody issuer, current Flow/ROE fencing. Synthetic: private fixture files,
FakePG original central rows and keys generated strictly for this test.
No real Browser, network listener, target, app DB or Docker.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.api.browser_host_original_enrollment_20261022 import (
    ENROLLMENT_DOMAIN,
    BrowserHostEnrollmentDenied,
    BrowserHostOriginalEnrollment,
    EnrolledBrowserOriginal,
)
from tests.qualification.test_browser_custody_readback_join_20261021 import (
    _denied,
    _post,
    operator_case,
)
from tests.test_native_browser_current_original_bridge_20261021 import bridge_case
from tests.qualification.test_browser_current_original_custody_join_20261021 import custody_case
from tests.qualification.test_browser_central_current_api_20261021 import api_case
from tests.qualification.test_browser_current_central_state_join_20261021 import (
    _proof,
    current_case as signed_current_case,
)


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


@pytest.fixture
def enrolled(
    operator_case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    case = operator_case
    original = case["record"]
    host_root = case["tenant"].parent
    raw_http = (
        b"GET /original HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    raw_path = case["tenant"] / "captures" / (uuid.uuid4().hex + ".http")
    raw_path.write_bytes(raw_http)
    all_files = {**case["paths"], "http_raw": raw_path}
    for path in all_files.values():
        # Host custody accepts only already sealed, read-only local originals.
        path.chmod(stat.S_IREAD)
    manifest = {
        kind: {
            "path": "captures/" + path.name,
            "sha256": _hash(path.read_bytes()),
            "size_bytes": len(path.read_bytes()),
        }
        for kind, path in all_files.items()
    }
    assert {name: manifest[name] for name in ("screenshot", "dom", "har")} == case["attestation"][
        "claims"
    ]["artifacts"]
    key = Ed25519PrivateKey.generate()
    claims = {
        "version": 1,
        "enrollment_id": "bhe-" + uuid.uuid4().hex,
        **original.expected,
        "artifacts": manifest,
        "root_path_sha256": _hash(str(host_root).encode("utf-8")),
        "issued_at": int(time.time()) - 1,
        "expires_at": int(time.time()) + 60,
        "purpose": "host_immutable_original_bytes_readonly",
    }
    proof = _proof(key, "hostEnrollment", ENROLLMENT_DOMAIN, claims)
    records = {
        (
            original.expected["engagement_id"],
            original.expected["request_id"],
        ): EnrolledBrowserOriginal(original, proof),
    }
    opts = {
        "host_root": host_root,
        "records": records,
        "enrollment_roots": {"hostEnrollment": key.public_key().public_bytes_raw()},
        "custody_roots": case["custody_roots"],
        "custody_signer": case["signer"],
        "central_client": case["central_client"],
        "provider_client": case["provider_client"],
        "central_bearer": "central-current-host-service-token-20261021",
        "provider_bearer": "local-readback-only-provider-token-20261021",
        "enabled": True,
    }
    case.update(
        {
            "host_opts": opts,
            "host_key": key,
            "host_claims": claims,
            "host_proof": proof,
            "host_paths": all_files,
            "host_root": host_root,
        }
    )
    return case


@pytest.mark.asyncio
async def test_mounted_original_http_png_dom_har_host_readback_is_independently_signed(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    enrollment = BrowserHostOriginalEnrollment(**case["host_opts"])
    service = enrollment.service()
    result = await _post(case, service=service)
    assert result.status_code == 200, result.text
    proof = result.json()
    assert proof["status"] == "CURRENT_ORIGINAL_CUSTODY_VERIFIED"
    assert proof["current_original_artifact_bytes_verified"] is True
    assert proof["independent_target_effect_verified"] is False
    assert proof["automatic_retry_authorized"] is False
    assert proof["production_release_certified"] is False
    assert set(proof["artifacts"]) == {"screenshot", "dom", "har"}
    assert "http_raw" not in proof["artifacts"]
    assert "Host: example" not in result.text
    assert str(case["host_root"]) not in result.text
    assert case["central_transport"].calls == 2
    assert case["native_transport"].calls == 2
    assert len(case["sign_events"]) == 1
    assert case["journal"].reserve() is False
    assert case["rows"]["action"]["status"] == "unknown"
    assert case["pg"].statements[0].endswith("READ ONLY")


@pytest.mark.asyncio
async def test_missing_enrollment_roots_or_custody_roots_is_503_with_zero_original_reads(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    for kind in ("enrollment_roots", "custody_roots", "custody_signer", "enabled"):
        opts = dict(case["host_opts"])
        opts[kind] = False if kind == "enabled" else None
        service = BrowserHostOriginalEnrollment(**opts).service()
        _denied(
            await _post(case, service=service),
            503,
            "INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED",
        )
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_independent_enrollment_signature_forgery_and_root_overlap_denied(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    original = case["record"]
    altered = copy.deepcopy(case["host_proof"])
    altered["claims"]["artifacts"]["http_raw"]["sha256"] = "f" * 64
    key = (original.expected["engagement_id"], original.expected["request_id"])
    forged = {key: EnrolledBrowserOriginal(original, altered)}
    opts = {**case["host_opts"], "records": forged}
    _denied(
        await _post(case, service=BrowserHostOriginalEnrollment(**opts).service()),
        503,
        "ORIGINAL_HOST_RECORD_UNAVAILABLE",
    )
    # Signer substitution with an enrolled custody key cannot be used as
    # independent enrollment; source/current/provider key overlaps deny too.
    opts = {**case["host_opts"], "enrollment_roots": case["custody_roots"]}
    _denied(
        await _post(case, service=BrowserHostOriginalEnrollment(**opts).service()),
        503,
        "INDEPENDENT_HOST_CUSTODY_NOT_ENROLLED",
    )
    opts = {**case["host_opts"], "enrollment_roots": case["host_opts"]["enrollment_roots"]}
    forged = _proof(
        Ed25519PrivateKey.generate(),
        "hostEnrollment",
        ENROLLMENT_DOMAIN,
        copy.deepcopy(case["host_claims"]),
    )
    opts["records"] = {key: EnrolledBrowserOriginal(original, forged)}
    _denied(
        await _post(case, service=BrowserHostOriginalEnrollment(**opts).service()),
        503,
        "ORIGINAL_HOST_RECORD_UNAVAILABLE",
    )
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_mutated_raw_http_bytes_denied_after_current_central_before_custody_signer(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    raw = case["host_paths"]["http_raw"]
    raw.chmod(stat.S_IWRITE | stat.S_IREAD)
    raw.write_bytes(raw.read_bytes() + b"TAMPER")
    raw.chmod(stat.S_IREAD)
    res = await _post(case, service=BrowserHostOriginalEnrollment(**case["host_opts"]).service())
    _denied(res, 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["central_transport"].calls == 1
    assert case["native_transport"].calls == 1
    assert case["sign_events"] == []
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_raw_http_mutated_after_first_host_read_before_final_current_denies_signer(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    enrollment = BrowserHostOriginalEnrollment(**case["host_opts"])
    service = enrollment.service()
    before = service.bridge.original_reader
    raw_path = case["host_paths"]["http_raw"]

    async def altered_after_read(binding: Any, manifest: Any) -> Any:
        original = await before(binding, manifest)
        # The native Browser provider has no fourth HTTP artifact, so its
        # native-after succeeds. The host must still recheck HTTP after the
        # central-after proof and before externally signing custody.
        raw_path.chmod(stat.S_IWRITE | stat.S_IREAD)
        raw_path.write_bytes(raw_path.read_bytes() + b"LATE_CHANGED_HTTP")
        raw_path.chmod(stat.S_IREAD)
        return original

    service.bridge.original_reader = altered_after_read
    result = await _post(case, service=service)
    _denied(result, 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["central_transport"].calls == 2
    assert case["native_transport"].calls == 2
    assert case["sign_events"] == []
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["screenshot", "dom", "har"])
async def test_mutated_native_original_bytes_rejected_without_host_custody(
    enrolled: dict[str, Any],
    kind: str,
) -> None:
    case = enrolled
    path = case["host_paths"][kind]
    path.chmod(stat.S_IREAD | stat.S_IWRITE)
    path.write_bytes(path.read_bytes() + b"TAMPER")
    path.chmod(stat.S_IREAD)
    result = await _post(case, service=BrowserHostOriginalEnrollment(**case["host_opts"]).service())
    _denied(result, 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["sign_events"] == []
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_raw_http_symlink_rejected_even_with_matching_content(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    raw = case["host_paths"]["http_raw"]
    outside = raw.with_name("other-original.http")
    outside.write_bytes(raw.read_bytes())
    outside.chmod(stat.S_IREAD)
    raw.chmod(stat.S_IWRITE | stat.S_IREAD)
    raw.unlink()
    try:
        raw.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Host prohibits unprivileged symlink creation")
    result = await _post(case, service=BrowserHostOriginalEnrollment(**case["host_opts"]).service())
    _denied(result, 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_raw_http_hardlink_rejected_despite_matching_sha(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    raw = case["host_paths"]["http_raw"]
    duplicate = raw.with_name("linked-original.http")
    os.link(raw, duplicate)
    result = await _post(case, service=BrowserHostOriginalEnrollment(**case["host_opts"]).service())
    _denied(result, 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_missing_host_http_and_mutable_file_mode_fail_with_no_secret_paths(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    raw = case["host_paths"]["http_raw"]
    raw.chmod(stat.S_IWRITE | stat.S_IREAD)
    result = await _post(case, service=BrowserHostOriginalEnrollment(**case["host_opts"]).service())
    _denied(result, 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert str(raw) not in result.text
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_original_enrollment_rejected_after_current_roe_revocation(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    case["rows"]["authorization"]["status"] = "revoked"
    result = await _post(case, service=BrowserHostOriginalEnrollment(**case["host_opts"]).service())
    _denied(result, 503, "CURRENT_ORIGINAL_CUSTODY_UNVERIFIED")
    assert case["central_transport"].calls == 1
    assert case["native_transport"].calls == 0
    assert case["sign_events"] == []


@pytest.mark.asyncio
async def test_host_issuer_revoked_when_enrollment_key_missing(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    opts = {
        **case["host_opts"],
        "enrollment_roots": {
            "otherEnrollment": Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        },
    }
    result = await _post(case, service=BrowserHostOriginalEnrollment(**opts).service())
    _denied(result, 503, "ORIGINAL_HOST_RECORD_UNAVAILABLE")
    assert case["sign_events"] == []


def test_manifest_rejects_traversal_symlinks_ambiguous_fields_and_wrong_http_sha(
    enrolled: dict[str, Any],
) -> None:
    case = enrolled
    key = next(iter(case["host_opts"]["records"]))
    for changed in (
        {"path": "captures/../../secret.http"},
        {"path": "captures/" + "0" * 32 + ".exe"},
        {"path": "captures//fake.http"},
        {"size_bytes": 5 * 1024 * 1024},
        {"sha256": "x" * 64},
    ):
        claims = copy.deepcopy(case["host_claims"])
        claims["artifacts"]["http_raw"].update(changed)
        enrollment = _proof(case["host_key"], "hostEnrollment", ENROLLMENT_DOMAIN, claims)
        opts = {
            **case["host_opts"],
            "records": {key: EnrolledBrowserOriginal(case["record"], enrollment)},
        }
        with pytest.raises(BrowserHostEnrollmentDenied):
            BrowserHostOriginalEnrollment(**opts)._admitted(key)
    assert case["central_transport"].calls == 0
