"""Disjoint CURRENT authority -> provider ORIGINAL-byte admission qualification.

REAL: mounted central FastAPI current route, native provider ASGI original-byte
readback, actual RequestJournal, locally signed Ed25519 source/provider/central
envelopes, real signed ROE verifier and private test-owned original artifact
bytes. NO browser, remote target, provider service, DB or Docker is contacted.

SIMULATED: original 0027/0034/Task/reviewer/lease PostgreSQL rows are the
existing SELECT-only FakePG fixture. The PNG/DOM/HAR files are synthetic bytes,
not Chromium screenshots or target-owner observations.

The important distinction is *capability*: a fresh signed central CURRENT
certificate does not grant access to provider-owned files, nor certify their
present bytes. This tests nontransitivity on actual mounted routes, not a
fictitious merged custody-admission endpoint.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Optional

import httpx
import pytest

from ai_osop.memory.browser_source_authority import DOMAIN as SOURCE_DOMAIN
from ai_osop.orchestrator.browser_current_authority_readback import (
    BrowserCurrentAuthorityDenied,
    EVIDENCE_DOMAIN,
    verify_current_browser_authority,
)
from tests.qualification.test_browser_central_current_api_20261021 import (
    HOST_TOKEN,
    SOURCE_TOKEN,
    _request as central_request,
    api_case,
)
from tests.qualification.test_browser_current_central_state_join_20261021 import (
    _proof,
    current_case as signed_current_case,
)
from tests.qualification.test_browser_current_original_custody_join_20261021 import (
    _complete_local_original,
    _expected,
    custody_case,
)


async def _current(case: dict[str, Any], *, body: Optional[bytes] = None) -> httpx.Response:
    # The imported FakePG retains a single transaction statement log. Each
    # readback is a separate synthetic READ ONLY snapshot, not an app DB reset.
    case["pg"].statements.clear()
    return await central_request(case, body=body)


async def _provider(
    case: dict[str, Any],
    *,
    token: Optional[str] = None,
    body: Optional[dict[str, Any]] = None,
) -> httpx.Response:
    headers = {} if token is None else {"authorization": "Bearer " + token}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=case["native"].app),
        base_url="http://offline-native-provider.invalid",
        follow_redirects=False,
    ) as client:
        return await client.post(
            "/mcp/request/evidence/readback",
            json=case["binding"] if body is None else body,
            headers=headers,
        )


def _assert_central_not_custody(result: httpx.Response, case: dict[str, Any]) -> dict[str, Any]:
    assert result.status_code == 200, result.text
    body = result.json()
    assert set(body) == {
        "status",
        "authority_proof",
        "original_browser_artifact_bytes_verified",
        "independent_target_effect_verified",
        "automatic_retry_authorized",
        "production_release_certified",
    }
    assert body["status"] == "current_central_authority_only"
    assert body["original_browser_artifact_bytes_verified"] is False
    assert body["independent_target_effect_verified"] is False
    assert body["automatic_retry_authorized"] is False
    assert body["production_release_certified"] is False
    claims = verify_current_browser_authority(body["authority_proof"], _expected(case))
    assert claims["purpose"] == "current_authority_readback_only"
    assert claims["authority_current"] is True
    assert claims["artifact_bytes_verified"] is False
    assert claims["target_effect_verified"] is False
    assert "artifacts" not in body and "bytes" not in body
    return body


@pytest.mark.asyncio
async def test_actual_central_certificate_is_not_native_original_byte_access_token(
    custody_case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = custody_case
    _complete_local_original(case)
    local_reads: list[dict[str, str]] = []
    original = case["native"].RequestJournal.current_evidence

    def counted(journal: Any) -> dict[str, Any]:
        local_reads.append(dict(journal.binding))
        return original(journal)

    monkeypatch.setattr(case["native"].RequestJournal, "current_evidence", counted)
    central = _assert_central_not_custody(await _current(case), case)
    # Central API itself has no native readback and cannot touch the files.
    assert local_reads == []
    assert case["pg"].statements[0].endswith("READ ONLY")
    assert all(sql.startswith("SELECT ") for sql in case["pg"].statements[1:])

    for leaked_capability in (
        None,
        HOST_TOKEN,
        SOURCE_TOKEN,
        central["authority_proof"]["signature"],
    ):
        response = await _provider(case, token=leaked_capability)
        assert response.status_code == 401
        assert "artifacts" not in response.text
        assert "target_effect" not in response.text
        assert local_reads == []

    # An independently authenticated provider-local read may authenticate
    # current original hashes, but it is NOT authorized by central cert bytes.
    allowed = await _provider(case, token="local-readback-only-provider-token-20261021")
    assert allowed.status_code == 200
    result = allowed.json()["result"]
    assert result["status"] == "current_provider_local_original_bytes_match"
    assert result["provider_signed_evidence_currently_matches"] is True
    assert result["current_authorization_verified"] is False
    assert result["independent_target_effect_verified"] is False
    assert result["safe_to_automatically_retry"] is False
    assert set(result["artifacts"]) == {"screenshot", "dom", "har"}
    assert local_reads == [case["binding"]]
    assert case["journal"].reserve() is False
    assert case["rows"]["action"]["status"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra",
    [
        {"read_original_bytes": True},
        {"reconcile_to_target_owner": True},
        {"current_byte_custody_grant": {"verified": True}},
    ],
)
async def test_mounted_central_route_has_no_original_byte_admission_request_shape(
    api_case: dict[str, Any],
    extra: dict[str, Any],
) -> None:
    case = api_case
    encoded = json.dumps(
        {
            "source_proof": case["source"],
            "provider_evidence": case["evidence"],
            **extra,
        }
    ).encode("utf-8")
    denied = await _current(case, body=encoded)
    assert denied.status_code == 422
    assert "authority_proof" not in denied.json()
    assert case["calls"] == []
    assert case["pg"].statements == []


@pytest.mark.asyncio
async def test_central_readback_certificate_cannot_be_sent_to_native_as_original_bytes(
    custody_case: dict[str, Any],
) -> None:
    case = custody_case
    _complete_local_original(case)
    central = _assert_central_not_custody(await _current(case), case)
    # Even with a real provider-local bearer, a *central* current certificate
    # is NOT an original RequestJournal identity, nor an original-byte payload.
    invalid = await _provider(
        case,
        token="local-readback-only-provider-token-20261021",
        body={"authority_proof": central["authority_proof"]},
    )
    assert invalid.status_code == 422
    assert "artifacts" not in invalid.text
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forgery",
    ["signed_foreign_owner", "signed_foreign_approval", "signed_provider_effect"],
)
async def test_genuinely_signed_forged_owner_or_target_effect_cannot_mint_admission(
    custody_case: dict[str, Any],
    forgery: str,
) -> None:
    case = custody_case
    _complete_local_original(case)
    normal = _assert_central_not_custody(await _current(case), case)
    original = copy.deepcopy(
        {"source_proof": case["source"], "provider_evidence": case["evidence"]}
    )
    if forgery.startswith("signed_foreign"):
        claims = copy.deepcopy(case["source"]["claims"])
        if forgery == "signed_foreign_owner":
            claims["owner_id"] = "operator-foreign-owner"
        else:
            claims["approval_id"] = "apr-foreign-review"
        original["source_proof"] = _proof(
            case["source_key"], "centralSource", SOURCE_DOMAIN, claims
        )
    else:
        evidence = copy.deepcopy(case["evidence"]["claims"])
        evidence["target_effect_verified"] = True
        original["provider_evidence"] = _proof(
            case["native_key"], "nativeBrowser", EVIDENCE_DOMAIN, evidence
        )
    # The *enrolled original signer* cryptographically signs an invented claim,
    # not merely a bit-flipped signature. Original durable current source/ROE
    # refuses the claim and central must not issue a new custody admission.
    denied = await _current(case, body=json.dumps(original).encode("utf-8"))
    assert denied.status_code == 503
    assert "authority_proof" not in denied.json()
    assert "original_browser_artifact_bytes_verified" not in denied.json()
    assert normal["original_browser_artifact_bytes_verified"] is False
    assert case["journal"].reserve() is False
    assert case["rows"]["action"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_short_lived_signed_authority_expires_and_revokes_without_byte_grant(
    custody_case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = custody_case
    _complete_local_original(case)
    central = _assert_central_not_custody(await _current(case), case)
    proof = central["authority_proof"]
    claims = proof["claims"]
    assert claims["expires_at"] - claims["checked_at"] == 5
    with pytest.raises(BrowserCurrentAuthorityDenied):
        verify_current_browser_authority(proof, _expected(case), now=claims["expires_at"])
    with monkeypatch.context() as changed:
        changed.setenv("OSOP_BROWSER_CURRENT_AUTHORITY_TRUSTED_PUBLIC_KEYS_JSON", "{}")
        with pytest.raises(BrowserCurrentAuthorityDenied):
            verify_current_browser_authority(proof, _expected(case))
        # A revoked central root cannot issue new current certificates.
        renewed = await _current(case)
        assert renewed.status_code == 503
        assert "authority_proof" not in renewed.json()
    case["rows"]["authorization"]["status"] = "revoked"
    denied = await _current(case)
    assert denied.status_code == 503
    assert "authority_proof" not in denied.json()
    # Producer-owned originally captured bytes still exist. Neither an old
    # valid central certificate nor an expired/revoked one grants new custody.
    assert case["journal"].reserve() is False
    assert case["rows"]["action"]["status"] == "unknown"
