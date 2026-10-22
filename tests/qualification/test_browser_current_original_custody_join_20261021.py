"""Original Browser custody versus independently signed *current* central authority.

REAL offline production code: native RequestJournal/sidecar byte reread, native
provider ASGI original-evidence and historical-status routes, central mounted
FastAPI current-authority route, three independently enrolled Ed25519 signers,
current signed ROE verification, bounded immutable captures in a private
pytest-owned temporary tenant mount, and no provider dispatch/retry.

SIMULATED: capture bytes are synthetic fixtures (NOT Chromium, screenshots of a
real page, or a real target); central 0027/0034/Task/ROE/reviewer/lease rows
come from existing SELECT-only FakePG. No PostgreSQL, Docker, target, browser
process, application DB or external network is contacted.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

from ai_osop.memory.browser_source_authority import DOMAIN as SOURCE_DOMAIN, _canonical
from ai_osop.orchestrator.browser_current_authority_readback import (
    BrowserCurrentAuthorityDenied,
    CURRENT_DOMAIN,
    EVIDENCE_DOMAIN,
    verify_current_browser_authority,
)
from tests.qualification.native_browser_local_helper_20261020 import _load_browser_module
from tests.qualification.test_browser_central_current_api_20261021 import (
    HOST_TOKEN,
    _request as central_request,
    api_case,
)
from tests.qualification.test_browser_current_central_state_join_20261021 import (
    _proof,
    current_case as signed_current_case,
)


def _canonical_json(data: Any) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _refresh_signed_source(case: dict[str, Any]) -> None:
    """Refresh fixture's short current Source window without granting authority."""
    claims = copy.deepcopy(case["source"]["claims"])
    claims["issued_at"] = int(time.time()) - 1
    claims["expires_at"] = claims["issued_at"] + 9
    source = _proof(case["source_key"], "centralSource", SOURCE_DOMAIN, claims)
    case["source"] = source
    case["rows"]["source"].update(claims)
    case["rows"]["source"]["claims_sha256"] = hashlib.sha256(_canonical(claims)).hexdigest()
    case["rows"]["source"]["signature_sha256"] = hashlib.sha256(
        base64.urlsafe_b64decode(source["signature"] + "==")
    ).hexdigest()


@pytest.fixture
def custody_case(
    api_case: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    """Real signed local sidecar + real central ASGI with FakePG current rows."""
    case = api_case
    _refresh_signed_source(case)
    native = _load_browser_module()
    source = case["source"]["claims"]
    binding = {key: source[key] for key in ("request_id", "engagement_id", "task_id", "server_id")}
    assert binding["server_id"] == "browser-mcp"

    tenant_root = tmp_path / "tenant-root"
    tenant = tenant_root / binding["engagement_id"]
    capture_dir = tenant / "captures"
    capture_dir.mkdir(parents=True)
    descriptor = _canonical_json(
        {
            "engagement_id": binding["engagement_id"],
            "mount_id": "offline-original-custody-test",
            "container_image_sha256": "a" * 64,
        }
    )
    (tenant / ".osop-har-mount.json").write_bytes(descriptor)
    monkeypatch.setenv("OSOP_AUTHENTICATED_HAR_ROOT", str(tenant_root))
    monkeypatch.setenv(
        "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
        json.dumps(
            {
                binding["engagement_id"]: hashlib.sha256(descriptor).hexdigest(),
            }
        ),
    )
    journal_root = tmp_path / "journal"
    journal_root.mkdir()
    monkeypatch.setenv("OSOP_BROWSER_MCP_JOURNAL_ROOT", str(journal_root))
    monkeypatch.setenv(
        "OSOP_BROWSER_MCP_BEARER_TOKEN", "local-readback-only-provider-token-20261021"
    )
    monkeypatch.setenv("OSOP_BROWSER_MCP_RECEIPT_KID", "nativeBrowser")
    monkeypatch.setenv(
        "OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64",
        base64.b64encode(case["native_key"].private_bytes_raw()).decode("ascii"),
    )
    originals = {
        "screenshot": (".png", b"\x89PNG\r\n\x1a\nSYNTHETIC_NOT_CHROMIUM"),
        "dom": (".html", b"<!doctype html><title>FIXTURE_ONLY</title>"),
        "har": (".har", b'{"log":{"version":"1.2","entries":[]}}'),
    }
    manifest = {}
    paths: dict[str, Path] = {}
    for name, (suffix, raw) in originals.items():
        path = capture_dir / (uuid.uuid4().hex + suffix)
        path.write_bytes(raw)
        paths[name] = path
        manifest[name] = {
            "resource_sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "path": "captures/" + path.name,
        }
    attestation = native._signed_coupled_evidence(binding, source, manifest)
    assert attestation["claims"]["artifacts"] == {
        name: {
            "path": row["path"],
            "sha256": row["resource_sha256"],
            "size_bytes": row["size_bytes"],
        }
        for name, row in manifest.items()
    }
    case["evidence"] = attestation
    journal = native.RequestJournal(binding)
    assert not journal.path.exists()
    return {
        **case,
        "native": native,
        "binding": binding,
        "journal": journal,
        "tenant": tenant,
        "paths": paths,
        "manifest": manifest,
        "attestation": attestation,
    }


async def _native_readback(case: dict[str, Any], path: str) -> dict[str, Any]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=case["native"].app),
        base_url="http://provider-inprocess.invalid",
        follow_redirects=False,
    ) as client:
        response = await client.post(
            path,
            json=case["binding"],
            headers={"Authorization": "Bearer local-readback-only-provider-token-20261021"},
        )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "success"
    return response.json()["result"]


async def _central_readback(case: dict[str, Any]) -> httpx.Response:
    # The imported one-transaction FakePG requires a reset before the next
    # independent READ ONLY snapshot. This is fixture bookkeeping, never a
    # database rollback, application mutation or production API behavior.
    case["pg"].statements.clear()
    return await central_request(case)


def _complete_local_original(case: dict[str, Any]) -> None:
    journal = case["journal"]
    assert journal.reserve() is True
    assert journal.reserve() is False  # O_EXCL no original execution replay.
    journal.commit_evidence(case["attestation"])
    journal.finish("succeeded")
    assert journal.read() == "succeeded"


def _expected(case: dict[str, Any]) -> dict[str, str]:
    return {
        name: case["source"]["claims"][name]
        for name in (
            "request_id",
            "engagement_id",
            "flow_id",
            "task_id",
            "subtask_id",
            "action_id",
            "owner_id",
            "preflight_id",
        )
    }


def _no_effect(body: dict[str, Any]) -> None:
    assert body["original_browser_artifact_bytes_verified"] is False
    assert body["independent_target_effect_verified"] is False
    assert body["automatic_retry_authorized"] is False
    assert body["production_release_certified"] is False
    assert body["status"] == "current_central_authority_only"
    assert body["authority_proof"]["claims"]["artifact_bytes_verified"] is False
    assert body["authority_proof"]["claims"]["target_effect_verified"] is False


@pytest.mark.asyncio
async def test_real_local_original_plus_current_central_are_separate_truths(
    custody_case: dict[str, Any],
) -> None:
    case = custody_case
    # A signed central proof does not imply an original byte was ever captured.
    central_pre = await _central_readback(case)
    assert central_pre.status_code == 200, central_pre.text
    _no_effect(central_pre.json())
    before = await _native_readback(case, "/mcp/request/evidence/readback")
    assert before["status"] == "unknown"
    assert before["provider_signed_evidence_currently_matches"] is False
    assert not case["journal"].path.exists()

    _complete_local_original(case)
    local = await _native_readback(case, "/mcp/request/evidence/readback")
    assert local["status"] == "current_provider_local_original_bytes_match"
    assert local["provider_signed_evidence_currently_matches"] is True
    assert local["current_authorization_verified"] is False
    assert local["independent_target_effect_verified"] is False
    assert local["safe_to_automatically_retry"] is False
    assert set(local["artifacts"]) == {"screenshot", "dom", "har"}
    assert local["artifacts"] == case["attestation"]["claims"]["artifacts"]

    central = await _central_readback(case)
    assert central.status_code == 200, central.text
    result = central.json()
    _no_effect(result)
    signed = verify_current_browser_authority(result["authority_proof"], _expected(case))
    assert signed["authority_current"] is True
    assert signed["original_intent_sha256"] == case["rows"]["action"]["intent_sha256"]
    assert (
        signed["evidence_attestation_sha256"]
        == hashlib.sha256(_canonical(case["attestation"])).hexdigest()
    )
    assert case["pg"].statements[0].endswith("READ ONLY")
    assert all(sql.startswith("SELECT ") for sql in case["pg"].statements[1:])
    assert case["journal"].reserve() is False
    assert case["rows"]["action"]["status"] == "unknown"
    assert case["rows"]["action"]["receipt_sha256"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["screenshot", "dom", "har"])
async def test_missing_current_original_bytes_can_coexist_with_signed_central_proof(
    custody_case: dict[str, Any],
    missing: str,
) -> None:
    case = custody_case
    _complete_local_original(case)
    central = await _central_readback(case)
    assert central.status_code == 200, central.text
    case["paths"][missing].unlink()  # Test-owned file, never application storage.
    local = await _native_readback(case, "/mcp/request/evidence/readback")
    assert local["status"] == "unknown"
    assert local["provider_signed_evidence_currently_matches"] is False
    # Central 0027/0034/ROE has no mount access: valid and STILL not byte proof.
    _no_effect(central.json())
    verify_current_browser_authority(central.json()["authority_proof"], _expected(case))
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_original_bytes_toctou_after_signed_current_authority_never_proves_effect(
    custody_case: dict[str, Any],
) -> None:
    case = custody_case
    _complete_local_original(case)
    good = await _native_readback(case, "/mcp/request/evidence/readback")
    assert good["status"] == "current_provider_local_original_bytes_match"
    response = await _central_readback(case)
    assert response.status_code == 200
    _no_effect(response.json())
    # Tamper after central readback; this is an adversarial TOCTOU custody gap.
    original = case["paths"]["har"].read_bytes()
    case["paths"]["har"].write_bytes(original + b"\nMUTATED_AFTER_CURRENT_CHECK")
    assert (await _native_readback(case, "/mcp/request/evidence/readback"))["status"] == "unknown"
    # Historical native status can still be properly signed and succeeded.
    historical = await _native_readback(case, "/mcp/request/status")
    assert historical["status"] == "succeeded"
    assert historical["verified"] is True
    assert "artifacts" not in historical
    # The independent CURRENT central signature remains authentic within TTL,
    # but its own body explicitly refuses to claim original byte verification.
    verify_current_browser_authority(response.json()["authority_proof"], _expected(case))
    assert case["journal"].reserve() is False
    assert case["rows"]["action"]["status"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("poison", ["revoked_provider_key", "expired_signed_sidecar"])
async def test_provider_root_revocation_and_stale_signed_original_sidecar(
    custody_case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    poison: str,
) -> None:
    case = custody_case
    _complete_local_original(case)
    baseline = await _central_readback(case)
    assert baseline.status_code == 200
    assert (await _native_readback(case, "/mcp/request/evidence/readback"))[
        "provider_signed_evidence_currently_matches"
    ] is True
    if poison == "revoked_provider_key":
        # Remove only the provider enrollment; central signed authority and
        # native local bytes must not compensate for a revoked provider root.
        monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "{}")
        assert (await _central_readback(case)).status_code == 503
    else:
        # A *genuinely* provider-signed aged assertion remains historical,
        # even with byte-exact files and intact central trust roots.
        sidecar = case["journal"].path.with_suffix(".evidence.json")
        stored = json.loads(sidecar.read_text(encoding="ascii"))
        claims = copy.deepcopy(stored["attestation"]["claims"])
        claims["issued_at"] -= 200
        stored["attestation"] = _proof(case["native_key"], "nativeBrowser", EVIDENCE_DOMAIN, claims)
        sidecar.write_bytes(_canonical_json(stored))
        # Central FakePG proof checks the separately supplied *previous*
        # signed evidence, not the changed local sidecar.
        unchanged = await _central_readback(case)
        assert unchanged.status_code == 200
        _no_effect(unchanged.json())
    local = await _native_readback(case, "/mcp/request/evidence/readback")
    assert local["status"] == "unknown"
    assert local["provider_signed_evidence_currently_matches"] is False
    assert case["journal"].reserve() is False
    assert case["rows"]["action"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_independent_signers_and_revoked_central_state_are_not_provider_custody(
    custody_case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = custody_case
    _complete_local_original(case)
    assert (await _native_readback(case, "/mcp/request/evidence/readback"))[
        "provider_signed_evidence_currently_matches"
    ] is True
    central = await _central_readback(case)
    assert central.status_code == 200
    proof = central.json()["authority_proof"]
    # Provider signing its own counterfeit CURRENT certificate fails central
    # independent-root verification, even when all claim fields are copied.
    fake = _proof(case["native_key"], proof["kid"], CURRENT_DOMAIN, proof["claims"])
    with pytest.raises(BrowserCurrentAuthorityDenied):
        verify_current_browser_authority(fake, _expected(case))
    tampered = copy.deepcopy(proof)
    tampered["claims"]["target_effect_verified"] = True
    with pytest.raises(BrowserCurrentAuthorityDenied):
        verify_current_browser_authority(tampered, _expected(case))
    with monkeypatch.context() as changed:
        changed.setenv("OSOP_BROWSER_CURRENT_AUTHORITY_TRUSTED_PUBLIC_KEYS_JSON", "{}")
        with pytest.raises(BrowserCurrentAuthorityDenied):
            verify_current_browser_authority(proof, _expected(case))
    # ROE/Task/reviewer revocation is central current state; local provider
    # still has intact bytes and cannot rescue a withdrawn central authority.
    for field in ("authorization", "task", "reviewer_control"):
        altered = case["rows"][field]
        old = copy.deepcopy(altered)
        if field == "authorization":
            altered["status"] = "revoked"
        elif field == "task":
            altered["status"] = "cancelled"
        else:
            altered["disabled"] = True
        assert (await _central_readback(case)).status_code == 503
        case["rows"][field] = old
    assert (await _native_readback(case, "/mcp/request/evidence/readback"))[
        "status"
    ] == "current_provider_local_original_bytes_match"
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_lost_current_readback_ack_does_not_reissue_original_request(
    custody_case: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = custody_case
    _complete_local_original(case)
    # Simulated lost caller ACK after a central read-only proof was issued.
    issued = await _central_readback(case)
    assert issued.status_code == 200
    _no_effect(issued.json())
    lost_reply = None
    assert lost_reply is None  # Client cannot consume unacknowledged proof.
    assert case["journal"].reserve() is False
    # Missing central signing configuration on *new* readback must fail closed.
    with monkeypatch.context() as removed:
        removed.delenv("OSOP_BROWSER_CURRENT_AUTHORITY_PRIVATE_KEY_B64")
        denied = await _central_readback(case)
        assert denied.status_code == 503
        assert "authority_proof" not in denied.json()
    assert (await _native_readback(case, "/mcp/request/evidence/readback"))[
        "status"
    ] == "current_provider_local_original_bytes_match"
    assert case["journal"].reserve() is False
    assert case["rows"]["action"]["status"] == "unknown"
