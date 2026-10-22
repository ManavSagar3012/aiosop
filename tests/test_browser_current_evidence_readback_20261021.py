"""Original capture byte readback against one-shot provider-signed sidecar.

Real offline Chromium and provider ASGI, controlled synthetic central 0034
database admission; no app DB, external targets, Docker or billable providers.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.qualification.native_browser_local_helper_20261020 import (
    native_browser_local,
    real_chromium_executable,
)
from tests.qualification.test_browser_full_evidence_source_contract_20261020 import (
    _REAL_HTTP,
    _body,
    _install_source,
    _native_payload,
    _original_case,
)


async def _readback(client: httpx.AsyncClient, binding: dict[str, str], headers: dict[str, str]):
    response = await client.post("/mcp/request/evidence/readback", json=binding, headers=headers)
    assert response.status_code == 200
    return response.json()["result"]


@pytest.mark.asyncio
async def test_owned_chromium_current_bytes_authentication_and_tamper_no_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, reason = await real_chromium_executable()
    if executable is None:
        pytest.skip(reason)
    async with native_browser_local(tmp_path, monkeypatch) as native:
        url = native.base_url + "/"
        ledger = _original_case(url)
        _central, _actions, _issuer = _install_source(tmp_path, monkeypatch, ledger, native)
        payload = _native_payload(ledger, url)
        binding = payload["execution_binding"]
        journal = native.native.RequestJournal(binding)
        # Prior to original navigation there is no readback and no status
        # observation may reserve/replay the original request on its behalf.
        async with _REAL_HTTP(
            transport=httpx.ASGITransport(app=native.native.app),
            base_url="http://browser-owned-original.invalid",
            timeout=30.0,
        ) as client:
            pre = await _readback(client, binding, native.headers())
            assert pre["status"] == "unknown"
            assert pre["provider_signed_evidence_currently_matches"] is False
            assert not journal.path.exists()
            # Recovery's UNKNOWN fallback is not proof of a committed
            # reservation: no sidecar may be created ahead of the Action.
            with pytest.raises(ValueError, match="must precede terminal"):
                journal.commit_evidence({"claims": {}, "kid": "forged", "signature": "x"})
            assert not journal.path.with_suffix(".evidence.json").exists()
            executed = (
                await client.post("/mcp/execute", json=payload, headers=native.headers())
            ).json()
            assert executed["status"] == "success", executed
            assert native.page_hits == ["/"]
            assert len(ledger.committed) == 1
            assert journal.read() == "succeeded"
            sidecar = journal.path.with_suffix(".evidence.json")
            assert sidecar.is_file()
            assert sidecar.stat().st_size <= native.native._MAX_CAPTURE_EVIDENCE_SIDECAR_BYTES
            current = await _readback(client, binding, native.headers())
            assert current["status"] == "current_provider_local_original_bytes_match"
            assert current["provider_signed_evidence_currently_matches"] is True
            assert current["current_authorization_verified"] is False
            assert current["independent_target_effect_verified"] is False
            assert current["safe_to_automatically_retry"] is False
            assert set(current["artifacts"]) == {"screenshot", "dom", "har"}
            assert (
                current["artifacts"]["har"]["sha256"]
                == executed["result"]["evidence"]["har"]["resource_sha256"]
            )

            for wrong in (
                {**binding, "request_id": "req-foreign-original"},
                {**binding, "task_id": "task-foreign-original"},
                {**binding, "engagement_id": "eng-foreign"},
                {**binding, "server_id": "source-map-mcp"},
            ):
                denied = await _readback(client, wrong, native.headers())
                assert denied["status"] == "unknown"
                assert denied["provider_signed_evidence_currently_matches"] is False
            assert (
                await client.post("/mcp/request/evidence/readback", json=binding)
            ).status_code == 401

            before = sidecar.read_bytes()
            original_sidecar = json.loads(before)
            signed = original_sidecar["attestation"]
            for poison in (
                b'{"binding":{},"attestation":{},"attestation":{}}',
                before + b"x" * 9000,
                json.dumps(
                    {"binding": {**binding, "task_id": "task-foreign"}, "attestation": signed}
                ).encode(),
                json.dumps(
                    {"binding": binding, "attestation": {**signed, "signature": "A" * 86}}
                ).encode(),
            ):
                sidecar.write_bytes(poison)
                denied = await _readback(client, binding, native.headers())
                assert denied["status"] == "unknown"
                assert denied["provider_signed_evidence_currently_matches"] is False
                sidecar.write_bytes(before)

            # A second hardlink is incompatible with immutable, private
            # original evidence, even when the bytes/signature still match.
            sidecar_hardlink = tmp_path / "sidecar-hardlink-fixture.json"
            os.link(sidecar, sidecar_hardlink)
            assert (await _readback(client, binding, native.headers()))["status"] == "unknown"
            sidecar_hardlink.unlink()
            assert (await _readback(client, binding, native.headers()))[
                "status"
            ] == "current_provider_local_original_bytes_match"

            png_path = native.tenant / current["artifacts"]["screenshot"]["path"]
            capture_hardlink = tmp_path / "capture-hardlink-fixture.png"
            os.link(png_path, capture_hardlink)
            assert (await _readback(client, binding, native.headers()))["status"] == "unknown"
            capture_hardlink.unlink()

            # An unenrolled/rotated provider key cannot validate a cached
            # provider-signed evidence sidecar, even with matching file bytes.
            with monkeypatch.context() as isolated:
                isolated.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "{}")
                assert (await _readback(client, binding, native.headers()))["status"] == "unknown"

            # A cancelled/ambiguous local journal cannot be promoted into a
            # completed original capture by a surviving signed evidence file.
            original_journal = journal.path.read_bytes()
            journal.path.write_text(
                json.dumps({"binding": binding, "status": "unknown"}),
                encoding="ascii",
            )
            assert (await _readback(client, binding, native.headers()))["status"] == "unknown"
            journal.path.write_bytes(original_journal)

            # A legitimately signed capture with stale issued_at is historical
            # evidence, not currently reauthenticated original artifact state.
            old_claims = copy.deepcopy(signed["claims"])
            old_claims["issued_at"] -= 200
            encoded = json.dumps(
                old_claims,
                sort_keys=True,
                ensure_ascii=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("ascii")
            signer, _kid = native.native._signer()
            stale = copy.deepcopy(original_sidecar)
            stale["attestation"]["claims"] = old_claims
            stale["attestation"]["signature"] = (
                base64.urlsafe_b64encode(
                    signer.sign(native.native._COUPLED_EVIDENCE_DOMAIN + encoded)
                )
                .decode("ascii")
                .rstrip("=")
            )
            sidecar.write_text(json.dumps(stale), encoding="ascii")
            assert (await _readback(client, binding, native.headers()))["status"] == "unknown"
            sidecar.write_bytes(before)

            # Signed historical provider status is independent of current
            # storage integrity; current readback detects the altered HAR.
            har = native.tenant / current["artifacts"]["har"]["path"]
            original_har = har.read_bytes()
            har.write_bytes(original_har + b"\nTAMPERED")
            assert (
                hashlib.sha256(har.read_bytes()).hexdigest()
                != current["artifacts"]["har"]["sha256"]
            )
            bad = await _readback(client, binding, native.headers())
            assert bad["status"] == "unknown"
            assert bad["provider_signed_evidence_currently_matches"] is False
            historical = (
                await client.post("/mcp/request/status", json=binding, headers=native.headers())
            ).json()["result"]
            assert historical["status"] == "succeeded"
            assert "artifacts" not in historical

            # Neither failed status nor current readback may navigate again.
            repeated = (
                await client.post("/mcp/execute", json=payload, headers=native.headers())
            ).json()
            assert repeated["status"] == "duplicate_request"
            assert native.page_hits == ["/"]
            assert len(ledger.committed) == 1
