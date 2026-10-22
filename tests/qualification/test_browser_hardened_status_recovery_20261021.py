"""Offline Browser status recovery and evidence integrity qualification.

REAL: production native HTTP handlers, Ed25519 provider and coupled evidence
signatures, original screenshot/DOM/HAR from cached headless Chromium, durable
local request journal, and central 0034 FastAPI source admission code.
SIMULATED: PostgreSQL/0027 Flow, Task, approval, revocation and 0034 INSERT use
the existing FakePG fixture; the central HTTPS connection uses ASGITransport.
No app DB, Docker, external network, targets or paid provider is contacted.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied
from tests.qualification.native_browser_local_helper_20261020 import (
    ENGAGEMENT,
    FOREIGN,
    TASK,
    native_browser_local,
    real_chromium_executable,
)
from tests.qualification.test_browser_full_evidence_source_contract_20261020 import (
    _REAL_HTTP,
    _body,
    _central,
    _install_source,
    _native_payload,
    _original_case,
    _verify_coupled_evidence,
)


def _signed_status_is_bound(receipt: Any, binding: dict[str, str]) -> bool:
    return provider_receipt_is_signed(
        receipt,
        binding["server_id"],
        binding["request_id"],
        binding["engagement_id"],
        binding["task_id"],
    )


@pytest.mark.asyncio
async def test_original_capture_status_recovery_is_strictly_bound_and_no_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real owned Chromium capture, then persisted status and malicious recovery."""
    executable, reason = await real_chromium_executable()
    if executable is None:
        pytest.skip(reason)
    async with native_browser_local(tmp_path, monkeypatch) as native:
        target = native.base_url + "/"
        ledger = _original_case(target)
        central, actions, _issuer = _install_source(tmp_path, monkeypatch, ledger, native)
        original_request = _body(ledger, target)
        payload = _native_payload(ledger, target)
        binding = payload["execution_binding"]

        # Mutate what the fake 0027 database returns, not the caller's Flow
        # claim: native's source request contains no caller-specified Flow ID.
        original_flow = ledger.row["flow_id"]
        ledger.row["flow_id"] = "flow-forged-different-flow"
        try:
            wrong_flow = await _central(central, original_request)
            assert wrong_flow.status_code == 409
        finally:
            ledger.row["flow_id"] = original_flow

        for changed in (
            {**original_request, "task_id": "task-other-flow"},
            {**original_request, "url_sha256": hashlib.sha256((target + "?unexpected=1").encode()).hexdigest()},
        ):
            refusal = await _central(central, changed)
            assert refusal.status_code == 409

        actions._approved_task.side_effect = MCPActionDenied(403, "Reviewer revoked")
        try:
            revoked = await _central(central, original_request)
            assert revoked.status_code == 409
        finally:
            actions._approved_task.side_effect = None
        assert not ledger.committed
        assert not native.page_hits

        # _install_source replaces the module-level httpx.AsyncClient for the
        # native central TLS bridge; retain the original client for the local
        # native HTTP ASGI entrypoint.
        async with _REAL_HTTP(
            transport=httpx.ASGITransport(app=native.native.app),
            base_url="http://browser-mcp-local-only.invalid",
            timeout=30.0,
            follow_redirects=False,
        ) as client:
            completed_response = await client.post(
                "/mcp/execute", json=payload, headers=native.headers()
            )
            assert completed_response.status_code == 200
            completed = completed_response.json()
            assert completed["status"] == "success", completed
            _verify_coupled_evidence(native, completed["result"], binding["request_id"])
            assert _signed_status_is_bound(completed["provider_receipt"], binding)
            assert native.page_hits == ["/"]
            assert len(ledger.committed) == 1
            assert ledger.row["status"] == "unknown"  # Central 0027 is not reconciled.

            recovered_response = await client.post(
                "/mcp/request/status", json=binding, headers=native.headers()
            )
            assert recovered_response.status_code == 200
            recovered = recovered_response.json()["result"]
            assert recovered["status"] == "succeeded"
            assert recovered["verified"] is True and recovered["stopped"] is True
            assert _signed_status_is_bound(recovered, binding)
            # A status receipt never claims the original artifact hashes.
            assert not {"evidence", "artifacts", "evidence_attestation"}.intersection(recovered)

            for mismatch in (
                {**binding, "request_id": "req-another-original"},
                {**binding, "task_id": "task-another-original"},
                {**binding, "engagement_id": FOREIGN},
                {**binding, "server_id": "source-map-mcp"},
            ):
                wrong = await client.post(
                    "/mcp/request/status", json=mismatch, headers=native.headers()
                )
                assert wrong.status_code == 200
                result = wrong.json()["result"]
                assert result["status"] == "unknown" and result["verified"] is False
                assert "attestation" not in result

            no_bearer = await client.post("/mcp/request/status", json=binding)
            assert no_bearer.status_code == 401

            for changed_field, substitute in (
                ("request_id", "req-counterfeit"),
                ("task_id", "task-counterfeit"),
                ("status", "failed"),
                ("verified", False),
            ):
                tampered = copy.deepcopy(recovered)
                tampered[changed_field] = substitute
                assert not _signed_status_is_bound(tampered, binding)

            # The original artifact bytes are independently checkable. If
            # storage subsequently changes, the old signed provider status
            # remains only a HISTORICAL status assertion, not fresh SHA proof.
            har = completed["result"]["evidence"]["har"]
            har_path = native.tenant / har["path"]
            har_path.write_bytes(har_path.read_bytes() + b"\nPOST_CAPTURE_CORRUPTION")
            assert hashlib.sha256(har_path.read_bytes()).hexdigest() != har["resource_sha256"]
            historical = (
                await client.post(
                    "/mcp/request/status", json=binding, headers=native.headers()
                )
            ).json()["result"]
            assert _signed_status_is_bound(historical, binding)
            assert "artifacts" not in historical

            # A tampered/corrupt local journal is UNKNOWN, never recreated or
            # silently accepted as an alternate request to sign a receipt for.
            journal = native.native.RequestJournal(binding)
            assert journal.read() == "succeeded"
            for poison in (
                {"binding": {**binding, "task_id": "task-forged"}, "status": "succeeded"},
                '{"binding":{},"status":"unknown","status":"succeeded"}',
                '{"binding":{},"status":"succeeded","junk":"' + "x" * 2500 + '"}',
                "{",
            ):
                journal.path.write_text(
                    poison if isinstance(poison, str) else json.dumps(poison),
                    encoding="utf-8",
                )
                checked = (
                    await client.post(
                        "/mcp/request/status", json=binding, headers=native.headers()
                    )
                ).json()["result"]
                assert checked["status"] == "unknown"
                assert checked["verified"] is False
                assert "attestation" not in checked
                refused_replay = await client.post(
                    "/mcp/execute", json=payload, headers=native.headers()
                )
                assert refused_replay.json()["status"] == "duplicate_request"
                assert native.page_hits == ["/"]
                assert len(ledger.committed) == 1

        assert native.blocked == []
        assert all("clients2.google.com/time" in url for url in native.proxy_attempts)
