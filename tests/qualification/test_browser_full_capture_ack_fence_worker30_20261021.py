"""Offline full-capture source ACK-uncertainty qualification; no Docker/DB.

REAL: Browser native FastAPI handler, mounted central FastAPI router and
BrowserSourceAuthorityStore, short-lived Ed25519 source signing/verification,
durable-on-filesystem Browser RequestJournal, actual cached Chromium process,
owned 127.0.0.1 listeners and denied external network through the local proxy.

SIMULATED: central PostgreSQL uses FakePG/Ledger from the prior qualification.
That fixture's current signed Flow/reviewer/lease authority callbacks are
AsyncMocks, not real database proofs or a migrated 0034 ledger. The central
HTTPS hop is an in-process ASGITransport, NOT a TLS handshake. An intercepted
response simulates either a lost ACK after central commit or an invalid source
signature. No app database, Docker, external targets, or paid providers.

The other worker's test_browser_full_capture_join_20261021.py already exists
in the shared dirty worktree; do not modify or execute its Docker fixture here.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.qualification.native_browser_local_helper_20261020 import (
    ENGAGEMENT,
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
)


class _OneShotResponseFailure(httpx.ASGITransport):
    """Invoke the REAL central router once, then corrupt or discard its ACK."""

    def __init__(self, *, app: Any, fault: str) -> None:
        super().__init__(app=app)
        assert fault in {"ack_lost", "signature_invalid"}
        self.fault = fault
        self.source_posts = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/native-browser/source-preflight"
        assert request.url.host == "authority.full-evidence.invalid"
        self.source_posts += 1
        response = await super().handle_async_request(request)
        # The source already performed and committed its one-time admission.
        assert response.status_code == 200
        source = json.loads(await response.aread())
        assert source["claims"]["evidence_mode"] == "screenshot_dom_har"
        assert len(source["claims"]) == 22
        await response.aclose()
        if self.fault == "ack_lost":
            raise httpx.ReadError("QUALIFICATION: ACK lost AFTER central commit", request=request)
        # Preserve binding but invalidate the cryptographic signature.
        signature = source["signature"]
        source["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]
        return httpx.Response(
            200,
            json=source,
            headers={"Content-Type": "application/json"},
            request=request,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["ack_lost", "signature_invalid"])
async def test_original_full_capture_no_replay_or_ack_after_source_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    """A committed one-shot source decision cannot be retried after ACK loss."""
    executable, status = await real_chromium_executable()
    if executable is None:
        pytest.skip(status)
    async with native_browser_local(tmp_path, monkeypatch) as native:
        target = native.base_url + "/"
        ledger = _original_case(target)
        central, actions, issuer = _install_source(tmp_path, monkeypatch, ledger, native)
        assert issuer is not None
        original = _body(ledger, target)
        payload = _native_payload(ledger, target)

        # Separate CA, independent native and source bearers, original consent.
        expected_ca = os.environ["OSOP_BROWSER_SOURCE_CA_BUNDLE"]
        assert os.environ["OSOP_BROWSER_MCP_BEARER_TOKEN"] != (
            os.environ["OSOP_BROWSER_SOURCE_SERVICE_TOKEN"]
        )
        fault_transport = _OneShotResponseFailure(app=central, fault=fault)

        def bridged_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            assert kwargs["verify"] == expected_ca
            assert kwargs["follow_redirects"] is False
            assert kwargs["trust_env"] is False
            return _REAL_HTTP(
                transport=fault_transport,
                verify=False,  # In-process ASGI; NOT an actual TLS test.
                follow_redirects=False,
                trust_env=False,
                timeout=kwargs["timeout"],
            )

        monkeypatch.setattr(native.native.httpx, "AsyncClient", bridged_client)
        async with _REAL_HTTP(
            transport=httpx.ASGITransport(app=native.native.app),
            base_url="http://owned-browser-only.invalid",
            timeout=15.0,
        ) as client:
            init = await client.post(
                "/mcp/initialize",
                json={"session_id": ENGAGEMENT},
                headers=native.headers(),
            )
            assert init.status_code == 200
            assert "mcp_request_status_v1" in init.json()["capabilities"]

            first = await client.post(
                "/mcp/execute",
                json=payload,
                headers=native.headers(),
            )
            assert first.status_code == 200
            assert first.json()["status"] == "error"
            assert "provider_receipt" not in first.json()
            assert "evidence_attestation" not in first.text
            assert fault_transport.source_posts == 1

            # FakePG 0034 INSERT committed, but Browser never got trusted ACK.
            assert len(ledger.committed) == 1
            committed = ledger.committed[ledger.row["request_id"]]
            assert committed["request_id"] == original["request_id"]
            assert committed["action_id"] == ledger.row["action_id"]
            assert committed["evidence_mode"] == "screenshot_dom_har"
            assert committed["url_sha256"] == original["url_sha256"]
            assert committed["kid"] == os.environ["OSOP_BROWSER_SOURCE_SIGNING_KID"]
            assert ledger.row["status"] == "unknown"
            assert native.native.RequestJournal(payload["execution_binding"]).read() == "unknown"
            assert native.page_hits == []
            captures = native.tenant / "captures"
            assert not captures.exists() or not list(captures.glob("*"))

            status_response = await client.post(
                "/mcp/request/status",
                json=payload["execution_binding"],
                headers=native.headers(),
            )
            assert status_response.status_code == 200
            status_data = status_response.json()
            assert status_data["result"]["status"] == "unknown"
            assert status_data["result"]["verified"] is False
            assert "attestation" not in status_data["result"]

            replay = await client.post(
                "/mcp/execute",
                json=payload,
                headers=native.headers(),
            )
            assert replay.status_code == 200
            assert replay.json()["status"] == "duplicate_request"
            assert "provider_receipt" not in replay.json()
            assert fault_transport.source_posts == 1
            assert native.page_hits == []
        central_replay = await _central(central, original)
        assert central_replay.status_code == 409
        assert len(ledger.committed) == 1
        assert actions._authority.await_count >= 1
        assert all("clients2.google.com/time" in item for item in native.proxy_attempts)
