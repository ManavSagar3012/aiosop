"""Owned real offline Chromium with a *stub central* signed Browser preflight.

Actual Playwright + loopback page + provider evidence, but no source PostgreSQL:
the central source authorization response is independently signed fake data.
Do not represent this test as an end-to-end ROE/Task admission certificate.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from tests.qualification.native_browser_local_helper_20261020 import (
    ENGAGEMENT,
    LABEL,
    TASK,
    native_browser_local,
)
from tests.test_browser_signed_source_preflight_20261020 import (
    SOURCE_KID,
    SOURCE_TOKEN,
    SOURCE_URL,
    _signed_reply,
)
from tests.test_native_browser_source_authority_20261020 import (
    Ledger,
    make_authority,
    original_row,
)
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    _DIGEST_DOMAIN,
    _digest,
)


def _request(request_id: str, url: str, action: str = "navigate") -> dict:
    return {
        "tool_name": "execute",
        "request_id": request_id,
        "execution_binding": {
            "request_id": request_id,
            "engagement_id": ENGAGEMENT,
            "task_id": TASK,
            "server_id": "browser-mcp",
        },
        "parameters": {"action": action, "url": url, "user_label": LABEL},
    }


@pytest.mark.asyncio
async def test_real_chromium_offline_navigation_source_signature_and_redirect_fence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch) as native:
        # The remote source is replaced with a deterministic signed stub; only
        # Chromium's owned loopback GET is real. TLS config is nevertheless
        # explicitly verified by the native preflight implementation.
        signer = Ed25519PrivateKey.generate()
        pub = signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        cert_key = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "offline-central")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(cert_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=15))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(cert_key, algorithm=None)
        )
        bundle = tmp_path / "independent-offline-test-ca.pem"
        bundle.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        monkeypatch.setenv("OSOP_BROWSER_SOURCE_URL", SOURCE_URL)
        monkeypatch.setenv("OSOP_BROWSER_SOURCE_CA_BUNDLE", str(bundle))
        monkeypatch.setenv("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", SOURCE_TOKEN)
        monkeypatch.setenv(
            "OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
            json.dumps({SOURCE_KID: base64.b64encode(pub).decode("ascii")}),
        )
        original_httpx = native.native.httpx
        calls: list[dict] = []

        class FakeCentral:
            def __init__(self, **kwargs):
                assert kwargs["verify"] == str(bundle)
                assert kwargs["follow_redirects"] is False
                assert kwargs["trust_env"] is False

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, url, *, json, headers):
                assert url == SOURCE_URL
                assert headers["Authorization"] == f"Bearer {SOURCE_TOKEN}"
                calls.append(dict(json))
                return httpx.Response(200, json=_signed_reply(signer, json))

        monkeypatch.setattr(
            native.native,
            "httpx",
            SimpleNamespace(AsyncClient=FakeCentral, Timeout=original_httpx.Timeout),
        )
        failures = []
        original_redeem = native.native._redeem_browser_navigation_source

        async def observe_source_failure(*args):
            try:
                return await original_redeem(*args)
            except ValueError as exc:
                failures.append((str(exc), str(exc.__cause__)))
                raise

        monkeypatch.setattr(
            native.native, "_redeem_browser_navigation_source", observe_source_failure
        )
        async with native.client() as client:
            request_id = "req-signed-local-source-1"
            succeeded = await client.post(
                "/mcp/execute",
                json=_request(request_id, native.base_url + "/"),
                headers=native.headers(),
            )
            assert succeeded.status_code == 200
            assert succeeded.json()["status"] == "success", {
                "preflight_errors": failures,
                "source_calls": calls,
                "page_hits": native.page_hits,
                "journal": native.native.RequestJournal(
                    _request(request_id, "")["execution_binding"]
                ).read(),
            }
            assert succeeded.json()["provider_receipt"]["status"] == "succeeded"
            assert native.page_hits == ["/"]
            assert len(calls) == 1
            assert calls[0]["request_id"] == request_id

            duplicate = await client.post(
                "/mcp/execute",
                json=_request(request_id, native.base_url + "/"),
                headers=native.headers(),
            )
            assert duplicate.json()["status"] == "duplicate_request"
            assert len(calls) == 1 and native.page_hits == ["/"]

            redirect_id = "req-signed-local-source-302"
            denied = await client.post(
                "/mcp/execute",
                json=_request(redirect_id, native.base_url + "/redirect"),
                headers=native.headers(),
            )
            assert denied.json()["status"] == "error"
            assert "provider_receipt" not in denied.json()
            assert (
                native.native.RequestJournal(_request(redirect_id, "")["execution_binding"]).read()
                == "unknown"
            )
            assert native.page_hits.count("/redirect") == 1

            # A distinct consequential operation requires its own independent
            # source authority (not the successful navigation from above).
            unreviewed = await client.post(
                "/mcp/execute",
                json=_request("req-signed-local-click", "", "click"),
                headers=native.headers(),
            )
            assert unreviewed.json()["status"] == "error"
            assert "provider_receipt" not in unreviewed.json()
        assert len(calls) == 2


@pytest.mark.asyncio
async def test_real_chromium_through_actual_mounted_central_source_asgi_with_fake_pg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Joined real Browser/central FastAPI/Ed25519 with ONLY fake PostgreSQL.

    The HTTPS native HTTPX transport is replaced by in-process ASGI here.
    This demonstrates original 0027 Action identity and durable one-shot
    *model* integration, not real TLS/Postgres multi-replica certification.
    """
    from fastapi import FastAPI
    from ai_osop.api.routers import native_browser_source_authority as central

    async with native_browser_local(tmp_path, monkeypatch) as native:
        approved_url = native.base_url + "/"
        row = original_row()
        row["engagement_id"] = ENGAGEMENT
        row["task_id"] = TASK
        row["safe_parameters"] = {
            "url": approved_url,
            "action": "navigate",
            "user_label": LABEL,
        }
        row["parameters_sha256"] = FlowMCPActionStore.parameters_sha256(row["safe_parameters"])
        binding = {
            "engagement_id": row["engagement_id"],
            "flow_id": row["flow_id"],
            "revision": row["flow_revision"],
            "version": row["authorization_version"],
            "authorization_id": row["authorization_id"],
            "authorization_sha256": row["authorization_sha256"],
        }
        intent = {
            **binding,
            **{
                k: row[k]
                for k in (
                    "task_id",
                    "subtask_id",
                    "action_id",
                    "owner_id",
                    "approval_id",
                    "lease_id",
                    "lease_owner_id",
                    "server_id",
                    "tool_name",
                    "side_effect_class",
                    "declaration_sha256",
                    "parameters_sha256",
                )
            },
        }
        row["intent_sha256"] = _digest(_DIGEST_DOMAIN, intent, 4096)
        row["request_id"] = "req-" + row["intent_sha256"][:48]
        ledger = Ledger(row)
        ledger.clock = int(time.time())
        authority, actions = make_authority(ledger)
        actions._authority.return_value["scope"] = {
            "engagement_id": ENGAGEMENT,
            "ips": ["127.0.0.1"],
        }
        monkeypatch.setattr(central, "FlowMCPActionStore", lambda *_: actions)
        monkeypatch.setattr(
            central,
            "state",
            {"orchestrator": SimpleNamespace(session_memory=object(), mcp_registry=object())},
        )
        central_app = FastAPI()
        central_app.include_router(central.router)

        signer = Ed25519PrivateKey.generate()
        signing_seed = signer.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public = signer.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        monkeypatch.setenv("OSOP_BROWSER_SOURCE_SIGNING_KID", SOURCE_KID)
        monkeypatch.setenv(
            "OSOP_BROWSER_SOURCE_SIGNING_PRIVATE_KEY_B64",
            base64.b64encode(signing_seed).decode("ascii"),
        )
        monkeypatch.setenv(
            "OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
            json.dumps({SOURCE_KID: base64.b64encode(public).decode("ascii")}),
        )
        monkeypatch.setenv("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", SOURCE_TOKEN)
        monkeypatch.setenv("OSOP_BROWSER_SOURCE_URL", SOURCE_URL)
        # Native requires an independently specified root; this stand-in
        # cannot establish a real TLS session. Live TLS is separately tested.
        certificate_key = Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "joined-test-ca")])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(certificate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(minutes=10))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(certificate_key, algorithm=None)
        )
        bundle = tmp_path / "joined-mock-transport-ca.pem"
        bundle.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        monkeypatch.setenv("OSOP_BROWSER_SOURCE_CA_BUNDLE", str(bundle))
        actual_httpx = native.native.httpx
        outbound_calls: list[dict] = []

        class JoinedInProcessCentral:
            def __init__(self, **kwargs):
                assert kwargs["verify"] == str(bundle)
                assert kwargs["trust_env"] is False
                assert kwargs["follow_redirects"] is False

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return None

            async def post(self, url, *, json, headers):
                assert url == SOURCE_URL
                outbound_calls.append(dict(json))
                async with actual_httpx.AsyncClient(
                    transport=actual_httpx.ASGITransport(app=central_app),
                    base_url="https://central-owned.invalid",
                ) as client:
                    return await client.post(
                        "/native-browser/source-preflight",
                        json=json,
                        headers=headers,
                    )

        monkeypatch.setattr(
            native.native,
            "httpx",
            SimpleNamespace(AsyncClient=JoinedInProcessCentral, Timeout=actual_httpx.Timeout),
        )
        async with native.client() as browser_client:
            operation = _request(row["request_id"], approved_url)
            succeeded = await browser_client.post(
                "/mcp/execute",
                json=operation,
                headers=native.headers(),
            )
            assert succeeded.status_code == 200
            assert succeeded.json()["status"] == "success"
            assert succeeded.json()["provider_receipt"]["status"] == "succeeded"
            assert len(ledger.committed) == 1
            assert ledger.committed[row["request_id"]]["action_id"] == row["action_id"]
            assert native.page_hits == ["/"]
            assert len(outbound_calls) == 1
            repeated = await browser_client.post(
                "/mcp/execute",
                json=operation,
                headers=native.headers(),
            )
            assert repeated.json()["status"] == "duplicate_request"
            assert len(outbound_calls) == 1 and native.page_hits == ["/"]
            # Distinct native caller label could never borrow this exact
            # committed central admission or change approved Browser identity.
            changed = _request("req-" + "f" * 48, approved_url)
            changed["parameters"]["user_label"] = "swapped-reviewer"
            denied = await browser_client.post(
                "/mcp/execute",
                json=changed,
                headers=native.headers(),
            )
            assert denied.json()["status"] == "error"
            assert len(ledger.committed) == 1 and native.page_hits == ["/"]
