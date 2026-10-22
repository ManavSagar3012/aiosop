"""Offline signed full-evidence Browser qualification without Docker or app DB.

REAL: production mounted FastAPI source router, original 0027 source-intent
digest validation, Ed25519 central source and native provider signatures,
native Browser ASGI handler, actual cached headless Playwright Chromium and
original screenshot/DOM/HAR bytes from the owned 127.0.0.1 site.

SIMULATED, NOT REAL POSTGRESQL: existing FakePG transaction/0027 rows in
tests.test_native_browser_source_authority_20261020. Current Flow/reviewer/
lease callbacks in that fixture are fake and revocation checks are simulated.
SIMULATED, NOT HTTPS: native-to-central service hop is an in-process ASGI
transport with independently supplied trust/CA configuration. No TLS handshake.
Nothing here claims a live PG issuer or a production authorization verdict.
This test NEVER attempts Docker, target scans, remote network or paid providers.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI

from ai_osop.api.routers import native_browser_source_authority as source_api
from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from ai_osop.memory.browser_source_authority import DOMAIN, exact_origin, _canonical
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    MCPActionDenied,
    _DIGEST_DOMAIN,
    _digest,
)
from tests.qualification.native_browser_local_helper_20261020 import (
    ENGAGEMENT,
    LABEL,
    TASK,
    native_browser_local,
    real_chromium_executable,
)
from tests.test_native_browser_source_authority_20261020 import Ledger, make_authority, original_row

_REAL_HTTP = httpx.AsyncClient
_SERVICE = "browser-independent-full-evidence-source-service-20261020"
_KID = "browser-full-evidence-issuer"
_PATH = "/native-browser/source-preflight"
_MODE = "screenshot_dom_har"


def _original_case(target: str) -> Ledger:
    """A FAKE PG original 0027 UNKNOWN row with genuine domain-separated SHA.

    The four reviewed parameters cannot be invented at dispatch time, and
    changing even one changes the original request identity.
    """
    row = original_row()
    params = {"url": target, "action": "navigate", "user_label": LABEL, "evidence_mode": _MODE}
    row["engagement_id"] = ENGAGEMENT
    row["task_id"] = TASK
    row["safe_parameters"] = params
    row["parameters_sha256"] = FlowMCPActionStore.parameters_sha256(params)
    binding = {
        "engagement_id": row["engagement_id"],
        "flow_id": row["flow_id"],
        "revision": row["flow_revision"],
        "version": row["authorization_version"],
        "authorization_id": row["authorization_id"],
        "authorization_sha256": row["authorization_sha256"],
    }
    original = {
        **binding,
        **{
            key: row[key]
            for key in (
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
    row["intent_sha256"] = _digest(_DIGEST_DOMAIN, original, 4096)
    row["request_id"] = "req-" + row["intent_sha256"][:48]
    assert row["status"] == "unknown"
    ledger = Ledger(row)
    ledger.clock = int(time.time())
    return ledger


def _body(ledger: Ledger, target: str) -> dict[str, str]:
    row = ledger.row
    return {
        "request_id": row["request_id"],
        "engagement_id": ENGAGEMENT,
        "task_id": TASK,
        "server_id": "browser-mcp",
        "tool_name": "execute",
        "action": "navigate",
        "user_label": LABEL,
        "evidence_mode": _MODE,
        "url_sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
        "origin": exact_origin(target),
    }


def _install_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ledger: Ledger,
    native: Any,
) -> tuple[FastAPI, Any, Ed25519PrivateKey]:
    """Mount the actual central source route on a fake-PG source action store."""
    signer = Ed25519PrivateKey.generate()
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_SIGNING_KID", _KID)
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_SIGNING_PRIVATE_KEY_B64",
        base64.b64encode(signer.private_bytes_raw()).decode("ascii"),
    )
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps(
            {
                _KID: base64.b64encode(
                    signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                ).decode("ascii")
            }
        ),
    )
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", _SERVICE)
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_URL",
        "https://authority.full-evidence.invalid/native-browser/source-preflight",
    )
    ca = tmp_path / "separate-signer-trusted-source-ca.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\n" + b"A" * 160 + b"\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_CA_BUNDLE", str(ca))
    _, actions = make_authority(ledger)
    # This fixture's current Flow/Task/approval/lease callbacks are simulated;
    # original source _source(), digest, event, ROE, parameter and 0034 INSERT
    # sequencing execute the actual production implementation on FakePG.
    actions._authority.return_value["scope"] = {
        "engagement_id": ENGAGEMENT,
        "domains": ["authorized.example"],
        "ips": ["127.0.0.1/32"],
        "allowed_techniques": ["execute"],
        "restrictions": [],
    }
    monkeypatch.setitem(
        source_api.state,
        "orchestrator",
        SimpleNamespace(session_memory=object(), mcp_registry=object()),
    )
    monkeypatch.setattr(source_api, "FlowMCPActionStore", lambda *_: actions)
    central = FastAPI()
    central.include_router(source_api.router)
    assert sum(r.path == _PATH for r in central.routes) == 1

    def bridge(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        # Only this transport is fake; both request and response flow through
        # genuine FastAPI and native Browser HTTP handlers.
        assert kwargs["verify"] == str(ca)
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return _REAL_HTTP(
            transport=httpx.ASGITransport(app=central),
            base_url="https://authority.full-evidence.invalid",
            trust_env=False,
            follow_redirects=False,
            verify=False,  # No TLS handshake exists with an in-memory ASGI hop.
            timeout=kwargs["timeout"],
        )

    monkeypatch.setattr(native.native.httpx, "AsyncClient", bridge)
    return central, actions, signer


async def _central(central: FastAPI, body: dict[str, str]) -> httpx.Response:
    async with _REAL_HTTP(
        transport=httpx.ASGITransport(app=central),
        base_url="https://authority.full-evidence.invalid",
        trust_env=False,
    ) as client:
        return await client.post(
            _PATH,
            json=body,
            headers={"Authorization": "Bearer " + _SERVICE},
        )


def _native_payload(ledger: Ledger, target: str) -> dict[str, Any]:
    return {
        "tool_name": "execute",
        "request_id": ledger.row["request_id"],
        "execution_binding": {
            "request_id": ledger.row["request_id"],
            "engagement_id": ENGAGEMENT,
            "task_id": TASK,
            "server_id": "browser-mcp",
        },
        "parameters": {
            "url": target,
            "action": "navigate",
            "user_label": LABEL,
            "evidence_mode": _MODE,
        },
    }


def _verify_coupled_evidence(
    native: Any,
    result: dict[str, Any],
    request_id: str,
) -> None:
    """Re-read three REAL original bytes and independently verify provider SHA."""
    assert result["status_code"] == 200
    assert result["evidence_mode"] == _MODE
    assert set(result["evidence"]) == {"screenshot", "dom", "har"}
    attestation = result["evidence_attestation"]
    claims = attestation["claims"]
    assert claims["request_id"] == request_id
    assert claims["engagement_id"] == ENGAGEMENT
    assert claims["task_id"] == TASK
    assert claims["server_id"] == "browser-mcp"
    assert claims["evidence_mode"] == _MODE
    assert set(claims["artifacts"]) == {"screenshot", "dom", "har"}
    assert claims["action_id"].startswith("action-")
    native_signing_public = json.loads(os.environ["OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON"])[
        "browser-mcp"
    ][attestation["kid"]]
    public = base64.b64decode(native_signing_public)
    encoded = json.dumps(
        claims,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    Ed25519PublicKey.from_public_bytes(public).verify(
        base64.urlsafe_b64decode(attestation["signature"] + "=="),
        native.native._COUPLED_EVIDENCE_DOMAIN + encoded,
    )
    for name, extension in (("screenshot", "png"), ("dom", "html"), ("har", "har")):
        metadata = result["evidence"][name]
        assert metadata["path"].startswith("captures/")
        assert metadata["path"].endswith("." + extension)
        assert metadata["capture_task_id"] == TASK
        source = native.tenant / metadata["path"]
        assert source.resolve().is_relative_to(native.tenant.resolve())
        data = source.read_bytes()
        assert data and metadata["size_bytes"] == len(data)
        assert hashlib.sha256(data).hexdigest() == metadata["resource_sha256"]
        assert claims["artifacts"][name] == {
            "path": metadata["path"],
            "sha256": metadata["resource_sha256"],
            "size_bytes": metadata["size_bytes"],
        }
        if name == "screenshot":
            assert data.startswith(b"\x89PNG\r\n\x1a\n")
        elif name == "dom":
            assert b"LOCAL_ONLY_BROWSER_PROOF" in data
        else:
            parsed = json.loads(data)
            assert any(
                item["request"]["url"].startswith(native.base_url)
                for item in parsed["log"]["entries"]
            )


@pytest.mark.asyncio
async def test_full_evidence_real_offline_chromium_with_fake_pg_central_asgi(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Offline Chromium + real signed SourceMap code, but FAKE PostgreSQL."""
    executable, note = await real_chromium_executable()
    if executable is None:
        pytest.skip(note)
    async with native_browser_local(tmp_path, monkeypatch) as native:
        target = native.base_url + "/"
        ledger = _original_case(target)
        central, actions, source_signer = _install_source(
            tmp_path,
            monkeypatch,
            ledger,
            native,
        )
        original = _body(ledger, target)

        # No original 4-field approval means no signed permission to capture.
        omitted = await _central(central, {**original, "evidence_mode": "none"})
        assert omitted.status_code == 409
        wrong_task = await _central(
            central,
            {**original, "task_id": "task-unreviewed"},
        )
        assert wrong_task.status_code == 409
        wrong_identity = await _central(
            central,
            {**original, "user_label": "user-not-reviewed"},
        )
        assert wrong_identity.status_code == 409
        wrong_url = await _central(
            central,
            {**original, "url_sha256": "0" * 64},
        )
        assert wrong_url.status_code == 409
        actions._approved_task.side_effect = MCPActionDenied(
            403,
            "Independent approving reviewer disabled",
        )
        revoked = await _central(central, original)
        assert revoked.status_code == 409
        actions._approved_task.side_effect = None
        actions._approved_task.return_value = {
            "action_id": ledger.row["action_id"],
            "approval_id": ledger.row["approval_id"],
            "lease_id": "lease-now-expired",
            "lease_owner_id": ledger.row["lease_owner_id"],
        }
        stale_lease = await _central(central, original)
        assert stale_lease.status_code == 409
        actions._approved_task.return_value = {
            key: ledger.row[key]
            for key in ("action_id", "approval_id", "lease_id", "lease_owner_id")
        }
        assert ledger.committed == {}
        assert native.page_hits == []

        # Single native signed navigation triggers screenshot+DOM+HAR together.
        async with _REAL_HTTP(
            transport=httpx.ASGITransport(app=native.native.app),
            base_url="http://owned-browser-only.invalid",
            timeout=30.0,
        ) as client:
            init = await client.post(
                "/mcp/initialize",
                json={"session_id": ENGAGEMENT},
                headers=native.headers(),
            )
            assert init.status_code == 200, init.text
            payload = _native_payload(ledger, target)
            first = await client.post(
                "/mcp/execute",
                json=payload,
                headers=native.headers(),
            )
            assert first.status_code == 200, first.text
            completed = first.json()
            assert completed["status"] == "success", completed
            assert provider_receipt_is_signed(
                completed["provider_receipt"],
                "browser-mcp",
                ledger.row["request_id"],
                ENGAGEMENT,
                TASK,
            )
            _verify_coupled_evidence(
                native,
                completed["result"],
                ledger.row["request_id"],
            )
            assert "LOCAL_ONLY_BROWSER_PROOF" not in first.text
            assert "data:image/" not in first.text
            assert native.page_hits == ["/"]
            assert len(ledger.committed) == 1
            record = ledger.committed[ledger.row["request_id"]]
            assert record["evidence_mode"] == _MODE
            assert record["action_id"] == ledger.row["action_id"]
            assert record["url_sha256"] == original["url_sha256"]
            assert record["kid"] == _KID
            assert ledger.row["status"] == "unknown"
            coupled = completed["result"]["evidence_attestation"]["claims"]
            assert coupled["source_preflight_id"] == record["preflight_id"]
            assert coupled["action_id"] == ledger.row["action_id"]
            assert coupled["authorization_sha256"] == ledger.row["authorization_sha256"]

            # Real source claims signed by the independent issuer after fake
            # transactional admission; don't misstate it as real PG persistence.
            claims = {
                name: record[name]
                for name in (
                    "version",
                    "preflight_id",
                    "request_id",
                    "engagement_id",
                    "flow_id",
                    "task_id",
                    "subtask_id",
                    "action_id",
                    "owner_id",
                    "server_id",
                    "tool_name",
                    "action",
                    "url_sha256",
                    "origin",
                    "user_label",
                    "evidence_mode",
                    "authorization_version",
                    "authorization_sha256",
                    "approval_id",
                    "lease_id",
                    "issued_at",
                    "expires_at",
                )
            }
            assert hashlib.sha256(_canonical(claims)).hexdigest() == record["claims_sha256"]
            # The issuer's private key never leaves the server configuration;
            # the native verifier already checked the returned 22-field proof.
            assert (
                len(
                    source_signer.public_key().public_bytes(
                        Encoding.Raw,
                        PublicFormat.Raw,
                    )
                )
                == 32
            )
            repeated = await client.post(
                "/mcp/execute",
                json=payload,
                headers=native.headers(),
            )
            assert repeated.json()["status"] == "duplicate_request"
            assert native.page_hits == ["/"]
        central_replay = await _central(central, original)
        assert central_replay.status_code == 409
        assert len(ledger.committed) == 1
        assert native.blocked == []
        # Chromium's ambient time-service attempts (if any) were intercepted
        # by the OWNED 403-only loopback proxy; no outbound connection occurs.
        assert all("clients2.google.com/time" in req for req in native.proxy_attempts)
