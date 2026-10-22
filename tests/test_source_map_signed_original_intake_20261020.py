"""Native SourceMap signed original-byte intake; fake central HTTPS issuer only.

All positive source decisions here are local signed fixtures, NOT a deployed
central PostgreSQL reviewer/ROE grant. No app DB, targets, DNS or real network.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import stat
import sys
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REAL_HTTPX_CLIENT = httpx.AsyncClient

SOURCE = Path(__file__).resolve().parents[1] / "mcp-servers/python/source_map_mcp.py"
REQUEST_ID = "req-" + "1" * 48
ENGAGEMENT = "eng-local-test"
TASK = "task-local-test"
APPROVAL = "apr-independent-reviewer"
ACTION = "action-" + "a" * 32
SERVICE = "unique-source-map-central-bearer-credential"
NATIVE = "unique-source-map-native-client-token-123456"
KID = "independent-source-issuer"
SECRET = "AKIAABCDEFGHIJKLMNOP"
DOCUMENT = json.dumps(
    {
        "version": 3,
        "sources": ["../../private/alice/config.js", "https://intranet.invalid/secret.js"],
        "sourcesContent": [
            "const key='" + SECRET + "';",
            "const password='private-test-password';",
        ],
    }
).encode("utf-8")
DIGEST = hashlib.sha256(DOCUMENT).hexdigest()


def load():
    name = "_signed_original_sourcemap_test"
    spec = importlib.util.spec_from_file_location(name, SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def request(digest=DIGEST, request_id=REQUEST_ID):
    return {
        "request_id": request_id,
        "tool_name": "inspect_local_original_sourcemap",
        "execution_binding": {
            "request_id": request_id,
            "engagement_id": ENGAGEMENT,
            "task_id": TASK,
            "server_id": "source-map-mcp",
        },
        "parameters": {"artifact_sha256": digest},
    }


async def call(mod, body, *, native_authorization=True):
    async with _REAL_HTTPX_CLIENT(
        transport=httpx.ASGITransport(app=mod.app),
        base_url="http://native.invalid",
    ) as client:
        return await client.post(
            "/mcp/execute",
            json=body,
            headers={"Authorization": "Bearer " + NATIVE} if native_authorization else {},
        )


def configure(monkeypatch, tmp_path, *, signed_handler=True, corrupted=False):
    """Owned local fixture trust. Never represents a real central source."""
    mod = load()
    tmp_path.mkdir(parents=True, exist_ok=True)
    original_root = tmp_path / "originals"
    original_root.mkdir(mode=0o700)
    ledger = tmp_path / "one-shot"
    ledger.mkdir(mode=0o700)
    # The independently enrolled NATIVE receipt key is not the central
    # source-preflight issuer key. Configured readiness must require both:
    # a local HTTP 200 without native completion testimony cannot settle 0027.
    native_signer = Ed25519PrivateKey.generate()
    native_private = tmp_path / "native-receipt.key"
    native_private.write_bytes(
        native_signer.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    native_private.chmod(0o400 if os.name == "posix" else stat.S_IREAD)
    native_public = native_signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KID", "local-native-receipt")
    monkeypatch.setenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KEY_FILE", str(native_private))
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps(
            {
                "source-map-mcp": {
                    "local-native-receipt": base64.b64encode(native_public).decode("ascii")
                }
            }
        ),
    )
    ca = tmp_path / "root.crt"
    ca.write_text("-----BEGIN CERTIFICATE-----\n" + "A" * 128 + "\n-----END CERTIFICATE-----\n")
    original = original_root / (DIGEST + ".map")
    original.write_bytes(DOCUMENT)
    original.chmod(0o400 if os.name == "posix" else stat.S_IREAD)
    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_URL",
        "https://authority.example.org/native-sourcemap/source-preflight",
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_CA_BUNDLE", str(ca))
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", SERVICE)
    monkeypatch.setenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", NATIVE)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({KID: base64.b64encode(public).decode("ascii")}),
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_ORIGINAL_READONLY_ROOT", str(original_root))
    monkeypatch.setenv("OSOP_SOURCEMAP_ONE_SHOT_ROOT", str(ledger))

    traffic = []
    real_client = _REAL_HTTPX_CLIENT

    def handle_central(request):
        traffic.append(
            {
                "path": request.url.path,
                "method": request.method,
                "body": json.loads(request.content),
            }
        )
        assert request.url.host == "authority.example.org"
        assert request.url.path == "/native-sourcemap/source-preflight"
        assert request.headers["Authorization"] == "Bearer " + SERVICE
        if not signed_handler:
            return httpx.Response(503, json={"status": "unavailable"})
        message = json.loads(request.content)
        now = int(time.time())
        claims = {
            **message,
            "task_id": TASK,  # separately approved task, never echo caller's claim
            "engagement_id": ENGAGEMENT,
            "version": 1,
            "preflight_id": "nsp-" + "f" * 32,
            "flow_id": "flow-approved",
            "subtask_id": "subtask-approved",
            "action_id": ACTION,
            "owner_id": "owner-approved",
            "manifest_sha256": "d" * 64,
            "approval_id": APPROVAL,
            "lease_id": "lease-verified",
            "authorization_version": 3,
            "authorization_sha256": "c" * 64,
            "issued_at": now,
            "expires_at": now + 10,
        }
        blob = json.dumps(
            claims,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        signature = signer.sign(mod._SOURCE_DOMAIN + blob)
        if corrupted:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        token = {
            "claims": claims,
            "kid": KID,
            "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        }
        return httpx.Response(200, json=token)

    def client(*args, **kwargs):
        assert kwargs.get("trust_env") is False
        assert kwargs.get("follow_redirects") is False
        assert kwargs.get("verify") == str(ca)
        return real_client(*args, transport=httpx.MockTransport(handle_central), **kwargs)

    monkeypatch.setattr(mod.httpx, "AsyncClient", client)
    return mod, original, ledger, traffic


@pytest.mark.asyncio
async def test_native_original_byte_path_real_ed25519_and_one_shot(monkeypatch, tmp_path):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path)
    first = await call(mod, request())
    assert first.status_code == 200, first.text
    result = first.json()
    assert result["status"] == "success"
    assert set(result["provider_receipt"]) == {
        "request_id",
        "engagement_id",
        "task_id",
        "server_id",
        "status",
        "verified",
        "stopped",
        "issued_at",
        "attestation",
    }
    from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed

    assert provider_receipt_is_signed(
        result["provider_receipt"], "source-map-mcp", REQUEST_ID, ENGAGEMENT, TASK
    )
    evidence = result["result"]
    assert evidence["source_side_signed_authorization_verified"] is True
    assert evidence["source_original_bytes_sha256_verified"] is True
    assert evidence["credentials_disclosed"] is False
    assert evidence["source_count"] == 2
    assert evidence["sources"] == ["source_0.js", "source_1.js"]
    assert evidence["findings"][0]["secret_type_counts"]["aws_access_key"] == 1
    assert SECRET not in first.text
    assert "private-test-password" not in first.text
    assert "alice" not in first.text
    assert len(list(ledger.glob("*.used"))) == 2
    assert len(traffic) == 1
    replay = await call(mod, request())
    assert replay.status_code == 503
    assert replay.json()["error"] == "signed_original_source_unavailable"
    assert len(traffic) == 2
    assert original.read_bytes() == DOCUMENT


@pytest.mark.asyncio
async def test_native_ready_registry_manifest_requires_independent_source_config(
    monkeypatch, tmp_path
):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path)
    async with _REAL_HTTPX_CLIENT(
        transport=httpx.ASGITransport(app=mod.app),
        base_url="http://native.local.invalid",
    ) as client:
        health = await client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "configured_unverified"
        assert health.json()["source_side_signed_authorization_verified"] is False
        ready = (await client.post("/mcp/initialize")).json()
        assert ready["status"] == "ready"
        assert ready["capabilities"] == [
            "mcp_bound_receipts_v1",
            "original_sourcemap_signed_preflight_v1",
        ]
        assert [tool["name"] for tool in ready["tools"]] == ["inspect_local_original_sourcemap"]
        assert ready["source_side_signed_authorization_verified"] is False
        assert traffic == []
        monkeypatch.setenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", SERVICE)
        assert (await client.get("/health")).status_code == 503
        assert (await client.post("/mcp/initialize")).json()["status"] == "unavailable"


@pytest.mark.asyncio
async def test_native_parallel_and_distinct_request_same_action_stay_one_shot(
    monkeypatch, tmp_path
):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path)
    replies = await asyncio.gather(*(call(mod, request()) for _ in range(8)))
    assert sum(reply.status_code == 200 for reply in replies) == 1
    assert sum(reply.status_code == 503 for reply in replies) == 7
    different_request = request(request_id="req-" + "2" * 48)
    refused = await call(mod, different_request)
    assert refused.status_code == 503
    assert len(list(ledger.glob("action_id-*.used"))) == 1
    assert len(list(ledger.glob("request_id-*.used"))) == 2
    assert original.read_bytes() == DOCUMENT


@pytest.mark.asyncio
async def test_missing_authority_denies_before_any_file_io(monkeypatch, tmp_path):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path)
    monkeypatch.delenv("OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
    response = await call(mod, request())
    assert response.status_code == 503
    assert not traffic
    assert not list(ledger.iterdir())
    assert original.read_bytes() == DOCUMENT


@pytest.mark.asyncio
async def test_missing_native_bearer_and_equal_service_secret_never_call_central(
    monkeypatch, tmp_path
):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path)
    assert (await call(mod, request(), native_authorization=False)).status_code == 503
    assert not traffic
    monkeypatch.setenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", SERVICE)
    assert (await call(mod, request())).status_code == 503
    assert not traffic
    assert not list(ledger.iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", ["wrong_server", "wrong_task", "wrong_sha", "not_bound", "unsigned"]
)
async def test_untrusted_source_cannot_grant_by_claimed_parameters(monkeypatch, tmp_path, case):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path, corrupted=case == "unsigned")
    data = request()
    if case == "wrong_server":
        data["execution_binding"]["server_id"] = "other-mcp"
    elif case == "wrong_task":
        data["execution_binding"]["task_id"] = "task-different"
    elif case == "wrong_sha":
        data["parameters"]["artifact_sha256"] = "0" * 64
    elif case == "not_bound":
        data.pop("execution_binding")
    response = await call(mod, data)
    assert response.status_code == 503
    assert response.json()["status"] == "error"
    if case in ("wrong_server", "not_bound", "wrong_task", "unsigned"):
        assert not list(ledger.iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["changed", "removed", "symlink", "hardlink"])
async def test_deleted_changed_symlink_and_hardlink_originals_denied(monkeypatch, tmp_path, case):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path)
    if case == "changed":
        if os.name == "nt":
            original.chmod(stat.S_IREAD | stat.S_IWRITE)
        original.write_bytes(DOCUMENT + b" ")
        original.chmod(0o400 if os.name == "posix" else stat.S_IREAD)
    elif case == "removed":
        if os.name == "nt":
            original.chmod(stat.S_IREAD | stat.S_IWRITE)
        original.unlink()
    elif case == "symlink":
        replacement = original.with_name("outside-file")
        original.rename(replacement)
        try:
            original.symlink_to(replacement)
        except OSError:
            pytest.skip("Symlinks unavailable under this test account")
    else:
        other_link = original.with_name("alias.map")
        try:
            os.link(original, other_link)
        except OSError:
            pytest.skip("Hardlinks unavailable under this test filesystem")
    response = await call(mod, request())
    assert response.status_code == 503
    assert response.json()["error"] == "signed_original_source_unavailable"
    assert len(traffic) == 1


@pytest.mark.asyncio
async def test_wrong_issuer_signature_and_central_503_denied(monkeypatch, tmp_path):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path, corrupted=True)
    response = await call(mod, request())
    assert response.status_code == 503
    assert not list(ledger.iterdir())
    mod, original, ledger, traffic = configure(
        monkeypatch, tmp_path / "another", signed_handler=False
    )
    response = await call(mod, request())
    assert response.status_code == 503
    assert not list(ledger.iterdir())


@pytest.mark.asyncio
async def test_legacy_network_route_still_denied_with_source_enabled(monkeypatch, tmp_path):
    mod, original, ledger, traffic = configure(monkeypatch, tmp_path)
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    output = await call(
        mod,
        {
            "request_id": REQUEST_ID,
            "tool_name": "fetch_and_parse_sourcemap",
            "parameters": {"url": "https://maps.example.org/asset.js"},
        },
    )
    assert output.status_code == 503
    assert output.json()["error"] == "signed_source_authority_unavailable"
    assert not traffic
    assert not list(ledger.iterdir())
