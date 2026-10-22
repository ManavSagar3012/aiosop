"""Synthetic protected SourceMap STATUS transport qualification.

The central STATUS route is registered at POST /native-sourcemap/status-preflight
with a distinct service bearer. Fake HTTPS uses independently signed Ed25519
test proofs and fake original 0027 SQL. No real DB/HTTPS/PID/Docker/targets.
The genuine supervisor-source acquisition still DENIES, so no original bytes
or execution capability is granted.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest

from tests import test_sourcemap_two_phase_bootstrap_20261021 as previous

# Reuse the isolated synthetic host fixture via pytest fixture discovery,
# without treating the fixture name as a caller-supplied transport identity.
pytest_plugins = ["tests.test_sourcemap_two_phase_bootstrap_20261021"]


@pytest.fixture
def channel(boot: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    ctx = boot["context"]
    mod = ctx["mod"]
    # The previous regression file deliberately injects fake signed STATUS.
    # Restore production method so these tests exercise the real host-owned
    # pinned TLS transport and Ed25519 verification end to end (offline).
    monkeypatch.setattr(
        boot["co"],
        "_trusted_status_after_0035",
        types.MethodType(
            mod.OriginalSourceMapHostCoordinator._trusted_status_after_0035,
            boot["co"],
        ),
    )
    state: dict[str, Any] = {"calls": [], "mode": "valid", "ca": None}

    class FakeClient:
        def __init__(self, **options: Any) -> None:
            assert options["trust_env"] is False
            assert options["follow_redirects"] is False
            assert options["verify"] in (
                os.environ["OSOP_SOURCEMAP_SOURCE_CA_BUNDLE"],
                os.environ["OSOP_SOURCEMAP_STATUS_CA_BUNDLE"],
            )

        async def __aenter__(self) -> "FakeClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        async def post(self, url: str, **options: Any) -> Any:
            assert options["follow_redirects"] is False
            assert options["json"] == previous.base.REQUEST
            assert options["headers"]["Cache-Control"] == "no-store"
            if url == os.environ["OSOP_SOURCEMAP_SOURCE_URL"]:
                assert options["headers"]["Authorization"] == (
                    "Bearer " + os.environ["OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN"]
                )
                state["calls"].append("0035-source")
                return types.SimpleNamespace(
                    status_code=200,
                    content=json.dumps(ctx["source_token"]).encode("ascii"),
                )
            assert url == os.environ["OSOP_SOURCEMAP_STATUS_URL"]
            assert options["headers"]["Authorization"] == (
                "Bearer " + os.environ["OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN"]
            )
            assert (
                os.environ["OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN"]
                != os.environ["OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN"]
            )
            state["calls"].append("0035-status")
            mode = state["mode"]
            if mode == "lost_ack":
                raise OSError("status ACK lost after central read-only check")
            if mode == "revoked":
                return types.SimpleNamespace(status_code=403, content=b"{}")
            if mode == "redirect":
                return types.SimpleNamespace(status_code=302, content=b"{}")
            original = ctx["claims"]
            now = int(time.time())
            claims = {
                **original,
                "status_id": "nss-" + "d" * 32,
                "issued_at": now,
                "expires_at": now + 5,
            }
            if mode == "expired":
                claims.update(issued_at=now - 9, expires_at=now - 4)
            if mode == "future":
                claims.update(issued_at=now + 4, expires_at=now + 9)
            if mode == "wrong_action":
                claims["action_id"] = "action-" + "f" * 32
            if mode == "wrong_preflight":
                claims["preflight_id"] = "nsp-" + "f" * 32
            if mode == "wrong_owner":
                claims["owner_id"] = "owner-foreign"
            if mode == "wrong_manifest":
                claims["manifest_sha256"] = "f" * 64
            if mode == "same_source_proof":
                return types.SimpleNamespace(
                    status_code=200,
                    content=json.dumps(ctx["source_token"]).encode("ascii"),
                )
            token = previous.base._token(
                ctx["stage"],
                claims,
                ctx["source"],
                previous.STATUS_DOMAIN,
                "central-source",
            )
            if mode == "forged_signature":
                token["claims"]["lease_id"] = "lease-foreign"
            if mode == "wrong_signer":
                token["kid"] = "unknown-source-root"
            if mode == "duplicate_keys":
                payload = json.dumps(token)
                return types.SimpleNamespace(
                    status_code=200,
                    content=b'{"claims":{},' + payload[1:].encode("ascii"),
                )
            if mode == "bad_json":
                return types.SimpleNamespace(status_code=200, content=b"not json")
            if mode == "oversize":
                return types.SimpleNamespace(status_code=200, content=b"z" * 4097)
            return types.SimpleNamespace(
                status_code=200,
                content=json.dumps(token).encode("ascii"),
            )

    monkeypatch.setattr(mod.httpx, "AsyncClient", FakeClient, raising=False)
    state["co"] = boot["co"]
    state["ctx"] = ctx
    return state


def attempt(channel: dict[str, Any]) -> None:
    with pytest.raises(channel["ctx"]["mod"].SourceMapHostCoordinationDenied):
        asyncio.run(
            channel["co"].coordinate_first_use(
                original_action_request=dict(previous.base.REQUEST),
            )
        )


@pytest.mark.skipif(sys.platform != "linux", reason="host Linux proof/stage boundary")
def test_real_host_pinned_status_transport_and_independent_supervisor_denial(
    channel: dict[str, Any],
) -> None:
    attempt(channel)
    assert channel["calls"] == ["0035-source", "0035-status"]
    assert len(list(channel["ctx"]["root"].glob(".issuer-*.used"))) == 1
    assert not (channel["ctx"]["root"] / (previous.base.DIGEST + ".map")).exists()
    attempt(channel)
    assert channel["calls"] == ["0035-source", "0035-status"]
    assert not (channel["ctx"]["root"] / (previous.base.DIGEST + ".proof.json")).exists()
    assert "OSOP_SOURCEMAP_MCP_BEARER_TOKEN" not in os.environ


@pytest.mark.skipif(sys.platform != "linux", reason="host Linux proof/stage boundary")
def test_fresh_status_must_not_extend_original_shorter_source_validity(
    channel: dict[str, Any],
) -> None:
    ctx = channel["ctx"]
    # Independently sign a valid but short-lived original source proof. Its
    # current 5s STATUS would outlive that original 0035 authorization.
    ctx["claims"]["expires_at"] = int(time.time()) + 3
    ctx["source_token"] = previous.base._token(
        ctx["stage"], ctx["claims"], ctx["source"], ctx["stage"].SOURCE_DOMAIN, "central-source"
    )
    attempt(channel)
    assert channel["calls"] == ["0035-source", "0035-status"]
    assert not list(ctx["root"].glob("*.map"))
    assert len(list(ctx["root"].glob(".issuer-*.used"))) == 1
    attempt(channel)
    assert channel["calls"] == ["0035-source", "0035-status"]


@pytest.mark.skipif(sys.platform != "linux", reason="host Linux proof/stage boundary")
@pytest.mark.parametrize(
    "mode",
    [
        "lost_ack",
        "revoked",
        "redirect",
        "expired",
        "future",
        "wrong_action",
        "wrong_preflight",
        "wrong_owner",
        "wrong_manifest",
        "same_source_proof",
        "forged_signature",
        "wrong_signer",
        "duplicate_keys",
        "bad_json",
        "oversize",
    ],
)
def test_untrusted_or_missing_status_never_reissues_0035_or_stages(
    channel: dict[str, Any],
    mode: str,
) -> None:
    channel["mode"] = mode
    attempt(channel)
    assert channel["calls"] == ["0035-source", "0035-status"]
    assert len(list(channel["ctx"]["root"].glob(".issuer-*.used"))) == 1
    assert not list(channel["ctx"]["root"].glob("*.map"))
    assert not list(channel["ctx"]["root"].glob("*.proof.json"))
    attempt(channel)
    assert channel["calls"] == ["0035-source", "0035-status"]


@pytest.mark.skipif(sys.platform != "linux", reason="host Linux proof/stage boundary")
@pytest.mark.parametrize(
    "bad",
    [
        "missing_url",
        "non_https",
        "wrong_path",
        "redirect_host",
        "url_credentials",
        "url_query",
        "bad_port",
        "empty_ca",
        "missing_ca",
        "ca_symlink",
        "unsafe_ca",
        "status_ca_group_writable",
        "source_ca_group_writable",
        "missing_token",
        "short_token",
        "source_reused",
        "native_reused",
    ],
)
def test_status_channel_preflight_denied_before_0035_tombstone(
    channel: dict[str, Any], monkeypatch: pytest.MonkeyPatch, bad: str, tmp_path: Path
) -> None:
    if bad == "missing_url":
        monkeypatch.delenv("OSOP_SOURCEMAP_STATUS_URL")
    elif bad == "non_https":
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_STATUS_URL",
            "http://approved-central.invalid/native-sourcemap/status-preflight",
        )
    elif bad == "wrong_path":
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_STATUS_URL",
            os.environ["OSOP_SOURCEMAP_SOURCE_URL"],
        )
    elif bad == "redirect_host":
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_STATUS_URL",
            "https://localhost/native-sourcemap/status-preflight",
        )
    elif bad == "url_credentials":
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_STATUS_URL",
            "https://user:pass@approved-central.invalid/native-sourcemap/status-preflight",
        )
    elif bad == "url_query":
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_STATUS_URL",
            "https://approved-central.invalid/native-sourcemap/status-preflight?secret=yes",
        )
    elif bad == "bad_port":
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_STATUS_URL",
            "https://approved-central.invalid:8443/native-sourcemap/status-preflight",
        )
    elif bad == "empty_ca":
        monkeypatch.delenv("OSOP_SOURCEMAP_STATUS_CA_BUNDLE")
    elif bad == "missing_ca":
        monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_CA_BUNDLE", str(tmp_path / "missing-ca.pem"))
    elif bad == "ca_symlink":
        link = tmp_path / "status-ca-link.pem"
        link.symlink_to(Path(os.environ["OSOP_SOURCEMAP_SOURCE_CA_BUNDLE"]))
        monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_CA_BUNDLE", str(link))
    elif bad == "unsafe_ca":
        unsafe = tmp_path / "unsafe-ca.pem"
        unsafe.write_bytes(b"invalid certificate")
        monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_CA_BUNDLE", str(unsafe))
    elif bad in {"status_ca_group_writable", "source_ca_group_writable"}:
        suffix = "STATUS" if bad.startswith("status_") else "SOURCE"
        name = "OSOP_SOURCEMAP_" + suffix + "_CA_BUNDLE"
        hostile = tmp_path / (suffix.lower() + "-writable-ca.pem")
        hostile.write_bytes(Path(os.environ[name]).read_bytes())
        hostile.chmod(0o660)  # Deliberately unsafe negative fixture only.
        monkeypatch.setenv(name, str(hostile))
    elif bad == "missing_token":
        monkeypatch.delenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN")
    elif bad == "short_token":
        monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", "no")
    elif bad == "source_reused":
        monkeypatch.setenv(
            "OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN",
            os.environ["OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN"],
        )
    elif bad == "native_reused":
        native = "native-separate-issuer-denied-test-bearer"
        monkeypatch.setenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", native)
        monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", native)
    attempt(channel)
    assert channel["calls"] == []
    assert not list(channel["ctx"]["root"].glob(".issuer-*.used"))
    assert not list(channel["ctx"]["root"].glob("*.map"))


@pytest.mark.skipif(sys.platform != "linux", reason="host Linux proof/stage boundary")
def test_status_configuration_changed_after_issuer_ack_fails_closed(
    channel: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    original = channel["ctx"]["mod"].httpx.AsyncClient

    class ChangedAfterSource(original):
        async def post(self, url: str, **options: Any) -> Any:
            response = await super().post(url, **options)
            if url == os.environ["OSOP_SOURCEMAP_SOURCE_URL"]:
                monkeypatch.setenv(
                    "OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN",
                    "modified-but-otherwise-well-formed-status-service-bearer",
                )
            return response

    monkeypatch.setattr(channel["ctx"]["mod"].httpx, "AsyncClient", ChangedAfterSource)
    attempt(channel)
    assert channel["calls"] == ["0035-source"]
    assert len(list(channel["ctx"]["root"].glob(".issuer-*.used"))) == 1
    assert not list(channel["ctx"]["root"].glob("*.map"))


def test_status_route_and_host_no_central_signer_contract() -> None:
    route = (
        Path(__file__).resolve().parents[1]
        / "src/ai_osop/api/routers/native_sourcemap_status_authority.py"
    ).read_text(encoding="utf-8")
    assert '@router.post("/native-sourcemap/status-preflight")' in route
    assert "OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN" in route
    assert "SourceMapStatusAuthorityStore" in route
    host = (
        Path(__file__).resolve().parents[1]
        / "src/ai_osop/orchestrator/sourcemap_original_host_coordinator.py"
    ).read_text(encoding="utf-8")
    import ast

    tree = ast.parse(host)
    klass = next(
        x
        for x in tree.body
        if isinstance(x, ast.ClassDef) and x.name == "OriginalSourceMapHostCoordinator"
    )
    method = next(
        x
        for x in klass.body
        if isinstance(x, ast.AsyncFunctionDef) and x.name == "_trusted_status_after_0035"
    )
    body = ast.get_source_segment(host, method)
    assert body is not None
    assert "SourceMapStatusAuthorityStore" not in body
    assert "SOURCE_SIGNING_PRIVATE_KEY_B64" not in body
    assert "httpx.AsyncClient(" in body
    assert "trust_env=False" in body and "follow_redirects=False" in body
