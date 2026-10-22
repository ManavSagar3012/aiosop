"""Focused offline coordinator qualification; no app DB, Docker, real network.

The positive case uses real independent Ed25519 keys, signed 0035 claims,
signed mount observer proof, host key-file verification and POSIX fsync stage.
Its stub post-commit provisioner is NOT evidence that 0035 PG or native mount
observation is available in a deployment.
"""

from __future__ import annotations

import base64
import asyncio
import hashlib
import importlib.util
import json
import os
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1] / "src" / "ai_osop"
ORCH = ROOT / "orchestrator"


def _module(name: str, file: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, file)
    assert spec is not None and spec.loader is not None
    obj = importlib.util.module_from_spec(spec)
    sys.modules[name] = obj
    spec.loader.exec_module(obj)
    return obj


@pytest.fixture
def modules(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any]:
    # Import only host components: the global orchestrator imports app DB
    # packages; this host boundary intentionally does not need them.
    for name, folder in (("ai_osop", ROOT), ("ai_osop.orchestrator", ORCH)):
        package = types.ModuleType(name)
        package.__path__ = [str(folder)]
        monkeypatch.setitem(sys.modules, name, package)
    for name in (
        "ai_osop.orchestrator.sourcemap_original_stage",
        "ai_osop.orchestrator.sourcemap_native_mount_observer",
        "ai_osop.orchestrator.sourcemap_original_host_coordinator",
    ):
        monkeypatch.delitem(sys.modules, name, raising=False)
    if "httpx" not in sys.modules:
        try:
            import httpx  # noqa: F401
        except ModuleNotFoundError:
            mock_httpx = types.ModuleType("httpx")
            mock_httpx.Timeout = lambda *_args, **_kwargs: object()
            monkeypatch.setitem(sys.modules, "httpx", mock_httpx)
    stage = _module(
        "ai_osop.orchestrator.sourcemap_original_stage",
        ORCH / "sourcemap_original_stage.py",
    )
    _module(
        "ai_osop.orchestrator.sourcemap_native_mount_observer",
        ORCH / "sourcemap_native_mount_observer.py",
    )
    coordinator = _module(
        "ai_osop.orchestrator.sourcemap_original_host_coordinator",
        ORCH / "sourcemap_original_host_coordinator.py",
    )
    yield stage, coordinator
    for name in (
        "ai_osop.orchestrator.sourcemap_original_stage",
        "ai_osop.orchestrator.sourcemap_native_mount_observer",
        "ai_osop.orchestrator.sourcemap_original_host_coordinator",
    ):
        monkeypatch.delitem(sys.modules, name, raising=False)


ORIGINAL = b'{"version":3,"sources":["original.ts"],"sourcesContent":["export {};"]}'
DIGEST = hashlib.sha256(ORIGINAL).hexdigest()
REQUEST = {
    "request_id": "req-" + "a" * 48,
    "engagement_id": "eng-approved",
    "task_id": "task-approved",
    "server_id": "source-map-mcp",
    "tool_name": "inspect_local_original_sourcemap",
    "artifact_sha256": DIGEST,
}


def _public(signer: Ed25519PrivateKey) -> str:
    raw = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def _token(stage: Any, fields: dict, signer: Ed25519PrivateKey, domain: bytes, kid: str) -> dict:
    return {
        "claims": fields,
        "kid": kid,
        "signature": base64.urlsafe_b64encode(signer.sign(domain + stage._canonical(fields)))
        .decode()
        .rstrip("="),
    }


@pytest.fixture
def context(
    modules: tuple[Any, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    stage, mod = modules
    root = tmp_path / "sourcemap-originals"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    source = Ed25519PrivateKey.generate()
    host = Ed25519PrivateKey.generate()
    observer = Ed25519PrivateKey.generate()
    supervisor = Ed25519PrivateKey.generate()
    key_file = tmp_path / "host-stage-signer.key"
    key_file.write_bytes(
        host.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    key_file.chmod(0o600)
    observer_key_file = tmp_path / "observer-stage-signer.key"
    observer_key_file.write_bytes(
        observer.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    observer_key_file.chmod(0o600)
    ca = tmp_path / "central-ca.pem"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\n" + b"A" * 150)
    ca.chmod(0o600)
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", str(root))
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"central-source": _public(source)}),
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"host-stage": _public(host)}),
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"native-observer": _public(observer)}),
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"native-supervisor-source": _public(supervisor)}),
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_SIGNING_KID", "native-observer")
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_SIGNING_KEY_FILE",
        str(observer_key_file),
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_NATIVE_READONLY_ROOT",
        "/run/osop-sourcemap/sourcemap-originals",
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_SIGNING_KID", "host-stage")
    monkeypatch.setenv("OSOP_SOURCEMAP_HOST_STAGE_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_URL",
        "https://approved-central.invalid/native-sourcemap/source-preflight",
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_SOURCE_CA_BUNDLE", str(ca))
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN",
        "separate-trusted-host-source-service-principal",
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", "separate-native-mcp-principal-token")
    time_now = int(time.time())
    source_claims = {
        "version": 1,
        "preflight_id": "nsp-" + "b" * 32,
        **REQUEST,
        "flow_id": "flow-reviewed",
        "subtask_id": "subtask-reviewed",
        "action_id": "action-" + "c" * 32,
        "owner_id": "owner-verified",
        "manifest_sha256": "d" * 64,
        "approval_id": "approval-independent",
        "lease_id": "lease-live",
        "authorization_version": 4,
        "authorization_sha256": "e" * 64,
        "issued_at": time_now,
        "expires_at": time_now + 10,
    }
    proof = _token(stage, source_claims, source, stage.SOURCE_DOMAIN, "central-source")
    st = root.stat()
    supervisor_claims = {
        "version": 1,
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "request_id": REQUEST["request_id"],
        "engagement_id": REQUEST["engagement_id"],
        "task_id": REQUEST["task_id"],
        "flow_id": source_claims["flow_id"],
        "subtask_id": source_claims["subtask_id"],
        "owner_id": source_claims["owner_id"],
        "approval_id": source_claims["approval_id"],
        "action_id": source_claims["action_id"],
        "lease_id": source_claims["lease_id"],
        "artifact_sha256": source_claims["artifact_sha256"],
        "manifest_sha256": source_claims["manifest_sha256"],
        "authorization_sha256": source_claims["authorization_sha256"],
        "signed_roe_sha256": "b" * 64,
        "container_id": "c" * 64,
        "epoch": 3,
        "pid": 22334,
        "pid_start_ticks": 998873,
        "mount_namespace_inode": 442342,
        "native_fsuid": os.getuid() if os.name == "posix" else 1000,
        "cgroup_sha256": "a" * 64,
        "native_stage_root": "/run/osop-sourcemap/sourcemap-originals",
        "status": "running",
        "source_current": True,
        "lease_active": True,
        "approval_current": True,
        "issued_at": time_now,
        "expires_at": time_now + 5,
    }
    import ai_osop.orchestrator.sourcemap_native_mount_observer as native_observer

    signed_supervisor = _token(
        stage,
        supervisor_claims,
        supervisor,
        native_observer.SUPERVISOR_SOURCE_DOMAIN,
        "native-supervisor-source",
    )
    monkeypatch.setattr(native_observer, "_observe_proc", lambda *_: st)
    return {
        "stage": stage,
        "mod": mod,
        "root": root,
        "key_file": key_file,
        "source": source,
        "host": host,
        "observer": observer,
        "supervisor": supervisor,
        "source_token": proof,
        "supervisor_source": signed_supervisor,
        "native_observer": native_observer,
        "claims": source_claims,
    }


def _setup_coordinator(ctx: dict[str, Any]) -> Any:
    mod = ctx["mod"]
    host = ctx["stage"].OriginalSourceMapHostStage()
    item = object.__new__(mod.OriginalSourceMapHostCoordinator)
    item._host = host
    item._signer = mod._host_signer(host)
    item._channel = mod._source_channel()
    item._observer_roots = mod._roots(
        "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON"
    )
    item._observer = mod.IndependentSourceMapNativeMountObserver(host)
    return item


def _http_stub(
    ctx: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    *,
    lost_ack: bool = False,
    source_token: Any = None,
) -> list[dict[str, Any]]:
    mod = ctx["mod"]
    calls: list[dict[str, Any]] = []

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            assert kwargs["verify"] == os.environ["OSOP_SOURCEMAP_SOURCE_CA_BUNDLE"]
            assert kwargs["trust_env"] is False
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def post(self, url: str, **kwargs: Any) -> Any:
            assert url == os.environ["OSOP_SOURCEMAP_SOURCE_URL"]
            assert kwargs["follow_redirects"] is False
            assert kwargs["headers"]["Authorization"] == (
                "Bearer " + os.environ["OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN"]
            )
            calls.append(kwargs["json"])
            if lost_ack:
                raise OSError("post-commit ambiguous HTTPS ACK")
            return types.SimpleNamespace(
                status_code=200,
                content=json.dumps(source_token or ctx["source_token"]).encode(),
            )

    monkeypatch.setattr(mod.httpx, "AsyncClient", Client, raising=False)
    return calls


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync staging")
def test_signed_https_once_then_stage_exact_proofs(
    context: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    co = _setup_coordinator(context)
    calls = _http_stub(context, monkeypatch)
    provisions: list[tuple[dict, dict]] = []

    class Provision:
        async def provision(self, *, source_proof: dict, provision_proof: dict) -> Path:
            provisions.append((source_proof, provision_proof))
            original_path = co._host.stage(
                original_bytes=ORIGINAL,
                source_proof=source_proof,
                provision_proof=provision_proof,
            )
            return original_path

    co._provisioner = Provision()
    result = asyncio.run(
        co.coordinate(
            original_action_request=dict(REQUEST),
            signed_supervisor_source=context["supervisor_source"],
        )
    )
    assert result == {
        "request_id": REQUEST["request_id"],
        "action_id": context["claims"]["action_id"],
        "artifact_sha256": DIGEST,
        "original_host_stage_complete": True,
        "native_execution_authorized": False,
    }
    assert calls == [REQUEST]
    assert len(provisions) == 1
    source, host = provisions[0]
    assert source == context["source_token"]
    assert host["kid"] == "host-stage"
    assert co._host.stage is not None
    assert (context["root"] / (DIGEST + ".map")).read_bytes() == ORIGINAL
    assert (context["root"] / (DIGEST + ".map")).stat().st_mode & 0o222 == 0
    assert sorted(p.name for p in context["root"].iterdir()).count(DIGEST + ".map") == 1
    with pytest.raises(context["mod"].SourceMapHostCoordinationDenied):
        asyncio.run(
            co.coordinate(
                original_action_request=dict(REQUEST),
                signed_supervisor_source=context["supervisor_source"],
            )
        )
    assert calls == [REQUEST]
    assert len(provisions) == 1


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync staging")
def test_lost_issuer_ack_cannot_reissue_after_new_coordinator(
    context: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    co = _setup_coordinator(context)
    calls = _http_stub(context, monkeypatch, lost_ack=True)

    class Forbidden:
        async def provision(self, **_kwargs: Any) -> None:
            raise AssertionError("MUST NOT stage after lost source ACK")

    co._provisioner = Forbidden()
    with pytest.raises(context["mod"].SourceMapHostCoordinationDenied):
        asyncio.run(
            co.coordinate(
                original_action_request=dict(REQUEST),
                signed_supervisor_source=context["supervisor_source"],
            )
        )
    assert calls == [REQUEST]
    after_restart = _setup_coordinator(context)
    after_restart._provisioner = Forbidden()
    with pytest.raises(context["mod"].SourceMapHostCoordinationDenied):
        asyncio.run(
            after_restart.coordinate(
                original_action_request=dict(REQUEST),
                signed_supervisor_source=context["supervisor_source"],
            )
        )
    assert calls == [REQUEST]


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync staging")
def test_host_mount_signer_and_source_fail_closed_before_issuance(
    context: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    co = _setup_coordinator(context)
    calls = _http_stub(context, monkeypatch)
    co._provisioner = object()
    valid = context["supervisor_source"]
    tamper = json.loads(json.dumps(valid))
    tamper["claims"]["lease_active"] = False
    bad_observer = json.loads(json.dumps(valid))
    bad_observer["signature"] = "A" * 86
    bad_epoch = _token(
        context["stage"],
        {**valid["claims"], "epoch": 0},
        context["supervisor"],
        context["native_observer"].SUPERVISOR_SOURCE_DOMAIN,
        "native-supervisor-source",
    )
    for invalid in (tamper, bad_observer, bad_epoch, {}, {"read_only": True}):
        with pytest.raises(context["mod"].SourceMapHostCoordinationDenied):
            asyncio.run(
                co.coordinate(
                    original_action_request=dict(REQUEST),
                    signed_supervisor_source=invalid,
                )
            )
    assert calls == []
    monkeypatch.delenv("OSOP_SOURCEMAP_HOST_STAGE_SIGNING_KID")
    with pytest.raises(context["mod"].SourceMapHostCoordinationDenied):
        asyncio.run(
            co.coordinate(original_action_request=dict(REQUEST), signed_supervisor_source=valid)
        )
    assert calls == []


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync staging")
def test_wrong_0035_signed_source_denied_without_provision(
    context: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrong = _token(
        context["stage"],
        {**context["claims"], "task_id": "task-cross-action"},
        context["source"],
        context["stage"].SOURCE_DOMAIN,
        "central-source",
    )
    co = _setup_coordinator(context)
    calls = _http_stub(context, monkeypatch, source_token=wrong)

    class Forbidden:
        async def provision(self, **_kwargs: Any) -> None:
            raise AssertionError("Forbidden provision")

    co._provisioner = Forbidden()
    with pytest.raises(context["mod"].SourceMapHostCoordinationDenied):
        asyncio.run(
            co.coordinate(
                original_action_request=dict(REQUEST),
                signed_supervisor_source=context["supervisor_source"],
            )
        )
    assert calls == [REQUEST]
    assert not (context["root"] / (DIGEST + ".map")).exists()


def test_no_unsigned_mount_or_request_accepted_without_runtime(
    modules: tuple[Any, Any],
) -> None:
    _stage, mod = modules
    with pytest.raises(mod.SourceMapHostCoordinationDenied):
        mod._safe_request({"request_id": REQUEST["request_id"]})
    with pytest.raises(mod.SourceMapHostCoordinationDenied):
        mod._safe_request({**REQUEST, "artifact_sha256": "../../unsafe.map"})
    with pytest.raises(mod.SourceMapHostCoordinationDenied):
        mod._safe_request({**REQUEST, "tool_name": "scan_target"})
