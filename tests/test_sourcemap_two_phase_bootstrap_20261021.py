"""Offline first-use SourceMap two-phase host coordination qualification.

All positive cryptographic source/status inputs are SYNTHETIC test keys and
FAKE PostgreSQL; an independently trusted live 0033 SourceMap supervisor
postproof service does not exist. Never interpret this suite as E2E readiness.
No app DB, Docker, real HTTPS, targets or native process is contacted.
"""

from __future__ import annotations

import asyncio
import base64
import copy
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

from tests import test_sourcemap_original_host_coordinator_20261021 as base


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_PATH = ROOT / "src" / "ai_osop" / "memory" / "sourcemap_original_bootstrap_witness.py"
ISSUER_PATH = ROOT / "src" / "ai_osop" / "orchestrator" / "sourcemap_supervisor_source_issuer.py"
STATUS_DOMAIN = b"ai-osop/sourcemap-original-status/v1\x00"


@pytest.fixture
def context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    # Do not depend on other tests' fixtures being registered by pytest when
    # this qualification file runs alone with --noconftest.
    setup = base.modules.__wrapped__(monkeypatch)
    modules = next(setup)
    try:
        yield base.context.__wrapped__(modules, tmp_path, monkeypatch)
    finally:
        setup.close()


@pytest.fixture
def boot(
    context: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> dict[str, Any]:
    """Reuse the existing synthetic coordinator keys and real verification."""
    stage = context["stage"]
    coordinator = context["mod"]
    actions_info: dict[str, Any] = {"queries": [], "statuses": 0, "fail": False}
    mem = types.ModuleType("ai_osop.memory")
    mem.__path__ = [str(ROOT / "src" / "ai_osop" / "memory")]
    monkeypatch.setitem(sys.modules, "ai_osop.memory", mem)

    class FakeTransaction:
        async def __aenter__(self) -> None:
            actions_info["queries"].append("BEGIN")

        async def __aexit__(self, *_args: Any) -> None:
            actions_info["queries"].append("END")

    class FakeSession:
        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def begin(self) -> FakeTransaction:
            return FakeTransaction()

    class FakeActions:
        def _sessions(self) -> Any:
            return FakeSession

    actions = FakeActions()
    action_module = types.ModuleType("ai_osop.memory.flow_mcp_action_dispatch")
    action_module.FlowMCPActionStore = FakeActions
    monkeypatch.setitem(sys.modules, action_module.__name__, action_module)
    source_module = types.ModuleType("ai_osop.memory.sourcemap_source_authority")

    def original_row() -> dict[str, Any]:
        source = context["claims"]
        return {
            **{
                field: source[field]
                for field in (
                    "request_id",
                    "engagement_id",
                    "flow_id",
                    "task_id",
                    "subtask_id",
                    "action_id",
                    "owner_id",
                    "server_id",
                    "tool_name",
                    "approval_id",
                    "lease_id",
                    "authorization_version",
                    "authorization_sha256",
                )
            },
            "lease_owner_id": "leaseowner-reviewed",
            "flow_revision": 3,
            "authorization_id": "authorization-current",
            "intent_sha256": "1" * 64,
            "declaration_sha256": "2" * 64,
            "parameters_sha256": "3" * 64,
            "status": "unknown",
            "cancel_requested": False,
            "receipt_sha256": None,
        }

    class FakeSource:
        def __init__(self, provided: FakeActions) -> None:
            assert provided is actions

        async def _source(self, db: FakeSession, request: dict[str, str]) -> tuple[dict, str]:
            actions_info["queries"].append("SELECT:original-0027-current")
            if actions_info["fail"]:
                raise ValueError("revoked original Action")
            assert request == base.REQUEST
            return original_row(), context["claims"]["manifest_sha256"]

        async def _now(self, db: FakeSession) -> int:
            actions_info["queries"].append("SELECT:db-clock")
            return int(time.time())

        async def admit(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("0035 central admit must NEVER be called here")

    source_module.SourceMapSourceAuthorityStore = FakeSource
    source_module.canonical = stage._canonical
    source_module.validate_request = coordinator._safe_request
    monkeypatch.setitem(sys.modules, source_module.__name__, source_module)

    bootstrap_name = "ai_osop.memory.sourcemap_original_bootstrap_witness"
    spec = importlib.util.spec_from_file_location(bootstrap_name, BOOTSTRAP_PATH)
    assert spec is not None and spec.loader is not None
    bootstrap = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, bootstrap_name, bootstrap)
    spec.loader.exec_module(bootstrap)
    status_module = types.ModuleType("ai_osop.memory.sourcemap_status_authority")

    class FakeStatus:
        def __init__(self, provided: FakeActions) -> None:
            assert provided is actions

        async def admit(self, request: dict[str, str]) -> dict[str, Any]:
            assert request == base.REQUEST
            actions_info["statuses"] += 1
            if actions_info.get("status_failure"):
                raise ValueError("Postcommit 0035 status missing")
            source = context["claims"]
            current = {
                **source,
                "status_id": "nss-" + "d" * 32,
                "issued_at": int(time.time()),
                "expires_at": int(time.time()) + 5,
            }
            return base._token(stage, current, context["source"], STATUS_DOMAIN, "central-source")

    status_module.SourceMapStatusAuthorityStore = FakeStatus
    monkeypatch.setitem(sys.modules, status_module.__name__, status_module)
    if "ai_osop.orchestrator.sourcemap_supervisor_source_issuer" in sys.modules:
        monkeypatch.delitem(
            sys.modules,
            "ai_osop.orchestrator.sourcemap_supervisor_source_issuer",
        )
    issuer = base._module("ai_osop.orchestrator.sourcemap_supervisor_source_issuer", ISSUER_PATH)
    assert issuer.SOURCE_STATUS_DOMAIN == STATUS_DOMAIN

    bootstrap_key = Ed25519PrivateKey.generate()
    pw = os.urandom(48)
    encrypted_path = tmp_path / "bootstrap-encrypted.pk8"
    encrypted_path.write_bytes(
        bootstrap_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(pw),
        )
    )
    encrypted_path.chmod(0o600)
    password_path = tmp_path / "bootstrap-password"
    password_path.write_bytes(pw)
    password_path.chmod(0o600)
    monkeypatch.setenv(
        bootstrap.TRUST_ENV, json.dumps({"bootstrap-new": base._public(bootstrap_key)})
    )
    monkeypatch.setenv(bootstrap.SIGNING_KID_ENV, "bootstrap-new")
    monkeypatch.setenv(bootstrap.SIGNING_KEY_FILE_ENV, str(encrypted_path))
    monkeypatch.setenv(bootstrap.SIGNING_PASSWORD_FILE_ENV, str(password_path))
    monkeypatch.delenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", raising=False)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_STATUS_URL",
        "https://approved-central.invalid/native-sourcemap/status-preflight",
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_STATUS_CA_BUNDLE",
        os.environ["OSOP_SOURCEMAP_SOURCE_CA_BUNDLE"],
    )
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN",
        "protected-independent-status-service-principal",
    )
    for optional in bootstrap._OTHER_TRUST_ENVS:
        if optional not in (
            "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
            "OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON",
            "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON",
            "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        ):
            monkeypatch.delenv(optional, raising=False)
    co = base._setup_coordinator(context)
    co._actions = actions

    # Explicitly TEST-ONLY: provide an in-memory signed STATUS, without
    # contacting the real, registered /native-sourcemap/status-preflight route
    # or exposing its central source signing private key to the host. Separate
    # pinned HTTPS transport is qualified in the host-status-channel tests.
    async def test_only_current_status(
        *,
        original_action_request: dict[str, str],
        source_proof: dict[str, Any],
        pinned_status_channel: tuple[str, str, str],
    ) -> dict[str, Any]:
        assert source_proof == context["source_token"]
        assert pinned_status_channel == coordinator._status_channel()
        return await FakeStatus(actions).admit(original_action_request)

    monkeypatch.setattr(co, "_trusted_status_after_0035", test_only_current_status)

    class NoStage:
        async def provision(self, **_kwargs: Any) -> None:
            raise AssertionError("May never stage without genuinely valid current supervisor")

    co._provisioner = NoStage()
    return {
        "context": context,
        "co": co,
        "bootstrap": bootstrap,
        "bootstrap_key": bootstrap_key,
        "actions": actions_info,
        "key": encrypted_path,
    }


def execute(boot: dict[str, Any]) -> Any:
    return asyncio.run(boot["co"].coordinate_first_use(original_action_request=dict(base.REQUEST)))


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync")
def test_synthetic_0027_precheck_then_one_post_and_signed_status_but_no_supervisor(
    boot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    posts = base._http_stub(boot["context"], monkeypatch)
    assert "OSOP_SOURCEMAP_MCP_BEARER_TOKEN" not in os.environ
    # MUST actually reach the protected post-status source after verifying
    # distinct source 10s and current STATUS 5s temporal windows.
    supervisor_called: list[tuple[str, str]] = []

    async def supervisor_missing(
        *, source_proof: dict[str, Any], source_status: dict[str, Any]
    ) -> dict[str, Any]:
        supervisor_called.append(
            (source_proof["claims"]["action_id"], source_status["claims"]["status_id"])
        )
        raise ValueError("no actual enrolled current 0033 CAS/PID producer")

    monkeypatch.setattr(boot["co"], "_trusted_supervisor_after_status", supervisor_missing)
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]
    assert boot["actions"]["statuses"] == 1
    assert supervisor_called == [(boot["context"]["claims"]["action_id"], "nss-" + "d" * 32)]
    assert boot["actions"]["queries"] == [
        "BEGIN",
        "SELECT:original-0027-current",
        "SELECT:db-clock",
        "END",
    ]
    assert not (boot["context"]["root"] / (base.DIGEST + ".map")).exists()
    assert len(list(boot["context"]["root"].glob(".issuer-*.used"))) == 1
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]
    assert boot["actions"]["statuses"] == 1
    assert not (boot["context"]["root"] / (base.DIGEST + ".proof.json")).exists()


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync")
def test_lost_0035_https_ack_permanently_consumes_local_request(
    boot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    posts = base._http_stub(boot["context"], monkeypatch, lost_ack=True)
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]
    assert boot["actions"]["statuses"] == 0
    assert len(list(boot["context"]["root"].glob(".issuer-*.used"))) == 1
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]
    assert not (boot["context"]["root"] / (base.DIGEST + ".map")).exists()


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync")
def test_failed_0027_precheck_and_forged_bootstrap_refuse_first_post(
    boot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    posts = base._http_stub(boot["context"], monkeypatch)
    boot["actions"]["fail"] = True
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == []
    boot["actions"]["fail"] = False
    original = boot["bootstrap"].verify_bootstrap_witness

    def attacker_verify(proof: dict[str, Any], roots: Any, request: Any) -> dict[str, Any]:
        altered = copy.deepcopy(proof)
        altered["claims"]["owner_id"] = "owner-attacker"
        return original(altered, roots, request)

    monkeypatch.setattr(boot["bootstrap"], "verify_bootstrap_witness", attacker_verify)
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == []
    assert not list(boot["context"]["root"].glob(".issuer-*.used"))


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync")
def test_stale_bootstrap_no_0035_even_with_test_enrolled_signature(
    boot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    posts = base._http_stub(boot["context"], monkeypatch)
    bootstrap = boot["bootstrap"]
    original = bootstrap.SourceMapOriginalBootstrapWitnessStore.attest

    async def stale(self: Any, request: dict[str, str]) -> dict[str, Any]:
        token = await original(self, request)
        claims = {
            **token["claims"],
            "observed_at": int(time.time()) - 20,
            "expires_at": int(time.time()) - 15,
        }
        key = boot["bootstrap_key"]
        return {
            "claims": claims,
            "kid": token["kid"],
            "signature": base64.urlsafe_b64encode(
                key.sign(bootstrap.BOOTSTRAP_DOMAIN + bootstrap.canonical(claims))
            )
            .decode("ascii")
            .rstrip("="),
        }

    monkeypatch.setattr(bootstrap.SourceMapOriginalBootstrapWitnessStore, "attest", stale)
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == []
    assert not list(boot["context"]["root"].glob(".issuer-*.used"))


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync")
def test_signed_0035_but_current_status_missing_is_unknown_no_stage(
    boot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    posts = base._http_stub(boot["context"], monkeypatch)
    boot["actions"]["status_failure"] = True
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]
    assert boot["actions"]["statuses"] == 1
    assert not (boot["context"]["root"] / (base.DIGEST + ".map")).exists()
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync")
def test_missing_test_status_transport_denies_without_central_signer(
    boot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    posts = base._http_stub(boot["context"], monkeypatch)
    monkeypatch.setattr(
        boot["co"],
        "_trusted_status_after_0035",
        types.MethodType(
            boot["context"]["mod"].OriginalSourceMapHostCoordinator._trusted_status_after_0035,
            boot["co"],
        ),
    )
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]
    assert boot["actions"]["statuses"] == 0
    assert not (boot["context"]["root"] / (base.DIGEST + ".map")).exists()


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync")
def test_forged_supervisor_or_missing_kernel_observation_never_stage(
    boot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    posts = base._http_stub(boot["context"], monkeypatch)

    async def forged(**_kwargs: Any) -> dict[str, Any]:
        return {"source_current": True, "pid": os.getpid()}

    monkeypatch.setattr(boot["co"], "_trusted_supervisor_after_status", forged)
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]
    assert not (boot["context"]["root"] / (base.DIGEST + ".map")).exists()


@pytest.mark.skipif(os.name != "posix", reason="host-only POSIX key and fsync")
def test_crypto_supervisor_but_kernel_readonly_observer_absent_no_stage(
    boot: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    posts = base._http_stub(boot["context"], monkeypatch)

    async def signed(**_kwargs: Any) -> dict[str, Any]:
        return boot["context"]["supervisor_source"]

    monkeypatch.setattr(boot["co"], "_trusted_supervisor_after_status", signed)
    monkeypatch.setattr(
        boot["co"]._observer,
        "observe",
        lambda *_args: (_ for _ in ()).throw(ValueError("no independently verified mount")),
    )
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]
    assert not (boot["context"]["root"] / (base.DIGEST + ".map")).exists()
    with pytest.raises(boot["context"]["mod"].SourceMapHostCoordinationDenied):
        execute(boot)
    assert posts == [base.REQUEST]


def test_coordinator_legacy_method_left_present(context: dict[str, Any]) -> None:
    co = context["mod"].OriginalSourceMapHostCoordinator
    assert callable(co.coordinate) and callable(co.coordinate_first_use)
    assert "signed_supervisor_source" in co.coordinate.__code__.co_varnames
    assert "signed_supervisor_source" not in co.coordinate_first_use.__code__.co_varnames
