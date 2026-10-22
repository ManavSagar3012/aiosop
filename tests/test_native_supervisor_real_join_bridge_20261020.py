"""Production-call-path supervisor bridge contracts, never joined PG/Docker evidence."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.orchestrator.native_mcp_docker_supervisor import (
    LEGACY_SUPERVISOR_OWNER_LABEL,
    NativeDockerSupervisorProvisioner,
)
from ai_osop.safety.native_mcp_worker_supervisor import (
    NativeMCPWorkerSupervisor,
    NativeSupervisorDenied,
    SourceAuthorityDecision,
    SupervisorBinding,
    SupervisorSession,
)
from tests.test_native_independent_docker_supervisor_20261020 import _grant
from tests.test_native_mcp_worker_supervisor_20261020 import (
    FakeDocker,
    _binding,
    _env,
    _supervisor,
    _decision,
)


def _bridge() -> tuple[SupervisorSession, NativeDockerSupervisorProvisioner, dict]:
    token, issuer_roots, _ = _grant()
    original = token["claims"]
    binding = SupervisorBinding(
        request_id=original["request_id"],
        engagement_id=original["engagement_id"],
        flow_id=original["flow_id"],
        task_id=original["task_id"],
        subtask_id=original["subtask_id"],
        action_id=original["action_id"],
        approval_id="apr-qualified",
        lease_id=original["lease_id"],
        issuer_kid="native-issuer-1",
        signed_roe_sha256="6" * 64,
        authorization_sha256=original["authorization_sha256"],
        manifest_sha256=original["manifest_sha256"],
        binary_sha256="7" * 64,
    )
    signer = Ed25519PrivateKey.generate()

    async def trusted_source(b: SupervisorBinding) -> SourceAuthorityDecision:
        from datetime import datetime
        import time

        now = int(time.time())
        return SourceAuthorityDecision(
            binding=b,
            authority_version=1,
            checked_at=now,
            expires_at=now + 15,
            issuer_trusted=True,
            signed_roe_valid=True,
            task_active=True,
            approval_current=True,
            lease_active=True,
        )

    fake_docker = SimpleNamespace(
        images=SimpleNamespace(get=lambda _: SimpleNamespace(id="sha256:" + "d" * 64)),
        close=lambda: None,
    )
    authority = NativeMCPWorkerSupervisor(
        source_authority=trusted_source,
        trusted_issuer_keys={
            key: base64.urlsafe_b64decode(value + "==") for key, value in issuer_roots.items()
        },
        supervisor_private_key=signer,
        supervisor_kid="independent-bridge-supervisor",
        docker_factory=lambda: fake_docker,
    )
    authority._exec = AsyncMock(
        return_value=json.dumps(
            {
                "http_status": 200,
                "body": {
                    "status": "success",
                    "result": {
                        "native_target_execution_enabled": False,
                        "target_contacted": False,
                        "provider_contacted": False,
                        "resource_bytes_received_verified": True,
                    },
                },
            }
        ).encode("ascii")
    )
    session = SupervisorSession(
        binding=binding,
        owner="osop-native-sup-" + "d" * 32,
        container_id="c" * 64,
        network_id="a" * 64,
        ownership_statement={},
        _supervisor=authority,
        worker_id="worker-bridge-0033",
        _public_supervisor_trust_ready=True,
        _public_supervisor_id="independent-observer-v1",
    )
    provisioner = NativeDockerSupervisorProvisioner(
        docker_client=fake_docker,
        source_port=18444,
        source_root_pem="-----BEGIN CERTIFICATE-----test",
        supervisor_id="independent-observer-v1",
        supervisor_kid=authority.kid,
        supervisor_secret="distinct-supervisor-credential-value",
        supervisor_private=signer,
        trusted_issuer_keys=issuer_roots,
    )
    provisioner.provision_inert_grant = AsyncMock(
        return_value={
            "grant_id": original["grant_id"],
            "worker_id": session.worker_id,
            "epoch": 23,
            "revision": 1,
            "state": "provisioned",
            "supervisor_observed": True,
            "native_provision_acknowledged": True,
            "durably_redeemed": False,
            "native_scanners_enabled": False,
            "independent_target_effect_verified": False,
        }
    )
    return session, provisioner, token


@pytest.mark.asyncio
async def test_0033_separate_proof_precedes_exact_one_inert_real_go_request() -> None:
    session, provisioner, token = _bridge()
    status, body = await session.invoke_supervised_authority_status(
        signed_grant=token,
        independent_provisioner=provisioner,
        owner_id="owner-qualified",
        approval_id="apr-qualified",
    )
    assert status == 200 and body["result"]["target_contacted"] is False
    assert session._successful_inert_redemption is True
    assert session.store_record == {
        "grant_id": token["claims"]["grant_id"],
        "worker_id": session.worker_id,
        "epoch": 23,
        "revision": 1,
        "state": "provisioned",
        "supervisor_observed": True,
    }
    sent = provisioner.provision_inert_grant.await_args.kwargs
    assert sent["grant"] == token
    assert sent["container_id"] == session.container_id
    assert sent["network_id"] == session.network_id
    assert sent["owner_nonce"] == session.owner
    assert sent["owner_label"] == LEGACY_SUPERVISOR_OWNER_LABEL
    assert sent["expected_image_id"] == "sha256:" + "d" * 64
    assert session._supervisor._exec.await_count == 1
    assert session._supervisor._exec.await_args.args[0] == session.owner + "-recon"
    with pytest.raises(NativeSupervisorDenied):
        await session.invoke_supervised_authority_status(
            signed_grant=token,
            independent_provisioner=provisioner,
            owner_id="owner-qualified",
            approval_id="apr-qualified",
        )
    assert provisioner.provision_inert_grant.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "unconfigured",
        "wrong-principal",
        "wrong-approval",
        "preexisting",
        "lost-proof-ack",
        "forged-ack",
        "lost-go-ack",
    ],
)
async def test_0033_join_fails_closed_and_never_replays_unknown(failure: str) -> None:
    session, provisioner, token = _bridge()
    if failure == "unconfigured":
        session._public_supervisor_trust_ready = False
    elif failure == "wrong-principal":
        session._public_supervisor_id = "another-supervisor"
    elif failure == "preexisting":
        session._invoked = True
    elif failure == "lost-proof-ack":
        provisioner.provision_inert_grant.side_effect = TimeoutError("source ACK unknown")
    elif failure == "forged-ack":
        provisioner.provision_inert_grant.return_value["worker_id"] = "worker-foreign"
    elif failure == "lost-go-ack":
        session._supervisor._exec.side_effect = TimeoutError("redeem committed, ACK lost")
    with pytest.raises(NativeSupervisorDenied):
        await session.invoke_supervised_authority_status(
            signed_grant=token,
            independent_provisioner=provisioner,
            owner_id="owner-qualified",
            approval_id="apr-wrong" if failure == "wrong-approval" else "apr-qualified",
        )
    assert session._successful_inert_redemption is False
    assert session._supervisor._exec.await_count == (1 if failure == "lost-go-ack" else 0)
    if failure not in {"unconfigured", "wrong-principal", "wrong-approval", "preexisting"}:
        assert session._invoked is True
    with pytest.raises(NativeSupervisorDenied):
        await session.invoke_supervised_authority_status(
            signed_grant=token,
            independent_provisioner=provisioner,
            owner_id="owner-qualified",
            approval_id="apr-wrong" if failure == "wrong-approval" else "apr-qualified",
        )


def test_public_supervisor_trust_rejects_mismatched_key_and_duplicate_json() -> None:
    backend = FakeDocker()
    supervisor = _supervisor(lambda b: _decision(b), backend)
    old_env = _env(supervisor._test_public_key)
    public = base64.urlsafe_b64encode(supervisor.public_key).decode().rstrip("=")
    exact = {
        "independent-observer-v1": {
            "kid": supervisor.kid,
            "public_key": public,
            "secret_sha256": "a" * 64,
        }
    }
    valid = {**old_env, "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON": json.dumps(exact)}
    assert supervisor._validate_environment(_binding(), valid)[
        "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"
    ] == json.dumps(exact)
    for altered in (
        {**exact, "independent-observer-v2": exact["independent-observer-v1"]},
        {"independent-observer-v1": {**exact["independent-observer-v1"], "public_key": "A" * 43}},
        {
            "independent-observer-v1": {
                **exact["independent-observer-v1"],
                "secret_sha256": "invalid",
            }
        },
    ):
        invalid = {**old_env, "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON": json.dumps(altered)}
        with pytest.raises(NativeSupervisorDenied):
            supervisor._validate_environment(_binding(), invalid)
    duplicate = (
        '{"independent-observer-v1":'
        + json.dumps(exact["independent-observer-v1"])
        + ',"independent-observer-v1":'
        + json.dumps(exact["independent-observer-v1"])
        + "}"
    )
    with pytest.raises(NativeSupervisorDenied):
        supervisor._validate_environment(
            _binding(), {**old_env, "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON": duplicate}
        )
