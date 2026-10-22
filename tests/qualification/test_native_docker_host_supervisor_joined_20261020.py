"""Opt-in REAL host-supervised Recon → Go → pinned HTTPS → disposable PG.

Requires a separately owned Linux Docker engine and fresh disposable PG. The
previous qualification used direct test-built supervisor proof; this distinct
test exercises the actual production host-side daemon-inspected signer and
fixed Docker-exec localhost proof delivery. It is NEVER a scanner/target test.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import text

from ai_osop.api.routers import native_mcp_redemption as redemption
from ai_osop.orchestrator.native_mcp_docker_supervisor import (
    NativeDockerSupervisorProvisioner,
    OWNER_LABEL,
)
from tests.qualification.native_linux_isolated_go_helper_20261020 import (
    isolated_linux_go_worker,
)
from tests.qualification.test_native_folder_stage_pg_20261020 import (
    _approved_folder_case,
)
from tests.qualification.test_native_isolated_stage_receipt_joined_20261020 import (
    _mounted_real_fastapi_tls,
    _record_observed_supervision,
    _supervised_claims,
)
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    _KID,
    _OWNER,
    _SECRET,
    disposable_native_pg,
    initialized_catalog,
    signing_material,
)


@pytest.mark.asyncio(scope="module")
async def test_real_host_daemon_observed_supervisor_0026_through_0033(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: ed25519.Ed25519PrivateKey,
) -> None:
    if (
        os.getenv("OSOP_DISPOSABLE_NATIVE_0029_PG") != "1"
        or os.getenv("OSOP_JOINED_HOST_SUPERVISOR_20261020") != "1"
    ):
        pytest.skip("Requires two explicit owned Linux Docker + disposable PG opt-ins")
    import docker  # No docker engine/network accessed unless opt-ins are explicit.

    supervisor_private = ed25519.Ed25519PrivateKey.generate()
    supervisor_id = "independent-host-process-supervisor-v1"
    supervisor_kid = "independent-host-process-key-v1"
    supervisor_secret = "disposable-host-supervisor-secret-v1"
    supervisor_public = supervisor_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setenv(
        "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON",
        json.dumps(
            {
                supervisor_id: {
                    "kid": supervisor_kid,
                    "public_key": base64.urlsafe_b64encode(supervisor_public).decode().rstrip("="),
                    "secret_sha256": hashlib.sha256(supervisor_secret.encode()).hexdigest(),
                }
            }
        ),
    )
    worker_private = ed25519.Ed25519PrivateKey.generate()
    worker_seed = worker_private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    worker_kid = "isolated-owned-host-worker-key-v1"
    worker_public = worker_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setenv(
        "OSOP_NATIVE_STAGE_RECEIPT_TRUST_JSON",
        json.dumps(
            {
                "recon-mcp": {
                    "kid": worker_kid,
                    "public_key": base64.urlsafe_b64encode(worker_public).decode().rstrip("="),
                }
            }
        ),
    )
    issuer_public = signing_material.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    case, digest, _, _, stage = await _approved_folder_case(
        disposable_native_pg, initialized_catalog, monkeypatch, signing_material
    )
    old = redemption.state.get("orchestrator")
    redemption.state["orchestrator"] = SimpleNamespace(
        session_memory=case.original.memory, mcp_registry=initialized_catalog
    )
    # Qualification-only source-side error classification. The mounted route
    # deliberately sends a generic HTTP409 to the worker; capture the trusted
    # source exception privately without weakening production error redaction.
    from ai_osop.api.routers import native_mcp_resources

    source_denials: list[dict[str, Any]] = []
    original_offer = native_mcp_resources.NativeMCPResourceDelivery.offer

    async def traced_offer(self: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return await original_offer(self, *args, **kwargs)
        except Exception as exc:
            source_denials.append(
                {
                    "kind": type(exc).__name__,
                    "code": getattr(exc, "status", None),
                    "reason_class": str(exc)[:180],
                }
            )
            raise

    monkeypatch.setattr(native_mcp_resources.NativeMCPResourceDelivery, "offer", traced_offer)
    client = None
    try:
        async with _mounted_real_fastapi_tls() as (port, root_pem):
            native_env = {
                "OSOP_RECON_MCP_LOCAL_PORT": "8082",
                "OSOP_NATIVE_MCP_STAGE_ROOT": "/run/osop-native-stage",
                "OSOP_NATIVE_MCP_LOCAL_TEST_TRACE": "1",
                "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON": json.dumps(
                    {_KID: base64.urlsafe_b64encode(issuer_public).decode().rstrip("=")}
                ),
                "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON": json.dumps({"recon-mcp": _SECRET}),
                "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM": root_pem,
                "OSOP_NATIVE_MCP_REDEEM_URL": "https://127.0.0.1:18443/native-grants/redeem",
                "OSOP_NATIVE_STAGE_RECEIPT_ED25519_SEED_B64": (
                    base64.urlsafe_b64encode(worker_seed).decode().rstrip("=")
                ),
                "OSOP_NATIVE_STAGE_RECEIPT_KID": worker_kid,
                "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON": os.environ[
                    "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"
                ],
            }
            client = docker.from_env(timeout=8)
            engine = client.info()
            assert engine.get("OSType") == "linux" and engine.get("Architecture") in {
                "amd64",
                "x86_64",
            }
            image_id = client.images.get("python:3.11-slim").id
            supervisor = NativeDockerSupervisorProvisioner(
                docker_client=client,
                source_port=port,
                source_root_pem=root_pem,
                supervisor_id=supervisor_id,
                supervisor_kid=supervisor_kid,
                supervisor_secret=supervisor_secret,
                supervisor_private=supervisor_private,
                trusted_issuer_keys={
                    _KID: base64.urlsafe_b64encode(issuer_public).decode().rstrip("=")
                },
            )
            worker_id = "worker-" + uuid.uuid4().hex
            async with isolated_linux_go_worker(
                native_env=native_env, validator_host_port=port
            ) as worker:
                code, initialized = await worker.post(
                    "/mcp/initialize",
                    {"scope": {}, "session_id": "owned-current-supervisor", "auth_credentials": {}},
                )
                assert code == 200 and initialized["status"] == "ready"
                assert [tool["name"] for tool in initialized["tools"]] == ["authority_status"]
                reserved = await case.original.reserve(case.binding, _OWNER, case.action_id)
                pending = await case.original.mark_dispatched(
                    case.binding,
                    _OWNER,
                    case.action_id,
                    case.request_id,
                    reserved["reservation_token"],
                )
                assert pending["status"] == "unknown"
                issued = await case.grants.issue(
                    case.binding,
                    _OWNER,
                    case.action_id,
                    case.request_id,
                    resource_sha256=digest,
                )
                grant = issued["token"]
                owner = worker._container_name.removesuffix("-recon")
                assert owner.startswith("osop-native-linux-")
                before = await supervisor.provision_inert_grant(
                    grant=grant,
                    worker_id=worker_id,
                    owner_id=_OWNER,
                    approval_id=case.approval_id,
                    container_id=worker.container_id,
                    network_id=worker.network_id,
                    owner_nonce=owner,
                    owner_label=OWNER_LABEL,
                    expected_image_id=image_id,
                    # default uses actual HOST docker-exec to Go loopback
                )
                assert before["state"] == "provisioned"
                assert before["native_provision_acknowledged"] is True
                assert before["durably_redeemed"] is False
                async with disposable_native_pg.connect() as db:
                    row = (
                        await db.execute(
                            text(
                                "SELECT state,epoch,revision,worker_id,container_id FROM "
                                "native_mcp_worker_supervisions WHERE grant_id=:grant"
                            ),
                            {"grant": issued["grant_id"]},
                        )
                    ).one()
                    assert row == (
                        "provisioned",
                        before["epoch"],
                        1,
                        worker_id,
                        worker.container_id,
                    )
                action = {
                    "tool_name": "authority_status",
                    "parameters": {},
                    "request_id": case.request_id,
                    "timeout_override": None,
                }
                status, answer = await worker.post(
                    "/mcp/execute",
                    action,
                    {"X-OSOP-Native-Grant": issued["native_grant_header"]},
                )
                if status != 200:
                    from tests.qualification.native_linux_isolated_go_helper_20261020 import _exec
                    import asyncio

                    try:
                        log_tail = await asyncio.to_thread(
                            _exec,
                            worker._container_name,
                            ["sh", "-c", "tail -c 2000 /tmp/recon.log"],
                            timeout=5,
                        )
                    except Exception:
                        log_tail = b"log_unavailable"
                    async with disposable_native_pg.connect() as db:
                        actual_grant = (
                            await db.execute(
                                text(
                                    "SELECT status FROM native_mcp_execution_grants WHERE grant_id=:grant"
                                ),
                                {"grant": issued["grant_id"]},
                            )
                        ).scalar_one()
                    pytest.fail(
                        "Inert native supervised Go denial: "
                        + json.dumps(
                            {
                                "status": status,
                                "error_class": answer.get("error"),
                                "durable_grant_status": actual_grant,
                                "owned_worker_trace": str(log_tail)[-800:],
                                "trusted_source_denials": source_denials,
                            }
                        )
                    )
                assert status == 200 and answer["status"] == "success", {
                    "native_http_status": status,
                    "native_result_status": answer.get("status"),
                    "native_error_class": answer.get("error"),
                    "native_reason": answer.get("reason"),
                }
                assert answer["result"]["resource_bytes_received_verified"] is True
                assert answer["result"]["target_contacted"] is False
                assert await worker.stage_root_empty()
                async with disposable_native_pg.connect() as db:
                    readback_sha = (
                        await db.execute(
                            text(
                                "SELECT readback_sha256 FROM native_mcp_stage_receipts "
                                "WHERE grant_id=:grant"
                            ),
                            {"grant": issued["grant_id"]},
                        )
                    ).scalar_one()
                running = await _record_observed_supervision(
                    port=port,
                    root_pem=root_pem,
                    signed_grant=grant,
                    private=supervisor_private,
                    supervisor_id=supervisor_id,
                    secret=supervisor_secret,
                    worker_kid=supervisor_kid,
                    claims=_supervised_claims(
                        grant,
                        worker_id=worker_id,
                        state="running",
                        epoch=before["epoch"],
                        revision=1,
                        container_id=worker.container_id,
                        evidence={"stage_empty": True, "host_daemon_observer": True},
                        folder=stage["staging_sha256"],
                        readback=readback_sha,
                    ),
                )
                assert running["revision"] == 2
                replay, _ = await worker.post(
                    "/mcp/execute",
                    action,
                    {"X-OSOP-Native-Grant": issued["native_grant_header"]},
                )
                assert replay == 503
            # The owned worker+network are already torn down by the independent
            # Docker context, and MUST be absent in the real daemon now.
            for resource, resource_id in (
                (client.containers, worker.container_id),
                (client.networks, worker.network_id),
            ):
                try:
                    resource.get(resource_id)
                except Exception as exc:
                    assert exc.__class__.__name__ == "NotFound"
                else:
                    raise AssertionError("Owned native worker/network survived teardown")
            terminated = await _record_observed_supervision(
                port=port,
                root_pem=root_pem,
                signed_grant=grant,
                private=supervisor_private,
                supervisor_id=supervisor_id,
                secret=supervisor_secret,
                worker_kid=supervisor_kid,
                claims=_supervised_claims(
                    grant,
                    worker_id=worker_id,
                    state="terminated",
                    epoch=before["epoch"],
                    revision=running["revision"],
                    container_id=worker.container_id,
                    evidence={"daemon_owned_container_removed": True},
                    folder=stage["staging_sha256"],
                    readback=readback_sha,
                ),
            )
            assert terminated["state"] == "terminated"
            reaped = await _record_observed_supervision(
                port=port,
                root_pem=root_pem,
                signed_grant=grant,
                private=supervisor_private,
                supervisor_id=supervisor_id,
                secret=supervisor_secret,
                worker_kid=supervisor_kid,
                claims=_supervised_claims(
                    grant,
                    worker_id=worker_id,
                    state="reaped",
                    epoch=before["epoch"],
                    revision=terminated["revision"],
                    container_id=worker.container_id,
                    evidence={"daemon_owned_network_removed": True},
                    folder=stage["staging_sha256"],
                    readback=readback_sha,
                ),
            )
            assert reaped["state"] == "reaped"
            async with disposable_native_pg.connect() as db:
                assert (
                    await db.execute(
                        text(
                            "SELECT status FROM flow_mcp_action_dispatches "
                            "WHERE action_id=:action"
                        ),
                        {"action": case.action_id},
                    )
                ).scalar_one() == "unknown"
    finally:
        if client is not None:
            client.close()
        if old is None:
            redemption.state.pop("orchestrator", None)
        else:
            redemption.state["orchestrator"] = old
