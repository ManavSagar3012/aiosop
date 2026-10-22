"""Opt-in actual isolated Go -> TLS FastAPI -> PostgreSQL stage receipt.

The only executable tool is inert ``authority_status``. The Linux worker has
no network egress or host mounts; a test-only Docker-exec stdin TLS tunnel
reaches this test's loopback-mounted FastAPI. No target,
provider, existing application database or consequential scanner is involved.

The durable 0032 receipt remains independently checked WORKER TESTIMONY, not
an independent sandbox or target-effect attestation. UNKNOWN is never replayed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
import ssl
import socket
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator

import pytest
import httpx
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import text

from ai_osop.api.routers import native_mcp_redemption as redemption
from ai_osop.api.routers.native_mcp_grants import _public as safe_grant_readback
from ai_osop.memory.native_mcp_worker_supervision import DOMAIN as SUPERVISOR_DOMAIN
from tests.qualification.test_native_folder_stage_pg_20261020 import _approved_folder_case
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    _KID,
    _OWNER,
    _SECRET,
    disposable_native_pg,
    initialized_catalog,
    signing_material,
)

SUPERVISOR_PROVISION_DOMAIN = b"ai-osop/native-grant-worker-redemption/v1\x00"
SUPERVISOR_PROVISION_CLAIMS = frozenset(
    {
        "version",
        "grant_id",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "owner_id",
        "server_id",
        "worker_id",
        "container_id",
        "supervisor_id",
        "epoch",
        "revision",
        "approval_id",
        "lease_id",
        "authorization_sha256",
        "claims_sha256",
        "resource_sha256",
        "nonce",
        "issued_at",
        "expires_at",
    }
)


def _signed_provision_proof(
    *,
    token: dict[str, Any],
    observed: dict[str, Any],
    container_id: str,
    owner_id: str,
    approval_id: str,
    lease_id: str,
    supervisor_id: str,
    supervisor_kid: str,
    signer: ed25519.Ed25519PrivateKey,
    now: int | None = None,
) -> dict[str, Any]:
    """Exact 23-field Go admission proof from source + durable 0033 observation.

    Requires the independently recorded worker id and monotone PG epoch, not
    caller-provided strings. No worker-held supervisor credential or issuer key.
    """
    original = token["claims"]
    issued_at = int(time.time()) if now is None else now
    expires_at = min(issued_at + 9, original["expires_at"])
    if (
        type(issued_at) is not int
        or not issued_at < expires_at <= issued_at + 10
        or not isinstance(container_id, str)
        or re.fullmatch(r"[a-f0-9]{64}", container_id) is None
        or observed.get("state") != "provisioned"
        or observed.get("grant_id") != original["grant_id"]
        or observed.get("revision") != 1
        or type(observed.get("epoch")) is not int
        or observed["epoch"] <= 0
        or not isinstance(observed.get("worker_id"), str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,95}", observed["worker_id"]) is None
    ):
        raise ValueError("Current independently observed worker proof unavailable")
    claims = {
        "version": 1,
        "grant_id": original["grant_id"],
        "request_id": original["request_id"],
        "engagement_id": original["engagement_id"],
        "flow_id": original["flow_id"],
        "task_id": original["task_id"],
        "subtask_id": original["subtask_id"],
        "action_id": original["action_id"],
        "owner_id": owner_id,
        "server_id": original["server_id"],
        "worker_id": observed["worker_id"],
        "container_id": container_id,
        "supervisor_id": supervisor_id,
        "epoch": observed["epoch"],
        "revision": observed["revision"],
        "approval_id": approval_id,
        "lease_id": lease_id,
        "authorization_sha256": original["authorization_sha256"],
        "claims_sha256": hashlib.sha256(
            json.dumps(original, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "ascii"
            )
        ).hexdigest(),
        "resource_sha256": original["resource_sha256"],
        "nonce": uuid.uuid4().hex,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    assert len(claims) == 23 and set(claims) == SUPERVISOR_PROVISION_CLAIMS
    canonical = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return {
        "claims": claims,
        "kid": supervisor_kid,
        "signature": base64.urlsafe_b64encode(signer.sign(SUPERVISOR_PROVISION_DOMAIN + canonical))
        .decode("ascii")
        .rstrip("="),
    }


def _local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _supervised_claims(
    token: dict[str, Any],
    *,
    worker_id: str,
    state: str,
    epoch: int,
    revision: int,
    container_id: str | None,
    evidence: dict[str, Any],
    folder: str | None = None,
    readback: str | None = None,
) -> dict[str, Any]:
    original = token["claims"]
    return {
        "version": 1,
        "grant_id": original["grant_id"],
        "request_id": original["request_id"],
        "server_id": original["server_id"],
        "worker_id": worker_id,
        "container_id": container_id,
        "epoch": epoch,
        "expected_revision": revision,
        "state": state,
        "observed_at": int(time.time()),
        "evidence_sha256": hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "ascii"
            )
        ).hexdigest(),
        "resource_sha256": original["resource_sha256"],
        "folder_staging_sha256": folder,
        "readback_sha256": readback,
    }


async def _record_observed_supervision(
    *,
    port: int,
    root_pem: str,
    signed_grant: dict[str, Any],
    private: ed25519.Ed25519PrivateKey,
    supervisor_id: str,
    secret: str,
    worker_kid: str,
    claims: dict[str, Any],
) -> dict[str, Any]:
    canonical = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    observation = {
        "claims": claims,
        "kid": worker_kid,
        "signature": base64.urlsafe_b64encode(private.sign(SUPERVISOR_DOMAIN + canonical))
        .decode("ascii")
        .rstrip("="),
    }
    context = ssl.create_default_context(cadata=root_pem)
    async with httpx.AsyncClient(
        verify=context, trust_env=False, follow_redirects=False, timeout=5.0
    ) as client:
        response = await client.post(
            f"https://127.0.0.1:{port}/native-supervisor/observe",
            json={"grant": signed_grant, "observation": observation},
            headers={
                "X-OSOP-Supervisor-ID": supervisor_id,
                "Authorization": "Bearer " + secret,
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 200, response.status_code
    result = response.json()
    assert result["supervisor_observed"] is True
    assert result["original_action_status"] == "unknown"
    assert result["independent_target_effect_verified"] is False
    return result


async def _provision_from_independent_observer(
    *,
    worker: Any,
    case: Any,
    issued: dict[str, Any],
    port: int,
    root_pem: str,
    supervisor_private: ed25519.Ed25519PrivateKey,
    supervisor_id: str,
    supervisor_kid: str,
    supervisor_secret: str,
    worker_id: str | None = None,
) -> dict[str, Any]:
    """Observe the real worker, persist 0033, then sign its short-lived proof.

    Test-only independently provisioned supervisor key never enters Go worker.
    This is not a production-level OS attestation or general runtime launcher.
    """
    token = issued["token"]
    source = token["claims"]
    observed = await _record_observed_supervision(
        port=port,
        root_pem=root_pem,
        signed_grant=token,
        private=supervisor_private,
        supervisor_id=supervisor_id,
        secret=supervisor_secret,
        worker_kid=supervisor_kid,
        claims=_supervised_claims(
            token,
            worker_id=worker_id or "worker-" + uuid.uuid4().hex,
            state="provisioned",
            epoch=0,
            revision=0,
            container_id=worker.container_id,
            evidence=await worker.stage_root_info(),
        ),
    )
    assert observed["state"] == "provisioned" and observed["revision"] == 1
    assert observed["grant_id"] == source["grant_id"]
    assert observed["worker_id"] == (worker_id or observed["worker_id"])
    signed = _signed_provision_proof(
        token=token,
        observed=observed,
        container_id=worker.container_id,
        owner_id=_OWNER,
        approval_id=case.approval_id,
        lease_id=case.lease_id,
        supervisor_id=supervisor_id,
        supervisor_kid=supervisor_kid,
        signer=supervisor_private,
    )
    status, answer = await worker.post("/native-supervisor/provision", signed)
    assert status == 200, answer
    assert answer["execution_enabled"] is False
    assert answer["durably_redeemed"] is False
    return observed


def _tls_files(directory: Path) -> tuple[Path, Path, str]:
    """Create disposable CA-like pinned local TLS identity, not a host key."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=15))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(private, hashes.SHA256())
    )
    cert_path = directory / "disposable-pinned-validator.pem"
    key_path = directory / "disposable-pinned-validator-key.pem"
    cert = certificate.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert)
    key_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, cert.decode("ascii")


@asynccontextmanager
async def _mounted_real_fastapi_tls() -> AsyncIterator[tuple[int, str]]:
    from ai_osop.api.main import app

    with tempfile.TemporaryDirectory(prefix="osop-joined-mounted-validator-") as tmp:
        cert, key, root = _tls_files(Path(tmp))
        port = _local_port()
        # Docker worker has zero egress and cannot access Windows host IPs.
        # The helper's Docker exec stdin tunnel forwards encrypted TLS bytes
        # only between container loopback and this host LOOPBACK FastAPI.
        # Python ASGI, source authority and PostgreSQL are all real.
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                ssl_certfile=str(cert),
                ssl_keyfile=str(key),
                lifespan="off",
                log_level="error",
                access_log=False,
            )
        )
        task = asyncio.create_task(server.serve())
        try:
            for _ in range(100):
                if server.started:
                    break
                if task.done():
                    raise RuntimeError("Disposable mounted FastAPI HTTPS listener exited")
                await asyncio.sleep(0.05)
            assert server.started
            yield port, root
        finally:
            server.should_exit = True
            try:
                await asyncio.wait_for(task, timeout=5)
            except asyncio.TimeoutError:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio(scope="module")
async def test_one_isolated_native_go_process_0026_through_0032_and_denied_replay(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: ed25519.Ed25519PrivateKey,
) -> None:
    """No synthetic source authority and no scanner handler or target call."""
    if os.environ.get("OSOP_DISPOSABLE_NATIVE_0029_PG") != "1":
        pytest.skip("Requires explicit disposable PostgreSQL opt-in")

    # Late import: the corresponding helper provisions disposable Linux
    # processes only for this explicitly opt-in qualification.
    from tests.qualification.native_linux_isolated_go_helper_20261020 import (
        isolated_linux_go_worker,
    )

    worker_private = ed25519.Ed25519PrivateKey.generate()
    seed = worker_private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    worker_pub = worker_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    worker_kid = "independent-isolated-linux-worker-v1"
    supervisor_private = ed25519.Ed25519PrivateKey.generate()
    supervisor_id = "independent-docker-observer-v1"
    supervisor_kid = "independent-sandbox-supervisor-v1"
    supervisor_secret = "independent-supervisor-qualification-credential"
    worker_observer_id = "worker-" + uuid.uuid4().hex
    supervisor_pub = supervisor_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setenv(
        "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON",
        json.dumps(
            {
                supervisor_id: {
                    "kid": supervisor_kid,
                    "public_key": base64.urlsafe_b64encode(supervisor_pub)
                    .decode("ascii")
                    .rstrip("="),
                    "secret_sha256": hashlib.sha256(supervisor_secret.encode("ascii")).hexdigest(),
                }
            }
        ),
    )
    monkeypatch.setenv(
        "OSOP_NATIVE_STAGE_RECEIPT_TRUST_JSON",
        json.dumps(
            {
                "recon-mcp": {
                    "kid": worker_kid,
                    "public_key": base64.urlsafe_b64encode(worker_pub).decode().rstrip("="),
                }
            }
        ),
    )
    issuer_pub = signing_material.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    case, digest, _, _, full_stage = await _approved_folder_case(
        disposable_native_pg, initialized_catalog, monkeypatch, signing_material
    )
    old = redemption.state.get("orchestrator")
    redemption.state["orchestrator"] = SimpleNamespace(
        session_memory=case.original.memory,
        mcp_registry=initialized_catalog,
    )
    try:
        async with _mounted_real_fastapi_tls() as (port, root_pem):
            native_env = {
                "OSOP_RECON_MCP_LOCAL_PORT": "8082",
                "OSOP_NATIVE_MCP_LOCAL_TEST_TRACE": "1",
                "OSOP_NATIVE_MCP_STAGE_ROOT": "/run/osop-native-stage",
                "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON": json.dumps(
                    {_KID: base64.urlsafe_b64encode(issuer_pub).decode().rstrip("=")}
                ),
                "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON": json.dumps({"recon-mcp": _SECRET}),
                "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM": root_pem,
                "OSOP_NATIVE_MCP_REDEEM_URL": ("https://127.0.0.1:18443/native-grants/redeem"),
                "OSOP_NATIVE_STAGE_RECEIPT_ED25519_SEED_B64": (
                    base64.urlsafe_b64encode(seed).decode().rstrip("=")
                ),
                "OSOP_NATIVE_STAGE_RECEIPT_KID": worker_kid,
                "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON": os.environ[
                    "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"
                ],
            }
            async with isolated_linux_go_worker(
                native_env=native_env, validator_host_port=port
            ) as worker:
                status, initialized = await worker.post(
                    "/mcp/initialize",
                    {"scope": {}, "credentials": {}, "session_id": "isolated-current-signed-flow"},
                )
                assert status == 200, initialized
                assert initialized["status"] == "ready"
                assert [tool["name"] for tool in initialized["tools"]] == ["authority_status"]
                # Grant freshness is at most 60 seconds. Compile and launch
                # the genuine isolated Go process BEFORE minting the one-use
                # authority, so infrastructure startup cannot expire it.
                held = await case.original.reserve(case.binding, _OWNER, case.action_id)
                sent = await case.original.mark_dispatched(
                    case.binding,
                    _OWNER,
                    case.action_id,
                    case.request_id,
                    held["reservation_token"],
                )
                assert sent["status"] == "unknown"
                issued = await case.grants.issue(
                    case.binding,
                    _OWNER,
                    case.action_id,
                    case.request_id,
                    resource_sha256=digest,
                )
                original_token = issued["token"]
                # Persist a real 0033 supervisor observation, not worker-
                # invented identity. This same worker ID is used for all
                # subsequent running / terminated / reaped events.
                first = await _record_observed_supervision(
                    port=port,
                    root_pem=root_pem,
                    signed_grant=original_token,
                    private=supervisor_private,
                    supervisor_id=supervisor_id,
                    secret=supervisor_secret,
                    worker_kid=supervisor_kid,
                    claims=_supervised_claims(
                        original_token,
                        worker_id=worker_observer_id,
                        state="provisioned",
                        epoch=0,
                        revision=0,
                        container_id=worker.container_id,
                        evidence=await worker.stage_root_info(),
                    ),
                )
                assert first["state"] == "provisioned" and first["revision"] == 1
                assert first["worker_id"] == worker_observer_id
                async with disposable_native_pg.connect() as db:
                    provisioned = (
                        await db.execute(
                            text(
                                "SELECT worker_id,container_id,supervisor_id,epoch,revision,state "
                                "FROM native_mcp_worker_supervisions WHERE grant_id=:grant"
                            ),
                            {"grant": original_token["claims"]["grant_id"]},
                        )
                    ).one()
                assert provisioned == (
                    worker_observer_id,
                    worker.container_id,
                    supervisor_id,
                    first["epoch"],
                    1,
                    "provisioned",
                )
                # The independent supervisor observes the actual Docker
                # container and signs a separate grant-specific ten-second
                # proof. The native Go worker only forwards this testimony;
                # possession of its original service bearer is insufficient.
                signed_proof = _signed_provision_proof(
                    token=original_token,
                    observed=first,
                    container_id=worker.container_id,
                    owner_id=_OWNER,
                    approval_id=case.approval_id,
                    lease_id=case.lease_id,
                    supervisor_id=supervisor_id,
                    supervisor_kid=supervisor_kid,
                    signer=supervisor_private,
                )
                # An independently signed proof is necessary but not alone
                # sufficient. The Go endpoint rejects malformed claims,
                # forged signatures, and missing supervisor-only credentials.
                forged = {**signed_proof, "signature": "A" * 86}
                malformed = {
                    **signed_proof,
                    "claims": {**signed_proof["claims"], "unreviewed": "false"},
                }
                for bad in (forged, malformed):
                    denied, rejected = await worker.post("/native-supervisor/provision", bad)
                    assert denied == 403, rejected
                    assert rejected["status"] == "error"
                stale_time = int(time.time()) - 25
                expired_claims = {
                    **signed_proof["claims"],
                    "issued_at": stale_time,
                    "expires_at": stale_time + 9,
                    "nonce": uuid.uuid4().hex,
                }
                expired_bytes = json.dumps(
                    expired_claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                ).encode("ascii")
                expired = {
                    "claims": expired_claims,
                    "kid": supervisor_kid,
                    "signature": base64.urlsafe_b64encode(
                        supervisor_private.sign(SUPERVISOR_PROVISION_DOMAIN + expired_bytes)
                    )
                    .decode("ascii")
                    .rstrip("="),
                }
                denied_ttl, rejected_ttl = await worker.post(
                    "/native-supervisor/provision", expired
                )
                assert denied_ttl == 403, rejected_ttl
                with pytest.raises(ValueError, match="cannot use caller-supplied headers"):
                    await worker.post(
                        "/native-supervisor/provision",
                        signed_proof,
                        {"X-OSOP-Native-Grant": issued["native_grant_header"]},
                    )
                # Mint the ten-second proof AFTER adversarial requests: slow
                # Docker exec startup must not silently age the good proof.
                signed_proof = _signed_provision_proof(
                    token=original_token,
                    observed=first,
                    container_id=worker.container_id,
                    owner_id=_OWNER,
                    approval_id=case.approval_id,
                    lease_id=case.lease_id,
                    supervisor_id=supervisor_id,
                    supervisor_kid=supervisor_kid,
                    signer=supervisor_private,
                )
                # Only the independent supervisor admits this one-time proof;
                # the ordinary MCP client has NO supervisor-proof header.
                admitted, admitted_body = await worker.post(
                    "/native-supervisor/provision", signed_proof
                )
                assert admitted == 200, admitted_body
                assert admitted_body["durably_redeemed"] is False
                request = {
                    "tool_name": "authority_status",
                    "parameters": {},
                    "request_id": case.request_id,
                    "timeout_override": None,
                }
                headers = {"X-OSOP-Native-Grant": issued["native_grant_header"]}
                code, answer = await worker.post("/mcp/execute", request, headers)
                assert code == 200, answer
                assert answer["status"] == "success"
                assert answer["result"]["resource_bytes_received_verified"] is True
                assert answer["result"]["native_target_execution_enabled"] is False
                assert answer["result"]["target_contacted"] is False
                assert answer["result"]["provider_contacted"] is False
                # Check one-shot admission only after the actual redemption:
                # a second Docker exec before redeem could exhaust its 9s TTL.
                duplicate, duplicate_body = await worker.post(
                    "/native-supervisor/provision", signed_proof
                )
                assert duplicate == 409 and duplicate_body["status"] == "error"
                # Independent Docker-exec inspection of a genuinely confined
                # private mount, separate from the worker's Ed25519 claims.
                assert await worker.stage_root_empty() is True
                async with disposable_native_pg.connect() as db:
                    readback_sha = (
                        await db.execute(
                            text(
                                "SELECT readback_sha256 FROM native_mcp_stage_receipts "
                                "WHERE grant_id=:id"
                            ),
                            {"id": issued["grant_id"]},
                        )
                    ).scalar_one()
                second = await _record_observed_supervision(
                    port=port,
                    root_pem=root_pem,
                    signed_grant=original_token,
                    private=supervisor_private,
                    supervisor_id=supervisor_id,
                    secret=supervisor_secret,
                    worker_kid=supervisor_kid,
                    claims=_supervised_claims(
                        original_token,
                        worker_id=worker_observer_id,
                        state="running",
                        epoch=first["epoch"],
                        revision=1,
                        container_id=worker.container_id,
                        evidence=await worker.stage_root_info(),
                        folder=full_stage["staging_sha256"],
                        readback=readback_sha,
                    ),
                )
                assert second["revision"] == 2 and second["state"] == "running"
                assert second["worker_id"] == worker_observer_id
                async with disposable_native_pg.connect() as db:
                    running_row = (
                        await db.execute(
                            text(
                                "SELECT worker_id,container_id,supervisor_id,epoch,revision,state "
                                "FROM native_mcp_worker_supervisions WHERE grant_id=:grant"
                            ),
                            {"grant": issued["grant_id"]},
                        )
                    ).one()
                assert running_row == (
                    worker_observer_id,
                    worker.container_id,
                    supervisor_id,
                    first["epoch"],
                    2,
                    "running",
                )
                # A separate manual attempt proves the global one-use guard;
                # production never retries an UNKNOWN consequential action.
                repeat_status, repeat_body = await worker.post("/mcp/execute", request, headers)
                assert repeat_status == 503, repeat_body

                async with isolated_linux_go_worker(
                    native_env=native_env, validator_host_port=port
                ) as stale_worker:
                    # A separate original signed Task must NOT deliver its files
                    # if a virtual folder assignment changes after approval.
                    # Here Go really redeems the fresh grant through FastAPI and
                    # reaches PostgreSQL, but 0031 denies its subsequent byte
                    # OFFER before staging or worker receipt can take place.
                    stale, stale_digest, _, _, _ = await _approved_folder_case(
                        disposable_native_pg,
                        initialized_catalog,
                        monkeypatch,
                        signing_material,
                    )
                    stale_hold = await stale.original.reserve(
                        stale.binding, _OWNER, stale.action_id
                    )
                    stale_sent = await stale.original.mark_dispatched(
                        stale.binding,
                        _OWNER,
                        stale.action_id,
                        stale.request_id,
                        stale_hold["reservation_token"],
                    )
                    assert stale_sent["status"] == "unknown"
                    stale_grant = await stale.grants.issue(
                        stale.binding,
                        _OWNER,
                        stale.action_id,
                        stale.request_id,
                        resource_sha256=stale_digest,
                    )
                    await _provision_from_independent_observer(
                        worker=stale_worker,
                        case=stale,
                        issued=stale_grant,
                        port=port,
                        root_pem=root_pem,
                        supervisor_private=supervisor_private,
                        supervisor_id=supervisor_id,
                        supervisor_kid=supervisor_kid,
                        supervisor_secret=supervisor_secret,
                    )
                    async with disposable_native_pg.begin() as db:
                        await db.execute(
                            text(
                                "UPDATE flow_resource_folder_catalogs SET revision=revision+1 "
                                "WHERE flow_id=:flow AND engagement_id=:eng"
                            ),
                            {
                                "flow": stale.binding["flow_id"],
                                "eng": stale.binding["engagement_id"],
                            },
                        )
                    stale_status, stale_response = await stale_worker.post(
                        "/mcp/execute",
                        {
                            **request,
                            "request_id": stale.request_id,
                        },
                        {"X-OSOP-Native-Grant": stale_grant["native_grant_header"]},
                    )
                    assert stale_status == 503, stale_response
                    assert stale_response["status"] == "error"
                    assert await stale_worker.stage_root_empty() is True

                    async with disposable_native_pg.connect() as db:
                        assert (
                            await db.execute(
                                text(
                                    "SELECT status FROM flow_mcp_action_dispatches "
                                    "WHERE action_id=:id"
                                ),
                                {"id": stale.action_id},
                            )
                        ).scalar_one() == "unknown"
                        for table in (
                            "native_mcp_resource_offers",
                            "native_mcp_stage_receipts",
                        ):
                            assert (
                                await db.execute(
                                    text(f"SELECT count(*) FROM {table} WHERE grant_id=:id"),
                                    {"id": stale_grant["grant_id"]},
                                )
                            ).scalar_one() == 0
                    # No second chance after the source-side stale denial.
                    denied_again, _ = await stale_worker.post(
                        "/mcp/execute",
                        {**request, "request_id": stale.request_id},
                        {"X-OSOP-Native-Grant": stale_grant["native_grant_header"]},
                    )
                    assert denied_again == 503

                async with isolated_linux_go_worker(
                    native_env=native_env, validator_host_port=port
                ) as revoked_worker:
                    # Independent original-byte senior reviewer revocation is
                    # live PostgreSQL authority, not a copied flag in the grant.
                    # A new signed approval/lease/grant cannot bypass it, even
                    # through a real isolated Go worker and pinned HTTPS.
                    revoked, revoked_digest, _, _, _ = await _approved_folder_case(
                        disposable_native_pg,
                        initialized_catalog,
                        monkeypatch,
                        signing_material,
                    )
                    revoked_hold = await revoked.original.reserve(
                        revoked.binding, _OWNER, revoked.action_id
                    )
                    revoked_sent = await revoked.original.mark_dispatched(
                        revoked.binding,
                        _OWNER,
                        revoked.action_id,
                        revoked.request_id,
                        revoked_hold["reservation_token"],
                    )
                    assert revoked_sent["status"] == "unknown"
                    revoked_grant = await revoked.grants.issue(
                        revoked.binding,
                        _OWNER,
                        revoked.action_id,
                        revoked.request_id,
                        resource_sha256=revoked_digest,
                    )
                    await _provision_from_independent_observer(
                        worker=revoked_worker,
                        case=revoked,
                        issued=revoked_grant,
                        port=port,
                        root_pem=root_pem,
                        supervisor_private=supervisor_private,
                        supervisor_id=supervisor_id,
                        supervisor_kid=supervisor_kid,
                        supervisor_secret=supervisor_secret,
                    )
                    async with disposable_native_pg.begin() as db:
                        await db.execute(
                            text(
                                "UPDATE operator_subject_controls SET disabled=true "
                                "WHERE actor_id='independent-staging-senior'"
                            )
                        )
                    revoked_status, revoked_body = await revoked_worker.post(
                        "/mcp/execute",
                        {**request, "request_id": revoked.request_id},
                        {"X-OSOP-Native-Grant": revoked_grant["native_grant_header"]},
                    )
                    assert revoked_status == 503, revoked_body
                    assert revoked_body["status"] == "error"
                    assert await revoked_worker.stage_root_empty() is True
                    async with disposable_native_pg.connect() as db:
                        assert (
                            await db.execute(
                                text(
                                    "SELECT status FROM flow_mcp_action_dispatches "
                                    "WHERE action_id=:id"
                                ),
                                {"id": revoked.action_id},
                            )
                        ).scalar_one() == "unknown"
                        for table in (
                            "native_mcp_resource_offers",
                            "native_mcp_stage_receipts",
                        ):
                            assert (
                                await db.execute(
                                    text(f"SELECT count(*) FROM {table} WHERE grant_id=:id"),
                                    {"id": revoked_grant["grant_id"]},
                                )
                            ).scalar_one() == 0

            import docker

            observer = docker.from_env(timeout=8)
            try:
                for collection, identity in (
                    (observer.containers, worker.container_id),
                    (observer.networks, worker.network_id),
                ):
                    with pytest.raises(docker.errors.NotFound):
                        collection.get(identity)
            finally:
                observer.close()
            vanished = {
                "owned_container_absent": True,
                "owned_network_absent": True,
                "previous_container_id": worker.container_id,
            }
            third = await _record_observed_supervision(
                port=port,
                root_pem=root_pem,
                signed_grant=original_token,
                private=supervisor_private,
                supervisor_id=supervisor_id,
                secret=supervisor_secret,
                worker_kid=supervisor_kid,
                claims=_supervised_claims(
                    original_token,
                    worker_id=worker_observer_id,
                    state="terminated",
                    epoch=first["epoch"],
                    revision=2,
                    container_id=worker.container_id,
                    evidence=vanished,
                    folder=full_stage["staging_sha256"],
                    readback=readback_sha,
                ),
            )
            assert third["state"] == "terminated"
            fourth = await _record_observed_supervision(
                port=port,
                root_pem=root_pem,
                signed_grant=original_token,
                private=supervisor_private,
                supervisor_id=supervisor_id,
                secret=supervisor_secret,
                worker_kid=supervisor_kid,
                claims=_supervised_claims(
                    original_token,
                    worker_id=worker_observer_id,
                    state="reaped",
                    epoch=first["epoch"],
                    revision=3,
                    container_id=worker.container_id,
                    evidence=vanished,
                    folder=full_stage["staging_sha256"],
                    readback=readback_sha,
                ),
            )
            assert fourth["state"] == "reaped"

        async with disposable_native_pg.connect() as db:
            action = (
                await db.execute(
                    text("SELECT status FROM flow_mcp_action_dispatches WHERE action_id=:id"),
                    {"id": case.action_id},
                )
            ).scalar_one()
            grant = (
                await db.execute(
                    text("SELECT status FROM native_mcp_execution_grants WHERE grant_id=:id"),
                    {"id": issued["grant_id"]},
                )
            ).scalar_one()
            offer = (
                await db.execute(
                    text(
                        "SELECT status,folder_staging_sha256 FROM native_mcp_resource_offers "
                        "WHERE grant_id=:id"
                    ),
                    {"id": issued["grant_id"]},
                )
            ).one()
            receipt = (
                await db.execute(
                    text(
                        "SELECT status,folder_staging_sha256,worker_key_id FROM native_mcp_stage_receipts "
                        "WHERE grant_id=:id"
                    ),
                    {"id": issued["grant_id"]},
                )
            ).one()
            historical = (
                (
                    await db.execute(
                        text(
                            "SELECT g.grant_id,g.action_id,g.request_id,g.server_id,g.tool_name,"
                            "g.status,g.issued_at,g.expires_at,g.resource_sha256,"
                            "o.status AS resource_offer_status,o.folder_staging_sha256,"
                            "s.status AS stage_receipt_status,"
                            "w.state AS supervisor_state,w.revision AS supervisor_revision,"
                            "false AS supervisor_recovery_intent_pending "
                            "FROM native_mcp_execution_grants AS g "
                            "LEFT JOIN native_mcp_resource_offers AS o ON o.grant_id=g.grant_id "
                            "AND o.engagement_id=g.engagement_id AND o.flow_id=g.flow_id "
                            "AND o.action_id=g.action_id AND o.request_id=g.request_id "
                            "AND o.server_id=g.server_id "
                            "LEFT JOIN native_mcp_stage_receipts AS s ON s.grant_id=g.grant_id "
                            "AND s.engagement_id=g.engagement_id AND s.flow_id=g.flow_id "
                            "AND s.action_id=g.action_id AND s.request_id=g.request_id "
                            "AND s.server_id=g.server_id "
                            "LEFT JOIN native_mcp_worker_supervisions AS w ON w.grant_id=g.grant_id "
                            "AND w.engagement_id=g.engagement_id AND w.flow_id=g.flow_id "
                            "AND w.action_id=g.action_id AND w.request_id=g.request_id "
                            "AND w.server_id=g.server_id "
                            "WHERE g.grant_id=:id AND g.engagement_id=:eng "
                            "AND g.flow_id=:flow AND g.owner_id=:owner"
                        ),
                        {
                            "id": issued["grant_id"],
                            "eng": case.binding["engagement_id"],
                            "flow": case.binding["flow_id"],
                            "owner": _OWNER,
                        },
                    )
                )
                .mappings()
                .one()
            )
            assert action == "unknown"
            assert grant == "redeemed"
            assert tuple(offer) == ("offered", full_stage["staging_sha256"])
            assert tuple(receipt) == (
                "worker_reported",
                full_stage["staging_sha256"],
                worker_kid,
            )
            safe = safe_grant_readback(dict(historical))
            assert safe["approved_folder_staging_bound"] is True
            assert safe["original_resource_bytes_offered_once"] is True
            assert safe["worker_stage_receipt_reported"] is True
            assert safe["supervisor_lifecycle_observed"] is True
            assert safe["supervisor_cleanup_observed"] is True
            assert safe["supervisor_state"] == "reaped"
            assert "folder_staging_sha256" not in safe
            assert "resource_sha256" not in safe
    finally:
        if old is None:
            redemption.state.pop("orchestrator", None)
        else:
            redemption.state["orchestrator"] = old
