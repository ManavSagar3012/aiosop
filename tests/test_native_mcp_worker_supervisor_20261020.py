"""Controlled independent supervisor tests; no application DB or targets."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import subprocess
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from ai_osop.safety.native_mcp_worker_supervisor import (
    NativeMCPWorkerSupervisor,
    NativeSupervisorDenied,
    SourceAuthorityDecision,
    SupervisorBinding,
    verify_supervisor_statement,
)
from ai_osop.memory.native_mcp_worker_supervision import DOMAIN as STORE_DOMAIN

_SHA = "a" * 64
_MOUNT = {
    "directory": True,
    "uid": 65534,
    "gid": 65534,
    "mode": 0o700,
    "entries": [],
    "mount": {"type": "tmpfs", "options": ["rw", "noexec", "nosuid", "nodev"]},
}


def _binding(binary_sha: str = _SHA) -> SupervisorBinding:
    return SupervisorBinding(
        request_id="req-current-one",
        engagement_id="eng-current-one",
        flow_id="flow-current-one",
        task_id="task-current-one",
        subtask_id="subtask-current-one",
        action_id="action-current-one",
        approval_id="apr-current-one",
        lease_id="lease-current-one",
        issuer_kid="issuer-verified-0033",
        signed_roe_sha256=_SHA,
        authorization_sha256=_SHA,
        manifest_sha256=_SHA,
        binary_sha256=binary_sha,
    )


def _keys() -> tuple[Ed25519PrivateKey, Ed25519PrivateKey, dict[str, bytes]]:
    issuer = Ed25519PrivateKey.generate()
    supervisor = Ed25519PrivateKey.generate()
    return (
        issuer,
        supervisor,
        {"issuer-verified-0033": issuer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)},
    )


def _decision(binding: SupervisorBinding, **changes: Any) -> SourceAuthorityDecision:
    now = int(time.time())
    return replace(
        SourceAuthorityDecision(
            binding=binding,
            authority_version=33,
            checked_at=now,
            expires_at=now + 40,
            issuer_trusted=True,
            signed_roe_valid=True,
            task_active=True,
            approval_current=True,
            lease_active=True,
        ),
        **changes,
    )


def _env(issuer: bytes) -> dict[str, str]:
    return {
        "OSOP_NATIVE_MCP_STAGE_ROOT": "/run/osop-native-stage",
        "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON": json.dumps(
            {
                "issuer-verified-0033": base64.urlsafe_b64encode(issuer).decode().rstrip("="),
            }
        ),
        "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON": json.dumps(
            {
                "recon-mcp": "isolated-test-only-native-identity-separate",
            }
        ),
        "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM": (
            "-----BEGIN CERTIFICATE-----\n"
            "test-certificate-placeholder-for-controlled-only-tests\n"
            "-----END CERTIFICATE-----"
        ),
        "OSOP_NATIVE_MCP_REDEEM_URL": "https://127.0.0.1:18443/native-grants/redeem",
    }


class FakeResource:
    def __init__(self, backend: "FakeDocker", kind: str, name: str, owner: str) -> None:
        self.backend = backend
        self.kind = kind
        self.name = name
        self.id = hashlib.sha256(name.encode("ascii")).hexdigest()
        self.attrs: dict[str, Any] = {"Labels": {"ai-osop.native-supervisor.owner": owner}}
        self.containers: list[Any] = []

    def reload(self) -> None:
        pass

    def remove(self, **kwargs: Any) -> None:
        self.backend.removals.append((self.kind, self.id, kwargs))
        if self.backend.fail_removal == self.kind:
            raise OSError("controlled hard-kill failure")
        if self.kind == "container":
            self.backend.containers_by_id.pop(self.id)
            self.backend.network_ref.containers.clear()
        else:
            self.backend.networks_by_id.pop(self.id)


class FakeDocker:
    def __init__(self, *, bad_policy: bool = False, fail_removal: str = "") -> None:
        self.bad_policy = bad_policy
        self.fail_removal = fail_removal
        self.calls: list[str] = []
        self.removals: list[tuple[str, str, dict[str, Any]]] = []
        self.containers_by_id: dict[str, FakeResource] = {}
        self.networks_by_id: dict[str, FakeResource] = {}
        self.network_ref: FakeResource
        self.images = SimpleNamespace(get=lambda image: SimpleNamespace(id="cached-test-image"))
        self.networks = SimpleNamespace(
            create=self.create_network,
            get=self.get_network,
        )
        self.containers = SimpleNamespace(run=self.run_container, get=self.get_container)

    def create_network(self, name: str, **kwargs: Any) -> FakeResource:
        self.calls.append("create_network")
        assert kwargs["internal"] is True
        network = FakeResource(
            self, "network", name, kwargs["labels"]["ai-osop.native-supervisor.owner"]
        )
        network.attrs["Internal"] = True
        network.attrs["Driver"] = "bridge"
        self.network_ref = network
        self.networks_by_id[network.id] = network
        return network

    def run_container(self, image: str, command: list[str], **kwargs: Any) -> FakeResource:
        self.calls.append("run_container")
        assert kwargs["volumes"] == {} and kwargs["ports"] == {}
        container = FakeResource(
            self, "container", kwargs["name"], kwargs["labels"]["ai-osop.native-supervisor.owner"]
        )
        uid = "0:0" if self.bad_policy else kwargs["user"]
        container.attrs.update(
            {
                "Config": {"Labels": kwargs["labels"], "User": uid},
                "HostConfig": {
                    "ReadonlyRootfs": kwargs["read_only"],
                    "Privileged": kwargs["privileged"],
                    "CapDrop": kwargs["cap_drop"],
                    "SecurityOpt": kwargs["security_opt"],
                    "PidsLimit": kwargs["pids_limit"],
                    "Memory": 192 * 1024 * 1024,
                    "MemorySwap": 192 * 1024 * 1024,
                    "NanoCpus": 500_000_000,
                    "Binds": None,
                    "Mounts": None,
                    "PortBindings": None,
                    "Tmpfs": kwargs["tmpfs"],
                },
                "NetworkSettings": {"Networks": {self.network_ref.name: {}}},
            }
        )
        self.network_ref.containers.append(container)
        self.containers_by_id[container.id] = container
        return container

    def get_network(self, resource_id: str) -> FakeResource:
        try:
            return self.networks_by_id[resource_id]
        except KeyError:
            raise NotFound() from None

    def get_container(self, resource_id: str) -> FakeResource:
        try:
            return self.containers_by_id[resource_id]
        except KeyError:
            raise NotFound() from None

    def close(self) -> None:
        pass


class NotFound(Exception):
    pass


def _executable(tmp_path: Path) -> tuple[Path, str]:
    # Fake ELF only for controlled Docker mock tests, never executed natively.
    raw = bytearray(b"\x7fELF\x02\x01" + bytes(1018))
    raw[18:20] = b"\x3e\x00"
    target = tmp_path / "fake-linux-recon"
    target.write_bytes(raw)
    return target, hashlib.sha256(raw).hexdigest()


def _runner(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
    command = args[0]
    if "-d" in command:
        return subprocess.CompletedProcess(command, 0, b"")
    if "-c" in command and any("mountinfo" in arg for arg in command):
        return subprocess.CompletedProcess(command, 0, json.dumps(_MOUNT).encode())
    if "-c" in command and any("/mcp/execute" in arg for arg in command):
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {
                    "http_status": 503,
                    "body": {"status": "error", "error": "native_execution_not_authorized"},
                }
            ).encode(),
        )
    return subprocess.CompletedProcess(command, 0, b"")


def _supervisor(
    decision: Any,
    backend: FakeDocker,
    *,
    now: Any = time.time,
    runner: Any = _runner,
) -> NativeMCPWorkerSupervisor:
    issuer, supervisor, keys = _keys()

    async def verify(binding: SupervisorBinding) -> SourceAuthorityDecision:
        if callable(decision):
            return decision(binding)
        return decision

    item = NativeMCPWorkerSupervisor(
        source_authority=verify,
        trusted_issuer_keys=keys,
        supervisor_private_key=supervisor,
        supervisor_kid="independent-supervisor-test",
        docker_factory=lambda: backend,
        command_runner=runner,
        clock=now,
    )
    # The real test builder needs the issuer key for its child Go config.
    item._test_public_key = keys["issuer-verified-0033"]
    return item


@pytest.mark.asyncio
async def test_untrusted_issuer_stale_roe_task_approval_lease_never_touch_docker(
    tmp_path: Path,
) -> None:
    binary, digest = _executable(tmp_path)
    binding = _binding(digest)
    states = [
        lambda b: _decision(b, issuer_trusted=False),
        lambda b: _decision(b, signed_roe_valid=False),
        lambda b: _decision(b, task_active=False),
        lambda b: _decision(b, approval_current=False),
        lambda b: _decision(b, lease_active=False),
        lambda b: _decision(b, expires_at=int(time.time()) - 1),
        lambda b: _decision(b, checked_at=int(time.time()) - 10),
        lambda b: _decision(replace(b, task_id="task-swapped-identity")),
    ]
    for make in states:
        docker = FakeDocker()
        supervisor = _supervisor(make, docker)
        with pytest.raises(NativeSupervisorDenied):
            async with supervisor.provision(
                binding, linux_binary=binary, native_env=_env(supervisor._test_public_key)
            ):
                pytest.fail("Source rejection unexpectedly provisioned Docker")
        assert docker.calls == []
    docker = FakeDocker()
    supervisor = _supervisor(lambda b: _decision(b), docker)
    with pytest.raises(NativeSupervisorDenied):
        async with supervisor.provision(
            replace(binding, issuer_kid="issuer-forged"),
            linux_binary=binary,
            native_env=_env(supervisor._test_public_key),
        ):
            pytest.fail("Untrusted issuer unexpectedly launched Docker")
    assert docker.calls == []


@pytest.mark.asyncio
async def test_owned_container_stage_and_signature_cleanup_are_independently_checked(
    tmp_path: Path,
) -> None:
    docker = FakeDocker()
    supervisor = _supervisor(lambda b: _decision(b), docker)
    binary, digest = _executable(tmp_path)
    binding = _binding(digest)
    async with supervisor.provision(
        binding, linux_binary=binary, native_env=_env(supervisor._test_public_key)
    ) as session:
        assert session.stage_observation is not None
        assert session.stage_observation["private_stage_mount_verified"] is True
        observed = await session.observe()
        assert observed["no_external_network"] is True
        status, body = await session.invoke_authority_status("A" * 128)
        assert status == 503 and body["error"] == "native_execution_not_authorized"
        with pytest.raises(NativeSupervisorDenied):
            await session.invoke_authority_status("A" * 128)
        assert verify_supervisor_statement(
            session.ownership_statement, public_key=supervisor.public_key, ownership=True
        )
    assert session.final_statement is not None
    assert session.final_statement["claims"]["cleanup_verified"] is True
    assert session.final_statement["claims"]["target_contacted"] is False
    assert verify_supervisor_statement(session.final_statement, public_key=supervisor.public_key)
    forged = json.loads(json.dumps(session.final_statement))
    forged["claims"]["cleanup_verified"] = False
    assert not verify_supervisor_statement(forged, public_key=supervisor.public_key)
    assert [kind for kind, _, _ in docker.removals] == ["container", "network"]
    assert not docker.containers_by_id and not docker.networks_by_id
    with pytest.raises(NativeSupervisorDenied):
        await session.observe()
    with pytest.raises(NativeSupervisorDenied):
        async with supervisor.provision(
            binding, linux_binary=binary, native_env=_env(supervisor._test_public_key)
        ):
            pytest.fail("Replayed supervisor lease unexpectedly ran")


@pytest.mark.asyncio
async def test_optional_disposable_real_docker_supervisor_mount_and_teardown() -> None:
    """Explicit opt-in; offline cross-compiled real Go, no app DB or targets."""
    if os.getenv("OSOP_NATIVE_SUPERVISOR_DOCKER_OPT_IN") != "1":
        pytest.skip("Set OSOP_NATIVE_SUPERVISOR_DOCKER_OPT_IN=1 for disposable Docker")
    import docker

    control = docker.from_env(timeout=8)
    assert control.info()["OSType"] == "linux"
    control.images.get("python:3.11-slim")  # Use cached image only.
    _, supervisor_key, trusted = _keys()

    async def source(binding: SupervisorBinding) -> SourceAuthorityDecision:
        return _decision(binding)

    supervisor = NativeMCPWorkerSupervisor(
        source_authority=source,
        trusted_issuer_keys=trusted,
        supervisor_private_key=supervisor_key,
        supervisor_kid="live-independent-supervisor",
    )
    certificate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(certificate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=15))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(certificate_key, hashes.SHA256())
    )
    child = _env(trusted["issuer-verified-0033"])
    child["OSOP_NATIVE_MCP_REDEEM_ROOT_PEM"] = certificate.public_bytes(
        serialization.Encoding.PEM
    ).decode("ascii")
    with tempfile.TemporaryDirectory(prefix="osop-supervisor-real-only-") as folder:
        executable = Path(folder) / "recon-mcp"
        repo = Path(__file__).resolve().parents[1] / "mcp-servers" / "go"
        build_env = os.environ.copy()
        build_env.update(
            {
                "GOOS": "linux",
                "GOARCH": "amd64",
                "CGO_ENABLED": "0",
                "GOPROXY": "off",
                "GOSUMDB": "off",
                "GOTOOLCHAIN": "local",
                "GOWORK": "off",
            }
        )
        subprocess.run(
            ["go", "build", "-trimpath", "-o", str(executable), "./cmd/recon-mcp"],
            cwd=repo,
            env=build_env,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=100,
        )
        binding = _binding(hashlib.sha256(executable.read_bytes()).hexdigest())
        async with supervisor.provision(
            binding, linux_binary=executable, native_env=child
        ) as session:
            observed = await session.observe()
            assert observed["network_internal"] is True
            assert observed["private_stage_mount_verified"] is True
            assert observed["stage_empty"] is True
            assert observed["no_host_mounts"] is True
            code, body = await session.invoke_authority_status("A" * 128)
            assert code == 503 and body["error"] == "native_execution_not_authorized"
        assert session.final_statement is not None
        assert verify_supervisor_statement(
            session.final_statement, public_key=supervisor.public_key
        )
        with pytest.raises(docker.errors.NotFound):
            control.containers.get(session.container_id)
        with pytest.raises(docker.errors.NotFound):
            control.networks.get(session.network_id)
        assert session.owner not in supervisor._owned
    control.close()


@pytest.mark.asyncio
async def test_bad_mount_wrong_owner_or_hard_kill_failure_never_attests_cleanup(
    tmp_path: Path,
) -> None:
    binary, digest = _executable(tmp_path)
    binding = _binding(digest)
    for docker in (FakeDocker(bad_policy=True), FakeDocker(fail_removal="container")):
        supervisor = _supervisor(lambda b: _decision(b), docker)
        session = None
        with pytest.raises((NativeSupervisorDenied, OSError, KeyError)):
            async with supervisor.provision(
                binding,
                linux_binary=binary,
                native_env=_env(supervisor._test_public_key),
            ) as running:
                session = running
        assert session is None or session.final_statement is None
        if not docker.fail_removal:
            assert docker.removals and not docker.containers_by_id

    bad_mount = dict(_MOUNT)
    bad_mount["mount"] = {"type": "overlay", "options": ["rw"]}

    def bad_runner(*args: Any, **kwargs: Any) -> Any:
        command = args[0]
        if "-c" in command and any("mountinfo" in arg for arg in command):
            return subprocess.CompletedProcess(command, 0, json.dumps(bad_mount).encode())
        return _runner(*args, **kwargs)

    docker = FakeDocker()
    supervisor = _supervisor(lambda b: _decision(b), docker, runner=bad_runner)
    with pytest.raises(NativeSupervisorDenied, match="stage mount"):
        async with supervisor.provision(
            binding, linux_binary=binary, native_env=_env(supervisor._test_public_key)
        ):
            pytest.fail("Bad private tmpfs unexpectedly passed")
    assert not docker.containers_by_id and not docker.networks_by_id


@pytest.mark.asyncio
async def test_bounded_signed_orphan_reap_never_prunes_foreign_resource() -> None:
    backend = FakeDocker()
    supervisor = _supervisor(lambda b: _decision(b), backend)
    owner = "osop-native-sup-" + "b" * 32
    network = backend.create_network(
        owner + "-private",
        internal=True,
        labels={"ai-osop.native-supervisor.owner": owner},
    )
    container = backend.run_container(
        "cached-test-image",
        ["sleep"],
        name=owner + "-recon",
        network=network.name,
        labels={"ai-osop.native-supervisor.owner": owner},
        volumes={},
        ports={},
        user="65534:65534",
        read_only=True,
        privileged=False,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        pids_limit=64,
        mem_limit="192m",
        tmpfs={},
    )
    proof = supervisor._signed_ownership(owner, container, network)
    supervisor.adopt_ownership(proof)
    assert await supervisor.reap_orphans(older_than_seconds=1, limit=1) == 0
    # Force the recorded age past the bounded orphan threshold.
    supervisor._owned[owner] = (proof, supervisor.clock() - 200)
    backend.containers_by_id[container.id].attrs["Config"]["Labels"] = {
        "ai-osop.native-supervisor.owner": "foreign",
    }
    with pytest.raises(
        NativeSupervisorDenied, match="owned network|ownership mismatch|Unknown container"
    ):
        await supervisor.reap_orphans(older_than_seconds=60, limit=1)
    assert container.id in backend.containers_by_id
    backend.containers_by_id[container.id].attrs["Config"]["Labels"] = {
        "ai-osop.native-supervisor.owner": owner,
    }
    assert await supervisor.reap_orphans(older_than_seconds=60, limit=1) == 1
    assert not backend.containers_by_id and not backend.networks_by_id
    with pytest.raises((ValueError, NativeSupervisorDenied)):
        supervisor.adopt_ownership(
            {"claims": {"owner": "foreign"}, "signature": "forged", "kid": "a"}
        )
    with pytest.raises(ValueError):
        await supervisor.reap_orphans(limit=999)


@pytest.mark.asyncio
async def test_exact_0033_observation_signatures_and_global_epoch_cas_are_separate(
    tmp_path: Path,
) -> None:
    docker = FakeDocker()
    supervisor = _supervisor(lambda b: _decision(b), docker)
    binary, digest = _executable(tmp_path)
    binding = replace(_binding(digest), request_id="req-" + "1" * 48)
    token = {
        "claims": {
            "grant_id": "ngr-" + "2" * 32,
            "request_id": binding.request_id,
            "server_id": "recon-mcp",
            "engagement_id": binding.engagement_id,
            "flow_id": binding.flow_id,
            "task_id": binding.task_id,
            "subtask_id": binding.subtask_id,
            "action_id": binding.action_id,
            "lease_id": binding.lease_id,
            "authorization_sha256": binding.authorization_sha256,
            "manifest_sha256": binding.manifest_sha256,
            "tool_name": "authority_status",
            "side_effect_class": "READ_ONLY",
            "resource_sha256": None,
        },
        "kid": "issuer-verified-0033",
        "signature": "opaque-issued-by-0029-store",
    }
    worker_id = "worker-independent-supervisor-0033"
    observations: list[dict[str, Any]] = []
    expected = {
        "version",
        "grant_id",
        "request_id",
        "server_id",
        "worker_id",
        "container_id",
        "epoch",
        "expected_revision",
        "state",
        "observed_at",
        "evidence_sha256",
        "resource_sha256",
        "folder_staging_sha256",
        "readback_sha256",
    }

    async def record(grant: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any]:
        assert grant == token
        assert set(observation) == {"kid", "claims", "signature"}
        claims = observation["claims"]
        assert set(claims) == expected
        raw = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
        signature = base64.urlsafe_b64decode(
            observation["signature"] + "=" * (-len(observation["signature"]) % 4)
        )
        Ed25519PublicKey.from_public_bytes(supervisor.public_key).verify(
            signature, STORE_DOMAIN + raw
        )
        observations.append(claims)
        if claims["state"] == "provisioned":
            assert claims["epoch"] == claims["expected_revision"] == 0
            assert claims["container_id"] is None
            return {
                "grant_id": token["claims"]["grant_id"],
                "worker_id": worker_id,
                "state": "provisioned",
                "epoch": 23,
                "revision": 1,
                "supervisor_observed": True,
            }
        assert claims["epoch"] == 23
        assert claims["expected_revision"] == len(observations) - 1
        assert claims["container_id"] is not None
        return {
            "grant_id": token["claims"]["grant_id"],
            "worker_id": worker_id,
            "state": claims["state"],
            "epoch": 23,
            "revision": len(observations),
            "supervisor_observed": True,
        }

    # Reserving an epoch before Docker may remain available for a no-resource
    # inert diagnostic; it cannot now create a resource-bound 0033 provision
    # that lacks independently observed original container identity.
    resource_token = {
        **token,
        "claims": {**token["claims"], "resource_sha256": "a" * 64},
    }
    with pytest.raises(NativeSupervisorDenied, match="Docker-observed"):
        await supervisor.record_0033_provisioned(
            binding, token=resource_token, worker_id=worker_id, record_callback=record
        )
    assert observations == []
    first = await supervisor.record_0033_provisioned(
        binding, token=token, worker_id=worker_id, record_callback=record
    )
    assert docker.calls == []  # Durable reservation before ANY Docker.

    def successful_inert(*args: Any, **kwargs: Any) -> Any:
        command = args[0]
        if any("/mcp/execute" in item for item in command):
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {
                        "http_status": 200,
                        "body": {
                            "status": "success",
                            "result": {
                                "native_target_execution_enabled": False,
                                "target_contacted": False,
                                "provider_contacted": False,
                            },
                        },
                    }
                ).encode(),
            )
        return _runner(*args, **kwargs)

    supervisor._command_runner = successful_inert
    async with supervisor.provision(
        binding,
        linux_binary=binary,
        native_env=_env(supervisor._test_public_key),
        worker_id=worker_id,
    ) as session:
        with pytest.raises(NativeSupervisorDenied, match="redeemed"):
            await supervisor.record_0033_transition(
                session,
                token=token,
                state="running",
                previous=first,
                record_callback=record,
            )
        status, _ = await session.invoke_authority_status("A" * 128)
        assert status == 200
        second = await supervisor.record_0033_transition(
            session,
            token=token,
            state="running",
            previous=first,
            record_callback=record,
        )
    assert session.final_statement is not None
    third = await supervisor.record_0033_transition(
        session,
        token=token,
        state="terminated",
        previous=second,
        record_callback=record,
    )
    fourth = await supervisor.record_0033_transition(
        session,
        token=token,
        state="reaped",
        previous=third,
        record_callback=record,
    )
    assert fourth["revision"] == 4
    assert [item["state"] for item in observations] == [
        "provisioned",
        "running",
        "terminated",
        "reaped",
    ]
    assert not docker.containers_by_id and not docker.networks_by_id
