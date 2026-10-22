"""No Docker daemon / target / provider calls: production observer boundary tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core.native_mcp_grant_signing import sign_grant
from ai_osop.orchestrator import native_mcp_docker_supervisor as dut


CONTAINER = "c" * 64
NETWORK = "a" * 64
IMAGE = "sha256:" + "d" * 64
OWNER = "osop-native-linux-" + "e" * 32
WORKER = "worker-independent-1"
SUPERVISOR = "independent-observer-1"
KID = "supervisor-key-1"


class Object:
    def __init__(self, *, id: str, name: str, attrs: dict):
        self.id = id
        self.name = name
        self.attrs = attrs

    def reload(self) -> None:
        return None

    def top(self, *, ps_args: str) -> dict:
        assert ps_args == "-eo pid,uid,args"
        return self.attrs["DockerTop"]


class Clients:
    def __init__(self) -> None:
        container = Object(
            id=CONTAINER,
            name="owned-recon",
            attrs={
                "Id": CONTAINER,
                "Image": IMAGE,
                "State": {
                    "Running": True,
                    "Pid": 4321,
                    "StartedAt": "2026-10-20T07:00:00.000000Z",
                },
                "DockerTop": {
                    "Titles": ["PID", "UID", "COMMAND"],
                    "Processes": [
                        ["4321", "65534", "python3 -c sleep"],
                        ["4322", "65534", "/qual/recon-mcp"],
                    ],
                },
                "Config": {
                    "User": "65534:65534",
                    "Labels": {dut.OWNER_LABEL: OWNER},
                    "Env": ["OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON=public-only"],
                    "ExposedPorts": None,
                },
                "HostConfig": {
                    "NetworkMode": "owned-private",
                    "ReadonlyRootfs": True,
                    "Privileged": False,
                    "CapDrop": ["ALL"],
                    "CapAdd": None,
                    "SecurityOpt": ["no-new-privileges:true"],
                    "PidsLimit": 64,
                    "Memory": 192 * 1024 * 1024,
                    "Binds": None,
                    "Mounts": None,
                    "Devices": [],
                    "PortBindings": None,
                    "PidMode": "",
                    "IpcMode": "private",
                    "Tmpfs": {
                        "/run/osop-native-stage": "rw,noexec,nodev,nosuid,mode=0700,uid=65534,gid=65534,size=8m",
                        "/qual": "rw,exec,nodev,nosuid,uid=65534,gid=65534,size=36m",
                        "/tmp": "rw,noexec,nodev,nosuid,mode=1777,size=4m",
                    },
                },
                "Mounts": [],
                "NetworkSettings": {"Networks": {"owned-private": {}}},
            },
        )
        network = Object(
            id=NETWORK,
            name="owned-private",
            attrs={
                "Id": NETWORK,
                "Internal": True,
                "Driver": "bridge",
                "Labels": {dut.OWNER_LABEL: OWNER},
                "Containers": {CONTAINER: {"Name": "owned-recon"}},
            },
        )
        self.c = container
        self.n = network
        self.containers = SimpleNamespace(get=lambda name: self._get(container, name))
        self.networks = SimpleNamespace(get=lambda name: self._get(network, name))

    @staticmethod
    def _get(item: Object, name: str) -> Object:
        if name != item.id:
            raise RuntimeError("NotFound")
        return item


def _inspect(fake: Clients) -> dut.ObservedNativeContainer:
    return dut.observe_isolated_native_container(
        fake,
        container_id=CONTAINER,
        network_id=NETWORK,
        owner_nonce=OWNER,
        expected_image_id=IMAGE,
    )


def _grant() -> tuple[dict, dict, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    now = int(time.time())
    claims = {
        "version": 1,
        "grant_id": "ngr-" + "a" * 32,
        "request_id": "req-" + "b" * 48,
        "engagement_id": "eng-" + "c" * 32,
        "flow_id": "flow-" + "d" * 32,
        "task_id": "task-" + "e" * 32,
        "subtask_id": "subtask-" + "f" * 32,
        "action_id": "action-" + "1" * 32,
        "server_id": "recon-mcp",
        "tool_name": "authority_status",
        "parameters_sha256": hashlib.sha256(b"{}").hexdigest(),
        "manifest_sha256": "2" * 64,
        "authorization_version": 1,
        "authorization_sha256": "3" * 64,
        "lease_id": "lease-" + "4" * 32,
        "resource_sha256": "5" * 64,
        "issued_at": now - 1,
        "expires_at": now + 55,
        "side_effect_class": "READ_ONLY",
    }
    signed = sign_grant(
        claims,
        kid="native-issuer-1",
        private_seed_b64url=base64.urlsafe_b64encode(seed).decode().rstrip("="),
        now=now,
    )
    return signed, {"native-issuer-1": base64.urlsafe_b64encode(public).decode().rstrip("=")}, key


def test_real_daemon_snapshot_passes_only_strictly_owned_isolation() -> None:
    clients = Clients()
    observed = _inspect(clients)
    assert observed.container_id == CONTAINER
    assert observed.network_id == NETWORK
    assert observed.process_pid == 4322
    assert observed.container_init_pid == 4321
    assert len(observed.evidence_sha256) == 64
    assert _inspect(clients) == observed


def test_existing_supervisor_owned_container_identity_remains_distinct() -> None:
    clients = Clients()
    owner = "osop-native-sup-" + "f" * 32
    label = dut.LEGACY_SUPERVISOR_OWNER_LABEL
    clients.c.attrs["Config"]["Labels"] = {label: owner}
    clients.n.attrs["Labels"] = {label: owner}
    observed = dut.observe_isolated_native_container(
        clients,
        container_id=CONTAINER,
        network_id=NETWORK,
        owner_nonce=owner,
        expected_image_id=IMAGE,
        owner_label=label,
    )
    assert observed.process_pid == 4322
    assert observed.container_id == CONTAINER
    with pytest.raises(dut.IndependentSupervisorDenied):
        dut.observe_isolated_native_container(
            clients,
            container_id=CONTAINER,
            network_id=NETWORK,
            owner_nonce=owner,
            expected_image_id=IMAGE,
            owner_label=dut.OWNER_LABEL,
        )
    with pytest.raises(dut.IndependentSupervisorDenied):
        dut.observe_isolated_native_container(
            clients,
            container_id=CONTAINER,
            network_id=NETWORK,
            owner_nonce=OWNER,
            expected_image_id=IMAGE,
            owner_label=label,
        )


@pytest.mark.parametrize(
    "target,key,value",
    [
        ("host", "ReadonlyRootfs", False),
        ("host", "Privileged", True),
        ("host", "Binds", ["/host:/host"]),
        ("host", "CapAdd", ["SYS_ADMIN"]),
        ("host", "PidMode", "host"),
        ("host", "NetworkMode", "bridge"),
        ("host", "PortBindings", {"8082/tcp": 8082}),
        ("host", "Memory", 0),
        ("state", "Running", False),
        ("state", "Pid", 0),
        ("network", "Internal", False),
        ("network", "Containers", {CONTAINER: {}, "f" * 64: {}}),
        ("config", "User", "root"),
        ("config", "Env", ["OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON=private"]),
        ("top", "Processes", [["4321", "65534", "python3 -c sleep"]]),
        ("top", "Titles", ["PID", "UID", "CMD"]),
    ],
)
def test_unsafe_daemon_policies_deny(target: str, key: str, value: object) -> None:
    clients = Clients()
    destinations = {
        "host": clients.c.attrs["HostConfig"],
        "state": clients.c.attrs["State"],
        "network": clients.n.attrs,
        "config": clients.c.attrs["Config"],
        "top": clients.c.attrs["DockerTop"],
    }
    destinations[target][key] = value
    with pytest.raises(dut.IndependentSupervisorDenied):
        _inspect(clients)


def test_stale_name_mismatched_image_or_owner_never_attests() -> None:
    clients = Clients()
    for change in ("container", "network", "owner", "image"):
        kw = dict(
            container_id=CONTAINER,
            network_id=NETWORK,
            owner_nonce=OWNER,
            expected_image_id=IMAGE,
        )
        kw[
            {
                "container": "container_id",
                "network": "network_id",
                "owner": "owner_nonce",
                "image": "expected_image_id",
            }[change]
        ] = {
            "container": "f" * 64,
            "network": "b" * 64,
            "owner": "osop-native-linux-" + "f" * 32,
            "image": "sha256:" + "f" * 64,
        }[
            change
        ]
        with pytest.raises(dut.IndependentSupervisorDenied):
            dut.observe_isolated_native_container(clients, **kw)


def test_independent_supervisor_docker_exec_uses_only_owned_container_local_proof(
    monkeypatch,
) -> None:
    calls = []

    def execute(argv, **kw):
        calls.append((argv, kw))
        assert argv[:6] == ["docker", "exec", "-i", "--user", "65534:65534", CONTAINER]
        assert argv[6:8] == ["python3", "-c"]
        assert "127.0.0.1:8082/native-supervisor/provision" in argv[8]
        assert "class NoRedirect" in argv[8]
        assert "ProxyHandler({})" in argv[8]
        assert kw["timeout"] == 5
        assert kw["check"] is True
        assert kw["input"] == b'{"claims":{},"kid":"key","signature":"test"}'
        assert "Bearer" not in repr(argv)
        return SimpleNamespace(
            stdout=b'{"status":200,"body":{"status":"supervisor_proof_provisioned"}}'
        )

    monkeypatch.setattr(dut.subprocess, "run", execute)
    result = dut.docker_exec_native_provision(
        container_id=CONTAINER,
        proof={"claims": {}, "kid": "key", "signature": "test"},
    )
    assert result == (200, {"status": "supervisor_proof_provisioned"})
    assert len(calls) == 1
    with pytest.raises(dut.IndependentSupervisorDenied):
        dut.docker_exec_native_provision(container_id="not-owned", proof={"claims": {}})
    assert len(calls) == 1


def test_lost_docker_exec_ack_never_retries(monkeypatch) -> None:
    calls = []

    def interrupted(*args, **kwargs):
        calls.append(1)
        raise TimeoutError("post-commit ack lost")

    monkeypatch.setattr(dut.subprocess, "run", interrupted)
    with pytest.raises(dut.IndependentSupervisorDenied):
        dut.docker_exec_native_provision(
            container_id=CONTAINER,
            proof={"claims": {}, "kid": "key", "signature": "test"},
        )
    assert calls == [1]


def test_supervisor_cannot_reuse_native_grant_issuer_key() -> None:
    _, public, issuer_private = _grant()
    with pytest.raises(dut.IndependentSupervisorDenied):
        dut.NativeDockerSupervisorProvisioner(
            docker_client=Clients(),
            source_port=18444,
            source_root_pem="-----BEGIN CERTIFICATE-----test",
            supervisor_id=SUPERVISOR,
            supervisor_kid=KID,
            supervisor_secret="supervisor-only-strong-secret",
            supervisor_private=issuer_private,
            trusted_issuer_keys=public,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("host_docker_channel", [False, True])
async def test_signed_source_then_daemon_recheck_then_separate_native_provision(
    monkeypatch,
    host_docker_channel: bool,
) -> None:
    clients = Clients()
    signed, issuer_keys, issuer_private = _grant()
    signer = Ed25519PrivateKey.generate()
    source_posts = []
    worker_posts = []

    class Source:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, path, **kwargs):
            source_posts.append((path, kwargs))
            obs = kwargs["json"]["observation"]
            canonical = json.dumps(
                obs["claims"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
            signer.public_key().verify(
                base64.urlsafe_b64decode(obs["signature"] + "=="),
                dut.OBSERVATION_DOMAIN + canonical,
            )
            assert obs["claims"]["container_id"] == CONTAINER
            assert obs["claims"]["evidence_sha256"] == _inspect(clients).evidence_sha256
            assert kwargs["json"]["grant"] == signed
            assert kwargs["headers"]["Authorization"].startswith("Bearer ")
            return SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "grant_id": signed["claims"]["grant_id"],
                    "worker_id": WORKER,
                    "epoch": 7,
                    "revision": 1,
                    "state": "provisioned",
                    "supervisor_observed": True,
                    "independent_target_effect_verified": False,
                    "original_action_status": "unknown",
                },
            )

    monkeypatch.setattr(dut.ssl, "create_default_context", lambda **_: object())
    monkeypatch.setattr(dut.httpx, "AsyncClient", lambda **_: Source())

    async def worker(path: str, proof: dict) -> tuple[int, dict]:
        worker_posts.append(path)
        assert path == "/native-supervisor/provision"
        canonical = json.dumps(
            proof["claims"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        signer.public_key().verify(
            base64.urlsafe_b64decode(proof["signature"] + "=="),
            dut.WORKER_DOMAIN + canonical,
        )
        assert proof["claims"]["container_id"] == CONTAINER
        assert proof["claims"]["epoch"] == 7
        assert proof["claims"]["revision"] == 1
        assert proof["claims"]["worker_id"] == WORKER
        assert proof["claims"]["resource_sha256"] == signed["claims"]["resource_sha256"]
        assert proof["claims"]["expires_at"] <= int(time.time()) + 8
        return 200, {
            "status": "supervisor_proof_provisioned",
            "execution_enabled": False,
            "durably_redeemed": False,
        }

    svc = dut.NativeDockerSupervisorProvisioner(
        docker_client=clients,
        source_port=18444,
        source_root_pem="-----BEGIN CERTIFICATE-----test",
        supervisor_id=SUPERVISOR,
        supervisor_kid=KID,
        supervisor_secret="supervisor-only-strong-secret",
        supervisor_private=signer,
        trusted_issuer_keys=issuer_keys,
    )
    if host_docker_channel:

        def host_deliver(*, container_id: str, proof: dict) -> tuple[int, dict]:
            assert container_id == CONTAINER
            worker_posts.append("/native-supervisor/provision")
            assert proof["claims"]["container_id"] == CONTAINER
            return 200, {
                "status": "supervisor_proof_provisioned",
                "execution_enabled": False,
                "durably_redeemed": False,
            }

        monkeypatch.setattr(dut, "docker_exec_native_provision", host_deliver)
    got = await svc.provision_inert_grant(
        grant=signed,
        worker_id=WORKER,
        owner_id="owner-qualified",
        approval_id="apr-qualified",
        container_id=CONTAINER,
        network_id=NETWORK,
        owner_nonce=OWNER,
        expected_image_id=IMAGE,
        send_to_worker=None if host_docker_channel else worker,
    )
    assert got["native_provision_acknowledged"] is True
    assert got["durably_redeemed"] is False
    assert got["independent_target_effect_verified"] is False
    assert len(source_posts) == len(worker_posts) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["bad-source", "restarted", "expired", "forged"])
async def test_source_denial_worker_restart_and_forged_grant_never_admit(
    monkeypatch, failure: str
) -> None:
    clients = Clients()
    signed, issuer_keys, _ = _grant()
    signer = Ed25519PrivateKey.generate()
    invoked = []

    class Source:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, path, **kwargs):
            invoked.append("source")
            if failure == "restarted":
                clients.c.attrs["State"]["Pid"] = 9999
            return SimpleNamespace(
                status_code=409 if failure == "bad-source" else 200,
                json=lambda: {
                    "grant_id": signed["claims"]["grant_id"],
                    "worker_id": WORKER,
                    "epoch": 1,
                    "revision": 1,
                    "state": "provisioned",
                    "supervisor_observed": True,
                    "independent_target_effect_verified": False,
                    "original_action_status": "unknown",
                },
            )

    monkeypatch.setattr(dut.ssl, "create_default_context", lambda **_: object())
    monkeypatch.setattr(dut.httpx, "AsyncClient", lambda **_: Source())
    if failure == "expired":
        signed["claims"]["expires_at"] = 1
    if failure == "forged":
        signed["claims"]["request_id"] = "req-" + "0" * 48

    async def worker(path: str, proof: dict) -> tuple[int, dict]:
        invoked.append("worker")
        raise AssertionError("Unauthorized worker proof provision")

    svc = dut.NativeDockerSupervisorProvisioner(
        docker_client=clients,
        source_port=18444,
        source_root_pem="-----BEGIN CERTIFICATE-----test",
        supervisor_id=SUPERVISOR,
        supervisor_kid=KID,
        supervisor_secret="supervisor-only-strong-secret",
        supervisor_private=signer,
        trusted_issuer_keys=issuer_keys,
    )
    with pytest.raises(dut.IndependentSupervisorDenied):
        await svc.provision_inert_grant(
            grant=signed,
            worker_id=WORKER,
            owner_id="owner-qualified",
            approval_id="apr-qualified",
            container_id=CONTAINER,
            network_id=NETWORK,
            owner_nonce=OWNER,
            expected_image_id=IMAGE,
            send_to_worker=worker,
        )
    assert "worker" not in invoked
    assert invoked.count("source") == (1 if failure in ("bad-source", "restarted") else 0)
