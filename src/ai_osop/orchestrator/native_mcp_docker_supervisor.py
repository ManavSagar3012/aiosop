"""Independent Docker-observed admission for inert, resource-bound native MCP.

This module belongs in a separately trusted supervisor process, NEVER in the
Go worker. It deliberately does not launch scanners, grant authority, retry an
ambiguous operation, or establish target-side effects. A Docker daemon report
is an independent control-plane observation, not hardware/OS attestation.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import ssl
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core.native_mcp_grant_signing import claim_sha256, verify_grant
from ai_osop.memory.native_mcp_worker_supervision import DOMAIN as OBSERVATION_DOMAIN


WORKER_DOMAIN = b"ai-osop/native-grant-worker-redemption/v1\x00"
OWNER_LABEL = "osop.native.worker.owner"
LEGACY_SUPERVISOR_OWNER_LABEL = "ai-osop.native-supervisor.owner"
STAGE_ROOT = "/run/osop-native-stage"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,95}\Z")
_EXPECTED_TMPFS = {"rw", "noexec", "nodev", "nosuid", "mode=0700", "uid=65534", "gid=65534"}

# Execute only a hardcoded inert provision request INSIDE the independently
# inspected container. There is no host network port, target URL or scanner.
# Only the short-lived signed proof (never the private signer) goes via stdin.
_NATIVE_PROVISION_CODE = r"""
import json, sys, urllib.request, urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
try:
    raw = sys.stdin.buffer.read(4097)
    if not 0 < len(raw) <= 4096:
        raise ValueError()
    proof = json.loads(raw)
    if not isinstance(proof, dict) or set(proof) != {"claims","kid","signature"}:
        raise ValueError()
    request = urllib.request.Request(
        "http://127.0.0.1:8082/native-supervisor/provision", data=raw,
        method="POST", headers={"Content-Type":"application/json"}
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=3)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        result = response.read(4097)
        if len(result) > 4096:
            raise ValueError()
        print(json.dumps({"status":response.status,"body":json.loads(result)}))
except Exception:
    raise SystemExit(1)
"""


class IndependentSupervisorDenied(ValueError):
    """Safe non-secret failure; never means an Action can be retried."""


def _fail() -> None:
    raise IndependentSupervisorDenied("Independent native worker observation unavailable")


def _canonical(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, dict):
        _fail()
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail()
    if len(raw) > 3072:
        _fail()
    return raw


def _url64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def docker_exec_native_provision(
    *, container_id: str, proof: dict[str, Any]
) -> tuple[int, dict[str, Any]]:
    """Bounded actual Go loopback provision via the host Docker control plane.

    The caller MUST already independently own/observe this exact container.
    This command cannot start/stop/delete containers. Lost ACK is UNKNOWN;
    never retry the same proof or any potentially consequential Action.
    """
    if type(container_id) is not str or _SHA.fullmatch(container_id) is None:
        _fail()
    body = _canonical(proof)
    try:
        completed = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                "--user",
                "65534:65534",
                container_id,
                "python3",
                "-c",
                _NATIVE_PROVISION_CODE,
            ],
            input=body,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=5,
        )
        if len(completed.stdout) > 4096:
            _fail()
        decoded = json.loads(completed.stdout)
        if (
            type(decoded) is not dict
            or set(decoded) != {"status", "body"}
            or type(decoded["status"]) is not int
            or type(decoded["body"]) is not dict
        ):
            _fail()
        return decoded["status"], decoded["body"]
    except IndependentSupervisorDenied:
        raise
    except Exception:
        _fail()


@dataclass(frozen=True)
class ObservedNativeContainer:
    """Reduced Docker control-plane evidence; no mounts, keys or env values."""

    container_id: str
    network_id: str
    process_pid: int
    container_init_pid: int
    started_at: str
    image_id: str
    evidence_sha256: str


def observe_isolated_native_container(
    docker_client: Any,
    *,
    container_id: str,
    network_id: str,
    owner_nonce: str,
    expected_image_id: str,
    expected_server_id: str = "recon-mcp",
    owner_label: str = OWNER_LABEL,
) -> ObservedNativeContainer:
    """Reinspect the daemon's actual owned Linux container and internal network.

    No worker-provided manifest, PID, labels, or JSON are trusted. The daemon
    MUST be independently reachable only by this supervisor, outside worker.
    This function never writes to or removes any Docker-owned resource.
    """
    if (
        type(container_id) is not str
        or _SHA.fullmatch(container_id) is None
        or type(network_id) is not str
        or _SHA.fullmatch(network_id) is None
        or type(owner_nonce) is not str
        or (
            (
                owner_label == OWNER_LABEL
                and re.fullmatch(r"osop-native-linux-[a-f0-9]{32}", owner_nonce) is None
            )
            or (
                owner_label == LEGACY_SUPERVISOR_OWNER_LABEL
                and re.fullmatch(r"osop-native-sup-[a-f0-9]{32}", owner_nonce) is None
            )
        )
        or type(expected_image_id) is not str
        or re.fullmatch(r"sha256:[a-f0-9]{64}", expected_image_id) is None
        or expected_server_id
        not in {
            "recon-mcp",
            "payload-mcp",
            "nuclei-mcp",
            "shodan-mcp",
            "threat-intel-mcp",
            "security-bridge",
        }
        or owner_label not in {OWNER_LABEL, LEGACY_SUPERVISOR_OWNER_LABEL}
    ):
        _fail()
    try:
        container = docker_client.containers.get(container_id)
        network = docker_client.networks.get(network_id)
        container.reload()
        network.reload()
        attrs = container.attrs
        n = network.attrs
        host = attrs["HostConfig"]
        config = attrs["Config"]
        state = attrs["State"]
        links = attrs["NetworkSettings"]["Networks"]
        mounts = host.get("Tmpfs") or {}
        stage = set(mounts.get(STAGE_ROOT, "").split(","))
        exe = set(mounts.get("/qual", "").split(","))
        tmp = set(mounts.get("/tmp", "").split(","))
        pid = state.get("Pid")
        started = state.get("StartedAt")
        image_id = attrs.get("Image")
        matching = (
            attrs.get("Id") == container_id
            and network.id == network_id
            and container.id == container_id
            and n.get("Id") == network_id
            and n.get("Internal") is True
            and n.get("Driver") == "bridge"
            and n.get("Labels", {}).get(owner_label) == owner_nonce
            and set(n.get("Containers") or {}) == {container_id}
            and config.get("Labels", {}).get(owner_label) == owner_nonce
            and type(links) is dict
            and set(links) == {network.name}
            and host.get("NetworkMode") == network.name
            and state.get("Running") is True
            and type(pid) is int
            and pid > 0
            and type(started) is str
            and len(started) <= 64
            and started != ""
            and image_id == expected_image_id
            and config.get("User") == "65534:65534"
            and host.get("ReadonlyRootfs") is True
            and host.get("Privileged") is False
            and set(host.get("CapDrop") or []) == {"ALL"}
            and not host.get("CapAdd")
            and "no-new-privileges:true" in (host.get("SecurityOpt") or [])
            and type(host.get("PidsLimit")) is int
            and 0 < host["PidsLimit"] <= 64
            and type(host.get("Memory")) is int
            and 0 < host["Memory"] <= 192 * 1024 * 1024
            and not host.get("Binds")
            and not host.get("Mounts")
            and not attrs.get("Mounts")
            and not host.get("Devices")
            and not host.get("PortBindings")
            and not config.get("ExposedPorts")
            and host.get("PidMode") in (None, "", "private")
            and host.get("IpcMode") in (None, "", "private")
            and set(mounts) == {STAGE_ROOT, "/qual", "/tmp"}
            and _EXPECTED_TMPFS.issubset(stage)
            and {"rw", "exec", "nodev", "nosuid", "uid=65534", "gid=65534"}.issubset(exe)
            and {"rw", "noexec", "nodev", "nosuid"}.issubset(tmp)
        )
        if not matching:
            _fail()
        # Docker inspect's State.Pid identifies the container INIT process,
        # which in the current restricted image can be a Python sleep helper.
        # It is NOT evidence that the actual Go MCP worker was started. Query
        # daemon-owned process inventory separately and bind the exact Go ELF
        # process identity to the signed supervisor observation.
        processes = container.top(ps_args="-eo pid,uid,args")
        titles = processes.get("Titles") if type(processes) is dict else None
        entries = processes.get("Processes") if type(processes) is dict else None
        if (
            type(titles) is not list
            or type(entries) is not list
            or len(titles) != 3
            or len(set(titles)) != 3
            or set(titles) != {"PID", "UID", "COMMAND"}
            or len(entries) > 64
        ):
            _fail()
        command_index, user_index, pid_index = (
            titles.index("COMMAND"),
            titles.index("UID"),
            titles.index("PID"),
        )
        found_pids = []
        for entry in entries:
            if type(entry) is not list or len(entry) != 3:
                _fail()
            if entry[command_index] != "/qual/" + expected_server_id:
                continue
            raw_pid = entry[pid_index]
            if (
                entry[user_index] != "65534"
                or type(raw_pid) is not str
                or re.fullmatch(r"[1-9][0-9]{0,9}", raw_pid) is None
                or int(raw_pid) == pid
            ):
                _fail()
            found_pids.append(int(raw_pid))
        if len(found_pids) != 1:
            _fail()
        native_pid = found_pids[0]
        # Do not leak secrets in Docker Config.Env; explicitly deny placing
        # supervisor signing private keys / native grant issuer seeds there.
        env = config.get("Env", [])
        if not isinstance(env, list) or any(
            type(entry) is not str
            or entry.split("=", 1)[0].startswith(
                (
                    "OSOP_NATIVE_WORKER_SUPERVISOR_PRIVATE",
                    "OSOP_NATIVE_WORKER_SUPERVISOR_SECRET",
                    "OSOP_NATIVE_MCP_GRANT_SIGNING",
                )
            )
            for entry in env
        ):
            _fail()
        # The owner nonce and actual daemon PID/StartedAt fence container-name
        # reuse and cross-worker replay; SHA does not prove independent effects.
        evidence = {
            "container_id": container_id,
            "network_id": network_id,
            "container_init_pid": pid,
            "native_go_pid": native_pid,
            "native_server_id": expected_server_id,
            "started_at": started,
            "image_id": image_id,
            "isolation_profile": "readonly-nonroot-internal-private-tmpfs-v1",
            "owner_nonce": owner_nonce,
        }
        return ObservedNativeContainer(
            container_id,
            network_id,
            native_pid,
            pid,
            started,
            image_id,
            hashlib.sha256(_canonical(evidence)).hexdigest(),
        )
    except IndependentSupervisorDenied:
        raise
    except Exception:
        _fail()


class NativeDockerSupervisorProvisioner:
    """Host-side supervisor source observation and one-shot native proof issuer.

    Provisioning does NOT redeem the grant, authorize scanner execution or
    initiate any target interaction. `send_to_worker` MUST be a constrained
    independent channel addressed to the exact observed container, such as a
    scoped Docker-exec localhost request, never an arbitrary user HTTP URL.
    """

    def __init__(
        self,
        *,
        docker_client: Any,
        source_port: int,
        source_root_pem: str,
        supervisor_id: str,
        supervisor_kid: str,
        supervisor_secret: str,
        supervisor_private: Ed25519PrivateKey,
        trusted_issuer_keys: dict[str, str],
    ) -> None:
        if (
            type(source_port) is not int
            or not 1024 <= source_port <= 65535
            or type(source_root_pem) is not str
            or "-----BEGIN CERTIFICATE-----" not in source_root_pem
            or type(supervisor_id) is not str
            or _ID.fullmatch(supervisor_id) is None
            or type(supervisor_kid) is not str
            or _ID.fullmatch(supervisor_kid) is None
            or type(supervisor_secret) is not str
            or not 20 <= len(supervisor_secret) <= 512
            or not isinstance(supervisor_private, Ed25519PrivateKey)
            or type(trusted_issuer_keys) is not dict
            or not 1 <= len(trusted_issuer_keys) <= 16
        ):
            _fail()
        supervisor_public = supervisor_private.public_key().public_bytes_raw()
        try:
            for kid, encoded in trusted_issuer_keys.items():
                if type(kid) is not str or type(encoded) is not str:
                    _fail()
                pub = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                if (
                    len(pub) != 32
                    or _url64(pub) != encoded
                    or hmac.compare_digest(supervisor_public, pub)
                ):
                    _fail()
        except IndependentSupervisorDenied:
            raise
        except Exception:
            _fail()
        self._docker_client = docker_client
        self._port = source_port
        self._root = source_root_pem
        self._id = supervisor_id
        self._kid = supervisor_kid
        self._secret = supervisor_secret
        self._private = supervisor_private
        self._issuers = dict(trusted_issuer_keys)

    def _sign(self, claims: dict[str, Any], domain: bytes) -> dict[str, Any]:
        return {
            "claims": claims,
            "kid": self._kid,
            "signature": _url64(self._private.sign(domain + _canonical(claims))),
        }

    async def provision_inert_grant(
        self,
        *,
        grant: dict[str, Any],
        worker_id: str,
        owner_id: str,
        approval_id: str,
        container_id: str,
        network_id: str,
        owner_nonce: str,
        expected_image_id: str,
        owner_label: str = OWNER_LABEL,
        send_to_worker: Optional[
            Callable[[str, dict[str, Any]], Awaitable[tuple[int, dict[str, Any]]]]
        ] = None,
        now: Optional[int] = None,
    ) -> dict[str, Any]:
        """Signed 0033 reservation → fresh Docker observation → Go admission.

        No automatic retries. A lost HTTP acknowledgment is UNKNOWN. The source
        independently verifies signed Task/ROE/reviewer/lease in PostgreSQL.
        """
        if (
            (send_to_worker is not None and not callable(send_to_worker))
            or type(worker_id) is not str
            or _ID.fullmatch(worker_id) is None
            or type(owner_id) is not str
            or _ID.fullmatch(owner_id) is None
            or type(approval_id) is not str
            or re.fullmatch(r"apr-[A-Za-z0-9._:-]{2,63}", approval_id) is None
        ):
            _fail()
        instant = int(time.time()) if now is None else now
        try:
            original = verify_grant(grant, public_keys=self._issuers, now=instant)
        except Exception:
            _fail()
        if original["resource_sha256"] is None:
            _fail()
        if original["server_id"] != "recon-mcp":
            # The presently implemented fixed Docker-exec side channel and
            # isolated original-byte lifecycle qualify Recon only. Never
            # suggest that the other five cmd binaries were stage-qualified.
            _fail()
        first = observe_isolated_native_container(
            self._docker_client,
            container_id=container_id,
            network_id=network_id,
            owner_nonce=owner_nonce,
            expected_image_id=expected_image_id,
            expected_server_id=original["server_id"],
            owner_label=owner_label,
        )
        observation_claims = {
            "version": 1,
            "grant_id": original["grant_id"],
            "request_id": original["request_id"],
            "server_id": original["server_id"],
            "worker_id": worker_id,
            # 0033 source must persist this independently observed identity
            # before the 0029 redemption proof can refer to the container.
            "container_id": first.container_id,
            "epoch": 0,
            "expected_revision": 0,
            "state": "provisioned",
            "observed_at": instant,
            "evidence_sha256": first.evidence_sha256,
            "resource_sha256": original["resource_sha256"],
            "folder_staging_sha256": None,
            "readback_sha256": None,
        }
        signed_observation = self._sign(observation_claims, OBSERVATION_DOMAIN)
        try:
            context = ssl.create_default_context(cadata=self._root)
            async with httpx.AsyncClient(
                verify=context, trust_env=False, follow_redirects=False, timeout=5.0
            ) as client:
                response = await client.post(
                    f"https://127.0.0.1:{self._port}/native-supervisor/observe",
                    json={"grant": grant, "observation": signed_observation},
                    headers={
                        "X-OSOP-Supervisor-ID": self._id,
                        "Authorization": "Bearer " + self._secret,
                        "Content-Type": "application/json",
                    },
                )
            if response.status_code != 200:
                _fail()
            ack = response.json()
            if (
                type(ack) is not dict
                or set(ack)
                != {
                    "grant_id",
                    "worker_id",
                    "epoch",
                    "revision",
                    "state",
                    "supervisor_observed",
                    "independent_target_effect_verified",
                    "original_action_status",
                }
                or ack["grant_id"] != original["grant_id"]
                or ack["worker_id"] != worker_id
                or ack["state"] != "provisioned"
                or type(ack["epoch"]) is not int
                or ack["epoch"] <= 0
                or type(ack["revision"]) is not int
                or ack["revision"] != 1
                or ack["supervisor_observed"] is not True
                or ack["independent_target_effect_verified"] is not False
                or ack["original_action_status"] != "unknown"
            ):
                _fail()
            second = observe_isolated_native_container(
                self._docker_client,
                container_id=container_id,
                network_id=network_id,
                owner_nonce=owner_nonce,
                expected_image_id=expected_image_id,
                expected_server_id=original["server_id"],
                owner_label=owner_label,
            )
            if second != first:
                _fail()
            issued_at = int(time.time())
            if issued_at < instant - 5 or issued_at > instant + 20:
                _fail()
            expires_at = min(issued_at + 8, original["expires_at"])
            if expires_at <= issued_at:
                _fail()
            import secrets

            proof_claims = {
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
                "worker_id": worker_id,
                "container_id": container_id,
                "supervisor_id": self._id,
                "epoch": ack["epoch"],
                "revision": ack["revision"],
                "approval_id": approval_id,
                "lease_id": original["lease_id"],
                "authorization_sha256": original["authorization_sha256"],
                "claims_sha256": claim_sha256(original),
                "resource_sha256": original["resource_sha256"],
                "nonce": secrets.token_hex(16),
                "issued_at": issued_at,
                "expires_at": expires_at,
            }
            signed_proof = self._sign(proof_claims, WORKER_DOMAIN)
            if send_to_worker is None:
                status, accepted = await asyncio.to_thread(
                    docker_exec_native_provision,
                    container_id=container_id,
                    proof=signed_proof,
                )
            else:
                status, accepted = await send_to_worker(
                    "/native-supervisor/provision", signed_proof
                )
            if (
                status != 200
                or type(accepted) is not dict
                or accepted.get("status") != "supervisor_proof_provisioned"
                or accepted.get("execution_enabled") is not False
                or accepted.get("durably_redeemed") is not False
            ):
                _fail()
            third = observe_isolated_native_container(
                self._docker_client,
                container_id=container_id,
                network_id=network_id,
                owner_nonce=owner_nonce,
                expected_image_id=expected_image_id,
                expected_server_id=original["server_id"],
                owner_label=owner_label,
            )
            if third != first:
                _fail()
            return {
                "grant_id": original["grant_id"],
                "worker_id": worker_id,
                "epoch": ack["epoch"],
                "revision": ack["revision"],
                "state": "provisioned",
                "supervisor_observed": True,
                "native_provision_acknowledged": True,
                "durably_redeemed": False,
                "native_scanners_enabled": False,
                "independent_target_effect_verified": False,
            }
        except IndependentSupervisorDenied:
            raise
        except Exception:
            _fail()
