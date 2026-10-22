"""Qualification-only independent Docker supervisor for inert native Recon.

The caller injects a trusted async authority verifier backed by the current
source-of-truth (0033). The verifier MUST independently check current signed
ROE, issuer, Task/Action, human approval and execution lease on EACH call.
This module does not implement, simulate or bypass that durable authority.
No production endpoint, scheduler or scanner invokes this supervisor.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import struct
import subprocess
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Mapping, Optional
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

_DOMAIN = b"ai-osop/native-supervisor/v1\x00"
_OWNERSHIP_DOMAIN = b"ai-osop/native-supervisor-owned/v1\x00"
_STORE_DOMAIN = b"ai-osop/native-worker-supervisor/v1\x00"
_LABEL = "ai-osop.native-supervisor.owner"
_IMAGE = "python:3.11-slim"
_STAGE = "/run/osop-native-stage"
_MAX_BINARY = 32 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9._:-]{4,128}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
_KID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_ALLOW_ENV = {
    "OSOP_RECON_MCP_LOCAL_PORT",
    "OSOP_NATIVE_MCP_STAGE_ROOT",
    "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
    "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
    "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM",
    "OSOP_NATIVE_MCP_REDEEM_URL",
    "OSOP_NATIVE_STAGE_RECEIPT_ED25519_SEED_B64",
    "OSOP_NATIVE_STAGE_RECEIPT_KID",
    "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON",
}
_REQUIRED_ENV = {
    "OSOP_NATIVE_MCP_STAGE_ROOT",
    "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON",
    "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
    "OSOP_NATIVE_MCP_REDEEM_ROOT_PEM",
    "OSOP_NATIVE_MCP_REDEEM_URL",
}

# This is a read-only and data-only inspection, invoked independently from the
# worker's own Go attestations. The supervisor does not accept a worker-provided
# mount statement. Any broken/missing mount evidence fails before approval.
_INSPECT_STAGE = """
import json, os, stat
root = "/run/osop-native-stage"
s = os.lstat(root)
mount = None
for entry in open("/proc/self/mountinfo", encoding="utf-8"):
    parts = entry.strip().split(" - ", 1)
    left = parts[0].split()
    right = parts[1].split() if len(parts) > 1 else []
    if len(left) > 5 and left[4] == root and len(right) >= 3:
        mount = {"type": right[0], "options": sorted(
            set(left[5].split(",") + right[2].split(","))
        )}
        break
print(json.dumps({
    "uid": s.st_uid, "gid": s.st_gid, "mode": stat.S_IMODE(s.st_mode),
    "directory": stat.S_ISDIR(s.st_mode), "entries": sorted(os.listdir(root)),
    "mount": mount,
}, sort_keys=True))
"""

_HTTP_POST = """
import json, sys, urllib.error, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
try:
    supplied = json.loads(sys.stdin.buffer.read(16385))
    if set(supplied) != {"header", "request_id"}:
        raise ValueError()
    body = json.dumps({
        "tool_name": "authority_status",
        "parameters": {},
        "request_id": supplied["request_id"],
        "timeout_override": None,
    }, separators=(",", ":")).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:8082/mcp/execute", method="POST", data=body,
        headers={
            "Content-Type": "application/json",
            "X-OSOP-Native-Grant": supplied["header"],
        },
    )
    try:
        response = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        ).open(request, timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = response.read(16385)
        if len(payload) > 16384:
            raise ValueError()
        print(json.dumps({"http_status": response.status, "body": json.loads(payload)}))
except Exception:
    raise SystemExit(1)
"""


class NativeSupervisorDenied(RuntimeError):
    """Generic fail-closed rejection; never contains credentials or grants."""


@dataclass(frozen=True)
class SupervisorBinding:
    request_id: str
    engagement_id: str
    flow_id: str
    task_id: str
    subtask_id: str
    action_id: str
    approval_id: str
    lease_id: str
    issuer_kid: str
    signed_roe_sha256: str
    authorization_sha256: str
    manifest_sha256: str
    binary_sha256: str
    # Untrusted caller must not choose another native tool or server.
    server_id: str = "recon-mcp"
    tool_name: str = "authority_status"

    def validate(self) -> None:
        for name in (
            "request_id",
            "engagement_id",
            "flow_id",
            "task_id",
            "subtask_id",
            "action_id",
            "approval_id",
            "lease_id",
            "issuer_kid",
        ):
            value = getattr(self, name)
            if type(value) is not str or _ID.fullmatch(value) is None:
                raise NativeSupervisorDenied("Invalid supervisor source binding")
        for name in (
            "signed_roe_sha256",
            "authorization_sha256",
            "manifest_sha256",
            "binary_sha256",
        ):
            if type(getattr(self, name)) is not str or not _SHA.fullmatch(getattr(self, name)):
                raise NativeSupervisorDenied("Invalid supervisor source digest")
        for name, prefix in (
            ("request_id", "req-"),
            ("engagement_id", "eng-"),
            ("flow_id", "flow-"),
            ("task_id", "task-"),
            ("subtask_id", "subtask-"),
            ("action_id", "action-"),
            ("lease_id", "lease-"),
        ):
            if not getattr(self, name).startswith(prefix):
                raise NativeSupervisorDenied("Supervisor binding family mismatch")
        if self.server_id != "recon-mcp" or self.tool_name != "authority_status":
            raise NativeSupervisorDenied("Only the inert native authority tool is permitted")


@dataclass(frozen=True)
class SourceAuthorityDecision:
    """0033 adapter output, derived from DURABLE source, never caller claims."""

    binding: SupervisorBinding
    authority_version: int
    checked_at: int
    expires_at: int
    issuer_trusted: bool
    signed_roe_valid: bool
    task_active: bool
    approval_current: bool
    lease_active: bool


AuthorityCallback = Callable[[SupervisorBinding], Awaitable[SourceAuthorityDecision]]
StoreRecordCallback = Callable[[dict[str, Any], dict[str, Any]], Awaitable[dict[str, Any]]]


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _sign(
    key: Ed25519PrivateKey, domain: bytes, claims: dict[str, Any], kid: str
) -> dict[str, Any]:
    signature = key.sign(domain + _canonical(claims))
    return {
        "kid": kid,
        "claims": claims,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def verify_supervisor_statement(
    statement: Mapping[str, Any], *, public_key: bytes, ownership: bool = False
) -> bool:
    """Public verification of independently signed facts/ownership records."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if type(statement) is not dict or set(statement) != {"kid", "claims", "signature"}:
            return False
        if not isinstance(statement["claims"], dict) or not _KID.fullmatch(statement["kid"]):
            return False
        signature = statement["signature"]
        if not isinstance(signature, str):
            return False
        raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if base64.urlsafe_b64encode(raw).decode().rstrip("=") != signature:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            raw, (_OWNERSHIP_DOMAIN if ownership else _DOMAIN) + _canonical(statement["claims"])
        )
        return True
    except (ValueError, TypeError, KeyError):
        return False
    except Exception:
        return False


@dataclass
class SupervisorSession:
    """Active only within the owning supervisor's async context."""

    binding: SupervisorBinding
    owner: str
    container_id: str
    network_id: str
    ownership_statement: dict[str, Any]
    _supervisor: "NativeMCPWorkerSupervisor" = field(repr=False)
    stage_observation: Optional[dict[str, Any]] = None
    final_statement: Optional[dict[str, Any]] = None
    _closed: bool = False
    _invoked: bool = False
    _successful_inert_redemption: bool = False
    worker_id: str = ""
    store_record: Optional[dict[str, Any]] = None
    _public_supervisor_trust_ready: bool = False
    _public_supervisor_id: str = ""

    async def invoke_supervised_authority_status(
        self,
        *,
        signed_grant: dict[str, Any],
        independent_provisioner: Any,
        owner_id: str,
        approval_id: str,
    ) -> tuple[int, dict[str, Any]]:
        """Compose separately signed 0033 provision + real Go + source 0029.

        Only an independently owned Docker process with trusted PUBLIC Go
        supervisor roots may take this path. All consequential Go handlers
        remain disabled. Attempt is consumed BEFORE any source/Docker I/O;
        ambiguous acknowledgment never causes automatic replay.
        """
        from ai_osop.core.native_mcp_grant_signing import header_value
        from ai_osop.orchestrator.native_mcp_docker_supervisor import (
            LEGACY_SUPERVISOR_OWNER_LABEL,
            NativeDockerSupervisorProvisioner,
        )

        if (
            self._closed
            or self._invoked
            or not self._public_supervisor_trust_ready
            or not isinstance(independent_provisioner, NativeDockerSupervisorProvisioner)
            or independent_provisioner._id != self._public_supervisor_id
            or independent_provisioner._private.public_key().public_bytes_raw()
            != self._supervisor.public_key
            or independent_provisioner._kid != self._supervisor.kid
        ):
            raise NativeSupervisorDenied("Independent supervisor provision not configured")
        await self._supervisor._verify_source(self.binding)
        claims = self._supervisor._store_token_identity(self.binding, signed_grant)
        if claims.get("resource_sha256") is None or approval_id != self.binding.approval_id:
            raise NativeSupervisorDenied("Original supervised resource grant required")
        self._invoked = True
        client = None
        try:
            client = await asyncio.to_thread(self._supervisor._docker_factory)
            expected_image = await asyncio.to_thread(lambda: client.images.get(_IMAGE).id)
            if (
                type(expected_image) is not str
                or re.fullmatch(r"sha256:[a-f0-9]{64}", expected_image) is None
            ):
                raise NativeSupervisorDenied("Owned cached Linux image missing")
            ack = await independent_provisioner.provision_inert_grant(
                grant=signed_grant,
                worker_id=self.worker_id,
                owner_id=owner_id,
                approval_id=approval_id,
                container_id=self.container_id,
                network_id=self.network_id,
                owner_nonce=self.owner,
                owner_label=LEGACY_SUPERVISOR_OWNER_LABEL,
                expected_image_id=expected_image,
            )
            if (
                type(ack) is not dict
                or ack.get("grant_id") != claims["grant_id"]
                or ack.get("worker_id") != self.worker_id
                or type(ack.get("epoch")) is not int
                or ack["epoch"] <= 0
                or type(ack.get("revision")) is not int
                or ack["revision"] != 1
                or ack.get("state") != "provisioned"
                or ack.get("supervisor_observed") is not True
                or ack.get("native_provision_acknowledged") is not True
                or ack.get("durably_redeemed") is not False
                or ack.get("independent_target_effect_verified") is not False
            ):
                raise NativeSupervisorDenied("Supervisor proof admission UNKNOWN")
            self.store_record = {
                "grant_id": claims["grant_id"],
                "worker_id": self.worker_id,
                "epoch": ack["epoch"],
                "revision": ack["revision"],
                "state": "provisioned",
                "supervisor_observed": True,
            }
            raw = await self._supervisor._exec(
                self.owner + "-recon",
                ["python3", "-c", _HTTP_POST],
                _canonical(
                    {
                        "header": header_value(signed_grant),
                        "request_id": self.binding.request_id,
                    }
                ),
                10,
            )
            decoded = json.loads(raw)
            if (
                type(decoded) is not dict
                or type(decoded.get("http_status")) is not int
                or type(decoded.get("body")) is not dict
            ):
                raise NativeSupervisorDenied("Native Go ACK is malformed or lost")
            body = decoded["body"]
            self._successful_inert_redemption = (
                decoded["http_status"] == 200
                and body.get("status") == "success"
                and type(body.get("result")) is dict
                and body["result"].get("native_target_execution_enabled") is False
                and body["result"].get("target_contacted") is False
                and body["result"].get("provider_contacted") is False
                and body["result"].get("resource_bytes_received_verified") is True
            )
            if not self._successful_inert_redemption:
                raise NativeSupervisorDenied("Native supervised redemption UNKNOWN")
            return decoded["http_status"], body
        except NativeSupervisorDenied:
            raise
        except Exception:
            raise NativeSupervisorDenied("Native supervised redemption UNKNOWN") from None
        finally:
            if client is not None and hasattr(client, "close"):
                client.close()

    async def observe(self) -> dict[str, Any]:
        if self._closed:
            raise NativeSupervisorDenied("Supervisor lifecycle already closed")
        return await self._supervisor._observe(self)

    async def invoke_authority_status(self, signed_grant_header: str) -> tuple[int, dict[str, Any]]:
        """Exactly one inert native call, after a NEW current-source verification."""
        if self._closed or self._invoked:
            raise NativeSupervisorDenied("Native authority request already used")
        await self._supervisor._verify_source(self.binding)
        if (
            type(signed_grant_header) is not str
            or not 32 <= len(signed_grant_header) <= 8192
            or re.fullmatch(r"[A-Za-z0-9_-]+", signed_grant_header) is None
        ):
            raise NativeSupervisorDenied("Native grant header is missing or malformed")
        self._invoked = True  # Consume before I/O; UNKNOWN has no retry.
        result = await self._supervisor._exec(
            self.owner + "-recon",
            ["python3", "-c", _HTTP_POST],
            _canonical({"header": signed_grant_header, "request_id": self.binding.request_id}),
            10,
        )
        try:
            value = json.loads(result)
            if (
                type(value) is not dict
                or type(value.get("http_status")) is not int
                or type(value.get("body")) is not dict
            ):
                raise ValueError()
            self._successful_inert_redemption = (
                value["http_status"] == 200
                and value["body"].get("status") == "success"
                and value["body"].get("result", {}).get("native_target_execution_enabled") is False
                and value["body"].get("result", {}).get("target_contacted") is False
                and value["body"].get("result", {}).get("provider_contacted") is False
            )
            return value["http_status"], value["body"]
        except (TypeError, ValueError):
            raise NativeSupervisorDenied(
                "Native result could not be independently decoded"
            ) from None


class NativeMCPWorkerSupervisor:
    """Injected 0033 authority + separate supervisor signing identity.

    Explicit qualification API only: no automatic discovery, production
    bootstrap or parent application database access. A deployment must provide
    its own trusted 0033 verifier and pinned native service credentials.
    """

    def __init__(
        self,
        *,
        source_authority: AuthorityCallback,
        trusted_issuer_keys: Mapping[str, bytes],
        supervisor_private_key: Ed25519PrivateKey,
        supervisor_kid: str,
        docker_factory: Optional[Callable[[], Any]] = None,
        command_runner: Optional[Callable[..., subprocess.CompletedProcess[bytes]]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            not callable(source_authority)
            or not callable(clock)
            or not callable(supervisor_private_key.sign)
        ):
            raise NativeSupervisorDenied("Independent trusted supervisor inputs required")
        if not _KID.fullmatch(supervisor_kid):
            raise NativeSupervisorDenied("Supervisor signing key ID invalid")
        if not trusted_issuer_keys or any(
            not _KID.fullmatch(k) or type(v) is not bytes or len(v) != 32
            for k, v in trusted_issuer_keys.items()
        ):
            raise NativeSupervisorDenied("Explicit trusted issuer keys required")
        supervisor_public = supervisor_private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        if supervisor_public in trusted_issuer_keys.values():
            raise NativeSupervisorDenied("Supervisor signing key must differ from issuer identity")
        self.source_authority = source_authority
        self.trusted_issuer_keys = dict(trusted_issuer_keys)
        self.private_key = supervisor_private_key
        self.public_key = supervisor_public
        self.kid = supervisor_kid
        self._docker_factory = docker_factory or self._real_docker
        self._command_runner = command_runner or subprocess.run
        self.clock = clock
        self._claim_lock = asyncio.Lock()
        self._claimed: set[tuple[str, str]] = set()
        self._owned: dict[str, tuple[dict[str, Any], float]] = {}

    @staticmethod
    def _real_docker() -> Any:
        import docker

        client = docker.from_env(timeout=6)
        data = client.info()
        if data.get("OSType") != "linux" or data.get("Architecture") not in ("amd64", "x86_64"):
            raise NativeSupervisorDenied("Only offline Linux amd64 isolation is supported")
        return client

    async def _verify_source(self, binding: SupervisorBinding) -> SourceAuthorityDecision:
        binding.validate()
        if binding.issuer_kid not in self.trusted_issuer_keys:
            raise NativeSupervisorDenied("Issuer is not explicitly trusted")
        try:
            # Store adapter uses a separate independent signed-ROE verifier,
            # current tenant/Task/approval and active lease checks (0033).
            decision = await asyncio.wait_for(self.source_authority(binding), timeout=3)
        except Exception:
            raise NativeSupervisorDenied("Current source authority unavailable") from None
        now = int(self.clock())
        if (
            type(decision) is not SourceAuthorityDecision
            or decision.binding != binding
            or type(decision.authority_version) is not int
            or decision.authority_version < 1
            or type(decision.checked_at) is not int
            or type(decision.expires_at) is not int
            or decision.checked_at > now
            or decision.checked_at < now - 5
            or decision.expires_at <= now
            or decision.expires_at > now + 60
            or any(
                getattr(decision, flag) is not True
                for flag in (
                    "issuer_trusted",
                    "signed_roe_valid",
                    "task_active",
                    "approval_current",
                    "lease_active",
                )
            )
        ):
            raise NativeSupervisorDenied("Source approval, Task or lease is stale or invalid")
        return decision

    @staticmethod
    def _store_token_identity(binding: SupervisorBinding, token: dict[str, Any]) -> dict[str, Any]:
        """Read identity only; 0033 independently validates signed grant bytes."""
        if type(token) is not dict or set(token) != {"claims", "kid", "signature"}:
            raise NativeSupervisorDenied("Complete 0029 signed grant token required")
        claims = token.get("claims")
        if type(claims) is not dict:
            raise NativeSupervisorDenied("Signed grant claim structure unavailable")
        if (
            claims.get("request_id") != binding.request_id
            or claims.get("server_id") != binding.server_id
            or claims.get("engagement_id") != binding.engagement_id
            or claims.get("flow_id") != binding.flow_id
            or claims.get("task_id") != binding.task_id
            or claims.get("subtask_id") != binding.subtask_id
            or claims.get("action_id") != binding.action_id
            or claims.get("lease_id") != binding.lease_id
            or claims.get("authorization_sha256") != binding.authorization_sha256
            or claims.get("manifest_sha256") != binding.manifest_sha256
            or claims.get("tool_name") != "authority_status"
            or claims.get("side_effect_class") != "READ_ONLY"
            or type(claims.get("grant_id")) is not str
            or re.fullmatch(r"ngr-[a-f0-9]{32}", claims["grant_id"]) is None
            or re.fullmatch(r"req-[a-f0-9]{48}", binding.request_id) is None
        ):
            raise NativeSupervisorDenied("Grant does not match signed supervisor source")
        return claims

    def _store_observation(
        self,
        *,
        binding: SupervisorBinding,
        token: dict[str, Any],
        worker_id: str,
        state: str,
        epoch: int,
        revision: int,
        container_id: Optional[str],
        observed: Mapping[str, Any],
        resource_sha256: Optional[str],
        folder_staging_sha256: Optional[str],
        readback_sha256: Optional[str],
    ) -> dict[str, Any]:
        """0033 exact claim set/domain; never use worker self-reported facts."""
        self._store_token_identity(binding, token)
        if (
            type(worker_id) is not str
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,95}", worker_id) is None
        ):
            raise NativeSupervisorDenied("Signed supervisor worker identifier unavailable")
        if state not in {
            "provisioned",
            "running",
            "terminating",
            "terminated",
            "unknown",
            "reaped",
        }:
            raise NativeSupervisorDenied("Invalid 0033 supervisor lifecycle transition")
        if state == "provisioned":
            if epoch != 0 or revision != 0 or container_id is not None:
                raise NativeSupervisorDenied("0033 unallocated provision must be empty")
        elif type(epoch) is not int or epoch < 1 or type(revision) is not int or revision < 1:
            raise NativeSupervisorDenied("Durable 0033 epoch and revision required")
        if container_id is not None and (
            type(container_id) is not str or re.fullmatch(r"[a-f0-9]{64}", container_id) is None
        ):
            raise NativeSupervisorDenied("Independently observed Docker container ID invalid")
        if state in {"running", "terminated"} and container_id is None:
            raise NativeSupervisorDenied("0033 active worker lacks observed container")
        for digest in (resource_sha256, folder_staging_sha256, readback_sha256):
            if digest is not None and (type(digest) is not str or _SHA.fullmatch(digest) is None):
                raise NativeSupervisorDenied("0033 evidence digest unavailable")
        if state == "provisioned" and (
            folder_staging_sha256 is not None or readback_sha256 is not None
        ):
            raise NativeSupervisorDenied("Unallocated worker cannot report staged data")
        evidence = hashlib.sha256(_canonical(dict(observed))).hexdigest()
        claims = {
            "version": 1,
            "grant_id": token["claims"]["grant_id"],
            "request_id": binding.request_id,
            "server_id": binding.server_id,
            "worker_id": worker_id,
            "container_id": container_id,
            "epoch": epoch,
            "expected_revision": revision,
            "state": state,
            "observed_at": int(self.clock()),
            "evidence_sha256": evidence,
            "resource_sha256": resource_sha256,
            "folder_staging_sha256": folder_staging_sha256,
            "readback_sha256": readback_sha256,
        }
        return _sign(self.private_key, _STORE_DOMAIN, claims, self.kid)

    @staticmethod
    async def _record_current_0033(
        callback: StoreRecordCallback,
        token: dict[str, Any],
        observation: dict[str, Any],
        *,
        state: str,
        worker_id: str,
    ) -> dict[str, Any]:
        if not callable(callback):
            raise NativeSupervisorDenied("Live 0033 durable record callback unavailable")
        try:
            recorded = await asyncio.wait_for(callback(token, observation), timeout=6)
        except Exception:
            raise NativeSupervisorDenied("Current durable 0033 outcome unknown") from None
        if (
            type(recorded) is not dict
            or recorded.get("state") != state
            or recorded.get("worker_id") != worker_id
            or type(recorded.get("epoch")) is not int
            or recorded["epoch"] < 1
            or type(recorded.get("revision")) is not int
            or recorded["revision"] < 1
            or recorded.get("supervisor_observed") is not True
        ):
            raise NativeSupervisorDenied("0033 durable readback did not confirm observation")
        return recorded

    async def record_0033_provisioned(
        self,
        binding: SupervisorBinding,
        *,
        token: dict[str, Any],
        worker_id: str,
        record_callback: StoreRecordCallback,
    ) -> dict[str, Any]:
        """Reserve global 0033 epoch BEFORE creating the disposable container.

        record_callback is an injection adapter for the actual
        NativeMCPWorkerSupervisionStore.record(token, observation,
        supervisor_id=<trusted-id>, supervisor_secret=<independent-secret>).
        """
        await self._verify_source(binding)
        claims = self._store_token_identity(binding, token)
        if claims.get("resource_sha256") is not None:
            # This historical pre-allocation helper has not observed a real
            # container. It is valid for inert resource-free diagnostics only.
            # 0033 resource-bound provision must instead go through the
            # daemon-inspected NativeDockerSupervisorProvisioner, which signs
            # AND persists the exact observed container identity up front.
            raise NativeSupervisorDenied(
                "Resource-bound worker requires independent Docker-observed provision"
            )
        observed = {
            "operator_source_verified": True,
            "allocation": "no_container_allocated",
            "source_approval_id": binding.approval_id,
            "lease_id": binding.lease_id,
            "roe_sha256": binding.signed_roe_sha256,
        }
        assertion = self._store_observation(
            binding=binding,
            token=token,
            worker_id=worker_id,
            state="provisioned",
            epoch=0,
            revision=0,
            container_id=None,
            observed=observed,
            resource_sha256=claims.get("resource_sha256"),
            folder_staging_sha256=None,
            readback_sha256=None,
        )
        return await self._record_current_0033(
            record_callback, token, assertion, state="provisioned", worker_id=worker_id
        )

    async def record_0033_transition(
        self,
        session: SupervisorSession,
        *,
        token: dict[str, Any],
        state: str,
        previous: dict[str, Any],
        record_callback: StoreRecordCallback,
        resource_sha256: Optional[str] = None,
        folder_staging_sha256: Optional[str] = None,
        readback_sha256: Optional[str] = None,
    ) -> dict[str, Any]:
        """Sign/store a real Docker observation with global 0033 CAS fencing.

        0033 itself independently verifies original signed grant, task source,
        offer/receipt, epoch, revision and state transition. This method does
        not claim an external target effect or grant scanner capabilities.
        """
        if (
            not isinstance(previous, dict)
            or previous.get("worker_id") != session.worker_id
            or previous.get("grant_id") != token.get("claims", {}).get("grant_id")
            or type(previous.get("epoch")) is not int
            or type(previous.get("revision")) is not int
        ):
            raise NativeSupervisorDenied("Missing exact prior durable supervisor CAS")
        if state == "running":
            if session._closed or not session._successful_inert_redemption:
                raise NativeSupervisorDenied("Worker has not redeemed one inert grant")
            await self._verify_source(session.binding)
            evidence = await session.observe()
            if not evidence["private_stage_mount_verified"]:
                raise NativeSupervisorDenied("Running worker isolation not confirmed")
        elif state in {"terminating", "terminated", "reaped", "unknown"}:
            # Must still record cleanup after revocation; do not require an
            # active lease for a terminal or recovery observation.
            if not session._closed and state in {"terminated", "reaped"}:
                raise NativeSupervisorDenied("Worker still active; cleanup not witnessed")
            if session._closed and session.final_statement is None:
                raise NativeSupervisorDenied("Signed independent cleanup missing")
            evidence = (
                session.final_statement["claims"] if session._closed else await session.observe()
            )
        else:
            raise NativeSupervisorDenied("Unsupported 0033 lifecycle state")
        observation = self._store_observation(
            binding=session.binding,
            token=token,
            worker_id=session.worker_id,
            state=state,
            epoch=previous["epoch"],
            revision=previous["revision"],
            container_id=session.container_id,
            observed=evidence,
            resource_sha256=resource_sha256,
            folder_staging_sha256=folder_staging_sha256,
            readback_sha256=readback_sha256,
        )
        recorded = await self._record_current_0033(
            record_callback,
            token,
            observation,
            state=state,
            worker_id=session.worker_id,
        )
        if (
            recorded["epoch"] != previous["epoch"]
            or recorded["revision"] != previous["revision"] + 1
        ):
            raise NativeSupervisorDenied("0033 epoch or revision changed during CAS")
        session.store_record = recorded
        return recorded

    def _validate_environment(
        self, binding: SupervisorBinding, native_env: Mapping[str, str]
    ) -> dict[str, str]:
        if (
            type(native_env) is not dict
            or set(native_env) - _ALLOW_ENV
            or not _REQUIRED_ENV.issubset(native_env)
        ):
            raise NativeSupervisorDenied("Incomplete or unexpected native process configuration")
        if any(type(v) is not str for v in native_env.values()):
            raise NativeSupervisorDenied("Non-string native process environment")
        safe = dict(native_env)
        safe["OSOP_RECON_MCP_LOCAL_PORT"] = "8082"
        if safe["OSOP_NATIVE_MCP_STAGE_ROOT"] != _STAGE:
            raise NativeSupervisorDenied("Native stage must use dedicated root")
        try:
            url = urlsplit(safe["OSOP_NATIVE_MCP_REDEEM_URL"])
            local_port = url.port
        except ValueError:
            raise NativeSupervisorDenied("Invalid pinned local HTTPS endpoint") from None
        if (
            url.scheme != "https"
            or url.hostname != "127.0.0.1"
            or url.path != "/native-grants/redeem"
            or url.username is not None
            or url.query
            or url.fragment
            or local_port is None
            or not 1024 <= local_port <= 65535
        ):
            raise NativeSupervisorDenied("Only pinned local HTTPS redemption is permitted")
        if "-----BEGIN CERTIFICATE-----" not in safe["OSOP_NATIVE_MCP_REDEEM_ROOT_PEM"]:
            raise NativeSupervisorDenied("Pinned root missing")
        try:
            keys = json.loads(safe["OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON"])
            secrets = json.loads(safe["OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON"])
            expected_key = (
                base64.urlsafe_b64encode(self.trusted_issuer_keys[binding.issuer_kid])
                .decode("ascii")
                .rstrip("=")
            )
            if (
                type(keys) is not dict
                or set(keys) != {binding.issuer_kid}
                or keys[binding.issuer_kid] != expected_key
                or type(secrets) is not dict
                or set(secrets) != {"recon-mcp"}
                or type(secrets["recon-mcp"]) is not str
                or not 20 <= len(secrets["recon-mcp"]) <= 512
            ):
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise NativeSupervisorDenied("Native trust does not match independent issuer") from None
        if sum(len(k) + len(v) for k, v in safe.items()) > 75000:
            raise NativeSupervisorDenied("Native configuration exceeds bound")
        # This separately provisioned worker receives ONLY the PUBLIC verifier
        # of the actual external supervisor. Absence retains legacy inert
        # tests but cannot enter the new resource-bound supervisor admission.
        public_trust = safe.get("OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON")
        if public_trust is not None:
            try:

                def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                    result: dict[str, Any] = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError("Duplicate supervisor public trust")
                        result[key] = value
                    return result

                trust = json.loads(public_trust, object_pairs_hook=strict_pairs)
                encoded_public = (
                    base64.urlsafe_b64encode(self.public_key).decode("ascii").rstrip("=")
                )
                if type(trust) is not dict or len(trust) != 1:
                    raise ValueError("Exactly one separate supervisor for isolated Recon")
                principal = next(iter(trust))
                if (
                    type(principal) is not str
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,95}", principal) is None
                ):
                    raise ValueError("Trusted supervisor principal invalid")
                entry = next(iter(trust.values()))
                if (
                    type(entry) is not dict
                    or set(entry) != {"kid", "public_key", "secret_sha256"}
                    or entry["kid"] != self.kid
                    or entry["public_key"] != encoded_public
                    or type(entry["secret_sha256"]) is not str
                    or _SHA.fullmatch(entry["secret_sha256"]) is None
                ):
                    raise ValueError("Supervisor public trust does not match observer")
            except (ValueError, KeyError, TypeError):
                raise NativeSupervisorDenied(
                    "Independent supervisor verifier trust invalid"
                ) from None
        if "OSOP_NATIVE_STAGE_RECEIPT_ED25519_SEED_B64" in safe:
            worker_seed = safe["OSOP_NATIVE_STAGE_RECEIPT_ED25519_SEED_B64"]
            try:
                decoded = base64.urlsafe_b64decode(worker_seed + "=" * (-len(worker_seed) % 4))
                supervisor_seed = self.private_key.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()
                )
            except Exception:
                raise NativeSupervisorDenied("Invalid independent worker signing key") from None
            if (
                len(decoded) != 32
                or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != worker_seed
                or decoded == supervisor_seed
            ):
                raise NativeSupervisorDenied("Supervisor and worker signing keys must be distinct")
        return safe

    @staticmethod
    def _binary_bytes(path: Path, binding: SupervisorBinding) -> bytes:
        with Path(path).resolve(strict=True).open("rb") as stream:
            data = stream.read(_MAX_BINARY + 1)
        if (
            not 1024 <= len(data) <= _MAX_BINARY
            or data[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", data, 18)[0] != 62
            or hashlib.sha256(data).hexdigest() != binding.binary_sha256
        ):
            raise NativeSupervisorDenied("Untrusted or mismatched Linux native binary")
        return data

    async def _exec(
        self, container: str, args: list[str], data: Optional[bytes], timeout: int
    ) -> bytes:
        def call() -> bytes:
            try:
                proc = self._command_runner(
                    ["docker", "exec", "-i", "--user", "65534:65534", container, *args],
                    input=data,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    check=True,
                )
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                raise NativeSupervisorDenied("Native Docker operation failed (redacted)") from None
            if len(proc.stdout) > 65536:
                raise NativeSupervisorDenied("Native Docker output exceeded bound")
            return proc.stdout

        return await asyncio.wait_for(asyncio.to_thread(call), timeout=timeout + 3)

    @staticmethod
    def _container_policy(container: Any, network: Any, owner: str) -> dict[str, Any]:
        container.reload()
        network.reload()
        facts = container.attrs
        host = facts["HostConfig"]
        config = facts["Config"]
        links = facts["NetworkSettings"]["Networks"]
        mounts = host.get("Tmpfs") or {}
        stage = set(mounts.get(_STAGE, "").split(","))
        executable = set(mounts.get("/qual", "").split(","))
        if not (
            (network.attrs.get("Labels") or {}).get(_LABEL) == owner
            and network.attrs.get("Internal") is True
            and network.attrs.get("Driver") == "bridge"
            and set(links) == {network.name}
            and config.get("User") == "65534:65534"
            and (config.get("Labels") or {}).get(_LABEL) == owner
            and host.get("ReadonlyRootfs") is True
            and host.get("Privileged") is False
            and set(host.get("CapDrop") or []) == {"ALL"}
            and "no-new-privileges:true" in (host.get("SecurityOpt") or [])
            and host.get("PidsLimit") == 64
            and 0 < host.get("Memory", 0) <= 192 * 1024 * 1024
            and 0 < host.get("MemorySwap", 0) <= 192 * 1024 * 1024
            and 0 < host.get("NanoCpus", 0) <= 500_000_000
            and not host.get("Binds")
            and not host.get("PortBindings")
            and not host.get("Mounts")
            and not facts.get("Mounts")
            and {"rw", "noexec", "nodev", "nosuid", "mode=0700", "uid=65534", "gid=65534"} <= stage
            and {"rw", "exec", "nodev", "nosuid", "mode=0700", "uid=65534", "gid=65534"}
            <= executable
        ):
            raise NativeSupervisorDenied("Actual Docker isolation policy does not match")
        return {
            "container_id": container.id,
            "network_id": network.id,
            "network_internal": True,
            "read_only_root": True,
            "nonroot_uid": 65534,
            "caps_dropped": True,
            "no_host_mounts": True,
            "no_published_ports": True,
            "no_external_network": True,
        }

    async def _observe(self, session: SupervisorSession) -> dict[str, Any]:
        state = self._owned.get(session.owner)
        if state is None or state[0]["claims"]["container_id"] != session.container_id:
            raise NativeSupervisorDenied("Owned supervisor runtime unavailable")
        client = self._docker_factory()
        try:
            container = await asyncio.to_thread(client.containers.get, session.container_id)
            network = await asyncio.to_thread(client.networks.get, session.network_id)
            policy = await asyncio.to_thread(
                self._container_policy, container, network, session.owner
            )
            raw = await self._exec(container.name, ["python3", "-c", _INSPECT_STAGE], None, 5)
            details = json.loads(raw)
            mount = details.get("mount") or {}
            if not (
                details.get("directory") is True
                and details.get("uid") == 65534
                and details.get("gid") == 65534
                and details.get("mode") == 0o700
                and mount.get("type") == "tmpfs"
                and {"noexec", "nosuid", "nodev"} <= set(mount.get("options", []))
            ):
                raise NativeSupervisorDenied("Independent private stage mount evidence invalid")
            observed = {
                **policy,
                "private_stage_mount_verified": True,
                "stage_empty": details.get("entries") == [],
                "observed_at": int(self.clock()),
            }
            session.stage_observation = observed
            return observed
        except NativeSupervisorDenied:
            raise
        except Exception:
            raise NativeSupervisorDenied("Independent Docker observation unavailable") from None
        finally:
            if hasattr(client, "close"):
                client.close()

    def _signed_ownership(self, owner: str, container: Any, network: Any) -> dict[str, Any]:
        return _sign(
            self.private_key,
            _OWNERSHIP_DOMAIN,
            {
                "version": 1,
                "owner": owner,
                "container_id": container.id,
                "network_id": network.id,
                "created_at": int(self.clock()),
            },
            self.kid,
        )

    @staticmethod
    def _owned_remove(client: Any, resource_id: str, owner: str, *, network: bool) -> None:
        target = client.networks if network else client.containers
        try:
            obj = target.get(resource_id)
        except Exception as exc:
            if exc.__class__.__name__ == "NotFound":
                return
            raise
        obj.reload()
        labels = (
            obj.attrs.get("Labels") if network else obj.attrs.get("Config", {}).get("Labels")
        ) or {}
        if labels.get(_LABEL) != owner:
            raise NativeSupervisorDenied("Resource ownership mismatch; deletion blocked")
        if network:
            if obj.containers:
                raise NativeSupervisorDenied("Unknown container attached to owned network")
            obj.remove()
        else:
            obj.remove(force=True, v=True)
        try:
            target.get(resource_id)
        except Exception as exc:
            if exc.__class__.__name__ == "NotFound":
                return
            raise
        raise NativeSupervisorDenied("Owned resource removal not independently confirmed")

    async def _cleanup(self, client: Any, owner: str, container_id: str, network_id: str) -> None:
        # Hard-kill owned process even when ordinary cooperative stop fails.
        try:
            if container_id:
                await asyncio.wait_for(
                    asyncio.to_thread(
                        self._owned_remove, client, container_id, owner, network=False
                    ),
                    timeout=7,
                )
        finally:
            if network_id:
                await asyncio.wait_for(
                    asyncio.to_thread(self._owned_remove, client, network_id, owner, network=True),
                    timeout=7,
                )

    @asynccontextmanager
    async def provision(
        self,
        binding: SupervisorBinding,
        *,
        linux_binary: Path,
        native_env: dict[str, str],
        worker_id: Optional[str] = None,
    ) -> AsyncIterator[SupervisorSession]:
        """One approved native process; consumes request/lease even on failure."""
        await self._verify_source(binding)  # ALWAYS before Docker/client access.
        environment = self._validate_environment(binding, native_env)
        binary = await asyncio.to_thread(self._binary_bytes, linux_binary, binding)
        claim = (binding.request_id, binding.lease_id)
        async with self._claim_lock:
            if claim in self._claimed:
                raise NativeSupervisorDenied("Supervisor Task lease already consumed")
            self._claimed.add(claim)
        owner = "osop-native-sup-" + uuid.uuid4().hex
        container = network = client = session = None
        clean = False
        final_stage_ok = False
        try:
            client = await asyncio.to_thread(self._docker_factory)
            image_id = await asyncio.to_thread(lambda: client.images.get(_IMAGE).id)
            network = await asyncio.to_thread(
                client.networks.create,
                owner + "-private",
                driver="bridge",
                internal=True,
                attachable=False,
                labels={_LABEL: owner},
                check_duplicate=True,
            )
            container = await asyncio.to_thread(
                client.containers.run,
                image_id,
                ["python3", "-c", "import time;time.sleep(300)"],
                name=owner + "-recon",
                detach=True,
                network=network.name,
                environment=environment,
                user="65534:65534",
                privileged=False,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                pids_limit=64,
                mem_limit="192m",
                memswap_limit="192m",
                nano_cpus=500_000_000,
                read_only=True,
                volumes={},
                ports={},
                tmpfs={
                    _STAGE: "rw,noexec,nosuid,nodev,size=8m,mode=0700,uid=65534,gid=65534",
                    "/qual": "rw,exec,nosuid,nodev,size=36m,mode=0700,uid=65534,gid=65534",
                    "/tmp": "rw,noexec,nosuid,nodev,size=4m,mode=1777",
                },
                labels={_LABEL: owner},
                auto_remove=False,
            )
            statement = self._signed_ownership(owner, container, network)
            self._owned[owner] = (statement, self.clock())
            session = SupervisorSession(binding, owner, container.id, network.id, statement, self)
            session.worker_id = worker_id or ("worker-" + uuid.uuid4().hex)
            session._public_supervisor_trust_ready = bool(
                environment.get("OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON")
            )
            if session._public_supervisor_trust_ready:
                session._public_supervisor_id = next(
                    iter(json.loads(environment["OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON"]))
                )
            self._container_policy(container, network, owner)
            await session.observe()
            if session.stage_observation is None or not session.stage_observation["stage_empty"]:
                raise NativeSupervisorDenied("New native private staging root is not empty")
            await self._exec(
                container.name,
                ["sh", "-c", "umask 077; cat >/qual/recon-mcp && chmod 500 /qual/recon-mcp"],
                binary,
                20,
            )
            # Native Go process starts only once, remains loopback in sandbox.
            await self._exec_detached(container.name)
            yield session
        finally:
            try:
                if session is not None and session.stage_observation is not None:
                    try:
                        final_observation = await session.observe()
                        final_stage_ok = final_observation.get("stage_empty") is True
                    except Exception:
                        # Never let independent observation failure prevent a
                        # hard kill. No cleanup attestation can be issued.
                        final_stage_ok = False
                if client is not None and (container is not None or network is not None):
                    await self._cleanup(
                        client,
                        owner,
                        container.id if container is not None else "",
                        network.id if network is not None else "",
                    )
                    clean = True
            finally:
                if session is not None:
                    session._closed = True
                    if clean and final_stage_ok and session.stage_observation is not None:
                        session.final_statement = _sign(
                            self.private_key,
                            _DOMAIN,
                            {
                                "version": 1,
                                "server_id": "recon-mcp",
                                "tool_name": "authority_status",
                                "binding": asdict(binding),
                                "observations": session.stage_observation,
                                "container_id": session.container_id,
                                "network_id": session.network_id,
                                "cleanup_verified": True,
                                "observed_at": int(self.clock()),
                                "target_contacted": False,
                                "provider_contacted": False,
                                "scanner_invoked": False,
                            },
                            self.kid,
                        )
                if clean:
                    self._owned.pop(owner, None)
                if client is not None and hasattr(client, "close"):
                    client.close()
            if session is not None and session.stage_observation is not None and not final_stage_ok:
                raise NativeSupervisorDenied(
                    "Final private staging cleanup was not independently observed"
                )

    async def _exec_detached(self, name: str) -> None:
        def start() -> None:
            try:
                self._command_runner(
                    [
                        "docker",
                        "exec",
                        "-d",
                        "--user",
                        "65534:65534",
                        name,
                        "sh",
                        "-c",
                        "exec /qual/recon-mcp >/tmp/native.log 2>&1",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=True,
                    timeout=7,
                )
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                raise NativeSupervisorDenied("Native Go launch failed (redacted)") from None

        await asyncio.wait_for(asyncio.to_thread(start), timeout=9)

    async def reap_orphans(self, *, older_than_seconds: int = 60, limit: int = 8) -> int:
        """Bounded ONLY previously tracked and cryptographically owned resources.

        The 0033 adapter may persist the signed ownership statement and later
        rehydrate it with adopt_ownership; no broad Docker-label sweep occurs.
        """
        if type(limit) is not int or not 1 <= limit <= 8 or older_than_seconds < 1:
            raise ValueError("Bounded orphan reap arguments required")
        count = 0
        for owner, (proof, created) in list(self._owned.items()):
            if count >= limit:
                break
            if self.clock() - created < older_than_seconds:
                continue
            if not verify_supervisor_statement(proof, public_key=self.public_key, ownership=True):
                raise NativeSupervisorDenied("Invalid signed owned-resource ledger")
            claims = proof["claims"]
            if claims["owner"] != owner:
                raise NativeSupervisorDenied("Orphan ownership source mismatch")
            client = self._docker_factory()
            try:
                await self._cleanup(client, owner, claims["container_id"], claims["network_id"])
                self._owned.pop(owner, None)
                count += 1
            finally:
                if hasattr(client, "close"):
                    client.close()
        return count

    def adopt_ownership(self, ownership_statement: dict[str, Any]) -> None:
        """Optional durable 0033 recovery of precisely named signed resources."""
        if not verify_supervisor_statement(
            ownership_statement, public_key=self.public_key, ownership=True
        ):
            raise NativeSupervisorDenied("Untrusted orphan ownership statement")
        claims = ownership_statement["claims"]
        owner = claims.get("owner")
        if (
            type(owner) is not str
            or not owner.startswith("osop-native-sup-")
            or not _ID.fullmatch(owner)
            or claims.get("version") != 1
            or any(
                type(claims.get(k)) is not str or not claims[k]
                for k in ("container_id", "network_id")
            )
            or type(claims.get("created_at")) is not int
        ):
            raise NativeSupervisorDenied("Unbounded or malformed owned resource identity")
        self._owned[owner] = (ownership_statement, float(claims["created_at"]))
