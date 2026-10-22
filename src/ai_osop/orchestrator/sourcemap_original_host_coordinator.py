"""Privileged host-side SourceMap issuance -> provision -> native proof handoff.

One *new* 0035 preflight is requested over the pinned central HTTPS channel,
exactly once. The existing DB-backed host provisioner verifies that committed
0035 record against the current signed Flow/Task/ROE, original reviewed 0013
BYTEA and reviewer/lease before staging the original .map and atomic signed
proof sidecar. Native host-stage-v1 reads that SAME proof and rechecks current
source status without issuing another 0035.

This is a host supervisor component, not an MCP tool or general-purpose API.
Its private Ed25519 host signing key is independently enrolled in a protected
local file, never accepted in a request or shared with the native process.
The native namespace must be *separately* observed and signed by an enrolled
mount observer; a caller's mount path, flag or self-report has no authority.
The current NativeMCPWorkerSupervisor provisions Recon/Go only and does not
produce the required SourceMap mount attestation. No Docker mounting is done.

No retry is permitted after the durable local issuance attempt reservation.
Central commit / lost HTTPS ACK and downstream failure remain UNKNOWN.

The optional coordinate_first_use() is ordered differently: independently
authenticated current ORIGINAL 0027/ROE bootstrap witness first, then a
durable local 0035 one-shot reservation and a single central HTTPS issuance,
then separately signed current 0035 STATUS and actual supervisor/mount proof.
The signed STATUS authority is a separate, registered central HTTPS route,
with its own pinned TLS channel and host-only service bearer. The SourceMap
specific current DB/0033/PID supervisor service is not yet wired: its
protected host-only acquisition seam denies explicitly; no caller-supplied
PID/boolean or unsigned callback can stage original bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.orchestrator.sourcemap_original_stage import (
    PROVISION_DOMAIN,
    SOURCE_DOMAIN,
    OriginalSourceMapHostStage,
    _canonical,
    _exclusive,
    _open_root,
    _roots,
    _safe_directory,
    _signed_claims,
    _SOURCE_FIELDS,
    verify_original_stage_proofs,
)
from ai_osop.orchestrator.sourcemap_native_mount_observer import (
    IndependentSourceMapNativeMountObserver,
    MOUNT_DOMAIN,
    MOUNT_FIELDS,
    verify_supervisor_source,
)

_REQUEST_FIELDS = frozenset(
    (
        "request_id",
        "engagement_id",
        "task_id",
        "server_id",
        "tool_name",
        "artifact_sha256",
    )
)
_MOUNT_FIELDS = MOUNT_FIELDS
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_REQUEST = re.compile(r"req-[a-f0-9]{48}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")


class SourceMapHostCoordinationDenied(ValueError):
    """Untrusted or ambiguous original SourceMap host handoff remains UNKNOWN."""


def _deny() -> None:
    raise SourceMapHostCoordinationDenied("SourceMap original host coordination denied or UNKNOWN")


def _safe_request(raw: Any) -> dict[str, str]:
    if (
        type(raw) is not dict
        or set(raw) != _REQUEST_FIELDS
        or any(type(value) is not str for value in raw.values())
        or _REQUEST.fullmatch(raw["request_id"]) is None
        or _SHA.fullmatch(raw["artifact_sha256"]) is None
        or not raw["engagement_id"].startswith("eng-")
        or not raw["task_id"].startswith("task-")
        or any(_IDENTITY.fullmatch(raw[field]) is None for field in ("engagement_id", "task_id"))
        or raw["server_id"] != "source-map-mcp"
        or raw["tool_name"] != "inspect_local_original_sourcemap"
    ):
        _deny()
    return dict(raw)


def _secure_ancestor(path: Path) -> None:
    """Reject mutable ancestors and symlink/reparse segments before key/CA IO."""
    if not path.is_absolute():
        _deny()
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            if not stat.S_ISDIR(info.st_mode):
                _deny()
            if os.name == "posix" and info.st_mode & 0o022:
                if not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                    _deny()
            if os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                _deny()
    except OSError as exc:
        raise SourceMapHostCoordinationDenied("Host signer/CA parent untrusted") from exc


def _host_signer(host: OriginalSourceMapHostStage) -> tuple[str, Ed25519PrivateKey]:
    """Load a host-only signer; its key must match *separately enrolled* roots."""
    if os.name != "posix":
        _deny()
    kid = os.getenv("OSOP_SOURCEMAP_HOST_STAGE_SIGNING_KID", "")
    raw_name = os.getenv("OSOP_SOURCEMAP_HOST_STAGE_SIGNING_KEY_FILE", "")
    if _KID.fullmatch(kid) is None or not 1 <= len(raw_name) <= 1024:
        _deny()
    path = Path(raw_name)
    if path.name in ("", ".", "..") or not path.is_absolute():
        _deny()
    _secure_ancestor(path.parent)
    # The key cannot live under the staged native-visible original directory.
    if path == host._root or host._root in path.parents:
        _deny()
    if kid not in host._provision_roots:
        _deny()
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != 32
            or before.st_uid != os.getuid()
            or before.st_mode & 0o077
        ):
            _deny()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            key = stream.read(33)
            after = os.fstat(stream.fileno())
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(key) != 32
        ):
            _deny()
        private = Ed25519PrivateKey.from_private_bytes(key)
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if not hmac.compare_digest(public, host._provision_roots[kid]):
            _deny()
        if public in host._source_roots.values():
            _deny()
        return kid, private
    except (OSError, ValueError, TypeError) as exc:
        raise SourceMapHostCoordinationDenied("Protected host signer unavailable") from exc


def _source_channel() -> tuple[str, str, str]:
    """Existing 0035 source router, pinned CA and dedicated service bearer."""
    url = os.getenv("OSOP_SOURCEMAP_SOURCE_URL", "")
    ca_raw = os.getenv("OSOP_SOURCEMAP_SOURCE_CA_BUNDLE", "")
    service = os.getenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", "")
    native_token = os.getenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", "")
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.path != "/native-sourcemap/source-preflight"
            or parsed.hostname is None
            or _DOMAIN.fullmatch(parsed.hostname.lower()) is None
            or parsed.hostname.lower() in ("localhost", "127.0.0.1")
            or parsed.port not in (None, 443)
            or parsed.netloc != parsed.hostname
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
            or not 32 <= len(service) <= 512
            or any(not 33 <= ord(ch) <= 126 for ch in service)
            or (native_token and hmac.compare_digest(service, native_token))
        ):
            _deny()
        ca = Path(ca_raw)
        if not ca.is_absolute():
            _deny()
        _secure_ancestor(ca.parent)
        before = ca.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 100 <= before.st_size <= 131072
            # A sticky trusted ancestor (e.g. /tmp) does not make a CA
            # *file* written by another UID an enrolled host trust root.
            or (os.name == "posix" and (before.st_uid != os.getuid() or before.st_mode & 0o022))
        ):
            _deny()
        fd = os.open(ca, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            contents = stream.read(131073)
            after = os.fstat(stream.fileno())
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or b"-----BEGIN CERTIFICATE-----" not in contents
        ):
            _deny()
        return url, str(ca), service
    except (ValueError, OSError, UnicodeError, TypeError) as exc:
        raise SourceMapHostCoordinationDenied("Pinned central source channel unavailable") from exc


def _status_channel() -> tuple[str, str, str]:
    """Pinned independent central 0035 STATUS channel, never an issuer call.

    The central router POST /native-sourcemap/status-preflight accepts ONLY
    OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN. The native tool token and 0035
    source issuance bearer cannot be reused. The status signer remains on the
    central service; this host validates its Ed25519 public root only.
    """
    url = os.getenv("OSOP_SOURCEMAP_STATUS_URL", "")
    ca_raw = os.getenv("OSOP_SOURCEMAP_STATUS_CA_BUNDLE", "")
    token = os.getenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", "")
    try:
        source_url, _source_ca, source_token = _source_channel()
        native_token = os.getenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", "")
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.path != "/native-sourcemap/status-preflight"
            or parsed.hostname is None
            or _DOMAIN.fullmatch(parsed.hostname.lower()) is None
            or parsed.hostname.lower() in ("localhost", "127.0.0.1")
            or parsed.port not in (None, 443)
            or parsed.netloc != parsed.hostname
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
            or url == source_url
            or not 32 <= len(token) <= 512
            or any(not 33 <= ord(ch) <= 126 for ch in token)
            or hmac.compare_digest(token, source_token)
            or (native_token and hmac.compare_digest(token, native_token))
        ):
            _deny()
        ca = Path(ca_raw)
        if not ca.is_absolute():
            _deny()
        _secure_ancestor(ca.parent)
        before = ca.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 100 <= before.st_size <= 131072
            or (os.name == "posix" and (before.st_uid != os.getuid() or before.st_mode & 0o022))
        ):
            _deny()
        fd = os.open(ca, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            contents = stream.read(131073)
            after = os.fstat(stream.fileno())
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or b"-----BEGIN CERTIFICATE-----" not in contents
        ):
            _deny()
        return url, str(ca), token
    except (ValueError, OSError, UnicodeError, TypeError) as exc:
        raise SourceMapHostCoordinationDenied(
            "Pinned independent SourceMap STATUS channel unavailable"
        ) from exc


def _native_mount_ready(
    proof: Any,
    host: OriginalSourceMapHostStage,
    roots: Mapping[str, bytes],
    supervisor_proof: Any,
    supervisor_roots: Mapping[str, bytes],
    request: Mapping[str, str],
) -> dict[str, Any]:
    """Require distinct, fresh mount-namespace observer signed evidence.

    The observer must independently inspect the native process' actual
    *read-only* filesystem view and bind its stat identity to the host source
    directory. This function verifies the signed observation, not a mount
    configured by the Action caller.
    """
    if (
        type(proof) is not dict
        or set(proof) != {"claims", "kid", "signature"}
        or type(proof["claims"]) is not dict
        or set(proof["claims"]) != _MOUNT_FIELDS
        or type(proof["kid"]) is not str
        or proof["kid"] not in roots
    ):
        _deny()
    claims = proof["claims"]
    now = int(time.time())
    if (
        type(claims["version"]) is not int
        or claims["version"] != 1
        or claims["server_id"] != "source-map-mcp"
        or claims["mode"] != "host-stage-v1"
        or claims["native_stage_root"] != "/run/osop-sourcemap/sourcemap-originals"
        or type(claims["read_only"]) is not bool
        or claims["read_only"] is not True
        or type(claims["observer_id"]) is not str
        or _IDENTITY.fullmatch(claims["observer_id"]) is None
        or type(claims["root_dev"]) is not int
        or type(claims["root_ino"]) is not int
        or claims["root_dev"] <= 0
        or claims["root_ino"] <= 0
        or type(claims["pid"]) is not int
        or type(claims["pid_start_ticks"]) is not int
        or type(claims["mount_namespace_inode"]) is not int
        or type(claims["native_fsuid"]) is not int
        or claims["native_fsuid"] <= 0
        or type(claims["epoch"]) is not int
        or any(claims[k] <= 0 for k in ("pid", "pid_start_ticks", "mount_namespace_inode", "epoch"))
        or type(claims["container_id"]) is not str
        or _SHA.fullmatch(claims["container_id"]) is None
        or type(claims["supervisor_source_sha256"]) is not str
        or _SHA.fullmatch(claims["supervisor_source_sha256"]) is None
        or type(claims["action_id"]) is not str
        or re.fullmatch(r"action-[a-f0-9]{32}", claims["action_id"]) is None
        or type(claims["lease_id"]) is not str
        or _IDENTITY.fullmatch(claims["lease_id"]) is None
        or type(claims["authorization_sha256"]) is not str
        or _SHA.fullmatch(claims["authorization_sha256"]) is None
        or type(claims["artifact_sha256"]) is not str
        or _SHA.fullmatch(claims["artifact_sha256"]) is None
        or type(claims["manifest_sha256"]) is not str
        or _SHA.fullmatch(claims["manifest_sha256"]) is None
        or any(claims[k] != request[k] for k in ("request_id", "engagement_id", "task_id"))
        or claims["artifact_sha256"] != request["artifact_sha256"]
        or type(claims["issued_at"]) is not int
        or type(claims["expires_at"]) is not int
        or not now - 5 <= claims["issued_at"] <= now + 2
        or not now < claims["expires_at"] <= claims["issued_at"] + 10
        or type(proof["signature"]) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]{86}", proof["signature"]) is None
    ):
        _deny()
    try:
        source, source_digest = verify_supervisor_source(
            supervisor_proof,
            supervisor_roots,
            "/run/osop-sourcemap/sourcemap-originals",
        )
    except Exception as exc:
        raise SourceMapHostCoordinationDenied(
            "Current signed SourceMap supervisor source unavailable"
        ) from exc
    if (
        not hmac.compare_digest(source_digest, claims["supervisor_source_sha256"])
        or any(
            source[key] != claims[key]
            for key in (
                "pid",
                "pid_start_ticks",
                "mount_namespace_inode",
                "native_fsuid",
                "container_id",
                "epoch",
                "request_id",
                "engagement_id",
                "task_id",
                "flow_id",
                "subtask_id",
                "owner_id",
                "approval_id",
                "action_id",
                "lease_id",
                "artifact_sha256",
                "manifest_sha256",
                "authorization_sha256",
            )
        )
        or claims["expires_at"] > source["expires_at"]
    ):
        _deny()
    try:
        signature = base64.urlsafe_b64decode(proof["signature"] + "==")
        if (
            len(signature) != 64
            or base64.urlsafe_b64encode(signature).decode().rstrip("=") != proof["signature"]
        ):
            _deny()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(roots[proof["kid"]]).verify(
            signature, MOUNT_DOMAIN + _canonical(claims)
        )
        observed = _safe_directory(host._root)
        if (observed.st_dev, observed.st_ino) != (
            claims["root_dev"],
            claims["root_ino"],
        ):
            _deny()
    except (ValueError, TypeError, binascii.Error) as exc:
        raise SourceMapHostCoordinationDenied("Signed native mount readiness unavailable") from exc
    except Exception as exc:
        raise SourceMapHostCoordinationDenied("Signed native mount readiness unavailable") from exc
    return claims


def _reserve_issuer_once(host: OriginalSourceMapHostStage, request_id: str) -> None:
    """Durably consume before HTTPS; ambiguous ACK has no local replay."""
    fd = _open_root(host._root)
    try:
        name = ".issuer-" + hashlib.sha256(request_id.encode("ascii")).hexdigest() + ".used"
        _exclusive(fd, name, b"issued-once\n", 0o400)
        os.fsync(fd)
    except OSError as exc:
        raise SourceMapHostCoordinationDenied("SourceMap source issuance UNKNOWN") from exc
    finally:
        os.close(fd)


class OriginalSourceMapHostCoordinator:
    """Compose the actual issuer endpoint, host BYTEA provisioner, native sidecar.

    Construct only in a protected host service with real FlowMCPActionStore.
    NativeMCPWorkerSupervisor's Recon/Go identity is NOT accepted as a
    SourceMap native mount observer. Missing separate mount proof denies before
    0035 issuance, and no Docker operation or mount is made here.
    """

    def __init__(self, actions: Any) -> None:
        from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
        from ai_osop.orchestrator.sourcemap_original_readonly_provisioner import (
            OriginalSourceMapReadonlyProvisioner,
        )

        if type(actions) is not FlowMCPActionStore:
            _deny()
        self._actions = actions
        self._provisioner = OriginalSourceMapReadonlyProvisioner(actions)
        self._host = self._provisioner._host
        self._signer = _host_signer(self._host)
        self._channel = _source_channel()
        self._observer_roots = _roots(
            "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON"
        )
        self._observer = IndependentSourceMapNativeMountObserver(self._host)
        if set(self._observer_roots.values()) & set(self._host._source_roots.values()) or set(
            self._observer_roots.values()
        ) & set(self._host._provision_roots.values()):
            _deny()

    async def _trusted_status_after_0035(
        self,
        *,
        original_action_request: dict[str, str],
        source_proof: dict[str, Any],
        pinned_status_channel: tuple[str, str, str],
    ) -> dict[str, Any]:
        """Fetch authenticated current read-only 0035 STATUS from central.

        Protected HOST bearer, pinned CA, no env proxies, retries, redirects or
        reissuance. Accept only a fresh independently signed STATUS matching
        the exact immutable signed original 0035 preflight and request. A lost
        ACK or revoked current authorization stays UNKNOWN: the already-fsynced
        local 0035 issuance tombstone forbids any second issue.
        """
        from ai_osop.orchestrator.sourcemap_supervisor_source_issuer import (
            SOURCE_STATUS_DOMAIN,
            _STATUS_FIELDS,
            _verified,
        )

        request = _safe_request(original_action_request)
        if (
            type(pinned_status_channel) is not tuple
            or len(pinned_status_channel) != 3
            or _status_channel() != pinned_status_channel
        ):
            _deny()
        source, _ = _signed_claims(
            source_proof,
            self._host._source_roots,
            SOURCE_DOMAIN,
            _SOURCE_FIELDS,
            int(time.time()),
        )
        if any(source[key] != value for key, value in request.items()):
            _deny()
        endpoint, ca, service = pinned_status_channel
        try:
            async with httpx.AsyncClient(
                verify=ca,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(3.0, connect=2.0),
            ) as client:
                response = await client.post(
                    endpoint,
                    json=request,
                    headers={
                        "Authorization": "Bearer " + service,
                        "Cache-Control": "no-store",
                    },
                    follow_redirects=False,
                )
                if response.status_code != 200 or not 0 < len(response.content) <= 4096:
                    _deny()

                def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                    values: dict[str, Any] = {}
                    for key, value in pairs:
                        if key in values:
                            _deny()
                        values[key] = value
                    return values

                status_proof = json.loads(
                    response.content,
                    object_pairs_hook=_unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
                )
            status, _ = _verified(
                status_proof,
                self._host._source_roots,
                SOURCE_STATUS_DOMAIN,
                _STATUS_FIELDS,
            )
            now = int(time.time())
            if (
                type(status["issued_at"]) is not int
                or type(status["expires_at"]) is not int
                or not now - 2 <= status["issued_at"] <= now + 1
                or not now < status["expires_at"] <= status["issued_at"] + 5
                or status["issued_at"] < source["issued_at"]
                # A separately fresh STATUS can never extend its underlying
                # one-use original 0035 preflight validity window.
                or status["expires_at"] > source["expires_at"]
                or type(status["status_id"]) is not str
                or re.fullmatch(r"nss-[a-f0-9]{32}", status["status_id"]) is None
                or any(
                    status[key] != value
                    for key, value in source.items()
                    if key not in ("issued_at", "expires_at")
                )
                or _status_channel() != pinned_status_channel
            ):
                _deny()
            return status_proof
        except SourceMapHostCoordinationDenied:
            raise
        except Exception as exc:
            raise SourceMapHostCoordinationDenied(
                "Independent SourceMap current STATUS unavailable or UNKNOWN"
            ) from exc

    async def _trusted_supervisor_after_status(
        self,
        *,
        source_proof: dict[str, Any],
        source_status: dict[str, Any],
    ) -> dict[str, Any]:
        """Reserved host-only production seam; never a caller callback.

        A future separately authenticated producer must independently obtain
        actual 0033 signed running lifecycle, current PostgreSQL CAS-fenced DB
        status and Linux process witness, and invoke the real enrolled
        SourceMapSupervisorSourceIssuer. Neither an original 0035 source proof
        nor a signed STATUS can attest a PID or a mount. That trusted producer
        does not currently exist in the original runtime.
        """
        _deny()

    async def coordinate_first_use(
        self,
        *,
        original_action_request: dict[str, str],
    ) -> dict[str, Any]:
        """Optional first-use TWO-PHASE host-only path, fail-closed by default.

        Unlike legacy coordinate(), neither first-use supervisor proofs nor
        native-side issuer credentials are supplied as arguments. The original
        0027 source authority is queried inside its existing read-only-effects
        transaction BEFORE 0035. Once this method durably reserves issuance,
        *any* status, signature, kernel observation, staging or network error
        is permanently UNKNOWN and cannot cause another source POST.

        Missing authenticated post-0035 supervisor source is an intentional
        production blocker; a test-only override does not certify a runtime.
        """
        from ai_osop.memory.sourcemap_original_bootstrap_witness import (
            SourceMapOriginalBootstrapWitnessStore,
            TRUST_ENV,
            _trusted_roots,
            verify_bootstrap_witness,
        )
        from ai_osop.orchestrator.sourcemap_supervisor_source_issuer import (
            SOURCE_STATUS_DOMAIN,
            _STATUS_FIELDS,
            _verified,
        )

        request = _safe_request(original_action_request)
        if (
            type(self) is not OriginalSourceMapHostCoordinator
            or type(self._observer) is not IndependentSourceMapNativeMountObserver
            or not hasattr(self, "_actions")
        ):
            _deny()
        try:
            enrolled_bootstrap = _trusted_roots(os.getenv(TRUST_ENV, ""))
            if any(
                set(enrolled_bootstrap.values()) & set(group.values())
                for group in (
                    self._host._source_roots,
                    self._host._provision_roots,
                    self._observer_roots,
                    self._observer._source_roots,
                )
            ):
                _deny()
            bootstrap_proof = await SourceMapOriginalBootstrapWitnessStore(self._actions).attest(
                request
            )
            bootstrap = verify_bootstrap_witness(bootstrap_proof, enrolled_bootstrap, request)
            # All private/enrolled keys and pinned host TLS channel are checked
            # BEFORE the durable attempt record. No bearer reaches native.
            kid, private = _host_signer(self._host)
            endpoint, ca, service = _source_channel()
            pinned_status_channel = _status_channel()
            if (
                kid,
                private.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ),
            ) != (
                self._signer[0],
                self._signer[1]
                .public_key()
                .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            ) or (
                endpoint,
                ca,
                service,
            ) != self._channel:
                _deny()
            if int(time.time()) >= bootstrap["expires_at"]:
                _deny()
        except SourceMapHostCoordinationDenied:
            raise
        except Exception as exc:
            raise SourceMapHostCoordinationDenied(
                "Independent original bootstrap authorization unavailable"
            ) from exc

        _reserve_issuer_once(self._host, request["request_id"])
        try:
            async with httpx.AsyncClient(
                verify=ca,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(3.0, connect=2.0),
            ) as client:
                response = await client.post(
                    endpoint,
                    json=request,
                    headers={
                        "Authorization": "Bearer " + service,
                        "Cache-Control": "no-store",
                    },
                    follow_redirects=False,
                )
                if response.status_code != 200 or not 0 < len(response.content) <= 4096:
                    _deny()

                def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                    values: dict[str, Any] = {}
                    for key, value in pairs:
                        if key in values:
                            _deny()
                        values[key] = value
                    return values

                source_proof = json.loads(
                    response.content,
                    object_pairs_hook=_unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
                )
            source, signature_hash = _signed_claims(
                source_proof,
                self._host._source_roots,
                SOURCE_DOMAIN,
                _SOURCE_FIELDS,
                int(time.time()),
            )
            if (
                any(source[k] != request[k] for k in request)
                or any(
                    source[k] != bootstrap[k]
                    for k in source
                    if k in bootstrap and k not in ("issued_at", "expires_at")
                )
                or int(time.time()) >= source["expires_at"]
            ):
                _deny()
            # A signed current STATUS arrives from the separately protected
            # central ROUTER, never its private issuer signing key locally.
            source_status = await self._trusted_status_after_0035(
                original_action_request=request,
                source_proof=source_proof,
                pinned_status_channel=pinned_status_channel,
            )
            status, _ = _verified(
                source_status,
                self._host._source_roots,
                SOURCE_STATUS_DOMAIN,
                _STATUS_FIELDS,
            )
            now = int(time.time())
            if (
                type(status["issued_at"]) is not int
                or type(status["expires_at"]) is not int
                or not now - 2 <= status["issued_at"] <= now + 1
                or not now < status["expires_at"] <= status["issued_at"] + 5
                or status["expires_at"] > source["expires_at"]
                # Current STATUS is deliberately signed with a NEW 5s
                # issued/expires interval, not the original 0035 10s window.
                # Only immutable 0035 provenance/authority must match.
                or any(
                    status[key] != value
                    for key, value in source.items()
                    if key not in ("issued_at", "expires_at")
                )
            ):
                _deny()

            # This host-only method is a trusted interface, NOT a caller-
            # supplied function argument or process-PID/permission assertion.
            # Default runtime implementation denies until an independently
            # provisioned, authentic SourceMap 0033 DB/process producer exists.
            supervisor_proof = await self._trusted_supervisor_after_status(
                source_proof=source_proof,
                source_status=source_status,
            )
            # Cryptographically verify the producer AGAIN and perform actual
            # kernel native readonly mount observation, never trust its label.
            supervisor_claims, _ = verify_supervisor_source(
                supervisor_proof,
                self._observer._source_roots,
                "/run/osop-sourcemap/sourcemap-originals",
            )
            if any(
                supervisor_claims[key] != source[key]
                for key in (
                    "request_id",
                    "engagement_id",
                    "task_id",
                    "flow_id",
                    "subtask_id",
                    "action_id",
                    "owner_id",
                    "approval_id",
                    "lease_id",
                    "artifact_sha256",
                    "manifest_sha256",
                    "authorization_sha256",
                )
            ):
                _deny()
            signed_mount = self._observer.observe(supervisor_proof)
            mount = _native_mount_ready(
                signed_mount,
                self._host,
                self._observer_roots,
                supervisor_proof,
                self._observer._source_roots,
                request,
            )
            if any(
                mount[key] != source[key]
                for key in (
                    "action_id",
                    "flow_id",
                    "subtask_id",
                    "owner_id",
                    "approval_id",
                    "lease_id",
                    "manifest_sha256",
                    "authorization_sha256",
                )
            ):
                _deny()
            if int(time.time()) >= min(source["expires_at"], status["expires_at"]):
                _deny()
            issued_at = int(time.time())
            provision_claims = {
                **source,
                "stage_id": "sms-" + secrets.token_hex(16),
                "source_proof_sha256": signature_hash,
                "issued_at": issued_at,
                "expires_at": min(source["expires_at"], status["expires_at"], issued_at + 10),
            }
            stage_proof = {
                "claims": provision_claims,
                "kid": kid,
                "signature": base64.urlsafe_b64encode(
                    private.sign(PROVISION_DOMAIN + _canonical(provision_claims))
                )
                .decode("ascii")
                .rstrip("="),
            }
            verify_original_stage_proofs(
                source_proof,
                stage_proof,
                self._host._source_roots,
                self._host._provision_roots,
            )
            # Native kernel mount/credentials must remain independent and
            # current immediately before committing host-side original bytes.
            again = self._observer.observe(supervisor_proof)
            _native_mount_ready(
                again,
                self._host,
                self._observer_roots,
                supervisor_proof,
                self._observer._source_roots,
                request,
            )
            if int(time.time()) >= min(source["expires_at"], status["expires_at"]):
                _deny()
            await self._provisioner.provision(
                source_proof=source_proof, provision_proof=stage_proof
            )
            return {
                "request_id": source["request_id"],
                "action_id": source["action_id"],
                "artifact_sha256": source["artifact_sha256"],
                "original_host_stage_complete": True,
                "native_execution_authorized": False,
            }
        except SourceMapHostCoordinationDenied:
            raise
        except Exception as exc:
            raise SourceMapHostCoordinationDenied(
                "Original SourceMap two-phase issuance or staging UNKNOWN"
            ) from exc

    async def coordinate(
        self,
        *,
        original_action_request: dict[str, str],
        signed_supervisor_source: dict[str, Any],
    ) -> dict[str, Any]:
        """One HTTPS issuer call, one trusted DB-backed stage; no execution."""
        request = _safe_request(original_action_request)
        if type(self._observer) is not IndependentSourceMapNativeMountObserver:
            _deny()
        try:
            initial_mount = self._observer.observe(signed_supervisor_source)
        except Exception as exc:
            raise SourceMapHostCoordinationDenied(
                "Independent Linux SourceMap mount observation unavailable"
            ) from exc
        mount_claims = _native_mount_ready(
            initial_mount,
            self._host,
            self._observer_roots,
            signed_supervisor_source,
            self._observer._source_roots,
            request,
        )
        # Validate enrollment, CA and key BEFORE reserving the one-use request.
        kid, private = _host_signer(self._host)
        endpoint, ca, service = _source_channel()
        if (
            kid,
            private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        ) != (
            self._signer[0],
            self._signer[1]
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        ) or (
            endpoint,
            ca,
            service,
        ) != self._channel:
            _deny()
        _reserve_issuer_once(self._host, request["request_id"])
        try:
            async with httpx.AsyncClient(
                verify=ca,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(3.0, connect=2.0),
            ) as client:
                response = await client.post(
                    endpoint,
                    json=request,
                    headers={
                        "Authorization": "Bearer " + service,
                        "Cache-Control": "no-store",
                    },
                    follow_redirects=False,
                )
                if response.status_code != 200 or not 0 < len(response.content) <= 4096:
                    _deny()

                # Reject JSON duplicate keys by comparing their occurrence.
                def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                    result: dict[str, Any] = {}
                    for key, value in pairs:
                        if key in result:
                            _deny()
                        result[key] = value
                    return result

                source_proof = json.loads(
                    response.content,
                    object_pairs_hook=_unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
                )
            source, signature_hash = _signed_claims(
                source_proof,
                self._host._source_roots,
                SOURCE_DOMAIN,
                _SOURCE_FIELDS,
                int(time.time()),
            )
            if any(source[k] != v for k, v in request.items()):
                _deny()
            if any(
                source[k] != mount_claims[k]
                for k in (
                    "flow_id",
                    "subtask_id",
                    "owner_id",
                    "approval_id",
                    "action_id",
                    "lease_id",
                    "artifact_sha256",
                    "manifest_sha256",
                    "authorization_sha256",
                )
            ):
                _deny()
            now = int(time.time())
            if now < source["issued_at"] or now >= source["expires_at"]:
                _deny()
            provision_claims = {
                **source,
                "stage_id": "sms-" + secrets.token_hex(16),
                "source_proof_sha256": signature_hash,
                "issued_at": now,
                "expires_at": min(source["expires_at"], now + 10),
            }
            stage_proof = {
                "claims": provision_claims,
                "kid": kid,
                "signature": base64.urlsafe_b64encode(
                    private.sign(PROVISION_DOMAIN + _canonical(provision_claims))
                )
                .decode("ascii")
                .rstrip("="),
            }
            verify_original_stage_proofs(
                source_proof,
                stage_proof,
                self._host._source_roots,
                self._host._provision_roots,
            )
            current_mount = self._observer.observe(signed_supervisor_source)
            _native_mount_ready(
                current_mount,
                self._host,
                self._observer_roots,
                signed_supervisor_source,
                self._observer._source_roots,
                request,
            )
            # This production store rechecks committed 0035 and live reviewed
            # bytes; it publishes the exact host/native signed proof sidecar.
            await self._provisioner.provision(
                source_proof=source_proof, provision_proof=stage_proof
            )
            if int(time.time()) >= source["expires_at"]:
                _deny()
            return {
                "request_id": source["request_id"],
                "action_id": source["action_id"],
                "artifact_sha256": source["artifact_sha256"],
                "original_host_stage_complete": True,
                "native_execution_authorized": False,
            }
        except SourceMapHostCoordinationDenied:
            raise
        except Exception as exc:
            # Includes central commit lost ACK. Never resend this request.
            raise SourceMapHostCoordinationDenied(
                "Original SourceMap host issuance or staging UNKNOWN"
            ) from exc
