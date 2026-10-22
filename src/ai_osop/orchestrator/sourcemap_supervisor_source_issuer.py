"""Fail-closed host-only SourceMap supervisor-source issuer.

The *existing* 0033 ledger signs a worker lifecycle observation, but it has
no PID, mount namespace, fsuid or signed current readback; the existing 0033
supervisor is Recon/Go-only. Therefore a mere signed 0033 historical receipt
must NEVER be upgraded to native SourceMap authorization.

This narrow adapter can sign the exact observer SUPERVISOR_FIELDS only if:
  * an enrolled 0033 supervisor signed the original running observation;
  * central SourceMap 0035 signed a fresh, non-consuming CURRENT status proof;
  * an independently enrolled current-DB authority signed current Action,
    Flow/ROE/Task/reviewer/approval/lease and exact latest 0033 revision;
  * the enrolled native supervisor signed actual kernel PID/process identity
    and bound it to that exact 0033 signed observation/epoch/container.

The latter two signed producers do NOT currently exist in production. No
caller-provided PID, booleans, paths, unsigned DB rows or fake currentness is
ever accepted. Missing enrolled producers, file-based private signer, or any
one proof fails closed. Test-generated proofs are NOT production witnesses.

Issuance writes a durable, exclusive request/Action tombstone before signing.
An uncertain outcome is never retried. This module does not fetch DB rows,
call Docker, mount files, contact targets, or issue a second 0035 preflight.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ai_osop.orchestrator.sourcemap_native_mount_observer import (
    SUPERVISOR_FIELDS,
    SUPERVISOR_SOURCE_DOMAIN,
    verify_supervisor_source,
)
from ai_osop.orchestrator.sourcemap_original_stage import (
    _canonical,
    _exclusive,
    _open_root,
    _roots,
    _safe_directory,
)

SOURCE_STATUS_DOMAIN = b"ai-osop/sourcemap-original-status/v1\x00"
LEDGER_DOMAIN = b"ai-osop/native-worker-supervisor/v1\x00"
CURRENT_DB_DOMAIN = b"ai-osop/sourcemap-native-supervisor-current-db/v1\x00"
PROCESS_DOMAIN = b"ai-osop/sourcemap-native-supervisor-process/v1\x00"

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_PROCESS_FIELDS = frozenset(
    {
        "version",
        "grant_id",
        "request_id",
        "worker_id",
        "container_id",
        "epoch",
        "supervisor_observation_sha256",
        "pid",
        "pid_start_ticks",
        "mount_namespace_inode",
        "native_fsuid",
        "cgroup_sha256",
        "native_stage_root",
        "observed_at",
        "expires_at",
    }
)
_DB_FIELDS = frozenset(
    {
        "version",
        "grant_id",
        "worker_id",
        "container_id",
        "epoch",
        "revision",
        "supervisor_observation_sha256",
        "status_proof_sha256",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "owner_id",
        "approval_id",
        "action_id",
        "lease_id",
        "artifact_sha256",
        "manifest_sha256",
        "authorization_sha256",
        "signed_roe_sha256",
        "status",
        "source_current",
        "lease_active",
        "approval_current",
        "reviewer_current",
        "roe_current",
        "observed_at",
        "expires_at",
    }
)
_LEDGER_FIELDS = frozenset(
    {
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
)
_STATUS_FIELDS = frozenset(
    {
        "version",
        "preflight_id",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "owner_id",
        "server_id",
        "tool_name",
        "artifact_sha256",
        "manifest_sha256",
        "approval_id",
        "lease_id",
        "authorization_version",
        "authorization_sha256",
        "status_id",
        "issued_at",
        "expires_at",
    }
)
_IDENTITY = (
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "owner_id",
    "approval_id",
    "action_id",
    "lease_id",
    "artifact_sha256",
    "manifest_sha256",
    "authorization_sha256",
)


class SourceMapSupervisorIssuerDenied(ValueError):
    """Trusted SourceMap supervisor current source unavailable or UNKNOWN."""


def _deny() -> None:
    raise SourceMapSupervisorIssuerDenied(
        "Trusted SourceMap supervisor source unavailable or UNKNOWN"
    )


def _verified(
    token: Any, roots: Mapping[str, bytes], domain: bytes, fields: frozenset[str]
) -> tuple[dict[str, Any], str]:
    if (
        type(token) is not dict
        or set(token) != {"claims", "kid", "signature"}
        or type(token["claims"]) is not dict
        or set(token["claims"]) != fields
        or type(token["kid"]) is not str
        or token["kid"] not in roots
        or type(token["signature"]) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]{86}", token["signature"]) is None
    ):
        _deny()
    try:
        sig = base64.urlsafe_b64decode(token["signature"] + "==")
        if (
            len(sig) != 64
            or base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=") != token["signature"]
        ):
            _deny()
        Ed25519PublicKey.from_public_bytes(roots[token["kid"]]).verify(
            sig, domain + _canonical(token["claims"])
        )
        return (
            token["claims"],
            hashlib.sha256(domain + _canonical(token["claims"]) + sig).hexdigest(),
        )
    except Exception as exc:
        raise SourceMapSupervisorIssuerDenied("Independent source signature unavailable") from exc


def _current_time(claims: Mapping[str, Any], now: int, *, max_age: int, lifespan: int) -> None:
    if (
        type(claims.get("observed_at", claims.get("issued_at"))) is not int
        or type(claims.get("expires_at")) is not int
        or not now - max_age <= claims.get("observed_at", claims.get("issued_at")) <= now + 1
        or not now < claims["expires_at"]
        or claims["expires_at"] > claims.get("observed_at", claims.get("issued_at")) + lifespan
    ):
        _deny()


def _private_key(
    roots: Mapping[str, bytes], other_roots: tuple[Mapping[str, bytes], ...]
) -> tuple[str, Ed25519PrivateKey]:
    if sys.platform != "linux" or os.name != "posix":
        _deny()
    kid = os.getenv("OSOP_SOURCEMAP_SUPERVISOR_SOURCE_SIGNING_KID", "")
    value = os.getenv("OSOP_SOURCEMAP_SUPERVISOR_SOURCE_SIGNING_KEY_FILE", "")
    if _KID.fullmatch(kid) is None or kid not in roots or not 1 <= len(value) <= 1024:
        _deny()
    path = Path(value)
    if not path.is_absolute():
        _deny()
    try:
        for parent in path.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode):
                _deny()
            if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                _deny()
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & 0o077
            or before.st_nlink != 1
            or before.st_size != 32
        ):
            _deny()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            seed = stream.read(33)
            after = os.fstat(stream.fileno())
        if (
            len(seed) != 32
            or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_size)
            or (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_size)
        ):
            _deny()
        private = Ed25519PrivateKey.from_private_bytes(seed)
        pub = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if not hmac.compare_digest(pub, roots[kid]):
            _deny()
        if any(pub in group.values() for group in other_roots):
            _deny()
        return kid, private
    except Exception as exc:
        raise SourceMapSupervisorIssuerDenied("Protected host-only issuer key unavailable") from exc


class SourceMapSupervisorSourceIssuer:
    """Issuer composed entirely from separately signed evidence and pinned roots.

    Production prerequisite: an independent read-only PostgreSQL source
    service must sign CURRENT_DB_DOMAIN with a current, 0033 CAS-fenced row
    and current Flow/Task/ROE/reviewer/lease; a real SourceMap supervisor must
    sign PROCESS_DOMAIN after independently inspecting the exact live PID.
    Neither producer is presently wired, so real issuance cannot succeed.
    """

    def __init__(self) -> None:
        try:
            self._issuer_roots = _roots(
                "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON"
            )
            self._ledger_roots = _roots("OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON")
            self._status_roots = _roots("OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
            self._current_db_roots = _roots(
                "OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_TRUSTED_PUBLIC_KEYS_JSON"
            )
            self._process_roots = _roots(
                "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON"
            )
        except Exception as exc:
            raise SourceMapSupervisorIssuerDenied("Independent enrollment unavailable") from exc
        groups = (
            self._issuer_roots,
            self._ledger_roots,
            self._status_roots,
            self._current_db_roots,
            self._process_roots,
        )
        if any(
            set(groups[a].values()) & set(groups[b].values())
            for a in range(len(groups))
            for b in range(a + 1, len(groups))
        ):
            _deny()
        self._kid, self._signer = _private_key(self._issuer_roots, groups[1:])
        self._root = Path(os.getenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", ""))
        if not self._root.is_absolute() or self._root.name != "sourcemap-originals":
            _deny()
        try:
            _safe_directory(self._root)
            private_path = Path(os.environ["OSOP_SOURCEMAP_SUPERVISOR_SOURCE_SIGNING_KEY_FILE"])
            if private_path == self._root or self._root in private_path.parents:
                _deny()
        except Exception as exc:
            raise SourceMapSupervisorIssuerDenied(
                "Unsafe SourceMap supervisor issuer root"
            ) from exc

    def issue(
        self,
        *,
        supervisor_observation: dict[str, Any],
        source_status: dict[str, Any],
        current_db_witness: dict[str, Any],
        live_process_witness: dict[str, Any],
    ) -> dict[str, Any]:
        """No raw PID/booleans accepted; verify all independent signatures first."""
        now = int(time.time())
        ledger, ledger_sha = _verified(
            supervisor_observation, self._ledger_roots, LEDGER_DOMAIN, _LEDGER_FIELDS
        )
        status, status_sha = _verified(
            source_status, self._status_roots, SOURCE_STATUS_DOMAIN, _STATUS_FIELDS
        )
        database, _ = _verified(
            current_db_witness, self._current_db_roots, CURRENT_DB_DOMAIN, _DB_FIELDS
        )
        process, _ = _verified(
            live_process_witness, self._process_roots, PROCESS_DOMAIN, _PROCESS_FIELDS
        )
        if (
            any(
                type(token["version"]) is not int or token["version"] != 1
                for token in (ledger, status, database, process)
            )
            or ledger["server_id"] != "source-map-mcp"
            or ledger["state"] != "running"
            or database["status"] != "running"
            or type(ledger["epoch"]) is not int
            or ledger["epoch"] < 1
            or type(ledger["expected_revision"]) is not int
            or ledger["expected_revision"] < 1
            or type(process["epoch"]) is not int
            or process["epoch"] < 1
            or type(database["epoch"]) is not int
            or database["epoch"] < 1
            or type(database["revision"]) is not int
            or database["revision"] < 1
            or type(ledger["container_id"]) is not str
            or _SHA.fullmatch(ledger["container_id"]) is None
            or type(ledger["grant_id"]) is not str
            or re.fullmatch(r"ngr-[a-f0-9]{32}", ledger["grant_id"]) is None
            or type(status["status_id"]) is not str
            or re.fullmatch(r"nss-[a-f0-9]{32}", status["status_id"]) is None
            or type(status["preflight_id"]) is not str
            or re.fullmatch(r"nsp-[a-f0-9]{32}", status["preflight_id"]) is None
            or status["server_id"] != "source-map-mcp"
            or status["tool_name"] != "inspect_local_original_sourcemap"
            or type(status["issued_at"]) is not int
            or not now - 2 <= status["issued_at"] <= now + 1
            or type(ledger["observed_at"]) is not int
            or not now - 3 <= ledger["observed_at"] <= now + 1
            or any(
                type(item["observed_at"]) is not int
                or not now - 2 <= item["observed_at"] <= now + 1
                for item in (database, process)
            )
        ):
            _deny()
        _current_time(status, now, max_age=2, lifespan=5)
        _current_time(database, now, max_age=2, lifespan=5)
        _current_time(process, now, max_age=2, lifespan=5)
        if (
            any(database[key] != status[key] for key in _IDENTITY)
            or database["status_proof_sha256"] != status_sha
            or database["supervisor_observation_sha256"] != ledger_sha
            or process["supervisor_observation_sha256"] != ledger_sha
            or any(
                database[key] != ledger[key]
                for key in ("grant_id", "worker_id", "container_id", "epoch")
            )
            # 0033's signed transition names the PRIOR CAS revision. A
            # successful original running transition increments the durable
            # supervisor row before appending its immutable event. Requiring
            # equality would reject every authentic running observation.
            or database["revision"] != ledger["expected_revision"] + 1
            or any(
                process[key] != ledger[key]
                for key in ("grant_id", "request_id", "worker_id", "container_id", "epoch")
            )
            or ledger["request_id"] != status["request_id"]
            or ledger["resource_sha256"] != status["manifest_sha256"]
            or any(
                type(database[key]) is not bool or database[key] is not True
                for key in (
                    "source_current",
                    "lease_active",
                    "approval_current",
                    "reviewer_current",
                    "roe_current",
                )
            )
            or type(database["signed_roe_sha256"]) is not str
            or _SHA.fullmatch(database["signed_roe_sha256"]) is None
            or type(process["native_stage_root"]) is not str
            or process["native_stage_root"] != "/run/osop-sourcemap/sourcemap-originals"
            or any(
                type(process[key]) is not int or process[key] <= 0
                for key in ("pid", "pid_start_ticks", "mount_namespace_inode", "native_fsuid")
            )
            or process["pid"] > 4194304
            or type(process["cgroup_sha256"]) is not str
            or _SHA.fullmatch(process["cgroup_sha256"]) is None
            or type(status["authorization_sha256"]) is not str
            or _SHA.fullmatch(status["authorization_sha256"]) is None
            or not 0 < status["authorization_version"]
            or any(status[k] is None for k in _IDENTITY)
        ):
            _deny()

        expires_at = min(
            now + 5, status["expires_at"], database["expires_at"], process["expires_at"]
        )
        if expires_at <= now:
            _deny()
        claims = {
            "version": 1,
            "server_id": "source-map-mcp",
            "tool_name": "inspect_local_original_sourcemap",
            **{field: database[field] for field in _IDENTITY},
            "signed_roe_sha256": database["signed_roe_sha256"],
            **{
                field: process[field]
                for field in (
                    "container_id",
                    "epoch",
                    "pid",
                    "pid_start_ticks",
                    "mount_namespace_inode",
                    "native_fsuid",
                    "cgroup_sha256",
                    "native_stage_root",
                )
            },
            "status": "running",
            "source_current": True,
            "lease_active": True,
            "approval_current": True,
            "issued_at": now,
            "expires_at": expires_at,
        }
        if set(claims) != SUPERVISOR_FIELDS:
            _deny()
        try:
            verify_supervisor_source(
                {
                    "claims": claims,
                    "kid": self._kid,
                    "signature": base64.urlsafe_b64encode(
                        self._signer.sign(SUPERVISOR_SOURCE_DOMAIN + _canonical(claims))
                    )
                    .decode("ascii")
                    .rstrip("="),
                },
                self._issuer_roots,
                "/run/osop-sourcemap/sourcemap-originals",
                now=now,
            )
            fd = _open_root(self._root)
            try:
                for field in ("action_id", "request_id"):
                    leaf = (
                        ".supervisor-source-"
                        + field
                        + "-"
                        + hashlib.sha256(claims[field].encode("ascii")).hexdigest()
                        + ".used"
                    )
                    _exclusive(fd, leaf, b"consumed\n", 0o400)
                    os.fsync(fd)
            finally:
                os.close(fd)
            if int(time.time()) >= expires_at:
                _deny()
            signature = self._signer.sign(SUPERVISOR_SOURCE_DOMAIN + _canonical(claims))
            return {
                "claims": claims,
                "kid": self._kid,
                "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
            }
        except SourceMapSupervisorIssuerDenied:
            raise
        except Exception as exc:
            raise SourceMapSupervisorIssuerDenied(
                "SourceMap supervisor source issuance UNKNOWN; never retry"
            ) from exc
