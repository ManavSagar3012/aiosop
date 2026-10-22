"""Host-only kernel-backed SourceMap process witness; no Docker or DB writes.

This is the missing PROCESS_DOMAIN producer for the SourceMap supervisor-source
issuer. A historical signed 0033 observation is NOT a current process binding:
its schema has no PID, mount namespace, filesystem UID or live cgroup identity.

To construct a witness, independently enrolled identities MUST provide:

* a signed 0033 *running* lifecycle observation;
* a fresh, separately signed read-only 0033/Flow/ROE/Task/reviewer/lease
  CURRENT_DB_DOMAIN readback bound to that lifecycle hash and current revision;
* a distinct, authenticated live SourceMap-supervisor PID binding with a
  single kernel PID/start/namespace/fsuid/cgroup/command fingerprint.

The last two independent producers do not currently exist in this repository;
existing Docker supervisor is limited to Recon/Go. With no real signed PID
binding, this class fails closed before opening /proc. The source PID cannot
be passed separately, obtained from an arbitrary Docker/worker statement,
or inferred from a process list. A synthetic test signer does not constitute
a production-qualified source.

The host itself performs bounded read-only /proc checks under pidfd, rejects
PID reuse, host mount namespace, missing container identity in cgroup, changed
process command/UID, and signs only the exact 15-field PROCESS_DOMAIN result.
On uncertain signing or lost ACK, a durable one-shot journal prevents reissue.
No app database, Docker, target, network or mount operation occurs here.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.orchestrator.sourcemap_original_stage import (
    _canonical,
    _exclusive,
    _open_root,
    _roots,
    _safe_directory,
)
from ai_osop.orchestrator.sourcemap_supervisor_source_issuer import (
    CURRENT_DB_DOMAIN,
    LEDGER_DOMAIN,
    PROCESS_DOMAIN,
    _DB_FIELDS,
    _LEDGER_FIELDS,
    _PROCESS_FIELDS,
    _verified,
)

PID_BINDING_DOMAIN = b"ai-osop/sourcemap-native-supervisor-observed-pid/v1\x00"
_PID_BINDING_FIELDS = frozenset(
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
        "cmdline_sha256",
        "native_stage_root",
        "observed_at",
        "expires_at",
    }
)
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_NS = re.compile(r"mnt:\[([1-9][0-9]*)\]\Z")
_CGROUP_ID = re.compile(r"[a-f0-9]{64}")
_ROOT = "/run/osop-sourcemap/sourcemap-originals"


class SourceMapProcessWitnessDenied(ValueError):
    """Genuine current SourceMap native process evidence unavailable or UNKNOWN."""


def _deny() -> None:
    raise SourceMapProcessWitnessDenied(
        "Current independently supervised SourceMap process unavailable or UNKNOWN"
    )


def _proc_read(fd: int, leaf: str, max_bytes: int) -> bytes:
    """Read-only procfs access relative to the pinned process directory."""
    try:
        stream = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            data = os.read(stream, max_bytes + 1)
        finally:
            os.close(stream)
        if not 0 < len(data) <= max_bytes:
            _deny()
        return data
    except OSError as exc:
        raise SourceMapProcessWitnessDenied("Live Linux process evidence unavailable") from exc


def _start_ticks(raw: bytes, pid: int) -> int:
    try:
        line = raw.decode("ascii")
        ending = line.rfind(") ")
        if not line.startswith(f"{pid} (") or ending <= 0:
            _deny()
        rest = line[ending + 2 :].split()
        if (
            len(rest) < 20
            or rest[0] not in ("R", "S")
            or not rest[19].isdecimal()
            or int(rest[19]) <= 0
        ):
            _deny()
        return int(rest[19])
    except (UnicodeError, ValueError) as exc:
        raise SourceMapProcessWitnessDenied("Linux process start unavailable") from exc


def _fsuid(raw: bytes) -> int:
    try:
        for line in raw.decode("ascii").splitlines():
            if line.startswith("Uid:"):
                values = line[4:].split()
                if len(values) != 4 or any(not x.isdecimal() for x in values):
                    _deny()
                uid = int(values[3])
                if uid <= 0:
                    _deny()
                return uid
    except (UnicodeError, ValueError) as exc:
        raise SourceMapProcessWitnessDenied("Linux process identity unavailable") from exc
    _deny()


def _cgroup_container_bound(raw: bytes, cid: str) -> bool:
    """Require exact 64hex container component from actual Linux cgroup paths."""
    if type(cid) is not str or _SHA.fullmatch(cid) is None:
        return False
    try:
        data = raw.decode("ascii")
    except UnicodeError:
        return False
    for line in data.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3 or not parts[0].isdecimal() or not parts[2].startswith("/"):
            return False
        segments = parts[2].split("/")
        # Docker cgroup v1/v2 (including systemd scopes) only. Namespaces
        # masking the container name are NOT independent proof of ownership.
        for segment in segments:
            if segment in (cid, f"docker-{cid}.scope", f"cri-containerd-{cid}.scope"):
                return True
    return False


def _live_kernel_identity(binding: Mapping[str, Any]) -> dict[str, Any]:
    """Observe the exact SIGNED PID, never enumerate or accept a bare PID arg."""
    if (
        sys.platform != "linux"
        or os.name != "posix"
        or not hasattr(os, "pidfd_open")
        or type(binding) is not dict
        or type(binding.get("pid")) is not int
        or not 1 <= binding["pid"] <= 4194304
    ):
        _deny()
    pid = binding["pid"]
    pidfd = -1
    procfd = -1
    try:
        pidfd = os.pidfd_open(pid, 0)
        procfd = os.open(
            f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        observed: dict[str, Any] = {}
        for attempt in range(2):
            ticks = _start_ticks(_proc_read(procfd, "stat", 8192), pid)
            uid = _fsuid(_proc_read(procfd, "status", 16384))
            cgroup = _proc_read(procfd, "cgroup", 16384)
            command = _proc_read(procfd, "cmdline", 8192)
            if not command.endswith(b"\x00") or command == b"\x00":
                _deny()
            namespace = os.readlink(f"/proc/{pid}/ns/mnt")
            match = _NS.fullmatch(namespace)
            if match is None:
                _deny()
            ns_inode = int(match[1])
            if ns_inode == os.stat("/proc/self/ns/mnt").st_ino:
                _deny()
            if not _cgroup_container_bound(cgroup, binding["container_id"]):
                _deny()
            values = {
                "pid": pid,
                "pid_start_ticks": ticks,
                "native_fsuid": uid,
                "mount_namespace_inode": ns_inode,
                "cgroup_sha256": hashlib.sha256(cgroup).hexdigest(),
                "cmdline_sha256": hashlib.sha256(command).hexdigest(),
            }
            if any(
                type(binding.get(field)) is not type(value)
                or not hmac.compare_digest(str(binding[field]), str(value))
                for field, value in values.items()
            ):
                _deny()
            if attempt and observed != values:
                _deny()
            observed = values
        return observed
    except SourceMapProcessWitnessDenied:
        raise
    except Exception as exc:
        raise SourceMapProcessWitnessDenied(
            "Linux PID/container observation could not be independently verified"
        ) from exc
    finally:
        if procfd >= 0:
            os.close(procfd)
        if pidfd >= 0:
            os.close(pidfd)


def _load_host_signer(
    roots: Mapping[str, bytes], others: tuple[Mapping[str, bytes], ...], stage: Path
) -> tuple[str, Ed25519PrivateKey]:
    if sys.platform != "linux" or os.name != "posix":
        _deny()
    kid = os.getenv("OSOP_SOURCEMAP_SUPERVISOR_PROCESS_SIGNING_KID", "")
    location = os.getenv("OSOP_SOURCEMAP_SUPERVISOR_PROCESS_SIGNING_KEY_FILE", "")
    if _KID.fullmatch(kid) is None or kid not in roots or not 1 <= len(location) <= 1024:
        _deny()
    path = Path(location)
    if not path.is_absolute() or path == stage or stage in path.parents:
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
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            seed = handle.read(33)
            after = os.fstat(handle.fileno())

        def attr(value: os.stat_result) -> tuple[int, int, int, int]:
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)

        if len(seed) != 32 or attr(before) != attr(opened) or attr(after) != attr(opened):
            _deny()
        key = Ed25519PrivateKey.from_private_bytes(seed)
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if not hmac.compare_digest(public, roots[kid]) or any(
            public in group.values() for group in others
        ):
            _deny()
        return kid, key
    except SourceMapProcessWitnessDenied:
        raise
    except Exception as exc:
        raise SourceMapProcessWitnessDenied("Protected process signer unavailable") from exc


class IndependentSourceMapSupervisorProcessWitness:
    """Trusted signed supervisor-PID + 0033 DB witness -> kernel check -> signature."""

    def __init__(self) -> None:
        try:
            self._process_roots = _roots(
                "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON"
            )
            self._ledger_roots = _roots("OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON")
            self._db_roots = _roots("OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_TRUSTED_PUBLIC_KEYS_JSON")
            self._binding_roots = _roots(
                "OSOP_SOURCEMAP_SUPERVISOR_PID_BINDING_TRUSTED_PUBLIC_KEYS_JSON"
            )
        except Exception as exc:
            raise SourceMapProcessWitnessDenied("Separate producer enrollment unavailable") from exc
        groups = (self._process_roots, self._ledger_roots, self._db_roots, self._binding_roots)
        if any(
            set(groups[i].values()) & set(groups[j].values())
            for i in range(len(groups))
            for j in range(i + 1, len(groups))
        ):
            _deny()
        self._root = Path(os.getenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", ""))
        if not self._root.is_absolute() or self._root.name != "sourcemap-originals":
            _deny()
        try:
            _safe_directory(self._root)
        except Exception as exc:
            raise SourceMapProcessWitnessDenied("Protected process source journal missing") from exc
        self._kid, self._signer = _load_host_signer(self._process_roots, groups[1:], self._root)

    def issue(
        self,
        *,
        supervisor_observation: dict[str, Any],
        current_db_witness: dict[str, Any],
        signed_supervisor_pid_binding: dict[str, Any],
    ) -> dict[str, Any]:
        """Issue once only from authentic, current, independently signed inputs."""
        try:
            ledger, digest = _verified(
                supervisor_observation, self._ledger_roots, LEDGER_DOMAIN, _LEDGER_FIELDS
            )
            current, _ = _verified(
                current_db_witness, self._db_roots, CURRENT_DB_DOMAIN, _DB_FIELDS
            )
            bound, _ = _verified(
                signed_supervisor_pid_binding,
                self._binding_roots,
                PID_BINDING_DOMAIN,
                _PID_BINDING_FIELDS,
            )
        except Exception as exc:
            raise SourceMapProcessWitnessDenied("Independent signed input missing") from exc
        now = int(time.time())
        if (
            any(
                type(item.get("version")) is not int or item["version"] != 1
                for item in (ledger, current, bound)
            )
            or ledger.get("server_id") != "source-map-mcp"
            or ledger.get("state") != "running"
            or current.get("status") != "running"
            or any(
                type(item.get("observed_at")) is not int
                or not now - 2 <= item["observed_at"] <= now + 1
                for item in (ledger, current, bound)
            )
            or any(
                type(item.get("expires_at")) is not int
                or not now < item["expires_at"] <= item["observed_at"] + 5
                for item in (current, bound)
            )
            or any(
                type(ledger.get(field)) is not int or ledger[field] <= 0
                for field in ("epoch", "expected_revision")
            )
            or any(
                type(current.get(field)) is not int or current[field] <= 0
                for field in ("epoch", "revision")
            )
            or any(
                type(current.get(k)) is not bool or current[k] is not True
                for k in (
                    "source_current",
                    "lease_active",
                    "approval_current",
                    "reviewer_current",
                    "roe_current",
                )
            )
            or type(ledger.get("container_id")) is not str
            or _SHA.fullmatch(ledger["container_id"]) is None
            or type(ledger.get("grant_id")) is not str
            or re.fullmatch(r"ngr-[a-f0-9]{32}", ledger["grant_id"]) is None
            or bound.get("native_stage_root") != _ROOT
            or any(
                type(bound.get(field)) is not int or bound[field] <= 0
                for field in (
                    "epoch",
                    "pid",
                    "pid_start_ticks",
                    "mount_namespace_inode",
                    "native_fsuid",
                )
            )
            or bound["pid"] > 4194304
            or any(
                type(bound.get(field)) is not str or _SHA.fullmatch(bound[field]) is None
                for field in (
                    "container_id",
                    "supervisor_observation_sha256",
                    "cgroup_sha256",
                    "cmdline_sha256",
                )
            )
            or bound["supervisor_observation_sha256"] != digest
            or current.get("supervisor_observation_sha256") != digest
            or any(
                bound.get(field) != ledger.get(field)
                for field in (
                    "grant_id",
                    "request_id",
                    "worker_id",
                    "container_id",
                    "epoch",
                )
            )
            or any(
                current.get(field) != ledger.get(field)
                for field in ("grant_id", "worker_id", "container_id", "epoch")
            )
            # The 0033 signed observation carries the CAS *expected* revision.
            # Its committed running transition advances the durable row once;
            # equal is pre-commit/stale, and larger skips an unverified event.
            or current["revision"] != ledger["expected_revision"] + 1
            or current.get("request_id") != ledger.get("request_id")
            or any(
                type(current.get(field)) is not str or _SHA.fullmatch(current[field]) is None
                for field in (
                    "authorization_sha256",
                    "signed_roe_sha256",
                    "artifact_sha256",
                    "manifest_sha256",
                    "status_proof_sha256",
                )
            )
            or ledger.get("resource_sha256") != current.get("manifest_sha256")
        ):
            _deny()
        _live_kernel_identity(bound)
        expires = min(now + 5, current["expires_at"], bound["expires_at"])
        if expires <= int(time.time()):
            _deny()
        claims = {
            "version": 1,
            **{
                field: bound[field]
                for field in (
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
                )
            },
            "observed_at": now,
            "expires_at": expires,
        }
        if set(claims) != _PROCESS_FIELDS:
            _deny()
        try:
            folder = _open_root(self._root)
            try:
                for field in ("request_id", "grant_id"):
                    leaf = (
                        ".supervisor-process-"
                        + field
                        + "-"
                        + hashlib.sha256(claims[field].encode("ascii")).hexdigest()
                        + ".used"
                    )
                    _exclusive(folder, leaf, b"consumed\n", 0o400)
                    os.fsync(folder)
            finally:
                os.close(folder)
            if int(time.time()) >= expires:
                _deny()
            signature = self._signer.sign(PROCESS_DOMAIN + _canonical(claims))
            return {
                "claims": claims,
                "kid": self._kid,
                "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
            }
        except SourceMapProcessWitnessDenied:
            raise
        except Exception as exc:
            raise SourceMapProcessWitnessDenied(
                "SourceMap process witness delivery UNKNOWN; do not retry"
            ) from exc
