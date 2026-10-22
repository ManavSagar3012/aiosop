"""Independent Linux /proc SourceMap read-only mount observer.

Requires a freshly signed *supervisor source* binding from an independently
enrolled SourceMap-specific supervisor: exact native PID, container, epoch,
kernel process start tick, mount namespace, cgroup hash, current Action/lease
and signed-ROE source. It is NOT the Recon/Go supervisor's ownership token.
The source signer is separate from the observer signer and 0035 issuer.

No PID, path, flags, or permission may be chosen by an MCP request. The native
mount is inspected twice from /proc, then a host-only owner-protected key signs
the observation. No mounts, Docker, app DB, scanner, or network are invoked.
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
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ai_osop.orchestrator.sourcemap_original_stage import (
    OriginalSourceMapHostStage,
    _canonical,
    _roots,
    _safe_directory,
)

SUPERVISOR_SOURCE_DOMAIN = b"ai-osop/sourcemap-native-supervisor-source/v1\x00"
MOUNT_DOMAIN = b"ai-osop/sourcemap-native-ro-mount-observation/v1\x00"
SUPERVISOR_FIELDS = frozenset(
    {
        "version",
        "server_id",
        "tool_name",
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
        "signed_roe_sha256",
        "container_id",
        "epoch",
        "pid",
        "pid_start_ticks",
        "mount_namespace_inode",
        "native_fsuid",
        "cgroup_sha256",
        "native_stage_root",
        "status",
        "source_current",
        "lease_active",
        "approval_current",
        "issued_at",
        "expires_at",
    }
)
MOUNT_FIELDS = frozenset(
    {
        "version",
        "server_id",
        "mode",
        "native_stage_root",
        "root_dev",
        "root_ino",
        "read_only",
        "observer_id",
        "issued_at",
        "expires_at",
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
        "supervisor_source_sha256",
    }
)
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_ACTION = re.compile(r"action-[a-f0-9]{32}\Z")
_REQUEST = re.compile(r"req-[a-f0-9]{48}\Z")
_MOUNT_NAMESPACE = re.compile(r"mnt:\[([1-9][0-9]*)\]\Z")
_UNESCAPE = re.compile(r"\\([0-7]{3})")
_MAX_PROC = 131072


class SourceMapNativeMountDenied(ValueError):
    """No valid independent native SourceMap mount or current supervisor source."""


def _deny() -> None:
    raise SourceMapNativeMountDenied("Independent SourceMap mount observation unavailable")


def _strict_signature(token: Any, roots: Mapping[str, bytes], domain: bytes) -> bytes:
    if (
        type(token) is not dict
        or set(token) != {"claims", "kid", "signature"}
        or type(token["claims"]) is not dict
        or type(token["kid"]) is not str
        or token["kid"] not in roots
        or type(token["signature"]) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]{86}", token["signature"]) is None
    ):
        _deny()
    try:
        raw = base64.urlsafe_b64decode(token["signature"] + "==")
        if (
            len(raw) != 64
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != token["signature"]
        ):
            _deny()
        Ed25519PublicKey.from_public_bytes(roots[token["kid"]]).verify(
            raw, domain + _canonical(token["claims"])
        )
        return raw
    except Exception as exc:
        raise SourceMapNativeMountDenied("Supervisor SourceMap signature rejected") from exc


def verify_supervisor_source(
    proof: Any,
    roots: Mapping[str, bytes],
    expected_root: str,
    *,
    now: Optional[int] = None,
) -> tuple[dict[str, Any], str]:
    """Read-only cryptographic verification; no caller-declared source truth."""
    if type(proof) is not dict or type(proof.get("claims")) is not dict:
        _deny()
    claims = proof["claims"]
    current = int(time.time()) if now is None else now
    if (
        set(claims) != SUPERVISOR_FIELDS
        or type(current) is not int
        or type(claims["version"]) is not int
        or claims["version"] != 1
        or claims["server_id"] != "source-map-mcp"
        or claims["tool_name"] != "inspect_local_original_sourcemap"
        or claims["native_stage_root"] != expected_root
        or type(claims["request_id"]) is not str
        or _REQUEST.fullmatch(claims["request_id"]) is None
        or type(claims["action_id"]) is not str
        or _ACTION.fullmatch(claims["action_id"]) is None
        or any(
            type(claims[k]) is not str or _IDENTITY.fullmatch(claims[k]) is None
            for k in (
                "engagement_id",
                "task_id",
                "flow_id",
                "subtask_id",
                "owner_id",
                "approval_id",
                "lease_id",
            )
        )
        or not claims["engagement_id"].startswith("eng-")
        or not claims["task_id"].startswith("task-")
        or any(
            type(claims[k]) is not str or _SHA.fullmatch(claims[k]) is None
            for k in (
                "artifact_sha256",
                "manifest_sha256",
                "authorization_sha256",
                "signed_roe_sha256",
                "container_id",
                "cgroup_sha256",
            )
        )
        or any(
            type(claims[k]) is not int or claims[k] <= 0
            for k in ("pid", "epoch", "pid_start_ticks", "mount_namespace_inode")
        )
        or type(claims["native_fsuid"]) is not int
        or claims["native_fsuid"] <= 0
        or claims["pid"] > 4194304
        or claims["status"] != "running"
        or any(
            type(claims[k]) is not bool or claims[k] is not True
            for k in ("source_current", "lease_active", "approval_current")
        )
        or type(claims["issued_at"]) is not int
        or type(claims["expires_at"]) is not int
        or not current - 2 <= claims["issued_at"] <= current + 1
        or not current < claims["expires_at"] <= claims["issued_at"] + 5
    ):
        _deny()
    raw = _strict_signature(proof, roots, SUPERVISOR_SOURCE_DOMAIN)
    digest = hashlib.sha256(SUPERVISOR_SOURCE_DOMAIN + _canonical(claims) + raw).hexdigest()
    return dict(claims), digest


def _safe_key_parent(path: Path) -> None:
    if not path.is_absolute():
        _deny()
    try:
        for ancestor in (path, *path.parents):
            info = ancestor.lstat()
            if not stat.S_ISDIR(info.st_mode):
                _deny()
            if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                _deny()
    except OSError as exc:
        raise SourceMapNativeMountDenied("Native mount signer parent unavailable") from exc


def _observer_signer(
    host: OriginalSourceMapHostStage, roots: Mapping[str, bytes]
) -> tuple[str, Ed25519PrivateKey]:
    """Signer lives outside native-visible stage and has no caller override."""
    if sys.platform != "linux" or os.name != "posix":
        _deny()
    kid = os.getenv("OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_SIGNING_KID", "")
    file_raw = os.getenv("OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_SIGNING_KEY_FILE", "")
    if _KID.fullmatch(kid) is None or kid not in roots or not 1 <= len(file_raw) <= 1024:
        _deny()
    path = Path(file_raw)
    if not path.is_absolute() or host._root == path or host._root in path.parents:
        _deny()
    _safe_key_parent(path.parent)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size != 32
            or before.st_mode & 0o077
        ):
            _deny()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            data = stream.read(33)
            after = os.fstat(stream.fileno())
        if (
            len(data) != 32
            or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_size)
            or (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_size)
        ):
            _deny()
        private = Ed25519PrivateKey.from_private_bytes(data)
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if not hmac.compare_digest(public, roots[kid]):
            _deny()
        return kid, private
    except (ValueError, TypeError, OSError) as exc:
        raise SourceMapNativeMountDenied("Protected mount observer signer unavailable") from exc


def _proc_text(path: Path, limit: int = _MAX_PROC) -> str:
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if not 0 < len(raw) <= limit or b"\x00" in raw:
            _deny()
        return raw.decode("utf-8", errors="strict")
    except (OSError, ValueError, UnicodeError) as exc:
        raise SourceMapNativeMountDenied("Linux proc observation unavailable") from exc


def _process_start_ticks(raw: str, pid: int) -> int:
    # Parentheses in comm may contain whitespace and closing ')' characters.
    marker = raw.rfind(") ")
    if not raw.startswith(str(pid) + " (") or marker < 0:
        _deny()
    rest = raw[marker + 2 :].split()
    if len(rest) < 20 or not rest[19].isdigit():
        _deny()
    return int(rest[19])


def _process_fsuid(raw: str) -> int:
    for line in raw.splitlines():
        if line.startswith("Uid:"):
            values = line[4:].split()
            if len(values) != 4 or any(not value.isdecimal() for value in values):
                _deny()
            return int(values[3])
    _deny()


def _native_dir_stat(pid: int, absolute: str, native_fsuid: int) -> os.stat_result:
    """Walk native root, explicitly checking DAC search permission.

    O_PATH ignores normal DAC; stat each path component and require owner or
    other search permission. Group-only access is conservatively denied.
    """
    if not absolute.startswith("/") or ".." in absolute.split("/"):
        _deny()
    root_fd = -1
    try:
        root_fd = os.open(f"/proc/{pid}/root", os.O_PATH | os.O_DIRECTORY)
        root_info = os.fstat(root_fd)
        if not (
            (root_info.st_uid == native_fsuid and root_info.st_mode & stat.S_IXUSR)
            or root_info.st_mode & stat.S_IXOTH
        ):
            _deny()
        for piece in absolute.split("/"):
            if not piece:
                continue
            next_fd = os.open(
                piece,
                os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
            checked = os.fstat(next_fd)
            if not (
                stat.S_ISDIR(checked.st_mode)
                and (
                    (checked.st_uid == native_fsuid and checked.st_mode & stat.S_IXUSR)
                    or checked.st_mode & stat.S_IXOTH
                )
            ):
                os.close(next_fd)
                _deny()
            os.close(root_fd)
            root_fd = next_fd
        info = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != native_fsuid
            or info.st_mode & 0o700 != 0o700
            or info.st_mode & 0o077
        ):
            _deny()
        return info
    except OSError as exc:
        raise SourceMapNativeMountDenied("Native root path cannot be verified") from exc
    finally:
        if root_fd >= 0:
            os.close(root_fd)


def _mount_options(info: str, path: str) -> frozenset[str]:
    """Kernel mountinfo VFS options from exact mountpoint, not superblock opts."""
    if len(info) > _MAX_PROC or not path.startswith("/"):
        _deny()
    matches: list[frozenset[str]] = []
    for line in info.splitlines():
        halves = line.split(" - ", 1)
        if len(halves) != 2:
            _deny()
        left = halves[0].split()
        right = halves[1].split()
        if len(left) < 6 or len(right) < 3:
            _deny()
        target = _UNESCAPE.sub(lambda match: chr(int(match[1], 8)), left[4])
        if target == path:
            matches.append(frozenset(left[5].split(",")))
    if len(matches) != 1:
        _deny()
    opts = matches[0]
    if not {"ro", "nosuid", "nodev", "noexec"}.issubset(opts) or "rw" in opts:
        _deny()
    return opts


def _observe_proc(claims: Mapping[str, Any], host: OriginalSourceMapHostStage) -> os.stat_result:
    """Live kernel observation, independently repeated across process identity."""
    if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
        _deny()
    pid = claims["pid"]
    base = Path("/proc") / str(pid)
    try:
        pid_fd = os.pidfd_open(pid, 0)
    except OSError as exc:
        raise SourceMapNativeMountDenied("Native PID unavailable") from exc
    try:
        before = _process_start_ticks(_proc_text(base / "stat", 8192), pid)
        namespace_raw = os.readlink(base / "ns" / "mnt")
        match = _MOUNT_NAMESPACE.fullmatch(namespace_raw)
        if (
            before != claims["pid_start_ticks"]
            or match is None
            or int(match[1]) != claims["mount_namespace_inode"]
            or int(match[1]) == os.stat("/proc/self/ns/mnt").st_ino
        ):
            _deny()
        cgroup = _proc_text(base / "cgroup", 16384)
        fsuid = _process_fsuid(_proc_text(base / "status", 16384))
        if fsuid != claims["native_fsuid"]:
            _deny()
        if not hmac.compare_digest(
            hashlib.sha256(cgroup.encode()).hexdigest(), claims["cgroup_sha256"]
        ):
            _deny()
        _mount_options(_proc_text(base / "mountinfo"), claims["native_stage_root"])
        host_info = _safe_directory(host._root)
        if host_info.st_uid != fsuid or host_info.st_mode & 0o700 != 0o700:
            _deny()
        actual = _native_dir_stat(pid, claims["native_stage_root"], fsuid)
        if (
            actual.st_dev != host_info.st_dev
            or actual.st_ino != host_info.st_ino
            or actual.st_nlink < 1
        ):
            _deny()
        # Race fencing: same live PID/start time, namespace and mounted inode.
        if (
            _process_start_ticks(_proc_text(base / "stat", 8192), pid) != before
            or os.readlink(base / "ns" / "mnt") != namespace_raw
            or hashlib.sha256(_proc_text(base / "cgroup", 16384).encode()).hexdigest()
            != claims["cgroup_sha256"]
            or _process_fsuid(_proc_text(base / "status", 16384)) != fsuid
        ):
            _deny()
        _mount_options(_proc_text(base / "mountinfo"), claims["native_stage_root"])
        again = _native_dir_stat(pid, claims["native_stage_root"], fsuid)
        if (again.st_dev, again.st_ino) != (actual.st_dev, actual.st_ino):
            _deny()
        return host_info
    except OSError as exc:
        raise SourceMapNativeMountDenied("Linux native mount observation UNKNOWN") from exc
    finally:
        os.close(pid_fd)


class IndependentSourceMapNativeMountObserver:
    """Host-owned SourceMap observer for verified supervisor source only."""

    def __init__(self, host: OriginalSourceMapHostStage) -> None:
        if type(host) is not OriginalSourceMapHostStage:
            _deny()
        self._host = host
        expected = os.getenv("OSOP_SOURCEMAP_NATIVE_READONLY_ROOT", "")
        if (
            sys.platform != "linux"
            or os.name != "posix"
            or expected != "/run/osop-sourcemap/sourcemap-originals"
        ):
            _deny()
        self._native_root = expected
        try:
            self._source_roots = _roots(
                "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON"
            )
            self._observer_roots = _roots(
                "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON"
            )
        except Exception as exc:
            raise SourceMapNativeMountDenied(
                "Enrolled independent SourceMap supervisor trust unavailable"
            ) from exc
        if (
            set(self._source_roots.values()) & set(self._observer_roots.values())
            or set(self._source_roots.values()) & set(host._source_roots.values())
            or set(self._source_roots.values()) & set(host._provision_roots.values())
            or set(self._observer_roots.values()) & set(host._source_roots.values())
            or set(self._observer_roots.values()) & set(host._provision_roots.values())
        ):
            _deny()
        self._signer = _observer_signer(host, self._observer_roots)

    def observe(self, signed_supervisor_source: Any) -> dict[str, Any]:
        """Return a fresh signed observation, never native execution authority."""
        source, digest = verify_supervisor_source(
            signed_supervisor_source, self._source_roots, self._native_root
        )
        before = _observe_proc(source, self._host)
        issued = int(time.time())
        if issued >= source["expires_at"]:
            _deny()
        claims = {
            "version": 1,
            "server_id": "source-map-mcp",
            "mode": "host-stage-v1",
            "native_stage_root": self._native_root,
            "root_dev": before.st_dev,
            "root_ino": before.st_ino,
            "read_only": True,
            "observer_id": self._signer[0],
            "issued_at": issued,
            "expires_at": min(issued + 5, source["expires_at"]),
            **{
                field: source[field]
                for field in (
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
            },
            "supervisor_source_sha256": digest,
        }
        if set(claims) != MOUNT_FIELDS or claims["expires_at"] <= issued:
            _deny()
        return {
            "claims": claims,
            "kid": self._signer[0],
            "signature": base64.urlsafe_b64encode(
                self._signer[1].sign(MOUNT_DOMAIN + _canonical(claims))
            )
            .decode("ascii")
            .rstrip("="),
        }
