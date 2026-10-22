"""Host-supervisor-only staging of one signed, reviewed original SourceMap.

The independent 0035 issuer first commits the current UNKNOWN 0027 Action
preflight, after checking the original senior-reviewed 0013 artifact and Task
manifest. A *separate*, externally enrolled supervisor signer provisions one
stage by binding the full 0035 signature and all its immutable source claims.
Neither signing key nor a signing function exists here. Supplied bytes are
accepted only at the exact original SHA-256 in both signed proofs.

This module performs no source-authority issuance, DB queries, network fetches,
container operations or retries. Uncertain/failed stages remain consumed.
Run only inside a dedicated host supervisor whose environment and stage root
cannot be modified by the invoking MCP worker.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SOURCE_DOMAIN = b"ai-osop/sourcemap-original-preflight/v1\x00"
PROVISION_DOMAIN = b"ai-osop/sourcemap-host-stage-provision/v1\x00"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_ACTION = re.compile(r"action-[a-f0-9]{32}\Z")
_REQUEST = re.compile(r"req-[a-f0-9]{48}\Z")
_SOURCE_FIELDS = frozenset(
    {
        "version", "preflight_id", "request_id", "engagement_id", "flow_id",
        "task_id", "subtask_id", "action_id", "owner_id", "server_id",
        "tool_name", "artifact_sha256", "manifest_sha256", "approval_id",
        "lease_id", "authorization_version", "authorization_sha256",
        "issued_at", "expires_at",
    }
)
# The original 0035 preflight identity is carried verbatim by a provision.
_PROVISION_FIELDS = _SOURCE_FIELDS | {"stage_id", "source_proof_sha256"}
_BOUND_FIELDS = _SOURCE_FIELDS - {"version", "issued_at", "expires_at"}
_MAX_BYTES = 1024 * 1024  # Matches native source_map_mcp._read_original_bytes.


class OriginalSourceMapStageDenied(ValueError):
    """Stage failed or is UNKNOWN; never retry the same source Action."""


def _deny() -> None:
    raise OriginalSourceMapStageDenied("Original SourceMap host stage denied or UNKNOWN")


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError) as exc:
        raise OriginalSourceMapStageDenied("Invalid signed stage metadata") from exc
    if len(raw) > 4096:
        _deny()
    return raw


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _deny()
        result[key] = value
    return result


def _roots(name: str) -> dict[str, bytes]:
    """Public keys are enrolled in the protected supervisor environment."""
    raw = os.getenv(name, "")
    if not 2 <= len(raw) <= 8192:
        _deny()
    try:
        decoded = json.loads(raw, object_pairs_hook=_unique)
        if type(decoded) is not dict or not 1 <= len(decoded) <= 16:
            _deny()
        result: dict[str, bytes] = {}
        for kid, encoded in decoded.items():
            if (
                type(kid) is not str
                or _KID.fullmatch(kid) is None
                or type(encoded) is not str
                or len(encoded) != 44
            ):
                _deny()
            key = base64.b64decode(encoded, validate=True)
            if len(key) != 32 or base64.b64encode(key).decode("ascii") != encoded:
                _deny()
            result[kid] = key
        return result
    except (ValueError, TypeError, binascii.Error, UnicodeError) as exc:
        raise OriginalSourceMapStageDenied("Independent signing trust unavailable") from exc


def _signed_claims(
    envelope: Any,
    roots: Mapping[str, bytes],
    domain: bytes,
    fields: frozenset[str],
    now: int,
) -> tuple[dict[str, Any], str]:
    if (
        type(envelope) is not dict
        or set(envelope) != {"claims", "kid", "signature"}
        or type(envelope["claims"]) is not dict
        or set(envelope["claims"]) != fields
        or type(envelope["kid"]) is not str
        or envelope["kid"] not in roots
        or type(envelope["signature"]) is not str
        or re.fullmatch(r"[A-Za-z0-9_-]{86}", envelope["signature"]) is None
    ):
        _deny()
    claims = envelope["claims"]
    if (
        type(claims["version"]) is not int
        or claims["version"] != 1
        or type(claims["issued_at"]) is not int
        or type(claims["expires_at"]) is not int
        or not now - 5 <= claims["issued_at"] <= now + 2
        or not now < claims["expires_at"] <= claims["issued_at"] + 10
        or type(claims["authorization_version"]) is not int
        or claims["authorization_version"] < 1
        or type(claims["preflight_id"]) is not str
        or re.fullmatch(r"nsp-[a-f0-9]{32}", claims["preflight_id"]) is None
        or type(claims["request_id"]) is not str
        or _REQUEST.fullmatch(claims["request_id"]) is None
        or type(claims["action_id"]) is not str
        or _ACTION.fullmatch(claims["action_id"]) is None
        or any(
            type(claims[k]) is not str or _SHA.fullmatch(claims[k]) is None
            for k in ("artifact_sha256", "manifest_sha256", "authorization_sha256")
        )
        or any(
            type(claims[k]) is not str or _IDENTITY.fullmatch(claims[k]) is None
            for k in (
                "engagement_id", "flow_id", "task_id", "subtask_id",
                "owner_id", "approval_id", "lease_id",
            )
        )
        or not claims["engagement_id"].startswith("eng-")
        or not claims["task_id"].startswith("task-")
        or claims["server_id"] != "source-map-mcp"
        or claims["tool_name"] != "inspect_local_original_sourcemap"
    ):
        _deny()
    try:
        signature = base64.urlsafe_b64decode(envelope["signature"] + "==")
        if (
            len(signature) != 64
            or base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
            != envelope["signature"]
        ):
            _deny()
        Ed25519PublicKey.from_public_bytes(roots[envelope["kid"]]).verify(
            signature, domain + _canonical(claims)
        )
    except (ValueError, TypeError, binascii.Error) as exc:
        raise OriginalSourceMapStageDenied("Stage signature rejected") from exc
    except Exception as exc:
        raise OriginalSourceMapStageDenied("Stage signature rejected") from exc
    proof_sha = hashlib.sha256(domain + _canonical(claims) + signature).hexdigest()
    return claims, proof_sha


def verify_original_stage_proofs(
    source_proof: Any,
    provision_proof: Any,
    source_roots: Mapping[str, bytes],
    provision_roots: Mapping[str, bytes],
    *,
    now: Optional[int] = None,
) -> dict[str, Any]:
    """Verify two independent enrolled signers; never mint authority from inputs."""
    if set(source_roots.values()) & set(provision_roots.values()):
        _deny()
    current = int(time.time()) if now is None else now
    if type(current) is not int or current <= 0:
        _deny()
    source, source_sha = _signed_claims(
        source_proof, source_roots, SOURCE_DOMAIN, _SOURCE_FIELDS, current
    )
    provision, _ = _signed_claims(
        provision_proof, provision_roots, PROVISION_DOMAIN, _PROVISION_FIELDS, current
    )
    if (
        type(provision["stage_id"]) is not str
        or re.fullmatch(r"sms-[a-f0-9]{32}", provision["stage_id"]) is None
        or type(provision["source_proof_sha256"]) is not str
        or _SHA.fullmatch(provision["source_proof_sha256"]) is None
        or not hmac.compare_digest(provision["source_proof_sha256"], source_sha)
        or any(provision[field] != source[field] for field in _BOUND_FIELDS)
        or provision["issued_at"] < source["issued_at"]
        or provision["issued_at"] >= source["expires_at"]
        or provision["expires_at"] > source["expires_at"]
    ):
        _deny()
    return dict(provision)


def _safe_directory(root: Path) -> os.stat_result:
    """Fail on mutable/symlinked/reparse ancestors, require private stage root."""
    if not root.is_absolute() or root.name != "sourcemap-originals":
        _deny()
    try:
        ancestors = (root, *root.parents)
        for index, directory in enumerate(ancestors):
            info = directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or (os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
            ):
                _deny()
            if os.name == "posix":
                if index == 0:
                    if info.st_uid != os.getuid() or info.st_mode & 0o077 or not info.st_mode & 0o200:
                        _deny()
                elif info.st_mode & 0o022:
                    # Root-owned sticky /tmp is safe for a separately owned 0700 child.
                    if not (
                        info.st_uid == 0
                        and info.st_mode & stat.S_ISVTX
                    ):
                        _deny()
        return root.lstat()
    except (OSError, ValueError, AttributeError) as exc:
        raise OriginalSourceMapStageDenied("Unsafe host stage root") from exc


def _open_root(root: Path) -> int:
    # Windows lacks Python dir_fd/O_NOFOLLOW guarantees. A Windows supervisor
    # must implement native reparse-safe handle staging before enabling writes.
    if os.name != "posix" or os.open not in os.supports_dir_fd:
        _deny()
    before = _safe_directory(root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open(root, flags)
        actual = os.fstat(fd)
        if (
            not stat.S_ISDIR(actual.st_mode)
            or (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino)
        ):
            os.close(fd)
            _deny()
        return fd
    except OSError as exc:
        raise OriginalSourceMapStageDenied("Unsafe host stage root") from exc


def _exclusive(root_fd: int, name: str, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(name, flags, mode, dir_fd=root_fd)
    with os.fdopen(fd, "wb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            _deny()
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def _readback(root_fd: int, name: str, digest: str, size: int) -> None:
    info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != size or info.st_mode & 0o222:
        _deny()
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
    with os.fdopen(fd, "rb") as stream:
        actual = os.fstat(stream.fileno())
        first = stream.read(_MAX_BYTES + 1)
        stream.seek(0)
        second = stream.read(_MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (
        (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino)
        or (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or info.st_mode & 0o222
        or first != second
        or len(first) != size
        or not hmac.compare_digest(hashlib.sha256(first).hexdigest(), digest)
    ):
        _deny()


class OriginalSourceMapHostStage:
    """Construct from protected host-only configuration, then stage exactly once."""

    def __init__(self) -> None:
        self._root = Path(os.getenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", ""))
        self._source_roots = _roots("OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
        self._provision_roots = _roots("OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON")
        if set(self._source_roots.values()) & set(self._provision_roots.values()):
            _deny()
        _safe_directory(self._root)

    def stage(
        self,
        *,
        original_bytes: bytes,
        source_proof: dict[str, Any],
        provision_proof: dict[str, Any],
    ) -> Path:
        """Consumes Action/request BEFORE writing; any uncertain ACK stays UNKNOWN."""
        claims = verify_original_stage_proofs(
            source_proof, provision_proof, self._source_roots, self._provision_roots
        )
        if (
            type(original_bytes) is not bytes
            or not 1 <= len(original_bytes) <= _MAX_BYTES
            or not hmac.compare_digest(
                hashlib.sha256(original_bytes).hexdigest(), claims["artifact_sha256"]
            )
        ):
            _deny()
        fd = _open_root(self._root)
        try:
            if int(time.time()) >= claims["expires_at"]:
                _deny()
            # Each identity is consumed durably with O_EXCL. Interrupted writes
            # and lost ACKs remain UNKNOWN and are never cleaned up for replay.
            for field in ("action_id", "request_id", "preflight_id", "stage_id"):
                key = hashlib.sha256(claims[field].encode("ascii")).hexdigest()
                _exclusive(fd, ".used-" + field + "-" + key, b"consumed\n", 0o400)
                os.fsync(fd)
            name = claims["artifact_sha256"] + ".map"
            _exclusive(fd, name, original_bytes, 0o400)
            os.fsync(fd)
            _readback(fd, name, claims["artifact_sha256"], len(original_bytes))
            if int(time.time()) >= claims["expires_at"]:
                _deny()
            # Return only while the protected path still resolves to the same
            # directory handle used for every exclusive create.
            current_root = _safe_directory(self._root)
            anchored_root = os.fstat(fd)
            if (current_root.st_dev, current_root.st_ino) != (
                anchored_root.st_dev, anchored_root.st_ino
            ):
                _deny()
            os.fsync(fd)
            return self._root / name
        except OSError as exc:
            raise OriginalSourceMapStageDenied("Original SourceMap stage outcome UNKNOWN") from exc
        finally:
            os.close(fd)
