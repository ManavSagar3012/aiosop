"""Local, tenant-bounded HAR snapshots; remote MCP paths confer no filesystem trust.

Only an operator-provisioned shared capture mount can make a browser-MCP
returned *relative* path readable by AI-OSOP. The mount layout must be
    <OSOP_AUTHENTICATED_HAR_ROOT>/<engagement-id>/<relative>.har
and the same path must be stored on the durable signed capture Task. It does
NOT assert the remote provider signed/authenticated the file contents.

Legacy/manual imports are deliberately confined to a separate per-engagement
manual import root (default: cwd/manual_har_imports). Never fall back from a
missing signed root to cwd, host filesystem root or the manual import root.
"""

import hashlib
import hmac
import json
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Dict, Tuple


class ResourcePathDenied(ValueError):
    """Untrusted root, tenant/path boundary or HAR contents."""


MAX_HAR_BYTES = 4 * 1024 * 1024
MAX_HAR_ENTRIES = 2000
_TENANT = re.compile(r"eng-[A-Za-z0-9._-]{1,80}\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MOUNT_ATTESTATION_FILE = ".osop-har-mount.json"
_MAX_MOUNT_ATTESTATION_BYTES = 4096
_MAX_OPERATOR_MOUNT_PINS_BYTES = 16384


def _deny() -> None:
    raise ResourcePathDenied("HAR resource unavailable or outside authenticated tenant boundary")


def _path_is_link(path: Path) -> bool:
    try:
        st = path.lstat()
        return stat.S_ISLNK(st.st_mode) or bool(
            getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )
    except (OSError, ValueError):
        _deny()


def _root(signed: bool) -> Path:
    variable = "OSOP_AUTHENTICATED_HAR_ROOT" if signed else "OSOP_MANUAL_HAR_ROOT"
    raw = os.environ.get(variable, "")
    if not raw and not signed:
        # Explicitly scoped legacy/manual import folder. Not the repository or
        # the browser provider's (potentially remote) working directory.
        return Path.cwd() / "manual_har_imports"
    if not isinstance(raw, str) or not raw or len(raw) > 2048:
        _deny()
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink():
        _deny()
    return path


def _relative_path(value: Any) -> Tuple[str, ...]:
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        _deny()
    if (
        "\\" in value
        or ":" in value
        or "\x00" in value
        or value.startswith(("/", "~"))
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in value)
    ):
        _deny()
    segments = tuple(value.split("/"))
    if (
        len(segments) > 8
        or any(
            segment in {"", ".", ".."} or not _COMPONENT.fullmatch(segment) for segment in segments
        )
        or not segments[-1].lower().endswith(".har")
    ):
        _deny()
    return segments


def _reparse_or_symlink(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        (getattr(info, "st_file_attributes", 0) or 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _identity(info: os.stat_result) -> Tuple[int, int]:
    return info.st_dev, info.st_ino


def _read_scoped_regular_file(
    root: Path, engagement_id: str, parts: Tuple[str, ...], limit: int,
) -> bytes:
    """Read bytes under a stable tenant directory, not through an unchecked path.

    POSIX directory-fd/openat traversal anchors every component with
    O_DIRECTORY|O_NOFOLLOW. On Windows, where Python lacks portable directory
    handles, use a guarded pathname fallback and refuse changed directory/file
    identity at the end; hostile rename-then-restore remains a Win32 deployment
    qualification boundary.
    """
    base = root / engagement_id
    parents = [
        root, base,
        *(base.joinpath(*parts[:idx]) for idx in range(1, len(parts))),
    ]
    leaf = base.joinpath(*parts)
    before_parents = []
    for directory in parents:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or _reparse_or_symlink(info):
            _deny()
        before_parents.append(info)
    before_leaf = leaf.lstat()
    if not stat.S_ISREG(before_leaf.st_mode) or _reparse_or_symlink(before_leaf):
        _deny()
    # NTFS/POSIX hard links defeat engagement-private provenance even though
    # the pathname is syntactically scoped to the correct tenant.
    if before_leaf.st_nlink != 1:
        _deny()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    anchored = (
        hasattr(os, "O_DIRECTORY")
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and os.open in getattr(os, "supports_dir_fd", ())
    )
    with ExitStack() as stack:
        if anchored:
            directory_flags = (
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
            )
            parent_fd = os.open(root, directory_flags)
            stack.callback(os.close, parent_fd)
            if _identity(os.fstat(parent_fd)) != _identity(before_parents[0]):
                _deny()
            for index, component in enumerate((engagement_id, *parts[:-1]), 1):
                next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
                stack.callback(os.close, next_fd)
                if _identity(os.fstat(next_fd)) != _identity(before_parents[index]):
                    _deny()
                parent_fd = next_fd
            file_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
        else:
            # No portable safe directory-relative open: at minimum reject
            # symlink/reparse components and ensure the canonical path is in
            # the tenant tree before opening its final component.
            if not leaf.resolve(strict=True).is_relative_to(base.resolve(strict=True)):
                _deny()
            file_fd = os.open(leaf, flags)
        with os.fdopen(file_fd, "rb") as reader:
            initial = os.fstat(reader.fileno())
            if (
                not stat.S_ISREG(initial.st_mode)
                or _reparse_or_symlink(initial)
                or initial.st_nlink != 1
                or _identity(initial) != _identity(before_leaf)
                or not 0 < initial.st_size <= limit
            ):
                _deny()
            blob = reader.read(limit + 1)
            final = os.fstat(reader.fileno())
            if (
                not 0 < len(blob) <= limit
                or len(blob) != initial.st_size
                or _identity(initial) != _identity(final)
                or initial.st_size != final.st_size
                or initial.st_mtime_ns != final.st_mtime_ns
                or initial.st_ctime_ns != final.st_ctime_ns
                or final.st_nlink != 1
            ):
                _deny()
    # Guard against a rename/rebind of the file or any ancestor while its
    # descriptor was open. Compare both sides to our already-open descriptor.
    current_leaf = leaf.lstat()
    if (
        not stat.S_ISREG(current_leaf.st_mode)
        or _reparse_or_symlink(current_leaf)
        or _identity(current_leaf) != _identity(final)
        or current_leaf.st_nlink != 1
        or current_leaf.st_size != final.st_size
        or current_leaf.st_mtime_ns != final.st_mtime_ns
        or current_leaf.st_ctime_ns != final.st_ctime_ns
    ):
        _deny()
    for directory, info in zip(parents, before_parents):
        current = directory.lstat()
        if (
            not stat.S_ISDIR(current.st_mode)
            or _reparse_or_symlink(current)
            or _identity(info) != _identity(current)
        ):
            _deny()
    return blob


def _strict_har_json(blob: bytes) -> Dict[str, Any]:
    def unique(pairs: list) -> Dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate HAR field")
            result[key] = value
        return result

    try:
        document = json.loads(
            blob.decode("utf-8", "strict"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid numeric field")),
        )
        if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
            raise ValueError()
        entries = document["log"].get("entries")
        if not isinstance(entries, list) or len(entries) > MAX_HAR_ENTRIES:
            raise ValueError()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError()
            request = entry.get("request")
            if not isinstance(request, dict):
                raise ValueError()
            if (
                not isinstance(request.get("url"), str)
                or not 1 <= len(request["url"]) <= 8192
                or not isinstance(request.get("method"), str)
                or not re.fullmatch(r"[A-Za-z]{1,20}", request["method"])
            ):
                raise ValueError()
    except (UnicodeError, TypeError, ValueError, RecursionError) as exc:
        raise ResourcePathDenied("HAR JSON is invalid or exceeds resource bounds") from exc
    return document


def signed_har_mount_attestation(
    engagement_id: str,
    *,
    expected_sha256: str | None = None,
) -> Tuple[str, str]:
    """Validate an operator-pinned, engagement-specific shared-mount descriptor.

    OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS is a deployment-owned JSON map of
    engagement IDs to SHA-256 hashes of the bytes at
    <root>/<engagement>/.osop-har-mount.json. The descriptor pins a named
    container image digest and an opaque mount ID, not credentials.

    A browser's self-reported path, exists flag, or digest alone is not an
    authenticated container-to-worker synchronization receipt. An unpinned
    mount or an old capture without its durable mount digest is refused.
    """
    if not isinstance(engagement_id, str) or not _TENANT.fullmatch(engagement_id):
        _deny()
    raw = os.environ.get("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS")
    if not isinstance(raw, str) or not 2 <= len(raw) <= _MAX_OPERATOR_MOUNT_PINS_BYTES:
        _deny()
    try:
        pins = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ResourcePathDenied("Signed HAR mount attestation unavailable") from exc
    if (
        not isinstance(pins, dict)
        or len(pins) > 128
        or not all(isinstance(k, str) and _TENANT.fullmatch(k) and
                   isinstance(v, str) and _SHA256.fullmatch(v) for k, v in pins.items())
        or engagement_id not in pins
    ):
        _deny()
    pinned = pins[engagement_id]
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or not _SHA256.fullmatch(expected_sha256)
        or not hmac.compare_digest(expected_sha256, pinned)
    ):
        _deny()

    root = _root(True)
    try:
        blob = _read_scoped_regular_file(
            root, engagement_id, (_MOUNT_ATTESTATION_FILE,),
            _MAX_MOUNT_ATTESTATION_BYTES,
        )
        attested = hashlib.sha256(blob).hexdigest()
        if not hmac.compare_digest(attested, pinned):
            _deny()
        descriptor_data = json.loads(
            blob.decode("utf-8", "strict"), object_pairs_hook=_unique_json_object,
        )
        if (
            not isinstance(descriptor_data, dict)
            or set(descriptor_data) != {
                "engagement_id", "mount_id", "container_image_sha256",
            }
            or descriptor_data["engagement_id"] != engagement_id
            or not isinstance(descriptor_data["mount_id"], str)
            or not _COMPONENT.fullmatch(descriptor_data["mount_id"])
            or not isinstance(descriptor_data["container_image_sha256"], str)
            or not _SHA256.fullmatch(descriptor_data["container_image_sha256"])
        ):
            _deny()
        return attested, descriptor_data["container_image_sha256"]
    except ResourcePathDenied:
        raise
    except (OSError, ValueError, RuntimeError, UnicodeError, TypeError) as exc:
        raise ResourcePathDenied("Signed HAR mount attestation unavailable") from exc


def _unique_json_object(pairs: list) -> Dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def snapshot_local_har(
    engagement_id: str,
    har_path: Any,
    *,
    signed: bool,
) -> Tuple[Dict[str, Any], str]:
    """Read a small inert HAR snapshot without passing an untrusted path to open.

    Reject traversal, symlink/reparse components, tenant boundary changes,
    hard links and non-regular files. On POSIX, open each directory from its
    parent's fd and read the leaf under O_NOFOLLOW. An operator-pinned signed
    mount is also revalidated on both sides of the snapshot, preventing a
    descriptor swap from silently changing the origin during ingestion.
    """
    if not isinstance(engagement_id, str) or not _TENANT.fullmatch(engagement_id):
        _deny()
    pieces = _relative_path(har_path)
    root = _root(signed)
    try:
        pin = None
        if signed and os.environ.get("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS"):
            pin = signed_har_mount_attestation(engagement_id)
        blob = _read_scoped_regular_file(root, engagement_id, pieces, MAX_HAR_BYTES)
        if pin is not None and signed_har_mount_attestation(engagement_id) != pin:
            _deny()
        return _strict_har_json(blob), hashlib.sha256(blob).hexdigest()
    except ResourcePathDenied:
        raise
    except (OSError, ValueError, RuntimeError) as exc:
        raise ResourcePathDenied(
            "HAR resource unavailable or outside authenticated tenant boundary"
        ) from exc
