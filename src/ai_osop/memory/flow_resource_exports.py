"""Read-only, inert export of verified signed-Flow PostgreSQL resources.

This is NOT PentAGI's host/container resource mirroring. There is no verified
AI-OSOP deployment sandbox or safe workdir lifecycle, so no user-controlled
path is written, extracted, executed, loaded as code, or passed to a tool.
Operators may inspect a hash manifest or download a bounded, uncompressed,
in-memory ZIP whose members are treated as *untrusted data*.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import re
import zipfile
from typing import Any, Dict, List, Tuple

from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore, safe_filename

MAX_EXPORT_FILES = 16
MAX_EXPORT_TOTAL_BYTES = 4 * 1024 * 1024
MAX_EXPORT_BUNDLE_BYTES = MAX_EXPORT_TOTAL_BYTES + 64 * 1024

# Data and source-text only; exclude shell, browser markup, notebooks, macros,
# executables, DLLs, installers, symlinks, tar/zip and any other archive type.
_TEXT_TYPES = frozenset(
    {
        ".txt",
        ".md",
        ".csv",
        ".tsv",
        ".json",
        ".jsonl",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".log",
        ".diff",
        ".patch",
        ".py",
        ".go",
        ".rs",
        ".java",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".css",
        ".sql",
    }
)
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT_ID = re.compile(r"artifact-[0-9a-f]{32}\Z")
_HTML_MARKUP = re.compile(
    r"<\s*(?:!doctype\s+html|html\b|head\b|body\b|script\b|"
    r"iframe\b|object\b|embed\b|svg\b|meta\b|link\b|form\b|"
    r"style\b|img\b|a\b|div\b|p\b|input\b|button\b|textarea\b|"
    r"video\b|audio\b|template\b|math\b|base\b|picture\b|"
    r"\?xml\b)",
    re.IGNORECASE,
)


def _canonical(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _kind_and_validate(name: str, blob: bytes) -> str:
    name = safe_filename(name)
    suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if suffix not in _TEXT_TYPES or name.startswith("."):
        raise ArtifactDenied(415, "Only inert UTF-8 text or code resources can be exported")
    if not isinstance(blob, bytes) or not blob:
        raise ArtifactDenied(503, "Flow resource bytes are invalid")
    try:
        source = blob.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ArtifactDenied(415, "Flow resource must be UTF-8 text") from exc
    # Explicitly disallow invisible control and bidirectional control
    # characters; these could disguise a filename, binary or HTML payload.
    if any(
        (ord(ch) < 32 and ch not in "\n\r\t")
        or ord(ch) == 127
        or 0x202A <= ord(ch) <= 0x202E
        or 0x2066 <= ord(ch) <= 0x2069
        for ch in source
    ):
        raise ArtifactDenied(415, "Flow resource contains unsafe control characters")
    stripped = source.lstrip("\ufeff \t\r\n")
    if (
        stripped.startswith("#!")
        or _HTML_MARKUP.search(source) is not None
        or "<!--" in source
        or "<![CDATA[" in source
    ):
        raise ArtifactDenied(415, "Active or markup Flow resource cannot be exported")
    return (
        "utf8_inert_source"
        if suffix
        in {
            ".py",
            ".go",
            ".rs",
            ".java",
            ".c",
            ".h",
            ".cpp",
            ".hpp",
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".sql",
            ".css",
        }
        else "utf8_inert_text"
    )


def make_manifest(
    flow_id: str,
    revision: int,
    version: int,
    snapshot: List[Tuple[Dict[str, Any], bytes]],
) -> Dict[str, Any]:
    """Verify *every* readback before exposing even the manifest metadata."""
    if (
        not isinstance(snapshot, list)
        or len(snapshot) > MAX_EXPORT_FILES
        or type(revision) is not int
        or revision < 0
        or type(version) is not int
        or version < 1
    ):
        raise ArtifactDenied(413, "Flow resource snapshot exceeds bounds")
    seen: set[str] = set()
    files: List[Dict[str, Any]] = []
    total = 0
    for metadata, blob in snapshot:
        if not isinstance(metadata, dict) or not isinstance(blob, bytes):
            raise ArtifactDenied(503, "Flow resource readback is invalid")
        name = metadata.get("name")
        kind = _kind_and_validate(name, blob)
        if name in seen:
            raise ArtifactDenied(503, "Flow resource names are not unique")
        seen.add(name)
        actual = hashlib.sha256(blob).hexdigest()
        if (
            type(metadata.get("size_bytes")) is not int
            or metadata["size_bytes"] != len(blob)
            or not isinstance(metadata.get("sha256"), str)
            or not _HASH.fullmatch(metadata["sha256"])
            or not hmac.compare_digest(metadata["sha256"], actual)
            or metadata.get("flow_id") != flow_id
            or type(metadata.get("flow_revision")) is not int
            or metadata["flow_revision"] != revision
            or type(metadata.get("authorization_version")) is not int
            or metadata["authorization_version"] != version
            or not isinstance(metadata.get("id"), str)
            or not _ARTIFACT_ID.fullmatch(metadata["id"])
        ):
            raise ArtifactDenied(503, "Flow resource integrity or authorization changed")
        total += len(blob)
        if total > MAX_EXPORT_TOTAL_BYTES:
            raise ArtifactDenied(413, "Flow resource export exceeds byte budget")
        files.append(
            {
                "artifact_id": metadata["id"],
                "name": name,
                "resource_path": "resources/" + name,
                "size_bytes": len(blob),
                "sha256": actual,
                "classification": kind,
            }
        )
    files.sort(key=lambda item: item["resource_path"])
    base: Dict[str, Any] = {
        "format": "ai-osop-inert-flow-resources-v1",
        "flow_id": flow_id,
        "flow_revision": revision,
        "authorization_version": version,
        "count": len(files),
        "total_size_bytes": total,
        "items": files,
        "read_only": True,
        "content_executed": False,
        "host_files_created": False,
        "archive_compression": "stored",
        "artifact_bytes_untrusted": True,
    }
    return {**base, "manifest_sha256": hashlib.sha256(_canonical(base)).hexdigest()}


def make_bundle(
    snapshot: List[Tuple[Dict[str, Any], bytes]],
    manifest: Dict[str, Any],
) -> bytes:
    """Package and independently SHA-read back an ephemeral, uncompressed ZIP.

    No filesystem writes or extraction: a crash leaves no stale resource
    directory, symlink, temp archive or runnable file behind.
    """
    if not isinstance(manifest, dict) or manifest.get("count") != len(snapshot):
        raise ArtifactDenied(503, "Flow resource export manifest mismatch")
    expected_manifest_digest = hashlib.sha256(
        _canonical({key: value for key, value in manifest.items() if key != "manifest_sha256"})
    ).hexdigest()
    if not isinstance(manifest.get("manifest_sha256"), str) or not hmac.compare_digest(
        manifest["manifest_sha256"],
        expected_manifest_digest,
    ):
        raise ArtifactDenied(503, "Flow resource export manifest integrity unavailable")
    by_name = {metadata["name"]: blob for metadata, blob in snapshot}
    if len(by_name) != len(snapshot):
        raise ArtifactDenied(503, "Flow resource filenames are not unique")
    if len(manifest.get("items", [])) != len(snapshot):
        raise ArtifactDenied(503, "Flow resource export entries are inconsistent")
    with io.BytesIO() as output:
        try:
            with zipfile.ZipFile(
                output,
                "w",
                compression=zipfile.ZIP_STORED,
                allowZip64=False,
            ) as archive:
                for item in manifest["items"]:
                    name = safe_filename(item["name"])
                    if item["resource_path"] != "resources/" + name:
                        raise ArtifactDenied(503, "Flow resource export path is invalid")
                    blob = by_name[name]
                    if (
                        not isinstance(blob, bytes)
                        or item["size_bytes"] != len(blob)
                        or not hmac.compare_digest(
                            item["sha256"],
                            hashlib.sha256(blob).hexdigest(),
                        )
                    ):
                        raise ArtifactDenied(503, "Flow resource SHA readback failed")
                    info = zipfile.ZipInfo(item["resource_path"])
                    info.compress_type = zipfile.ZIP_STORED
                    info.create_system = 3
                    info.external_attr = 0o100400 << 16  # regular, read-only
                    archive.writestr(info, blob)
                archive.writestr("resource-manifest.json", _canonical(manifest))
            packed = output.getvalue()
            if len(packed) > MAX_EXPORT_BUNDLE_BYTES:
                raise ArtifactDenied(413, "Flow resource archive exceeds size limit")
            with zipfile.ZipFile(io.BytesIO(packed), "r") as verify:
                members = verify.infolist()
                if (
                    len(members) != manifest["count"] + 1
                    or any(item.compress_type != zipfile.ZIP_STORED for item in members)
                    or verify.read("resource-manifest.json") != _canonical(manifest)
                ):
                    raise ArtifactDenied(503, "Flow resource archive readback failed")
                expected = {"resource-manifest.json"}
                for item in manifest["items"]:
                    path = item["resource_path"]
                    expected.add(path)
                    fresh = verify.read(path)
                    if len(fresh) != item["size_bytes"] or not hmac.compare_digest(
                        hashlib.sha256(fresh).hexdigest(),
                        item["sha256"],
                    ):
                        raise ArtifactDenied(503, "Flow resource archive SHA readback failed")
                if set(verify.namelist()) != expected:
                    raise ArtifactDenied(503, "Flow resource archive members changed")
            return packed
        except ArtifactDenied:
            raise
        except (KeyError, ValueError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise ArtifactDenied(503, "Flow resource archive unavailable") from exc


class FlowResourceExports:
    """Actual signed/owned Flow artifact storage consumer used by API routes."""

    def __init__(self, store: FlowArtifactStore):
        self.store = store

    async def prepare(
        self,
        flow_id: str,
        owner: str,
        revision: int,
        version: int,
    ) -> Tuple[Dict[str, Any], List[Tuple[Dict[str, Any], bytes]]]:
        snapshot = await self.store.read_resource_snapshot(
            flow_id,
            owner,
            revision,
            version,
        )
        return make_manifest(flow_id, revision, version, snapshot), snapshot
