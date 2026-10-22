"""Bounded, explicitly allowlisted HTTPS source-map *metadata* inspection.

This native server has no access to the authoritative signed Flow/Task/ROE.
Consequently HTTP execution is unavailable even with an administrator
allowlist: an allowlist is a destination restriction, not Task authority.
Only secret *types/counts* are returned; secret values and source bodies never
leave this endpoint. No DNS-rebinding window: outbound TCP uses a vetted IP,
with the original hostname pinned for Host, TLS SNI and certificate checking.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import stat
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Optional, Union
from urllib.parse import urljoin, urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(title="Source Map MCP Server")

_DOMAIN = re.compile(r"(?=.{4,253}\Z)(?:[a-z][a-z0-9-]{0,61}[a-z0-9]\.|[a-z]\.)+" r"[a-z]{2,63}\Z")
_SOURCE_MAP = re.compile(r"(?m)//[#@]\s*sourceMappingURL=([^\s]+)")
_INPUT_BYTES = 2048
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_SOURCES = 128
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_REQUEST = re.compile(r"req-[a-f0-9]{48}\Z")
_ACTION = re.compile(r"action-[a-f0-9]{32}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_SOURCE_DOMAIN = b"ai-osop/sourcemap-original-preflight/v1\x00"
_STATUS_DOMAIN = b"ai-osop/sourcemap-original-status/v1\x00"
_HOST_STAGE_DOMAIN = b"ai-osop/sourcemap-host-stage-provision/v1\x00"
_SOURCE_REQUEST = frozenset(
    {
        "request_id",
        "engagement_id",
        "task_id",
        "server_id",
        "tool_name",
        "artifact_sha256",
    }
)
_SOURCE_CLAIMS = frozenset(
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
        "issued_at",
        "expires_at",
    }
)
_STATUS_CLAIMS = _SOURCE_CLAIMS | frozenset({"status_id"})
_PATTERNS = {
    "google_api": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "generic_api_key": re.compile(
        r"""(?i)(?:api[_-]?key|secret|token|password)['"]?\s*[:=]\s*['"]([^'"]{1,256})['"]"""
    ),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.?[A-Za-z0-9_.+/-]*"),
}


class SourceMapDenied(ValueError):
    """Untrusted URL, scope or outbound metadata is not safe to retrieve."""


class SourceMapUnavailable(RuntimeError):
    """Transport or upstream result UNKNOWN; never include remote exception text."""


class MCPExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(min_length=1, max_length=64)
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = Field(default=None, max_length=128)
    timeout_override: Optional[int] = Field(default=None, ge=1, le=30)
    execution_binding: Optional[Dict[str, str]] = None


class MCPStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_id: str
    engagement_id: str
    task_id: str
    server_id: str


@app.get("/health")
async def health() -> JSONResponse:
    configured = _approved_original_transport_configured()
    return JSONResponse(
        status_code=200 if configured else 503,
        content={
            "status": "configured_unverified" if configured else "unavailable",
            "server": "source-map-mcp",
            "execution_enabled": False,
            "source_side_signed_authorization_verified": False,
            "original_artifact_source_configured": configured,
        },
    )


@app.post("/mcp/initialize")
async def mcp_initialize() -> Dict[str, Any]:
    configured = _approved_original_transport_configured()
    capabilities = ["mcp_bound_receipts_v1", "original_sourcemap_signed_preflight_v1"]
    if configured and _status_transport_configured():
        capabilities.append("mcp_request_status_v1")
    return {
        "server_id": "source-map-mcp",
        "version": "1.1.0",
        "capabilities": (
            capabilities if configured else ["execution_unavailable_no_signed_source_authorization"]
        ),
        "status": "ready" if configured else "unavailable",
        "execution_enabled": False,
        "source_side_signed_authorization_verified": False,
        "tools": (
            [
                {
                    "name": "fetch_and_parse_sourcemap",
                    "description": (
                        "UNAVAILABLE: independently verified signed Flow/Task/ROE "
                        "authority is required before fetching even administrator-allowlisted "
                        "public HTTPS source maps; "
                        "return only opaque source indices and counts, never credentials or source bodies. "
                        "Native server has no independent signed Flow/ROE/Task verifier; "
                        "the allowlist does not grant operator authorization."
                    ),
                    "parameters": [
                        {
                            "name": "url",
                            "type": "string",
                            "description": "Approved public HTTPS URL, 2048 bytes maximum",
                            "required": True,
                        }
                    ],
                    "returns": {
                        "type": "object",
                        "description": "Bounded source filename and secret-type count metadata only",
                    },
                    "side_effect_class": "RECON_ACTIVE",
                    "requires_approval": True,
                    "scope_check": True,
                    "timeout_seconds": 10,
                    "required_permissions": ["signed_source_map_scope"],
                },
                {
                    "name": "inspect_local_original_sourcemap",
                    "description": (
                        "Read a separately approved immutable Flow original-source artifact. "
                        "Requires fresh independent central signed SourceMap authorization, "
                        "no generic URLs and no outbound target fetch. Configured "
                        "transport is not proof of current authorization."
                    ),
                    "parameters": [
                        {
                            "name": "artifact_sha256",
                            "type": "string",
                            "description": "SHA256 of centrally reviewed original bytes",
                            "required": True,
                        }
                    ],
                    "returns": {
                        "type": "object",
                        "description": "Opaque source indices and secret type counts",
                    },
                    "side_effect_class": "READ_ONLY",
                    "requires_approval": True,
                    "scope_check": True,
                    "timeout_seconds": 10,
                    "required_permissions": ["signed_original_sourcemap_artifact"],
                },
            ][1:]
            if configured
            else [
                {
                    "name": "fetch_and_parse_sourcemap",
                    "description": "UNAVAILABLE: arbitrary public URL fetch lacks independent signed original Task authority.",
                    "parameters": [
                        {
                            "name": "url",
                            "type": "string",
                            "description": "Untrusted URL",
                            "required": True,
                        }
                    ],
                    "returns": {"type": "object", "description": "No approved public fetch"},
                    "side_effect_class": "RECON_ACTIVE",
                    "requires_approval": True,
                    "scope_check": True,
                },
            ]
        ),
    }


def _approved_original_transport_configured() -> bool:
    """Readiness means local trust configured, NOT an Action redeemed or target read."""
    try:
        config = _local_original_config()
        _native_receipt_signer(config[3])
        host_roots = _preissued_handoff_roots(config)
        if host_roots is not None:
            _status_transport_config(config)
        native = os.getenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", "")
        other = (
            os.getenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", "")
            if host_roots is not None
            else os.getenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", "")
        )
        return (
            32 <= len(native) <= 512
            and all(33 <= ord(ch) <= 126 for ch in native)
            and not hmac.compare_digest(native, other)
        )
    except (SourceMapDenied, OSError, ValueError, TypeError):
        return False


def _status_transport_config(
    original: tuple[str, str, str, dict[str, bytes], Path, Path],
) -> tuple[str, str]:
    """Status has its own central identity on the SAME pinned HTTPS authority."""
    source_url, _, source_token, _, _, _ = original
    status_url = os.getenv("OSOP_SOURCEMAP_STATUS_URL", "")
    status_token = os.getenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", "")
    native_token = os.getenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", "")
    host_mode = os.getenv("OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE", "") == "host-stage-v1"
    expected_host = urlsplit(source_url).hostname if not host_mode else None
    target = urlsplit(status_url)
    if (
        target.scheme != "https"
        or target.path != "/native-sourcemap/status-preflight"
        or not target.hostname
        or _DOMAIN.fullmatch(target.hostname.lower()) is None
        or (not host_mode and target.hostname != expected_host)
        or target.netloc != target.hostname
        or target.port not in (None, 443)
        or target.username is not None
        or target.password is not None
        or target.query
        or target.fragment
        or not 32 <= len(status_token) <= 512
        or any(not 33 <= ord(char) <= 126 for char in status_token)
        or (source_token and hmac.compare_digest(status_token, source_token))
        or hmac.compare_digest(status_token, native_token)
    ):
        raise SourceMapDenied()
    return status_url, status_token


def _status_transport_configured() -> bool:
    try:
        original = _local_original_config()
        _native_receipt_signer(original[3])
        _status_transport_config(original)
        return _approved_original_transport_configured()
    except (SourceMapDenied, OSError, ValueError, TypeError):
        return False


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceMapDenied()
        result[key] = value
    return result


def _canonical(data: dict[str, Any]) -> bytes:
    raw = json.dumps(
        data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    if len(raw) > 4096:
        raise SourceMapDenied()
    return raw


def _trusted_path(raw: str, *, writable: bool = False) -> Path:
    if type(raw) is not str or not 1 <= len(raw) <= 1024:
        raise SourceMapDenied()
    path = Path(raw)
    if not path.is_absolute():
        raise SourceMapDenied()
    # Reject reparse/symlink roots and parents; a mutable ancestor can
    # otherwise silently redirect a supposedly pinned original-byte mount.
    if any(piece.is_symlink() for piece in (path, *path.parents)):
        raise SourceMapDenied()
    try:
        info = path.stat()
    except OSError as exc:
        raise SourceMapDenied() from exc
    if not stat.S_ISDIR(info.st_mode):
        raise SourceMapDenied()
    if os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise SourceMapDenied()
    if os.name == "posix" and info.st_mode & 0o022:
        raise SourceMapDenied()
    if writable and not os.access(path, os.W_OK):
        raise SourceMapDenied()
    return path


def _local_original_config() -> tuple[str, str, str, dict[str, bytes], Path, Path]:
    """Legacy issuer vs host-stage status only; share PUBLIC issuer trust roots.

    In host-stage-v1 the native process must not possess source issuance URL
    or source-service bearer. The separately pinned status service can ONLY
    recheck an existing committed 0035 row, never mint another proof.
    """
    endpoint = os.getenv("OSOP_SOURCEMAP_SOURCE_URL", "")
    ca = os.getenv("OSOP_SOURCEMAP_SOURCE_CA_BUNDLE", "")
    token = os.getenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", "")
    keys_raw = os.getenv("OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON", "")
    mode = os.getenv("OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE", "")
    try:
        if mode not in ("", "host-stage-v1"):
            raise SourceMapDenied()
        if mode == "host-stage-v1":
            # Any source capability, even a malformed endpoint or partial
            # bearer, is a mixed-mode misconfiguration, never a fallback.
            if endpoint or token:
                raise SourceMapDenied()
        else:
            parsed = urlsplit(endpoint)
            if (
                parsed.scheme != "https"
                or parsed.path != "/native-sourcemap/source-preflight"
                or not parsed.hostname
                or _DOMAIN.fullmatch(parsed.hostname.lower()) is None
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or parsed.port not in (None, 443)
                or parsed.netloc != parsed.hostname
                or not 32 <= len(token) <= 512
                or any(ord(c) < 33 or ord(c) > 126 for c in token)
            ):
                raise SourceMapDenied()
        if not 2 <= len(keys_raw) <= 8192:
            raise SourceMapDenied()
        trust = _trusted_path(str(Path(ca).parent))
        ca_path = Path(ca)
        if (
            not ca_path.is_absolute()
            or ca_path.is_symlink()
            or ca_path.parent != trust
            or not ca_path.is_file()
            or not 100 <= ca_path.stat().st_size <= 128 * 1024
            or b"-----BEGIN CERTIFICATE-----" not in ca_path.read_bytes()
        ):
            raise SourceMapDenied()
        roots = json.loads(keys_raw, object_pairs_hook=_unique)
        if type(roots) is not dict or not 1 <= len(roots) <= 16:
            raise SourceMapDenied()
        trusted: dict[str, bytes] = {}
        for kid, encoded in roots.items():
            if type(kid) is not str or _KID.fullmatch(kid) is None:
                raise SourceMapDenied()
            if type(encoded) is not str or len(encoded) != 44:
                raise SourceMapDenied()
            raw_key = base64.b64decode(encoded, validate=True)
            if len(raw_key) != 32 or base64.b64encode(raw_key).decode("ascii") != encoded:
                raise SourceMapDenied()
            trusted[kid] = raw_key
        original = _trusted_path(os.getenv("OSOP_SOURCEMAP_ORIGINAL_READONLY_ROOT", ""))
        journal = _trusted_path(os.getenv("OSOP_SOURCEMAP_ONE_SHOT_ROOT", ""), writable=True)
        if original == journal:
            raise SourceMapDenied()
        return endpoint, str(ca_path), token, trusted, original, journal
    except (OSError, ValueError, TypeError, UnicodeError, base64.binascii.Error) as exc:
        raise SourceMapDenied() from exc


def _preissued_handoff_roots(
    config: tuple[str, str, str, dict[str, bytes], Path, Path],
) -> Optional[dict[str, bytes]]:
    """Only a protected host-stage filesystem may present the already-used 0035 proof.

    A host stage must never fall through to the central one-shot issuer on a
    native read. A standalone legacy original fixture remains compatible.
    """
    mode = os.getenv("OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE", "")
    stage_root = config[4]
    if not mode:
        if stage_root.name == "sourcemap-originals":
            raise SourceMapDenied()
        return None
    if (
        mode != "host-stage-v1"
        or os.name != "posix"
        or stage_root.name != "sourcemap-originals"
        or os.getenv("OSOP_SOURCEMAP_HOST_STAGE_ROOT", "") != str(stage_root)
    ):
        raise SourceMapDenied()
    try:
        # Unlike a 0035 source issuance, status admission is read-only and
        # rechecks the CURRENT Task/reviewer/lease against the committed row.
        _status_transport_config(config)
        info = stage_root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or stage_root.is_symlink():
            raise SourceMapDenied()
        encoded = os.getenv("OSOP_SOURCEMAP_HOST_STAGE_TRUSTED_PUBLIC_KEYS_JSON", "")
        if not 2 <= len(encoded) <= 8192:
            raise SourceMapDenied()
        supplied = json.loads(encoded, object_pairs_hook=_unique)
        if type(supplied) is not dict or not 1 <= len(supplied) <= 16:
            raise SourceMapDenied()
        trusted: dict[str, bytes] = {}
        for kid, value in supplied.items():
            if (
                type(kid) is not str
                or _KID.fullmatch(kid) is None
                or type(value) is not str
                or len(value) != 44
            ):
                raise SourceMapDenied()
            key = base64.b64decode(value, validate=True)
            if len(key) != 32 or base64.b64encode(key).decode("ascii") != value:
                raise SourceMapDenied()
            trusted[kid] = key
        native = (
            _native_receipt_signer(config[3])[1]
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        if set(trusted.values()).intersection(config[3].values()) or native in trusted.values():
            raise SourceMapDenied()
        return trusted
    except (OSError, ValueError, TypeError, UnicodeError, base64.binascii.Error) as exc:
        raise SourceMapDenied() from exc


def _native_receipt_signer(
    source_issuers: dict[str, bytes],
) -> tuple[str, Ed25519PrivateKey]:
    """Load an operator-enrolled provider identity, separate from the source issuer.

    Never accept a signing key or a key id from an incoming MCP request. The
    native process must have a private raw Ed25519 key in an owner-only local
    file, with its public counterpart separately enrolled in core receipt trust.
    """
    kid = os.getenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KID", "")
    file_name = os.getenv("OSOP_SOURCEMAP_RECEIPT_SIGNING_KEY_FILE", "")
    configured = os.getenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "")
    if (
        _KID.fullmatch(kid) is None
        or not 2 <= len(configured) <= 65536
        or type(file_name) is not str
        or not 1 <= len(file_name) <= 1024
    ):
        raise SourceMapDenied()
    try:
        trusted = json.loads(configured, object_pairs_hook=_unique)
        server = trusted.get("source-map-mcp") if type(trusted) is dict else None
        if type(server) is not dict or not 1 <= len(server) <= 32:
            raise SourceMapDenied()
        encoded = server.get(kid)
        if type(encoded) is not str or len(encoded) != 44:
            raise SourceMapDenied()
        expected = base64.b64decode(encoded, validate=True)
        if len(expected) != 32 or base64.b64encode(expected).decode("ascii") != encoded:
            raise SourceMapDenied()
        path = Path(file_name)
        parent = _trusted_path(str(path.parent))
        if not path.is_absolute() or path.parent != parent or path.is_symlink():
            raise SourceMapDenied()
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != 32
            or (os.name == "posix" and (before.st_uid != os.getuid() or before.st_mode & 0o077))
            or (
                os.name == "nt"
                and (
                    before.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
                    or not before.st_file_attributes & stat.FILE_ATTRIBUTE_READONLY
                )
            )
        ):
            raise SourceMapDenied()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            actual = os.fstat(stream.fileno())
            key_bytes = stream.read(33)
            after = os.fstat(stream.fileno())
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns)
            or (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(key_bytes) != 32
        ):
            raise SourceMapDenied()
        signer = Ed25519PrivateKey.from_private_bytes(key_bytes)
        public = signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if public in source_issuers.values() or not hmac.compare_digest(public, expected):
            raise SourceMapDenied()
        return kid, signer
    except (
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        UnicodeError,
        base64.binascii.Error,
    ) as exc:
        raise SourceMapDenied() from exc


def _signed_native_receipt(
    bound: dict[str, str], signer: tuple[str, Ed25519PrivateKey]
) -> dict[str, Any]:
    status = {
        "request_id": bound["request_id"],
        "engagement_id": bound["engagement_id"],
        "task_id": bound["task_id"],
        "server_id": "source-map-mcp",
        "status": "succeeded",
        "verified": True,
        "stopped": False,
        "issued_at": int(time.time()),
    }
    # Exactly the eight fields and UTF-8 canonicalization consumed by core
    # receipt_attestation.py; this receipt asserts native processing only.
    raw = json.dumps(
        status, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    signature = signer[1].sign(raw)
    return {
        **status,
        "attestation": {
            "kid": signer[0],
            "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        },
    }


def _persist_native_receipt(
    directory: Path,
    claims: dict[str, Any],
    result: dict[str, Any],
    provider_receipt: dict[str, Any],
) -> None:
    """Persist the processed metadata and attested status before acknowledging.

    An exclusive record is bound to the centrally issued original Action.
    Failed writes leave the Action consumed and UNKNOWN. No retry is attempted.
    """
    evidence = {
        "preflight_id": claims["preflight_id"],
        "action_id": claims["action_id"],
        "artifact_sha256": claims["artifact_sha256"],
        "metadata": result,
        "provider_receipt": provider_receipt,
    }
    raw = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > 65536:
        raise SourceMapDenied()
    name = "completed-" + hashlib.sha256(claims["action_id"].encode("ascii")).hexdigest() + ".json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(directory / name, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError as exc:
        raise SourceMapDenied() from exc


def _fsynced_exclusive_json(directory: Path, filename: str, value: dict[str, Any]) -> None:
    """An index is durable only once its completed Action receipt is durable."""
    raw = _canonical(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(directory / filename, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            folder = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(folder)
            finally:
                os.close(folder)
    except OSError as exc:
        raise SourceMapDenied() from exc


def _journal_filename(prefix: str, identifier: str, suffix: str) -> str:
    return prefix + hashlib.sha256(identifier.encode("ascii")).hexdigest() + suffix


def _read_journal_file(filename: Path, *, max_bytes: int) -> bytes:
    """Read twice from one regular, single-linked fd; no path-following or races."""
    try:
        before = filename.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= max_bytes
            or (os.name == "posix" and (before.st_uid != os.getuid() or before.st_mode & 0o077))
            or (os.name == "nt" and before.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        ):
            raise SourceMapDenied()
        fd = os.open(
            filename, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        with os.fdopen(fd, "rb") as stream:
            actual = os.fstat(stream.fileno())
            one = stream.read(max_bytes + 1)
            stream.seek(0)
            two = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        if (
            not stat.S_ISREG(actual.st_mode)
            or actual.st_nlink != 1
            or identity(before) != identity(actual)
            or identity(actual) != identity(after)
            or len(one) != before.st_size
            or one != two
        ):
            raise SourceMapDenied()
        return one
    except OSError as exc:
        raise SourceMapDenied() from exc


def _journal_json(path: Path, *, max_bytes: int) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_journal_file(path, max_bytes=max_bytes),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(SourceMapDenied()),
        )
        if type(value) is not dict:
            raise SourceMapDenied()
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise SourceMapDenied() from exc


def _persist_request_index(directory: Path, source: dict[str, Any]) -> None:
    if set(source) != _SOURCE_CLAIMS or _REQUEST.fullmatch(source["request_id"]) is None:
        raise SourceMapDenied()
    _fsynced_exclusive_json(
        directory,
        _journal_filename("request-index-", source["request_id"], ".json"),
        {"original_claims": source},
    )


def _source_binding(request: MCPExecuteRequest) -> dict[str, str]:
    binding = request.execution_binding
    if (
        type(binding) is not dict
        or set(binding) != {"request_id", "engagement_id", "task_id", "server_id"}
        or type(request.request_id) is not str
        or _REQUEST.fullmatch(request.request_id) is None
        or any(type(value) is not str for value in binding.values())
        or binding["request_id"] != request.request_id
        or not binding["engagement_id"].startswith("eng-")
        or not binding["task_id"].startswith("task-")
        or any(_IDENTITY.fullmatch(binding[key]) is None for key in ("engagement_id", "task_id"))
        or binding["server_id"] != "source-map-mcp"
    ):
        raise SourceMapDenied()
    return binding


def _native_caller(authorization: Optional[str]) -> None:
    """A separate native-client principal, never the central service bearer."""
    native = os.environ.get("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", "")
    central = os.environ.get("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", "")
    mode = os.environ.get("OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE", "")
    if mode == "host-stage-v1":
        # The STATUS credential can only revalidate committed authority.
        # An issuer bearer, issuer URL, or ambiguous mixed mode is forbidden.
        if central or os.getenv("OSOP_SOURCEMAP_SOURCE_URL", ""):
            raise SourceMapDenied()
        central = os.environ.get("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", "")
    elif mode:
        raise SourceMapDenied()
    if (
        type(authorization) is not str
        or not authorization.startswith("Bearer ")
        or len(authorization) > 520
        or not 32 <= len(native) <= 512
        or not 32 <= len(central) <= 512
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in native + central)
        or hmac.compare_digest(native, central)
        or not hmac.compare_digest(authorization[7:], native)
    ):
        raise SourceMapDenied()


def _source_proof(token: Any, expected: dict[str, str], roots: dict[str, bytes]) -> dict[str, Any]:
    if (
        type(token) is not dict
        or set(token) != {"claims", "kid", "signature"}
        or type(token["claims"]) is not dict
        or set(token["claims"]) != _SOURCE_CLAIMS
        or type(token["kid"]) is not str
        or token["kid"] not in roots
    ):
        raise SourceMapDenied()
    claims = token["claims"]
    now = int(time.time())
    if (
        any(
            type(claims.get(key)) is not str or claims[key] != value
            for key, value in expected.items()
        )
        or type(claims["version"]) is not int
        or claims["version"] != 1
        or type(claims["authorization_version"]) is not int
        or claims["authorization_version"] < 1
        or type(claims["issued_at"]) is not int
        or type(claims["expires_at"]) is not int
        or not now - 5 <= claims["issued_at"] <= now + 2
        or not now < claims["expires_at"] <= claims["issued_at"] + 10
        or type(claims["preflight_id"]) is not str
        or re.fullmatch(r"nsp-[a-f0-9]{32}", claims["preflight_id"]) is None
        or any(
            type(claims[k]) is not str or _SHA.fullmatch(claims[k]) is None
            for k in ("manifest_sha256", "authorization_sha256")
        )
        or any(
            type(claims[k]) is not str or _IDENTITY.fullmatch(claims[k]) is None
            for k in ("flow_id", "subtask_id", "owner_id", "approval_id", "lease_id")
        )
        or type(claims["action_id"]) is not str
        or _ACTION.fullmatch(claims["action_id"]) is None
    ):
        raise SourceMapDenied()
    signature = token["signature"]
    if type(signature) is not str or re.fullmatch(r"[A-Za-z0-9_-]{86}", signature) is None:
        raise SourceMapDenied()
    try:
        decoded = base64.urlsafe_b64decode(signature + "==")
    except (ValueError, base64.binascii.Error) as exc:
        raise SourceMapDenied() from exc
    if (
        len(decoded) != 64
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != signature
    ):
        raise SourceMapDenied()
    try:
        Ed25519PublicKey.from_public_bytes(roots[token["kid"]]).verify(
            decoded, _SOURCE_DOMAIN + _canonical(claims)
        )
    except Exception as exc:
        raise SourceMapDenied() from exc
    return claims


def _preissued_host_proof(
    source_proof: dict[str, Any],
    provision: Any,
    source: dict[str, Any],
    host_roots: dict[str, bytes],
) -> dict[str, Any]:
    """Bind the independent host signer to the exact 0035 Ed25519 signature."""
    if (
        type(provision) is not dict
        or set(provision) != {"claims", "kid", "signature"}
        or type(provision["claims"]) is not dict
        or set(provision["claims"]) != _SOURCE_CLAIMS | {"stage_id", "source_proof_sha256"}
        or type(provision["kid"]) is not str
        or provision["kid"] not in host_roots
    ):
        raise SourceMapDenied()
    stage = provision["claims"]
    original_signature = source_proof["signature"]
    try:
        decoded_source = base64.urlsafe_b64decode(original_signature + "==")
    except (ValueError, TypeError, base64.binascii.Error) as exc:
        raise SourceMapDenied() from exc
    proof_hash = hashlib.sha256(_SOURCE_DOMAIN + _canonical(source) + decoded_source).hexdigest()
    if (
        type(stage["version"]) is not int
        or stage["version"] != 1
        or type(stage["stage_id"]) is not str
        or re.fullmatch(r"sms-[a-f0-9]{32}", stage["stage_id"]) is None
        or type(stage["source_proof_sha256"]) is not str
        or not hmac.compare_digest(stage["source_proof_sha256"], proof_hash)
        or any(
            type(stage[field]) is not type(source[field]) or stage[field] != source[field]
            for field in _SOURCE_CLAIMS - {"issued_at", "expires_at"}
        )
        or type(stage["issued_at"]) is not int
        or type(stage["expires_at"]) is not int
        or not source["issued_at"] <= stage["issued_at"] < source["expires_at"]
        or not stage["issued_at"] <= int(time.time()) < stage["expires_at"]
        or stage["expires_at"] > source["expires_at"]
    ):
        raise SourceMapDenied()
    signature = provision["signature"]
    if type(signature) is not str or re.fullmatch(r"[A-Za-z0-9_-]{86}", signature) is None:
        raise SourceMapDenied()
    try:
        raw = base64.urlsafe_b64decode(signature + "==")
        if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != signature:
            raise SourceMapDenied()
        Ed25519PublicKey.from_public_bytes(host_roots[provision["kid"]]).verify(
            raw, _HOST_STAGE_DOMAIN + _canonical(stage)
        )
    except (InvalidSignature, ValueError, TypeError, base64.binascii.Error) as exc:
        raise SourceMapDenied() from exc
    return stage


def _preissued_source_handoff(
    bound: dict[str, str],
    artifact_sha256: str,
    config: tuple[str, str, str, dict[str, bytes], Path, Path],
    host_roots: dict[str, bytes],
) -> dict[str, Any]:
    """Read fixed host-authenticated sidecar, never mint another 0035 issuance."""
    root = config[4]
    sidecar = root / (artifact_sha256 + ".proof.json")
    try:
        info = sidecar.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o222:
            raise SourceMapDenied()
        envelope = _journal_json(sidecar, max_bytes=8192)
    except OSError as exc:
        raise SourceMapDenied() from exc
    if (
        set(envelope) != {"version", "source_proof", "provision_proof"}
        or type(envelope["version"]) is not int
        or envelope["version"] != 1
    ):
        raise SourceMapDenied()
    original_proof = envelope["source_proof"]
    expected = {
        **bound,
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": artifact_sha256,
    }
    if set(expected) != _SOURCE_REQUEST:
        raise SourceMapDenied()
    source = _source_proof(original_proof, expected, config[3])
    stage = _preissued_host_proof(original_proof, envelope["provision_proof"], source, host_roots)
    for field in ("action_id", "request_id", "preflight_id", "stage_id"):
        identifier = stage[field]
        if type(identifier) is not str:
            raise SourceMapDenied()
        tombstone = root / (
            ".used-" + field + "-" + hashlib.sha256(identifier.encode("ascii")).hexdigest()
        )
        try:
            recorded = tombstone.lstat()
            if (
                not stat.S_ISREG(recorded.st_mode)
                or recorded.st_nlink != 1
                or recorded.st_mode & 0o222
                or _read_journal_file(tombstone, max_bytes=16) != b"consumed\n"
            ):
                raise SourceMapDenied()
        except OSError as exc:
            raise SourceMapDenied() from exc
    return source


def _status_proof(token: Any, expected: dict[str, Any], roots: dict[str, bytes]) -> dict[str, Any]:
    """Verify fresh, domain-separated central authority over the ORIGINAL Action."""
    if (
        type(token) is not dict
        or set(token) != {"claims", "kid", "signature"}
        or type(token["claims"]) is not dict
        or set(token["claims"]) != _STATUS_CLAIMS
        or type(token["kid"]) is not str
        or token["kid"] not in roots
    ):
        raise SourceMapDenied()
    claims = token["claims"]
    now = int(time.time())
    if (
        any(
            type(claims.get(key)) is not type(value) or claims[key] != value
            for key, value in expected.items()
        )
        or claims["version"] != 1
        or type(claims["status_id"]) is not str
        or re.fullmatch(r"nss-[a-f0-9]{32}", claims["status_id"]) is None
        or type(claims["issued_at"]) is not int
        or type(claims["expires_at"]) is not int
        or not now - 2 <= claims["issued_at"] <= now + 2
        or not now < claims["expires_at"] <= claims["issued_at"] + 5
    ):
        raise SourceMapDenied()
    signature = token["signature"]
    if type(signature) is not str or re.fullmatch(r"[A-Za-z0-9_-]{86}", signature) is None:
        raise SourceMapDenied()
    try:
        decoded = base64.urlsafe_b64decode(signature + "==")
        if (
            len(decoded) != 64
            or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != signature
        ):
            raise SourceMapDenied()
        Ed25519PublicKey.from_public_bytes(roots[token["kid"]]).verify(
            decoded, _STATUS_DOMAIN + _canonical(claims)
        )
    except (InvalidSignature, ValueError, TypeError, base64.binascii.Error) as exc:
        raise SourceMapDenied() from exc
    return claims


async def _central_original_status(
    bound: dict[str, str],
    original: dict[str, Any],
    config: tuple[str, str, str, dict[str, bytes], Path, Path],
) -> dict[str, Any]:
    status_endpoint, status_bearer = _status_transport_config(config)
    expected_request = {
        **bound,
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": original["artifact_sha256"],
    }
    if set(expected_request) != _SOURCE_REQUEST:
        raise SourceMapDenied()
    try:
        async with httpx.AsyncClient(
            verify=config[1],
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(3.0, connect=2.0),
        ) as client:
            response = await client.post(
                status_endpoint,
                json=expected_request,
                headers={"Authorization": "Bearer " + status_bearer, "Cache-Control": "no-store"},
                follow_redirects=False,
            )
            if response.status_code != 200 or len(response.content) > 4096:
                raise SourceMapUnavailable()
            signed = json.loads(
                response.content,
                object_pairs_hook=_unique,
                parse_constant=lambda _: (_ for _ in ()).throw(SourceMapDenied()),
            )
            # Original issue/expiry were for ONE execution. Status has a
            # completely new five-second issuance without resurrecting it.
            same_original = {
                key: value
                for key, value in original.items()
                if key not in {"issued_at", "expires_at"}
            }
            return _status_proof(signed, same_original, config[3])
    except (httpx.HTTPError, ValueError, UnicodeError, SourceMapDenied) as exc:
        raise SourceMapUnavailable() from exc


def _completed_original_status(
    directory: Path,
    bound: dict[str, str],
    signer: tuple[str, Ed25519PrivateKey],
) -> dict[str, Any]:
    index = _journal_json(
        directory / _journal_filename("request-index-", bound["request_id"], ".json"),
        max_bytes=4096,
    )
    if set(index) != {"original_claims"} or type(index["original_claims"]) is not dict:
        raise SourceMapDenied()
    original = index["original_claims"]
    if (
        set(original) != _SOURCE_CLAIMS
        or original["version"] != 1
        or any(original.get(key) != value for key, value in bound.items())
        or original["server_id"] != "source-map-mcp"
        or original["tool_name"] != "inspect_local_original_sourcemap"
        or type(original["artifact_sha256"]) is not str
        or _SHA.fullmatch(original["artifact_sha256"]) is None
        or type(original["action_id"]) is not str
        or _ACTION.fullmatch(original["action_id"]) is None
        or type(original["preflight_id"]) is not str
        or re.fullmatch(r"nsp-[a-f0-9]{32}", original["preflight_id"]) is None
        or type(original["issued_at"]) is not int
        or type(original["expires_at"]) is not int
        or not 0 < original["expires_at"] - original["issued_at"] <= 10
    ):
        raise SourceMapDenied()
    # Original issuance is immutable; both one-use durable marks retain the
    # digest of that SAME 19-field originally validated central source claim.
    expected_digest = hashlib.sha256(_canonical(original)).digest()
    for field in ("request_id", "action_id"):
        used = _read_journal_file(
            directory / _journal_filename(field + "-", original[field], ".used"),
            max_bytes=32,
        )
        if not hmac.compare_digest(used, expected_digest):
            raise SourceMapDenied()
    completed = _journal_json(
        directory / _journal_filename("completed-", original["action_id"], ".json"),
        max_bytes=65536,
    )
    if set(completed) != {
        "preflight_id",
        "action_id",
        "artifact_sha256",
        "metadata",
        "provider_receipt",
    } or any(
        completed.get(field) != original[field]
        for field in ("preflight_id", "action_id", "artifact_sha256")
    ):
        raise SourceMapDenied()
    receipt = completed["provider_receipt"]
    signed_fields = {
        "request_id",
        "engagement_id",
        "task_id",
        "server_id",
        "status",
        "verified",
        "stopped",
        "issued_at",
    }
    if (
        type(receipt) is not dict
        or set(receipt) != signed_fields | {"attestation"}
        or any(receipt.get(key) != value for key, value in bound.items())
        or receipt.get("status") != "succeeded"
        or receipt.get("verified") is not True
        or receipt.get("stopped") is not False
        or type(receipt.get("issued_at")) is not int
        or not original["issued_at"] - 5 <= receipt["issued_at"] <= original["expires_at"] + 2
        or type(receipt["attestation"]) is not dict
        or set(receipt["attestation"]) != {"kid", "signature"}
        or receipt["attestation"]["kid"] != signer[0]
    ):
        raise SourceMapDenied()
    try:
        signature = receipt["attestation"]["signature"]
        if type(signature) is not str or re.fullmatch(r"[A-Za-z0-9_-]{86}", signature) is None:
            raise SourceMapDenied()
        decoded = base64.urlsafe_b64decode(signature + "==")
        if (
            len(decoded) != 64
            or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != signature
        ):
            raise SourceMapDenied()
        raw = json.dumps(
            {key: receipt[key] for key in signed_fields},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        signer[1].public_key().verify(decoded, raw)
    except (InvalidSignature, ValueError, TypeError, base64.binascii.Error) as exc:
        raise SourceMapDenied() from exc
    return original


def _status_binding(request: MCPStatusRequest) -> dict[str, str]:
    bound = request.model_dump()
    if (
        set(bound) != {"request_id", "engagement_id", "task_id", "server_id"}
        or _REQUEST.fullmatch(bound["request_id"]) is None
        or not bound["engagement_id"].startswith("eng-")
        or not bound["task_id"].startswith("task-")
        or any(_IDENTITY.fullmatch(bound[key]) is None for key in ("engagement_id", "task_id"))
        or bound["server_id"] != "source-map-mcp"
    ):
        raise SourceMapDenied()
    return bound


@app.post("/mcp/request/status", response_model=None)
async def mcp_request_status(
    req: MCPStatusRequest, authorization: Optional[str] = Header(default=None)
) -> Union[Dict[str, Any], JSONResponse]:
    """No original-byte read or execution. Revalidate current central authority."""
    try:
        _native_caller(authorization)
        bound = _status_binding(req)
        config = _local_original_config()
        _status_transport_config(config)
        signer = _native_receipt_signer(config[3])
        original = _completed_original_status(config[5], bound, signer)
        status = await _central_original_status(bound, original, config)
        if int(time.time()) >= status["expires_at"]:
            raise SourceMapUnavailable()
        # Fresh native signed testimony about the VALIDATED completed record.
        # Its issue time is new; no scanner, file read, or original grant replay.
        return _signed_native_receipt(bound, signer)
    except (SourceMapDenied, SourceMapUnavailable, OSError, ValueError, TypeError):
        return JSONResponse(
            status_code=503,
            content={"request_id": req.request_id, "status": "unknown"},
        )


async def _central_original_source(
    bound: dict[str, str],
    digest: str,
    config: tuple[str, str, str, dict[str, bytes], Path, Path],
) -> dict[str, Any]:
    if os.getenv("OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE", ""):
        # Defensive fence even for direct helper callers: never issue a second
        # globally unique 0035 original preflight from a staged native worker.
        raise SourceMapDenied()
    endpoint, ca, service, roots, _, _ = config
    expected = {
        **bound,
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": digest,
    }
    if set(expected) != _SOURCE_REQUEST:
        raise SourceMapDenied()
    try:
        async with httpx.AsyncClient(
            verify=ca,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(3.0, connect=2.0),
        ) as client:
            # A single server-side authorization transaction: never retry a
            # committed one-shot if the response/ACK is lost.
            response = await client.post(
                endpoint,
                json=expected,
                headers={"Authorization": "Bearer " + service, "Cache-Control": "no-store"},
                follow_redirects=False,
            )
            if response.status_code != 200 or len(response.content) > 4096:
                raise SourceMapUnavailable()
            envelope = json.loads(
                response.content,
                object_pairs_hook=_unique,
                parse_constant=lambda _: (_ for _ in ()).throw(SourceMapDenied()),
            )
            return _source_proof(envelope, expected, roots)
    except (httpx.HTTPError, ValueError, UnicodeError, SourceMapDenied) as exc:
        raise SourceMapUnavailable() from exc


def _reserve_original_once(directory: Path, claims: dict[str, Any]) -> None:
    """Two durable exclusive indexes for Action and request, no recovery replay."""
    for field in ("request_id", "action_id"):
        digest = hashlib.sha256(claims[field].encode("ascii")).hexdigest()
        name = f"{field}-{digest}.used"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(directory / name, flags, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(hashlib.sha256(_canonical(claims)).digest())
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise SourceMapDenied() from exc


def _read_original_bytes(root: Path, digest: str) -> bytes:
    """Content-addressed, regular, single-linked immutable original artifact."""
    if _SHA.fullmatch(digest) is None:
        raise SourceMapDenied()
    path = root / (digest + ".map")
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= _MAX_RESPONSE_BYTES
            or (os.name == "posix" and before.st_mode & 0o222)
            or (os.name == "nt" and not before.st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
            or (os.name == "nt" and before.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        ):
            raise SourceMapDenied()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            actual = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(actual.st_mode)
                or actual.st_nlink != 1
                or (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino)
                or actual.st_size != before.st_size
            ):
                raise SourceMapDenied()
            data = stream.read(_MAX_RESPONSE_BYTES + 1)
            stream.seek(0)
            reread = stream.read(_MAX_RESPONSE_BYTES + 1)
            after = os.fstat(stream.fileno())
            if (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) or data != reread:
                raise SourceMapDenied()
        if len(data) != before.st_size or hashlib.sha256(data).hexdigest() != digest:
            raise SourceMapDenied()
        return data
    except OSError as exc:
        raise SourceMapDenied() from exc


def _inspect_original_map(data: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise SourceMapDenied() from exc
    if (
        type(parsed) is not dict
        or type(parsed.get("version")) is not int
        or parsed["version"] != 3
        or type(parsed.get("sources")) is not list
        or type(parsed.get("sourcesContent")) is not list
        or not 1 <= len(parsed["sources"]) <= _MAX_SOURCES
        or len(parsed["sources"]) != len(parsed["sourcesContent"])
        or any(type(name) is not str or len(name) > 2048 for name in parsed["sources"])
        or any(
            type(contents) is not str or len(contents) > _MAX_RESPONSE_BYTES
            for contents in parsed["sourcesContent"]
        )
    ):
        raise SourceMapDenied()
    findings = [
        _inspect_content(f"source_{index}.js", source)
        for index, source in enumerate(parsed["sourcesContent"])
    ]
    return {
        "sources": [finding["file"] for finding in findings],
        "findings": findings,
        "source_count": len(findings),
        "credentials_disclosed": False,
        "source_side_signed_authorization_verified": True,
        "source_original_bytes_sha256_verified": True,
    }


async def _inspect_trusted_local_original(
    request: MCPExecuteRequest,
) -> tuple[dict[str, Any], dict[str, Any]]:
    bound = _source_binding(request)
    params = request.parameters
    if (
        type(params) is not dict
        or set(params) != {"artifact_sha256"}
        or type(params["artifact_sha256"]) is not str
        or _SHA.fullmatch(params["artifact_sha256"]) is None
    ):
        raise SourceMapDenied()
    config = _local_original_config()
    # Missing, swapped or unenrolled native signing credentials deny the
    # request before central preflight or any original artifact filesystem read.
    signer = _native_receipt_signer(config[3])
    host_roots = _preissued_handoff_roots(config)
    if host_roots is None:
        receipt = await _central_original_source(bound, params["artifact_sha256"], config)
    else:
        # Host mode consumes the existing committed 0035 proof. There is NO
        # network issuer call or fallback on absent/invalid host handoff.
        receipt = _preissued_source_handoff(bound, params["artifact_sha256"], config, host_roots)
        # A signed proof can become stale after staging. Recheck the SAME
        # committed 0035 Action through the non-consuming central status gate.
        current = await _central_original_status(bound, receipt, config)
        if int(time.time()) >= current["expires_at"]:
            raise SourceMapUnavailable()
    # Source central proof MUST precede all filesystem read and must be
    # unique even after a lost/unknown native ACK.
    _reserve_original_once(config[5], receipt)
    content = _read_original_bytes(config[4], params["artifact_sha256"])
    result = _inspect_original_map(content)
    # Processing cannot extend a short-lived reviewer/lease authorization.
    # Expiration after the original read leaves the one-shot permanently used.
    if int(time.time()) >= receipt["expires_at"]:
        raise SourceMapUnavailable()
    provider_receipt = _signed_native_receipt(bound, signer)
    _persist_native_receipt(config[5], receipt, result, provider_receipt)
    # A failed/missing index leaves the Action consumed and UNKNOWN, never
    # an HTTP 200 whose future status cannot be safely recovered.
    _persist_request_index(config[5], receipt)
    return result, provider_receipt


def _allowlisted_hosts() -> frozenset[str]:
    """Only exact DNS names from a trusted process environment; no wildcards."""
    supplied = os.environ.get("OSOP_SOURCEMAP_ALLOWED_HOSTS", "")
    if len(supplied) > 4096:
        raise SourceMapDenied()
    labels = [label.strip().lower() for label in supplied.split(",") if label.strip()]
    if len(labels) > 32 or any(
        not label.isascii() or "xn--" in label or _DOMAIN.fullmatch(label) is None
        for label in labels
    ):
        raise SourceMapDenied()
    return frozenset(labels)


def _allowlist_configured() -> bool:
    try:
        return bool(_allowlisted_hosts())
    except SourceMapDenied:
        return False


def _validated_url(raw: Any, *, initial_host: Optional[str] = None) -> tuple[str, str]:
    if (
        type(raw) is not str
        or not raw
        or len(raw.encode("utf-8", errors="ignore")) > _INPUT_BYTES
        or not raw.isascii()
        or any(ord(character) < 0x21 or character == "\\" for character in raw)
    ):
        raise SourceMapDenied()
    try:
        uri = urlsplit(raw)
        host = uri.hostname
        port = uri.port
    except ValueError as exc:
        raise SourceMapDenied() from exc
    if (
        uri.scheme != "https"
        or not host
        or not host.isascii()
        or "xn--" in host.lower()
        or _DOMAIN.fullmatch(host.lower()) is None
        or uri.username is not None
        or uri.password is not None
        or (port is not None and port != 443)
        or uri.fragment
        or uri.query
        or (initial_host is not None and host.lower() != initial_host)
        or host.lower() not in _allowlisted_hosts()
    ):
        raise SourceMapDenied()
    return raw, host.lower()


async def _resolve_public_ip(host: str) -> str:
    """Validate *all* DNS replies; pick a public address that will be TCP-pinned."""
    try:
        results = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            ),
            timeout=2.0,
        )
        addresses = {ipaddress.ip_address(result[4][0]) for result in results}
        if not addresses or len(addresses) > 24:
            raise SourceMapDenied()
        if any(
            not address.is_global
            or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)
            for address in addresses
        ):
            raise SourceMapDenied()
        # Deterministic address pinning. The DNS name is *not* resolved again
        # by HTTPX: direct IP transport + original Host and TLS SNI.
        return sorted(addresses, key=lambda address: (address.version, str(address)))[0].compressed
    except (OSError, asyncio.TimeoutError, ValueError) as exc:
        raise SourceMapDenied() from exc


async def _fetch_public_https(url: str, *, initial_host: Optional[str] = None) -> str:
    validated, hostname = _validated_url(url, initial_host=initial_host)
    ip = await _resolve_public_ip(hostname)
    # Replacing host with vetted IP forces network stack to connect to that IP.
    # Original DNS hostname is retained for HTTP Host and TLS certificate/SNI.
    pinned = httpx.URL(validated).copy_with(host=ip)
    try:
        async with httpx.AsyncClient(
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(5.0, connect=2.0),
        ) as client:
            async with client.stream(
                "GET",
                pinned,
                headers={"Host": hostname},
                extensions={"sni_hostname": hostname},
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    raise SourceMapUnavailable()
                content_length = response.headers.get("content-length", "")
                if content_length and (
                    not content_length.isdecimal() or int(content_length) > _MAX_RESPONSE_BYTES
                ):
                    raise SourceMapUnavailable()
                received = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(received) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise SourceMapUnavailable()
                    received.extend(chunk)
                return received.decode("utf-8", errors="replace")
    except (httpx.HTTPError, UnicodeError, ValueError) as exc:
        raise SourceMapUnavailable() from exc


def _display_filename(candidate: Any, index: int) -> str:
    # Source filenames may themselves be API keys, user names or private URLs.
    # Do not echo even apparently harmless basenames from untrusted source maps.
    return f"source_{index}.js"


def _inspect_content(name: str, contents: str) -> dict[str, Any]:
    if len(contents) > _MAX_RESPONSE_BYTES:
        raise SourceMapUnavailable()
    found = Counter(
        {
            label: sum(1 for _ in expression.finditer(contents))
            for label, expression in _PATTERNS.items()
        }
    )
    return {
        "file": name,
        "secret_type_counts": {label: min(found[label], 1000) for label in _PATTERNS},
    }


async def analyze_sourcemap(url: str) -> Dict[str, Any]:
    """No secret content or raw upstream/network diagnostics cross this boundary."""
    validated, host = _validated_url(url)
    content = await _fetch_public_https(validated)
    # A JS sourceMappingURL can point only to another separately validated,
    # allowlisted URL on the *same host*, with independent pinned DNS validation.
    if urlsplit(validated).path.lower().endswith(".js"):
        match = _SOURCE_MAP.search(content)
        if match:
            next_url = urljoin(validated, match.group(1).strip())
            _validated_url(next_url, initial_host=host)
            content = await _fetch_public_https(next_url, initial_host=host)
    try:
        metadata = json.loads(content)
    except (ValueError, TypeError):
        return {
            "sources": [_display_filename(urlsplit(validated).path, 0)],
            "findings": [_inspect_content("source_0.js", content)],
            "source_count": 1,
            "credentials_disclosed": False,
            "source_side_signed_authorization_verified": False,
        }
    if not isinstance(metadata, dict):
        raise SourceMapUnavailable()
    filenames = metadata.get("sources", [])
    sources = metadata.get("sourcesContent", [])
    if (
        not isinstance(filenames, list)
        or not isinstance(sources, list)
        or len(filenames) > _MAX_SOURCES
        or len(sources) > _MAX_SOURCES
    ):
        raise SourceMapUnavailable()
    inspected = [
        _inspect_content(
            _display_filename(filenames[index] if index < len(filenames) else None, index), source
        )
        for index, source in enumerate(sources)
        if isinstance(source, str)
    ]
    return {
        "sources": [entry["file"] for entry in inspected],
        "findings": inspected,
        "source_count": len(inspected),
        "credentials_disclosed": False,
        "source_side_signed_authorization_verified": False,
    }


@app.post("/mcp/execute", response_model=None)
async def mcp_execute(
    req: MCPExecuteRequest, authorization: Optional[str] = Header(default=None)
) -> Union[Dict[str, Any], JSONResponse]:
    request_id = (
        req.request_id
        if req.request_id and re.fullmatch(r"req-[A-Za-z0-9_-]{1,120}", req.request_id)
        else f"req-{uuid.uuid4().hex}"
    )
    if req.tool_name == "inspect_local_original_sourcemap":
        try:
            _native_caller(authorization)
            result, receipt = await _inspect_trusted_local_original(req)
            return {
                "request_id": request_id,
                "status": "success",
                "result": result,
                "provider_receipt": receipt,
            }
        except (SourceMapDenied, SourceMapUnavailable, OSError, ValueError, TypeError):
            # This includes a central 404/503, missing trust, malformed artifact,
            # one-use conflict, lost ACK, invalid receipt and local storage errors.
            return JSONResponse(
                status_code=503,
                content={
                    "request_id": request_id,
                    "status": "error",
                    "error": "signed_original_source_unavailable",
                },
            )
    if req.tool_name != "fetch_and_parse_sourcemap":
        return {"request_id": request_id, "status": "error", "error": "unsupported_tool"}
    params = req.parameters
    if not isinstance(params, dict) or set(params) != {"url"}:
        return {"request_id": request_id, "status": "error", "error": "source_map_input_denied"}
    try:
        # Keep strict, independent input validation. Valid hostnames are still
        # insufficient: there is no trusted, revocation-aware signed Task/Flow
        # authority source in this native service. This check MUST precede DNS,
        # HTTP, and any optional future caller-supplied authorization fields.
        _validated_url(params["url"])
    except SourceMapDenied:
        return {"request_id": request_id, "status": "error", "error": "source_map_input_denied"}
    return JSONResponse(
        status_code=503,
        content={
            "request_id": request_id,
            "status": "error",
            "error": "signed_source_authority_unavailable",
            "execution_enabled": False,
        },
    )


if __name__ == "__main__":
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8096)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
