"""Independently enrolled host-side Browser ORIGINAL byte-custody admission.

This factory never generates signer keys or enables Browser navigation. An
operator-provisioned, distinctly pinned Ed25519 enrollment root signs a
four-artifact immutable manifest (raw HTTP, PNG, DOM, HAR). Its separately
configured custody signer is checked by the existing central CURRENT bridge.
All file reads are host-local, descriptor based, no-follow and read-only.

The legacy Browser provider attests *three* files only; HTTP raw is an
independently enrolled fourth prerequisite. A successful bridge proves
host-original byte comparison, not a target-side HTTP effect or release.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

import httpx

from ai_osop.adapters.native_browser_current_original_bridge import (
    CustodySigner,
    NativeBrowserCurrentOriginalBridge,
    _external_roots,
)
from ai_osop.api.browser_current_custody_readback import (
    BrowserCurrentCustodyReadback,
    OriginalBrowserHostRecord,
)
from ai_osop.memory.browser_source_authority import exact_origin
from ai_osop.orchestrator.browser_current_authority_readback import _verify

ENROLLMENT_DOMAIN = b"ai-osop/browser-host-original-immutable-enrollment/v1\x00"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ENG = re.compile(r"eng-[A-Za-z0-9._:@-]{1,75}\Z")
_REQ = re.compile(r"req-[a-f0-9]{48}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}\Z")
_KIND = {
    "http_raw": ("http", 4 * 1024 * 1024),
    "screenshot": ("png", 4 * 1024 * 1024),
    "dom": ("html", 1024 * 1024),
    "har": ("har", 4 * 1024 * 1024),
}
_IDENTITY = (
    "engagement_id",
    "request_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "preflight_id",
    "authorization_sha256",
    "original_intent_sha256",
    "url_sha256",
)
_CLAIMS = frozenset(
    {
        "version",
        "enrollment_id",
        *_IDENTITY,
        "artifacts",
        "root_path_sha256",
        "issued_at",
        "expires_at",
        "purpose",
    }
)


class BrowserHostEnrollmentDenied(RuntimeError):
    """Independently trusted original bytes or current authority unavailable."""

    def __init__(self) -> None:
        # Fixed, non-attributable denial: no paths, original URLs, keys or bytes.
        super().__init__("Independent Browser original host enrollment unavailable")


def _deny() -> None:
    raise BrowserHostEnrollmentDenied()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _validate_manifest(value: Any) -> dict[str, dict[str, Any]]:
    if type(value) is not dict or set(value) != set(_KIND):
        _deny()
    verified: dict[str, dict[str, Any]] = {}
    for name, (suffix, limit) in _KIND.items():
        item = value[name]
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256", "size_bytes"}
            or type(item["path"]) is not str
            or re.fullmatch(r"captures/[a-f0-9]{32}\." + suffix, item["path"]) is None
            or type(item["sha256"]) is not str
            or not _SHA.fullmatch(item["sha256"])
            or type(item["size_bytes"]) is not int
            or not 0 < item["size_bytes"] <= limit
        ):
            _deny()
        verified[name] = dict(item)
    return verified


def _trusted_host_root(value: Path) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts:
        _deny()
    return value


def _safe_read_posix(root: Path, rel: str, cap: int) -> bytes:
    """Walk from / with directory-relative O_NOFOLLOW FDs; no path reopen."""
    import contextlib

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_flags = flags | os.O_DIRECTORY
    with contextlib.ExitStack() as stack:
        fd = os.open(root.anchor, directory_flags)
        stack.callback(os.close, fd)
        for part in (*root.parts[1:], *rel.split("/")[:-1]):
            if not part or part in {".", ".."}:
                _deny()
            fd = os.open(part, directory_flags, dir_fd=fd)
            stack.callback(os.close, fd)
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                _deny()
        file_fd = os.open(rel.split("/")[-1], flags | os.O_NONBLOCK, dir_fd=fd)
        stack.callback(os.close, file_fd)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o222:
            _deny()
        raw = bytearray()
        while len(raw) <= cap:
            piece = os.read(file_fd, min(65536, cap + 1 - len(raw)))
            if not piece:
                break
            raw.extend(piece)
        end = os.fstat(file_fd)
        if (
            len(raw) < 1
            or len(raw) > cap
            or info.st_size != len(raw)
            or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            != (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns)
        ):
            _deny()
        return bytes(raw)


def _safe_read_windows(root: Path, rel: str, cap: int) -> bytes:
    """Hold each ancestor handle against delete/rename; reject all reparse hops.

    FILE_SHARE_READ excludes write/delete shares while every ancestor handle
    is held. FILE_FLAG_OPEN_REPARSE_POINT rejects junctions and symlinks,
    including the final file. The handle is read directly (no path reopen).
    """
    import contextlib
    import ctypes
    import ctypes.wintypes as wt
    import msvcrt

    FILE_READ_ATTRIBUTES = 0x80
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x1
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_DIRECTORY = 0x10
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_ATTRIBUTE_READONLY = 0x1
    FILETIME = wt.FILETIME

    class FileInfo(ctypes.Structure):
        _fields_ = [
            ("attributes", wt.DWORD),
            ("created", FILETIME),
            ("accessed", FILETIME),
            ("written", FILETIME),
            ("volume", wt.DWORD),
            ("high", wt.DWORD),
            ("low", wt.DWORD),
            ("links", wt.DWORD),
            ("index_high", wt.DWORD),
            ("index_low", wt.DWORD),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        wt.DWORD,
        wt.LPVOID,
        wt.DWORD,
        wt.DWORD,
        wt.HANDLE,
    ]
    kernel.CreateFileW.restype = wt.HANDLE
    kernel.GetFileInformationByHandle.argtypes = [wt.HANDLE, ctypes.POINTER(FileInfo)]
    kernel.GetFileInformationByHandle.restype = wt.BOOL
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    kernel.CloseHandle.restype = wt.BOOL
    # Read-only pinned root; no network paths/UNC shares.
    if (
        not re.fullmatch(r"[A-Za-z]:\\", root.anchor)
        or str(root).startswith("\\\\")
        or ":" in str(root)[2:]
    ):
        _deny()
    parts = (*root.parts[1:], *rel.split("/"))
    current = root.anchor
    with contextlib.ExitStack() as stack:
        for number, part in enumerate(("", *parts)):
            if number:
                if not part or part in {".", ".."} or "\\" in part or "/" in part:
                    _deny()
                current = os.path.join(current, part)
            final = number == len(parts)
            handle = kernel.CreateFileW(
                current,
                GENERIC_READ if final else FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            if handle == ctypes.c_void_p(-1).value or handle is None:
                _deny()
            if not final:
                stack.callback(kernel.CloseHandle, handle)
            info = FileInfo()
            if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
                if final:
                    kernel.CloseHandle(handle)
                _deny()
            if (
                info.attributes & FILE_ATTRIBUTE_REPARSE_POINT
                or bool(info.attributes & FILE_ATTRIBUTE_DIRECTORY) == final
            ):
                if final:
                    kernel.CloseHandle(handle)
                _deny()
            if final:
                if info.links != 1 or not info.attributes & FILE_ATTRIBUTE_READONLY:
                    kernel.CloseHandle(handle)
                    _deny()
                # open_osfhandle assumes ownership, and os.fdopen closes it.
                fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
                with os.fdopen(fd, "rb", closefd=True) as src:
                    before = os.fstat(src.fileno())
                    raw = src.read(cap + 1)
                    after = os.fstat(src.fileno())
                if (
                    not 0 < len(raw) <= cap
                    or before.st_size != len(raw)
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                ):
                    _deny()
                return raw
    _deny()


def _safe_read(root: Path, relative: str, cap: int) -> bytes:
    # The caller supplies a trusted regex-validated signed relative filename.
    try:
        if os.name == "nt":
            return _safe_read_windows(root, relative, cap)
        if os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"):
            return _safe_read_posix(root, relative, cap)
    except (OSError, ValueError, OverflowError, TypeError):
        _deny()
    _deny()


@dataclass(frozen=True)
class EnrolledBrowserOriginal:
    """Host-pinned original record; never constructed from operator HTTP."""

    original: OriginalBrowserHostRecord
    signed_enrollment: Mapping[str, Any]


class BrowserHostOriginalEnrollment:
    """Bind independent host-pinned originals to the existing CURRENT bridge."""

    def __init__(
        self,
        *,
        host_root: Path,
        records: Mapping[tuple[str, str], EnrolledBrowserOriginal],
        enrollment_roots: Mapping[str, bytes],
        custody_roots: Mapping[str, bytes],
        custody_signer: CustodySigner,
        central_client: Optional[httpx.AsyncClient],
        provider_client: Optional[httpx.AsyncClient],
        central_bearer: str,
        provider_bearer: str,
        enabled: bool = False,
    ) -> None:
        self._enabled = enabled
        self._host_root = _trusted_host_root(host_root)
        self._records = records
        self._enrollment_roots = enrollment_roots
        self._custody_roots = custody_roots
        self._custody_signer = custody_signer
        self._central_client = central_client
        self._provider_client = provider_client
        self._central_bearer = central_bearer
        self._provider_bearer = provider_bearer
        # This is configuration validation, never permission to mint signer.
        self._root_identity = _sha(str(self._host_root).encode("utf-8"))

    def _admitted(
        self, key: tuple[str, str]
    ) -> tuple[OriginalBrowserHostRecord, dict[str, dict[str, Any]]]:
        if (
            self._enabled is not True
            or not callable(self._custody_signer)
            or type(self._records) is not dict
            or type(self._enrollment_roots) is not dict
            or type(self._custody_roots) is not dict
            or not self._enrollment_roots
            or not self._custody_roots
        ):
            _deny()
        try:
            signed = self._records[key]
            # Verify distinct, independently configured roots before reading
            # any original bytes; absence/revocation fails closed.
            enrolled = _external_roots(self._enrollment_roots)
            custodian = _external_roots(self._custody_roots)
            if set(enrolled.values()) & set(custodian.values()):
                _deny()
            claims = _verify(signed.signed_enrollment, enrolled, ENROLLMENT_DOMAIN, _CLAIMS)
            original = signed.original
            expected = original.expected
            if (
                not isinstance(original, OriginalBrowserHostRecord)
                or type(expected) is not dict
                or set(expected) != set(_IDENTITY)
                or any(type(v) is not str or not v for v in expected.values())
                or any(claims.get(name) != expected[name] for name in _IDENTITY)
                or claims.get("version") != 1
                or type(claims.get("enrollment_id")) is not str
                or re.fullmatch(r"bhe-[a-f0-9]{32}", claims["enrollment_id"]) is None
                or claims.get("purpose") != "host_immutable_original_bytes_readonly"
                or claims.get("root_path_sha256") != self._root_identity
                or key != (expected["engagement_id"], expected["request_id"])
                or _ENG.fullmatch(key[0]) is None
                or _REQ.fullmatch(key[1]) is None
                or type(original.original_uri) is not str
                or _sha(original.original_uri.encode("utf-8")) != expected["url_sha256"]
                or exact_origin(original.original_uri) != original.source_proof["claims"]["origin"]
                or type(claims.get("issued_at")) is not int
                or type(claims.get("expires_at")) is not int
                or not claims["issued_at"] <= int(time.time()) < claims["expires_at"]
                or not 0 < claims["expires_at"] - claims["issued_at"] <= 86400
            ):
                _deny()
            artifacts = _validate_manifest(claims["artifacts"])
            claimed_provider = original.provider_evidence["claims"]["artifacts"]
            if (
                type(claimed_provider) is not dict
                or set(claimed_provider) != {"screenshot", "dom", "har"}
                or any(
                    claimed_provider[name] != artifacts[name]
                    for name in ("screenshot", "dom", "har")
                )
            ):
                _deny()
            return original, artifacts
        except BrowserHostEnrollmentDenied:
            raise
        except Exception:
            _deny()

    async def host_record_resolver(
        self, engagement_id: str, request_id: str, actor_id: str
    ) -> OriginalBrowserHostRecord:
        if type(actor_id) is not str or not _ID.fullmatch(actor_id):
            _deny()
        original, _ = self._admitted((engagement_id, request_id))
        return original

    async def original_reader(
        self, binding: Mapping[str, str], manifest: Mapping[str, Mapping[str, Any]]
    ) -> Mapping[str, bytes]:
        if (
            type(binding) is not dict
            or set(binding) != {"request_id", "engagement_id", "task_id", "server_id"}
            or binding["server_id"] != "browser-mcp"
            or type(manifest) is not dict
            or set(manifest) != {"screenshot", "dom", "har"}
        ):
            _deny()
        original, enrolled = self._admitted((binding["engagement_id"], binding["request_id"]))
        if (
            original.expected["task_id"] != binding["task_id"]
            or original.source_proof["claims"].get("server_id") != "browser-mcp"
            or any(manifest[name] != enrolled[name] for name in ("screenshot", "dom", "har"))
        ):
            _deny()
        # Check a separately host-enrolled raw original HTTP prerequisite even
        # though the 0034 Browser provider's three-file wire lacks raw HTTP.
        results: dict[str, bytes] = {}
        for name, (_, limit) in _KIND.items():
            item = enrolled[name]
            raw = _safe_read(self._host_root, binding["engagement_id"] + "/" + item["path"], limit)
            if len(raw) != item["size_bytes"] or not hmac.compare_digest(_sha(raw), item["sha256"]):
                _deny()
            results[name] = raw
        # Only the current bridge's exact PNG/DOM/HAR reader interface escapes.
        # HTTP raw never leaves host-owned reader, signer, or API response.
        return {name: results[name] for name in ("screenshot", "dom", "har")}

    async def custody_signer_recheck(self, claims: Mapping[str, Any]) -> Mapping[str, Any]:
        """Read all sealed originals again after the bridge's second CURRENT.

        The bridge calls its signer only after provider-after + central-after.
        Rechecking the fourth raw-HTTP prerequisite here detects mutations
        between the host reader and final independent custody signature.
        Pass only claims, never raw bytes or paths, to the external signer.
        """
        if (
            type(claims) is not dict
            or type(claims.get("engagement_id")) is not str
            or type(claims.get("request_id")) is not str
        ):
            _deny()
        original, sealed = self._admitted((claims["engagement_id"], claims["request_id"]))
        if (
            any(
                claims.get(name) != original.expected[name]
                for name in (
                    "engagement_id",
                    "request_id",
                    "flow_id",
                    "task_id",
                    "subtask_id",
                    "action_id",
                    "owner_id",
                    "preflight_id",
                    "authorization_sha256",
                    "original_intent_sha256",
                )
            )
            or claims.get("target_effect_verified") is not False
            or claims.get("automatic_retry_authorized") is not False
            or claims.get("original_bytes_read") is not True
            or claims.get("purpose") != "host_readonly_original_custody"
        ):
            _deny()
        for name, (_, limit) in _KIND.items():
            item = sealed[name]
            actual = _safe_read(
                self._host_root, claims["engagement_id"] + "/" + item["path"], limit
            )
            if len(actual) != item["size_bytes"] or not hmac.compare_digest(
                _sha(actual), item["sha256"]
            ):
                _deny()
        return await self._custody_signer(claims)

    def service(self) -> BrowserCurrentCustodyReadback:
        # On unavailable host roots or any missing independent attachment,
        # configuration produces a denied service; no registry side effects.
        try:
            if self._enabled is not True:
                _deny()
            _external_roots(self._enrollment_roots)
            _external_roots(self._custody_roots)
            if set(self._enrollment_roots.values()) & set(self._custody_roots.values()):
                _deny()
            if not callable(self._custody_signer) or not self._records:
                _deny()
            bridge = NativeBrowserCurrentOriginalBridge(
                enabled=True,
                central_client=self._central_client,
                provider_client=self._provider_client,
                central_bearer=self._central_bearer,
                provider_bearer=self._provider_bearer,
                original_reader=self.original_reader,
                independent_signer=self.custody_signer_recheck,
                independent_roots=self._custody_roots,
            )
            return BrowserCurrentCustodyReadback(
                enabled=True,
                independent_host_enrolled=True,
                bridge=bridge,
                host_record_resolver=self.host_record_resolver,
            )
        except Exception:
            return BrowserCurrentCustodyReadback()
