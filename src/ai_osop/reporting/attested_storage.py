"""Bounded, read-only retrieval of existing signed reporting-agent bundles.

No untrusted file paths or unsigned fallback. The configured root must be the
same persistent `reports/` directory used by ReportingAgent. The caller must
separately enforce durable owner/senior access and current signed-ROE trust.
"""

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Mapping

from ai_osop.reporting.attestation import (
    ARTIFACT_ALLOWLIST,
    ReportAttestationError,
    _unique_object_pairs,
    verify_report_attestation,
)

_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_FILE_LIMITS = {
    "md": 2_000_000,
    "html": 2_000_000,
    "graph.html": 2_000_000,
    "json": 2_000_000,
    "manifest": 16_384,
    "attestation": 65_536,
}


class AttestedStorageUnavailable(RuntimeError):
    """The configured report bundle cannot be safely retrieved or verified."""


def validated_report_id(session_id: str, report_id: str) -> bool:
    """Only a server-derived reporting-agent name may identify stored files."""
    if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
        return False
    prefix = f"report-{session_id}-"
    return (
        isinstance(report_id, str)
        and report_id.startswith(prefix)
        and bool(_VERSION.fullmatch(report_id[len(prefix) :]))
        and len(report_id) <= 140
    )


def _read_trusted_file(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AttestedStorageUnavailable("Attested report bundle unavailable")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
                raise AttestedStorageUnavailable("Attested report artifact unavailable")
            content = stream.read(limit + 1)
            if len(content) > limit:
                raise AttestedStorageUnavailable("Attested report artifact unavailable")
            return content
    except OSError as exc:
        raise AttestedStorageUnavailable("Attested report artifact unavailable") from exc


def load_attested_bundle(session_id: str, report_id: str) -> Dict[str, Any]:
    """Read strictly named report files from an administrator-chosen root.

    Returns bytes to the trusted server verifier, NOT raw content to clients.
    No directory enumeration, arbitrary path, unsigned report, or auto-index.
    """
    if not validated_report_id(session_id, report_id):
        raise AttestedStorageUnavailable("Attested report identifier is invalid")
    configured = os.environ.get("OSOP_ATTESTED_REPORT_ROOT", "")
    if not configured or not os.path.isabs(configured):
        raise AttestedStorageUnavailable("Attested report storage is not configured")
    try:
        root = Path(configured)
        directory = root / session_id
        if (
            not root.is_dir()
            or root.is_symlink()
            or not directory.is_dir()
            or directory.is_symlink()
            or directory.resolve().parent != root.resolve()
        ):
            raise AttestedStorageUnavailable("Attested report storage unavailable")
        files = {
            extension: _read_trusted_file(directory / f"{report_id}.{extension}", maximum)
            for extension, maximum in _FILE_LIMITS.items()
        }
        envelope = json.loads(files["attestation"], object_pairs_hook=_unique_object_pairs)
        manifest = json.loads(files["manifest"], object_pairs_hook=_unique_object_pairs)
        if not isinstance(envelope, dict) or not isinstance(manifest, dict):
            raise ValueError()
        # The reporting agent writes sorted, compact UTF-8 JSON without a
        # trailing newline. Accepting a semantically reserialized manifest
        # while returning only its parsed object can mask an original-byte
        # custody change before the generation Task receipt is examined.
        # Require the exact format emitted by ReportingAgent for a signed
        # archive, rather than silently accepting changed disk bytes.
        original_manifest = json.dumps(
            manifest,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if files["manifest"] != original_manifest:
            raise ValueError("Original report manifest bytes changed")
        return {
            "artifacts": {ext: files[ext] for ext in ARTIFACT_ALLOWLIST},
            "manifest": manifest,
            "attestation": envelope,
            "attestation_sha256": hashlib.sha256(files["attestation"]).hexdigest(),
            "manifest_sha256": hashlib.sha256(files["manifest"]).hexdigest(),
        }
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise AttestedStorageUnavailable("Attested report bundle unavailable") from exc


def verify_loaded_bundle(
    loaded: Mapping[str, Any],
    *,
    session_id: str,
    report_id: str,
    evidence_by_finding: Mapping[str, Any],
) -> Dict[str, Any]:
    """Verify current signer trust, artifact bytes, manifest and raw evidence.

    The verifier uses only independently provisioned report signer keys. No
    key supplied inside the report is ever trusted as a root of authority.
    """
    try:
        envelope = loaded["attestation"]
        manifest = loaded["manifest"]
        checked = verify_report_attestation(
            envelope,
            artifacts=loaded["artifacts"],
            evidence_by_finding=evidence_by_finding,
        )
        if checked["engagement_id"] != session_id or checked["report_id"] != report_id:
            raise ReportAttestationError("Report engagement identifier mismatch")
        if (
            not isinstance(manifest, dict)
            or set(manifest)
            != {
                "engagement_id",
                "report_id",
                "hash_algorithm",
                "signature_status",
                "artifacts",
                "attestation_sha256",
            }
            or manifest["engagement_id"] != session_id
            or manifest["report_id"] != report_id
            or manifest["hash_algorithm"] != "sha256"
            or manifest["signature_status"] != "ed25519_signed"
            or manifest["artifacts"] != envelope["attestation"]["artifacts"]
            or manifest["attestation_sha256"] != loaded["attestation_sha256"]
        ):
            raise ReportAttestationError("Report manifest integrity mismatch")
        bound = envelope["attestation"].get("generation_binding") is not None
        return {
            "verification": checked,
            "manifest": manifest,
            "signed_attestation": envelope,
            "release_status": (
                "generation_binding_pending_verification" if bound else "draft_snapshot_only"
            ),
            "operator_approval_verified": False,
            "engagement_completion_verified": False,
            "independent_verification": (
                "Signature and bytes checked against the current server trust registry and "
                "durable evidence. No operator report sign-off, exploit success, "
                "source authenticity, or engagement completeness is certified. "
                "Independently verify using an out-of-band trusted public key, "
                "report artifact bytes, and authorized original evidence."
            ),
        }
    except (ReportAttestationError, TypeError, ValueError, KeyError) as exc:
        raise AttestedStorageUnavailable("Attested report verification failed") from exc
