"""Host-only, DB-backed original SourceMap provisioning after source issuance.

This adapter cannot issue a SourceMap 0035 preflight. Native /mcp/execute
currently issues that UNIQUE(request_id, action_id) proof itself. A trusted
coordinator must arrange a *single* committed 0035 proof to reach native and
this host, together with an independently signed host-stage provision proof.
Neither that coordinator nor its independent host signer is wired here.
Calling this module before native's current issuance consumes the sole slot
and would make native fail. Do not use it to pre-issue or replay 0035.

Only a trusted, non-MCP host process may call provision(). Its SQL reads use
the production 0035 _source checks: signed live Flow/ROE/owner, original 0027
UNKNOWN action/dispatch event, current Task/subtask, independent approval,
lease, 0013 BYTEA checksums, 0015 senior review and the original signed Task
resource manifest. The optional 0026 virtual-folder catalog is checked when
present; 0031 native folder offer hashes are *not* SourceMap byte authority.
Caller JSON/paths/bytes never establish authority. The separate host stage
verifies two independent Ed25519 proofs, performs an exclusive POSIX no-link
content-addressed .map write and fsync, and consumes the stage once. On
Windows it denies because equivalent safe directory handles are unavailable.

No INSERT, UPDATE, DELETE, signer, source admission, network fetch or retry.
The row locks used by the existing issuer's _source checker are non-mutating,
but are not compatible with a PostgreSQL READ ONLY transaction setting.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Mapping

from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.sourcemap_source_authority import (
    SourceMapSourceAuthorityStore,
    canonical,
)
from ai_osop.orchestrator.sourcemap_original_stage import (
    OriginalSourceMapHostStage,
    _exclusive,
    _open_root,
    _readback,
    _safe_directory,
    verify_original_stage_proofs,
)


_MAX_ORIGINAL = 1024 * 1024
_MAX_SIDECAR = 8192
_FIELDS = (
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
)


class OriginalSourceMapProvisionDenied(ValueError):
    """No trusted provisioning permission, or source/stage outcome UNKNOWN."""


def _deny() -> None:
    raise OriginalSourceMapProvisionDenied("Original SourceMap provision denied or UNKNOWN")


def _equal(left: Any, right: Any) -> bool:
    """Avoid Python truthy type coercion at a durable identity boundary."""
    return type(left) is type(right) and (
        hmac.compare_digest(left, right) if isinstance(left, (str, bytes)) else left == right
    )


def _signed_original(
    source_proof: Any, host: OriginalSourceMapHostStage, provision: Any
) -> dict[str, Any]:
    # The signer and enrolled roots belong to an isolated supervisor. This
    # module has NO private key and cannot bless a caller's claims.
    return verify_original_stage_proofs(
        source_proof,
        provision,
        host._source_roots,
        host._provision_roots,
    )


async def _committed_and_current_original(
    db: Any,
    actions: FlowMCPActionStore,
    proof: dict[str, Any],
    claims: Mapping[str, Any],
) -> bytes:
    """Verify *existing* issuer row, then recheck current authority and BYTEA.

    _source is reused rather than independently approximating its 0013/0015,
    ROE, reviewed Task, manifest, lease, immutable 0027 event and authorization
    checks. It performs SELECT ... FOR UPDATE but never writes.
    """
    if (
        type(proof) is not dict
        or type(proof.get("claims")) is not dict
        or set(proof["claims"]) != set(_FIELDS)
        or type(claims) is not dict
        or any(not _equal(proof["claims"][key], claims.get(key)) for key in _FIELDS)
    ):
        _deny()
    signed_bytes = canonical(proof["claims"])
    try:
        signature = base64.urlsafe_b64decode(proof["signature"] + "==")
    except (binascii.Error, ValueError, TypeError) as exc:
        raise OriginalSourceMapProvisionDenied("Source signature unavailable") from exc
    if len(signature) != 64:
        _deny()
    saved = (
        (
            await db.execute(
                text(
                    "SELECT * FROM native_sourcemap_source_preflights "
                    "WHERE request_id=:request AND action_id=:action "
                    "AND preflight_id=:preflight FOR SHARE"
                ),
                {
                    "request": claims["request_id"],
                    "action": claims["action_id"],
                    "preflight": claims["preflight_id"],
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if saved is None or any(
        name not in saved or not _equal(saved[name], claims[name]) for name in _FIELDS
    ):
        _deny()
    if (
        not _equal(saved.get("kid"), proof["kid"])
        or not _equal(saved.get("claims_sha256"), hashlib.sha256(signed_bytes).hexdigest())
        or not _equal(saved.get("signature_sha256"), hashlib.sha256(signature).hexdigest())
    ):
        _deny()

    request = {
        key: claims[key]
        for key in (
            "request_id",
            "engagement_id",
            "task_id",
            "server_id",
            "tool_name",
            "artifact_sha256",
        )
    }
    # Issuer source check is read-only here. Never call .admit(), which would
    # consume a second 0035 permission and break the live native handoff.
    original, manifest = await SourceMapSourceAuthorityStore(actions)._source(db, request)
    for key in (
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "owner_id",
        "server_id",
        "tool_name",
        "approval_id",
        "lease_id",
        "authorization_version",
        "authorization_sha256",
    ):
        if not _equal(original.get(key), claims[key]):
            _deny()
    if not _equal(manifest, claims["manifest_sha256"]):
        _deny()

    # The 0026 metadata-only folder catalog is optional; when present it must
    # still refer to this exact signed owner/Flow/manifest. The 0031
    # native_mcp_resource_offers.folder_staging_sha256 is *not* permission to
    # stage a SourceMap .map and is never accepted as one.
    folder = (
        (
            await db.execute(
                text(
                    "SELECT flow_id,engagement_id,owner_sub,flow_revision,"
                    "authorization_id,authorization_version,authorization_sha256,"
                    "manifest_sha256 FROM flow_resource_folder_catalogs "
                    "WHERE flow_id=:flow AND engagement_id=:eng FOR SHARE"
                ),
                {"flow": claims["flow_id"], "eng": claims["engagement_id"]},
            )
        )
        .mappings()
        .one_or_none()
    )
    if folder is not None and any(
        not _equal(folder.get(field), expected)
        for field, expected in (
            ("flow_id", claims["flow_id"]),
            ("engagement_id", claims["engagement_id"]),
            ("owner_sub", claims["owner_id"]),
            ("flow_revision", original["flow_revision"]),
            ("authorization_id", original["authorization_id"]),
            ("authorization_version", claims["authorization_version"]),
            ("authorization_sha256", claims["authorization_sha256"]),
            ("manifest_sha256", claims["manifest_sha256"]),
        )
    ):
        _deny()

    # Select the artifact ID from the already signed, checked Task, never a
    # caller-provided path or filename; repeat the BYTEA SHA on the exact row.
    task = (
        (
            await db.execute(
                text(
                    "SELECT payload FROM tasks WHERE id=:task " "AND engagement_id=:eng FOR SHARE"
                ),
                {"task": claims["task_id"], "eng": claims["engagement_id"]},
            )
        )
        .mappings()
        .one_or_none()
    )
    payload = task.get("payload") if task is not None else None
    if (
        type(payload) is not dict
        or type(payload.get("resource_artifact_id")) is not str
        or payload.get("resource_artifact_sha256") != claims["artifact_sha256"]
        or payload.get("resource_manifest_sha256") != claims["manifest_sha256"]
        or payload.get("resource_authorization_sha256") != claims["authorization_sha256"]
        or payload.get("resource_command_sha256") != original["parameters_sha256"]
    ):
        _deny()
    artifact = (
        (
            await db.execute(
                text(
                    "SELECT id,flow_id,engagement_id,owner_id,flow_revision,"
                    "authorization_version,authorization_sha256,sha256,size_bytes,"
                    "content FROM flow_artifacts WHERE id=:artifact AND flow_id=:flow "
                    "AND engagement_id=:eng AND owner_id=:owner FOR SHARE"
                ),
                {
                    "artifact": payload["resource_artifact_id"],
                    "flow": claims["flow_id"],
                    "eng": claims["engagement_id"],
                    "owner": claims["owner_id"],
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if artifact is None:
        _deny()
    raw = artifact.get("content")
    if type(raw) is memoryview:
        raw = raw.tobytes()
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_ORIGINAL:
        _deny()
    if any(
        not _equal(artifact.get(field), expected)
        for field, expected in (
            ("id", payload["resource_artifact_id"]),
            ("flow_id", claims["flow_id"]),
            ("engagement_id", claims["engagement_id"]),
            ("owner_id", claims["owner_id"]),
            ("flow_revision", original["flow_revision"]),
            ("authorization_version", claims["authorization_version"]),
            ("authorization_sha256", claims["authorization_sha256"]),
            ("sha256", claims["artifact_sha256"]),
            ("size_bytes", len(raw)),
        )
    ):
        _deny()
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), claims["artifact_sha256"]):
        _deny()
    if int(time.time()) >= claims["expires_at"]:
        _deny()
    return raw


def _proof_sidecar_bytes(source_proof: dict[str, Any], provision_proof: dict[str, Any]) -> bytes:
    """Two intact, verified signed envelopes; no caller-supplied path or token.

    worker33 native contract: mode=host-stage-v1, version=1 plus the exact
    source_proof/provision_proof signed envelopes, <sha>.proof.json.
    Keep the original signed claims and original signatures unchanged.
    """
    if (
        type(source_proof) is not dict
        or type(provision_proof) is not dict
        or any(
            set(item) != {"claims", "kid", "signature"} or type(item["claims"]) is not dict
            for item in (source_proof, provision_proof)
        )
    ):
        _deny()
    try:
        payload = json.dumps(
            {
                "version": 1,
                "source_proof": source_proof,
                "provision_proof": provision_proof,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise OriginalSourceMapProvisionDenied("Signed proof sidecar unavailable") from exc
    if not 0 < len(payload) <= _MAX_SIDECAR:
        _deny()
    return payload


def _publish_proof_sidecar(
    host: OriginalSourceMapHostStage,
    original: Path,
    original_size: int,
    expected_root: tuple[int, int],
    source_proof: dict[str, Any],
    provision_proof: dict[str, Any],
) -> Path:
    """Exclusively publish after stage, with no partial final-file visibility.

    POSIX same-directory hard-link publication is atomic and refuses an
    existing destination, unlike rename/replace. The private temporary link
    is removed and both directory changes fsynced before returning; final
    sidecar must be a readonly regular file with exactly one link. A failure
    leaves the original Action consumed/UNKNOWN and cannot retry the stage.
    """
    claims = source_proof["claims"]
    root = host._root
    leaf = claims["artifact_sha256"] + ".proof.json"
    if (
        original != root / (claims["artifact_sha256"] + ".map")
        or not root.is_absolute()
        or root.name != "sourcemap-originals"
        or os.name != "posix"
        or os.open not in os.supports_dir_fd
        or os.link not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
    ):
        _deny()
    payload = _proof_sidecar_bytes(source_proof, provision_proof)
    checksum = hashlib.sha256(payload).hexdigest()
    directory = _open_root(root)
    try:
        # Match the original-stage root inode to prevent exchanging a private
        # root between its .map stage and this separate sidecar publication.
        pinned = os.fstat(directory)
        current = _safe_directory(root)
        if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino) or (
            pinned.st_dev,
            pinned.st_ino,
        ) != expected_root:
            _deny()
        _readback(
            directory,
            claims["artifact_sha256"] + ".map",
            claims["artifact_sha256"],
            original_size,
        )
        if int(time.time()) >= claims["expires_at"]:
            _deny()
        temporary = ".proof-" + claims["artifact_sha256"] + "-" + secrets.token_hex(16) + ".tmp"
        _exclusive(directory, temporary, payload, 0o400)
        os.fsync(directory)
        _readback(directory, temporary, checksum, len(payload))
        # Atomic no-overwrite final publication: after link(), native sees
        # either no sidecar or its entire fsynced immutable byte sequence.
        os.link(
            temporary,
            leaf,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.fsync(directory)
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
        _readback(directory, leaf, checksum, len(payload))
        current = _safe_directory(root)
        if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino) or int(
            time.time()
        ) >= claims["expires_at"]:
            _deny()
        os.fsync(directory)
        return root / leaf
    except OSError as exc:
        raise OriginalSourceMapProvisionDenied("Signed SourceMap proof staging UNKNOWN") from exc
    finally:
        os.close(directory)


class OriginalSourceMapReadonlyProvisioner:
    """Dedicated host-only post-commit SourceMap byte fetch and fsync staging."""

    def __init__(self, actions: FlowMCPActionStore) -> None:
        if type(actions) is not FlowMCPActionStore:
            _deny()
        self._actions = actions
        # Missing enrolled *independent* supervisor root and private stage
        # directory deny before a DB read. No caller override is supported.
        self._host = OriginalSourceMapHostStage()

    async def provision(
        self, *, source_proof: dict[str, Any], provision_proof: dict[str, Any]
    ) -> Path:
        claims = _signed_original(source_proof, self._host, provision_proof)
        try:
            async with self._actions._sessions()() as db:
                async with db.begin():
                    original = await _committed_and_current_original(
                        db, self._actions, source_proof, claims
                    )
                    root_identity = _safe_directory(self._host._root)
                    # Intentionally hold current DB Flow/Task/lease/reviewer
                    # row locks through the host write to fence revocation.
                    original_path = self._host.stage(
                        original_bytes=original,
                        source_proof=source_proof,
                        provision_proof=provision_proof,
                    )
                    _publish_proof_sidecar(
                        self._host,
                        original_path,
                        len(original),
                        (root_identity.st_dev, root_identity.st_ino),
                        source_proof,
                        provision_proof,
                    )
                    return original_path
        except OriginalSourceMapProvisionDenied:
            raise
        except Exception as exc:
            # On DB disconnect/fsync failure/lost ACK, no automatic retry.
            raise OriginalSourceMapProvisionDenied(
                "Original SourceMap host provision unavailable or UNKNOWN"
            ) from exc
