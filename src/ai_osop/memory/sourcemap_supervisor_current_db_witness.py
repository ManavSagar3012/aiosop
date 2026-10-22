"""Host-only, read-only PostgreSQL current-SourceMap-supervisor witness.

The currently shipped 0033 supervisor is a Go ``authority_status`` lifecycle,
whereas SourceMap 0035 requires a different original 0027 Action and tool.
0033 persists only SHA256s of signed observations and increments the row
revision *after* a running observation is signed. The CURRENT_DB_DOMAIN v1
contract therefore requires the signed expected revision PLUS ONE to be the
current row revision; never witness an old row or replay a prior observation.

This bounded adapter rechecks current signed 0035 status, committed immutable
0035 source, exact original signed 0027/Flow/Task/ROE/lease/reviewer and the
latest 0033 event inside one PostgreSQL transaction. A caller must present the
actual independent 0033 signed observation, as 0033 stores its digests only.
No request fields, unsigned current-state booleans or raw PID are trusted.
No writes, migration, network fetch, source reissue or native key delivery.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_worker_supervision import NativeMCPWorkerSupervisionStore
from ai_osop.memory.sourcemap_source_authority import validate_request
from ai_osop.memory.sourcemap_status_authority import SourceMapStatusAuthorityStore
from ai_osop.orchestrator.sourcemap_original_stage import _canonical, _roots
from ai_osop.orchestrator.sourcemap_supervisor_source_issuer import (
    CURRENT_DB_DOMAIN,
    LEDGER_DOMAIN,
    SOURCE_STATUS_DOMAIN,
    _DB_FIELDS,
    _LEDGER_FIELDS,
    _STATUS_FIELDS,
    _verified,
)

_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_REQUEST = re.compile(r"req-[a-f0-9]{48}\Z")
_GRANT = re.compile(r"ngr-[a-f0-9]{32}\Z")
_IDENTITY = (
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "approval_id",
    "lease_id",
    "authorization_sha256",
    "artifact_sha256",
    "manifest_sha256",
)


class SourceMapCurrentDBDenied(ValueError):
    """Current independent SourceMap supervisor database authority is absent."""


def _deny(reason: str = "Current signed SourceMap DB source unavailable") -> None:
    raise SourceMapCurrentDBDenied(reason)


def _key_from_host_file(
    roots: Mapping[str, bytes],
    foreign_roots: tuple[Mapping[str, bytes], ...],
) -> tuple[str, Ed25519PrivateKey]:
    """Separate enrolled Linux-host signer; private key never sent to native."""
    if sys.platform != "linux" or os.name != "posix":
        _deny("Protected Linux host-only current-DB signer unavailable")
    kid = os.environ.get("OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_SIGNING_KID", "")
    raw_path = os.environ.get("OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_SIGNING_KEY_FILE", "")
    if _KID.fullmatch(kid) is None or kid not in roots or not 1 <= len(raw_path) <= 1024:
        _deny()
    key_file = Path(raw_path)
    if not key_file.is_absolute():
        _deny()
    try:
        for ancestor in key_file.parents:
            metadata = ancestor.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                _deny()
            if metadata.st_mode & 0o022 and not (
                metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
            ):
                _deny()
        before = key_file.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & 0o077
            or before.st_nlink != 1
            or before.st_size != 32
        ):
            _deny()
        fd = os.open(key_file, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            seed = stream.read(33)
            after = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if (
            len(seed) != 32
            or identity(before) != identity(opened)
            or identity(after) != identity(opened)
        ):
            _deny()
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if not hmac.compare_digest(public, roots[kid]):
            _deny()
        if any(public in other.values() for other in foreign_roots):
            _deny("Current-DB signer shares another trust principal")
        return kid, private
    except SourceMapCurrentDBDenied:
        raise
    except (OSError, TypeError, ValueError, AttributeError) as exc:
        raise SourceMapCurrentDBDenied("Protected host current-DB key unavailable") from exc


def _strict_verified(
    token: Any, roots: Mapping[str, bytes], domain: bytes, fields: frozenset[str]
) -> tuple[dict[str, Any], str]:
    try:
        return _verified(token, roots, domain, fields)
    except Exception as exc:
        raise SourceMapCurrentDBDenied("Independent signed source invalid") from exc


def _fresh_status(proof: Mapping[str, Any], now: int) -> None:
    if (
        type(proof["version"]) is not int
        or proof["version"] != 1
        or proof["server_id"] != "source-map-mcp"
        or proof["tool_name"] != "inspect_local_original_sourcemap"
        or type(proof["issued_at"]) is not int
        or type(proof["expires_at"]) is not int
        or not now - 2 <= proof["issued_at"] <= now + 1
        or not now < proof["expires_at"] <= proof["issued_at"] + 5
        or type(proof["request_id"]) is not str
        or _REQUEST.fullmatch(proof["request_id"]) is None
        or type(proof["authorization_version"]) is not int
        or proof["authorization_version"] < 1
        or type(proof["artifact_sha256"]) is not str
        or _SHA.fullmatch(proof["artifact_sha256"]) is None
    ):
        _deny("Fresh signed 0035 status unavailable")


class SourceMapSupervisorCurrentDBWitness:
    """Independently revalidate sources on the host, without granting access."""

    _folder_plan = staticmethod(NativeMCPWorkerSupervisionStore._current_folder)

    def __init__(self, actions: FlowMCPActionStore) -> None:
        if not isinstance(actions, FlowMCPActionStore):
            _deny("Original signed 0027 PostgreSQL source required")
        self._actions = actions
        self._status = SourceMapStatusAuthorityStore(actions)
        try:
            self._db_roots = _roots("OSOP_SOURCEMAP_SUPERVISOR_CURRENT_DB_TRUSTED_PUBLIC_KEYS_JSON")
            self._ledger_roots = _roots("OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON")
            self._status_roots = _roots("OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
            self._source_issuer_roots = _roots(
                "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON"
            )
            self._process_roots = _roots(
                "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON"
            )
        except Exception as exc:
            raise SourceMapCurrentDBDenied("Enrolled host witness roots unavailable") from exc
        all_roots = (
            self._db_roots,
            self._ledger_roots,
            self._status_roots,
            self._source_issuer_roots,
            self._process_roots,
        )
        if any(
            set(all_roots[a].values()) & set(all_roots[b].values())
            for a in range(len(all_roots))
            for b in range(a + 1, len(all_roots))
        ):
            _deny("Distinct independently enrolled current-DB trust required")
        self._kid, self._private = _key_from_host_file(
            self._db_roots,
            (
                self._ledger_roots,
                self._status_roots,
                self._source_issuer_roots,
                self._process_roots,
            ),
        )

    async def issue(
        self,
        *,
        supervisor_observation: dict[str, Any],
        source_status: dict[str, Any],
    ) -> dict[str, Any]:
        """Read one atomic current source; deny historical or foreign 0033 records.

        Neither proof is an assertion of currentness. Both must be independently
        signed, and every binding is checked against the database inside the
        current original Action transaction.
        """
        ledger, ledger_digest = _strict_verified(
            supervisor_observation, self._ledger_roots, LEDGER_DOMAIN, _LEDGER_FIELDS
        )
        status, status_digest = _strict_verified(
            source_status, self._status_roots, SOURCE_STATUS_DOMAIN, _STATUS_FIELDS
        )
        current = int(time.time())
        _fresh_status(status, current)
        if (
            type(ledger["version"]) is not int
            or ledger["version"] != 1
            or ledger["state"] != "running"
            or ledger["server_id"] != "source-map-mcp"
            or ledger["request_id"] != status["request_id"]
            or ledger["resource_sha256"] != status["manifest_sha256"]
            or type(ledger["grant_id"]) is not str
            or _GRANT.fullmatch(ledger["grant_id"]) is None
            or type(ledger["container_id"]) is not str
            or _SHA.fullmatch(ledger["container_id"]) is None
            or type(ledger["epoch"]) is not int
            or ledger["epoch"] <= 0
            or type(ledger["expected_revision"]) is not int
            or ledger["expected_revision"] <= 0
            or type(ledger["observed_at"]) is not int
            or not current - 3 <= ledger["observed_at"] <= current + 1
        ):
            _deny("Current signed 0033 SourceMap observation unavailable")
        try:
            request = validate_request(
                {
                    key: status[key]
                    for key in (
                        "request_id",
                        "engagement_id",
                        "task_id",
                        "server_id",
                        "tool_name",
                        "artifact_sha256",
                    )
                }
            )
            async with self._actions._sessions()() as db:
                async with db.begin():
                    # _source performs signed-current Flow/ROE/Task/approval/
                    # reviewer/lease and exact 0013/0015 original-byte checks.
                    original, manifest = await self._status.sources._source(db, request)
                    if (
                        any(
                            original.get(field) != status[field]
                            for field in (
                                "request_id",
                                "engagement_id",
                                "flow_id",
                                "task_id",
                                "subtask_id",
                                "action_id",
                                "owner_id",
                                "approval_id",
                                "lease_id",
                                "authorization_version",
                                "authorization_sha256",
                            )
                        )
                        or manifest != status["manifest_sha256"]
                    ):
                        _deny("Current original SourceMap action changed")
                    pg_now = await self._status.sources._now(db)
                    _fresh_status(status, pg_now)
                    preflight = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_sourcemap_source_preflights "
                                    "WHERE action_id=:action AND request_id=:request "
                                    "AND engagement_id=:eng AND task_id=:task FOR SHARE"
                                ),
                                {
                                    "action": status["action_id"],
                                    "request": status["request_id"],
                                    "eng": status["engagement_id"],
                                    "task": status["task_id"],
                                },
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    self._status._verify_issued(
                        preflight,
                        original,
                        manifest,
                        status["artifact_sha256"],
                        current_kid=source_status["kid"],
                        now=pg_now,
                    )
                    if status["issued_at"] < pg_now - 2 or pg_now >= status["expires_at"]:
                        _deny("Status proof expired while reading current DB")

                    grant = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_mcp_execution_grants "
                                    "WHERE grant_id=:grant FOR SHARE"
                                ),
                                {"grant": ledger["grant_id"]},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if (
                        grant is None
                        or any(
                            grant.get(key) != original.get(key)
                            for key in (
                                "request_id",
                                "engagement_id",
                                "flow_id",
                                "task_id",
                                "subtask_id",
                                "action_id",
                                "owner_id",
                                "server_id",
                                "approval_id",
                                "lease_id",
                                "lease_owner_id",
                                "flow_revision",
                                "authorization_id",
                                "authorization_version",
                                "authorization_sha256",
                            )
                        )
                        or (
                            grant.get("tool_name") != "inspect_local_original_sourcemap"
                            or grant.get("status") != "redeemed"
                            or grant.get("resource_sha256") != manifest
                            or type(grant.get("expires_at")) is not int
                            or pg_now >= grant["expires_at"]
                        )
                    ):
                        # The existing 0029 migration CHECK forces
                        # authority_status, so a genuine SourceMap original
                        # cannot pass until a reviewed schema/issuer extension.
                        _deny("0033 grant cannot bind original SourceMap Action")
                    folder_sha = await self._folder_plan(db, grant)
                    if (
                        type(folder_sha) is not str
                        or _SHA.fullmatch(folder_sha) is None
                        or ledger["folder_staging_sha256"] != folder_sha
                    ):
                        _deny("Current 0026 folder and 0031 staging approval absent")
                    offer = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_mcp_resource_offers "
                                    "WHERE grant_id=:grant FOR SHARE"
                                ),
                                {"grant": grant["grant_id"]},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if (
                        offer is None
                        or any(
                            offer.get(key) != grant.get(key)
                            for key in (
                                "grant_id",
                                "engagement_id",
                                "flow_id",
                                "action_id",
                                "request_id",
                                "server_id",
                            )
                        )
                        or (
                            offer.get("status") != "offered"
                            or offer.get("manifest_sha256") != manifest
                            or offer.get("folder_staging_sha256") != folder_sha
                        )
                    ):
                        _deny("0031 immutable SourceMap staging offer unavailable")

                    supervisor = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_mcp_worker_supervisions "
                                    "WHERE grant_id=:grant FOR SHARE"
                                ),
                                {"grant": ledger["grant_id"]},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if supervisor is None:
                        _deny("No SourceMap-specific current 0033 supervisor row")
                    identical = (
                        "request_id",
                        "engagement_id",
                        "flow_id",
                        "task_id",
                        "subtask_id",
                        "action_id",
                        "owner_id",
                        "approval_id",
                        "lease_id",
                        "server_id",
                        "authorization_version",
                        "authorization_sha256",
                    )
                    if (
                        any(
                            supervisor.get(key)
                            != (status[key] if key in status else original.get(key))
                            for key in identical
                        )
                        or supervisor.get("resource_sha256") != manifest
                        or supervisor.get("grant_id") != ledger["grant_id"]
                        or supervisor.get("worker_id") != ledger["worker_id"]
                        or supervisor.get("container_id") != ledger["container_id"]
                        or supervisor.get("epoch") != ledger["epoch"]
                        or supervisor.get("state") != "running"
                        or supervisor.get("folder_staging_sha256") != folder_sha
                        or supervisor.get("supervisor_kid") != supervisor_observation["kid"]
                        or type(supervisor.get("revision")) is not int
                        or supervisor["revision"] < 2
                    ):
                        _deny("Current 0033 SourceMap worker/Action identity mismatch")
                    observation_bytes = _canonical(ledger)
                    signature = base64.urlsafe_b64decode(supervisor_observation["signature"] + "==")
                    event = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_mcp_worker_supervision_events "
                                    "WHERE grant_id=:grant AND epoch=:epoch AND revision=:revision "
                                    "ORDER BY recorded_at DESC LIMIT 2 FOR SHARE"
                                ),
                                {
                                    "grant": ledger["grant_id"],
                                    "epoch": supervisor["epoch"],
                                    "revision": supervisor["revision"],
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if len(event) != 1 or any(
                        event[0].get(key) != value
                        for key, value in {
                            "grant_id": ledger["grant_id"],
                            "epoch": ledger["epoch"],
                            "revision": supervisor["revision"],
                            "state": "running",
                            "kid": supervisor["supervisor_kid"],
                            "supervisor_id": supervisor["supervisor_id"],
                            "observed_at": ledger["observed_at"],
                            "evidence_sha256": ledger["evidence_sha256"],
                            "claims_sha256": hashlib.sha256(observation_bytes).hexdigest(),
                            "signature_sha256": hashlib.sha256(signature).hexdigest(),
                        }.items()
                    ):
                        _deny("Current signed 0033 event not durably reproducible")

                    # Running 0033 transitions sign expected_revision=r and
                    # atomically commit revision=r+1. This equality is required
                    # independently of the signed event hash check above.
                    if supervisor["revision"] != ledger["expected_revision"] + 1:
                        _deny("Stale 0033 running observation revision")

                    claims = {
                        "version": 1,
                        "grant_id": supervisor["grant_id"],
                        "worker_id": supervisor["worker_id"],
                        "container_id": supervisor["container_id"],
                        "epoch": supervisor["epoch"],
                        "revision": supervisor["revision"],
                        "supervisor_observation_sha256": ledger_digest,
                        "status_proof_sha256": status_digest,
                        **{key: status[key] for key in _IDENTITY},
                        # Signed policy hash is the signed ROE authority hash;
                        # _source above verified that policy against current ROE.
                        "signed_roe_sha256": original["authorization_sha256"],
                        "status": "running",
                        "source_current": True,
                        "lease_active": True,
                        "approval_current": True,
                        "reviewer_current": True,
                        "roe_current": True,
                        "observed_at": pg_now,
                        "expires_at": min(pg_now + 5, status["expires_at"]),
                    }
                    if set(claims) != _DB_FIELDS or claims["expires_at"] <= pg_now:
                        _deny("SourceMap current-DB witness contract unavailable")
                    signed = self._private.sign(CURRENT_DB_DOMAIN + _canonical(claims))
                    return {
                        "claims": claims,
                        "kid": self._kid,
                        "signature": base64.urlsafe_b64encode(signed).decode("ascii").rstrip("="),
                    }
        except SourceMapCurrentDBDenied:
            raise
        except Exception as exc:
            raise SourceMapCurrentDBDenied(
                "Current independently reviewed 0033/0035 source unavailable"
            ) from exc


__all__ = ["SourceMapCurrentDBDenied", "SourceMapSupervisorCurrentDBWitness"]
