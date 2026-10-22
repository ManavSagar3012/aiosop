"""Immutable, tenant-owned Flow file snapshots entirely inside PostgreSQL.

Unlike PentAGI's additional container synchronization, this is a safe data
storage interface only. User bytes never become a host path or executable.
There is no global filesystem cache and thus no symlink/traversal primitive.
Uploads and their redacted event/outbox entries commit atomically. All reads
revalidate durable owner, active signed ROE and exact current Flow revision.
"""

import hashlib
import hmac
import json
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text

from ai_osop.memory.authorization_store import AuthorizationDenied, guard_sql

MAX_BYTES = 2 * 1024 * 1024
MAX_FILES = 64
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class ArtifactDenied(Exception):
    """Authorization, stale revision, missing artifact or durable failure."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def safe_filename(name: str) -> str:
    # Reject instead of silently flattening traversal, Unicode confusables,
    # Windows reserved devices, or separators in caller-provided paths.
    if (
        not isinstance(name, str)
        or not _FILENAME.fullmatch(name)
        or name in {".", ".."}
        or name.endswith(".")
        or name.split(".")[0].upper()
        in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
        }
    ):
        raise ArtifactDenied(422, "Unsafe artifact filename")
    return name


def _identity(flow_id: str, owner: str, revision: int, version: int) -> None:
    if (
        not isinstance(flow_id, str)
        or not _IDENTIFIER.fullmatch(flow_id)
        or not isinstance(owner, str)
        or not 0 < len(owner) <= 64
        or not owner.strip()
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in owner)
        or type(revision) is not int
        or revision < 0
        or type(version) is not int
        or version <= 0
    ):
        raise ArtifactDenied(422, "Invalid Flow or authorization fence")


def _metadata(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "flow_id": row["flow_id"],
        "name": row["name"],
        "size_bytes": row["size_bytes"],
        "sha256": row["sha256"],
        "flow_revision": row["flow_revision"],
        "authorization_version": row["authorization_version"],
        "created_at": row["created_at"].isoformat(),
    }


class FlowArtifactStore:
    def __init__(self, session_memory: Any):
        self.session_memory = session_memory

    def _sessions(self) -> Any:
        maker = getattr(self.session_memory, "_async_session", None)
        if not callable(maker):
            raise ArtifactDenied(503, "Durable artifact storage unavailable")
        return maker

    @staticmethod
    async def _fence(
        db: Any, flow_id: str, owner: str, revision: int, version: int, *, writing: bool = False
    ) -> Tuple[str, str]:
        # Session first, Flow second: shared order for uploads/reads, and the
        # transaction holds both locks through every file operation. No Redis
        # or in-process owner cache participates in the authorization result.
        resolved = (
            (
                await db.execute(
                    text("SELECT engagement_id FROM execution_flows WHERE id=:fid"),
                    {"fid": flow_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if resolved is None:
            raise ArtifactDenied(404, "Flow not found")
        sid = resolved["engagement_id"]
        session = (
            (
                await db.execute(
                    text(
                        "SELECT created_by, phase FROM session_states "
                        "WHERE session_id=:sid FOR SHARE"
                    ),
                    {"sid": sid},
                )
            )
            .mappings()
            .one_or_none()
        )
        if session is None:
            raise ArtifactDenied(404, "Flow not found")
        # Even seniors must be this Flow's durable tenant owner; never
        # substitute a global shared bearer for a human upload identity.
        if session["created_by"] != owner:
            raise ArtifactDenied(403, "Flow owner required")
        try:
            signed = await guard_sql(db, sid, expected_version=version)
        except AuthorizationDenied as exc:
            raise ArtifactDenied(403, "Current signed Flow authorization required") from exc
        locked = (
            (
                await db.execute(
                    text(
                        "SELECT id, engagement_id, revision, status FROM execution_flows "
                        f"WHERE id=:fid AND engagement_id=:sid {'FOR UPDATE' if writing else 'FOR SHARE'}"
                    ),
                    {"fid": flow_id, "sid": sid},
                )
            )
            .mappings()
            .one_or_none()
        )
        if locked is None:
            raise ArtifactDenied(404, "Flow not found")
        if locked["revision"] != revision:
            raise ArtifactDenied(409, "Flow revision changed")
        if writing and (
            locked["status"] not in {"pending", "running"}
            or session["phase"] in {"halted", "completed"}
        ):
            raise ArtifactDenied(409, "Flow is not accepting artifacts")
        return sid, signed.policy_sha256

    async def upload(
        self, flow_id: str, owner: str, revision: int, version: int, name: str, blob: bytes
    ) -> Dict[str, Any]:
        _identity(flow_id, owner, revision, version)
        name = safe_filename(name)
        if not isinstance(blob, bytes) or not 0 < len(blob) <= MAX_BYTES:
            raise ArtifactDenied(413, "Artifact size exceeds limit or is empty")
        digest = hashlib.sha256(blob).hexdigest()
        identifier = "artifact-" + uuid.uuid4().hex
        event_id = "evt-" + uuid.uuid4().hex
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    sid, auth_digest = await self._fence(
                        db,
                        flow_id,
                        owner,
                        revision,
                        version,
                        writing=True,
                    )
                    occupied = (
                        await db.execute(
                            text(
                                "SELECT id FROM flow_artifacts WHERE flow_id=:fid " "AND name=:name"
                            ),
                            {"fid": flow_id, "name": name},
                        )
                    ).scalar_one_or_none()
                    if occupied:
                        raise ArtifactDenied(409, "Artifact filename already exists")
                    count = (
                        await db.execute(
                            text("SELECT COUNT(*) FROM flow_artifacts WHERE flow_id=:fid"),
                            {"fid": flow_id},
                        )
                    ).scalar_one()
                    if count >= MAX_FILES:
                        raise ArtifactDenied(409, "Flow artifact count limit reached")
                    inserted = (
                        (
                            await db.execute(
                                text(
                                    "INSERT INTO flow_artifacts (id, flow_id, engagement_id, "
                                    "owner_id, name, size_bytes, sha256, authorization_version, "
                                    "authorization_sha256, flow_revision, content) "
                                    "VALUES (:id,:fid,:sid,:owner,:name,:size,:sha,:version, "
                                    ":auth_sha,:revision,:content) RETURNING id,flow_id,name, "
                                    "size_bytes,sha256,flow_revision,authorization_version,created_at"
                                ),
                                {
                                    "id": identifier,
                                    "fid": flow_id,
                                    "sid": sid,
                                    "owner": owner,
                                    "name": name,
                                    "size": len(blob),
                                    "sha": digest,
                                    "version": version,
                                    "auth_sha": auth_digest,
                                    "revision": revision,
                                    "content": blob,
                                },
                            )
                        )
                        .mappings()
                        .one()
                    )
                    event = {
                        "flow_id": flow_id,
                        "artifact_id": identifier,
                        "sha256": digest,
                        "size_bytes": len(blob),
                        "flow_revision": revision,
                        "authorization_version": version,
                    }
                    await db.execute(
                        text(
                            "INSERT INTO supervision_events "
                            "(id,engagement_id,kind,actor_id,payload,idempotency_key) "
                            "VALUES (:id,:sid,'flow.artifact_uploaded',:owner,"
                            "CAST(:payload AS jsonb),:idem)"
                        ),
                        {
                            "id": event_id,
                            "sid": sid,
                            "owner": owner,
                            "payload": json.dumps(event),
                            "idem": "artifact:" + identifier,
                        },
                    )
                    await db.execute(
                        text(
                            "INSERT INTO supervision_outbox "
                            "(id,event_id,engagement_id,topic,payload) "
                            "VALUES (:id,:event,:sid,'flow.artifact_uploaded',CAST(:payload AS jsonb))"
                        ),
                        {
                            "id": "out-" + uuid.uuid4().hex,
                            "event": event_id,
                            "sid": sid,
                            "payload": json.dumps(event),
                        },
                    )
                    return _metadata(inserted)
        except ArtifactDenied:
            raise
        except Exception as exc:
            raise ArtifactDenied(503, "Durable Flow artifact write unavailable") from exc

    async def list(
        self, flow_id: str, owner: str, revision: int, version: int
    ) -> List[Dict[str, Any]]:
        _identity(flow_id, owner, revision, version)
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    sid, auth_digest = await self._fence(db, flow_id, owner, revision, version)
                    rows = (
                        (
                            await db.execute(
                                text(
                                    "SELECT id,flow_id,name,size_bytes,sha256,flow_revision, "
                                    "authorization_version,authorization_sha256,created_at "
                                    "FROM flow_artifacts WHERE engagement_id=:sid AND flow_id=:fid "
                                    "AND owner_id=:owner ORDER BY created_at,id LIMIT :limit"
                                ),
                                {
                                    "sid": sid,
                                    "fid": flow_id,
                                    "owner": owner,
                                    "limit": MAX_FILES + 1,
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if len(rows) > MAX_FILES:
                        raise ArtifactDenied(503, "Flow artifact catalog inconsistent")
                    if any(
                        row["authorization_version"] != version
                        or row["flow_revision"] != revision
                        or not hmac.compare_digest(row["authorization_sha256"], auth_digest)
                        for row in rows
                    ):
                        raise ArtifactDenied(409, "Flow artifact authorization changed")
                    return [_metadata(row) for row in rows]
        except ArtifactDenied:
            raise
        except Exception as exc:
            raise ArtifactDenied(503, "Durable Flow artifact listing unavailable") from exc

    async def read(
        self, flow_id: str, artifact_id: str, owner: str, revision: int, version: int
    ) -> Tuple[Dict[str, Any], bytes]:
        _identity(flow_id, owner, revision, version)
        if not isinstance(artifact_id, str) or not re.fullmatch(
            r"artifact-[0-9a-f]{32}", artifact_id
        ):
            raise ArtifactDenied(404, "Artifact not found")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    sid, auth_digest = await self._fence(db, flow_id, owner, revision, version)
                    row = (
                        (
                            await db.execute(
                                text(
                                    "SELECT id,flow_id,name,size_bytes,sha256,flow_revision, "
                                    "authorization_version,authorization_sha256,created_at,content "
                                    "FROM flow_artifacts WHERE engagement_id=:sid AND flow_id=:fid "
                                    "AND owner_id=:owner AND id=:id"
                                ),
                                {"sid": sid, "fid": flow_id, "owner": owner, "id": artifact_id},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if row is None:
                        raise ArtifactDenied(404, "Artifact not found")
                    blob = row["content"]
                    if (
                        row["authorization_version"] != version
                        or row["flow_revision"] != revision
                        or not isinstance(row["authorization_sha256"], str)
                        or not hmac.compare_digest(row["authorization_sha256"], auth_digest)
                    ):
                        raise ArtifactDenied(409, "Flow artifact authorization changed")
                    if (
                        not isinstance(blob, bytes)
                        or not 0 < len(blob) <= MAX_BYTES
                        or row["size_bytes"] != len(blob)
                        or not hmac.compare_digest(row["sha256"], hashlib.sha256(blob).hexdigest())
                    ):
                        raise ArtifactDenied(503, "Artifact integrity unavailable")
                    return _metadata(row), blob
        except ArtifactDenied:
            raise
        except Exception as exc:
            raise ArtifactDenied(503, "Durable Flow artifact read unavailable") from exc

    async def read_resource_snapshot(
        self,
        flow_id: str,
        owner: str,
        revision: int,
        version: int,
    ) -> List[Tuple[Dict[str, Any], bytes]]:
        """Snapshot a bounded Flow resource set under one signed PG read fence.

        The caller classifies *inert* content before returning anything.
        Do not use multiple list/read API calls: a Flow revision or signed
        authorization could change between calls. All content, its persisted
        SHA, version, immutable owner, and revision are rechecked here.
        """
        _identity(flow_id, owner, revision, version)
        # Imported lazily to keep the unprivileged artifact upload route
        # independent of the stricter optional resource-export policies.
        from ai_osop.memory.flow_resource_exports import (
            MAX_EXPORT_FILES,
            MAX_EXPORT_TOTAL_BYTES,
        )

        try:
            async with self._sessions()() as db:
                async with db.begin():
                    sid, auth_digest = await self._fence(
                        db,
                        flow_id,
                        owner,
                        revision,
                        version,
                    )
                    rows = (
                        (
                            await db.execute(
                                text(
                                    "SELECT id,flow_id,name,size_bytes,sha256,flow_revision, "
                                    "authorization_version,authorization_sha256,created_at,content "
                                    "FROM flow_artifacts WHERE engagement_id=:sid AND flow_id=:fid "
                                    "AND owner_id=:owner ORDER BY created_at,id LIMIT :limit"
                                ),
                                {
                                    "sid": sid,
                                    "fid": flow_id,
                                    "owner": owner,
                                    "limit": MAX_EXPORT_FILES + 1,
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if len(rows) > MAX_EXPORT_FILES:
                        raise ArtifactDenied(413, "Flow resource count exceeds export limit")
                    used = 0
                    seen: set[str] = set()
                    snapshot: List[Tuple[Dict[str, Any], bytes]] = []
                    for row in rows:
                        name = safe_filename(row["name"])
                        if name in seen:
                            raise ArtifactDenied(503, "Duplicate Flow resource names")
                        seen.add(name)
                        blob = row["content"]
                        if (
                            row["flow_id"] != flow_id
                            or row["authorization_version"] != version
                            or row["flow_revision"] != revision
                            or not isinstance(row["authorization_sha256"], str)
                            or not hmac.compare_digest(row["authorization_sha256"], auth_digest)
                        ):
                            raise ArtifactDenied(409, "Flow resource authorization changed")
                        if (
                            not isinstance(blob, bytes)
                            or not 0 < len(blob) <= MAX_BYTES
                            or type(row["size_bytes"]) is not int
                            or row["size_bytes"] != len(blob)
                            or not isinstance(row["sha256"], str)
                            or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                            or not hmac.compare_digest(
                                row["sha256"],
                                hashlib.sha256(blob).hexdigest(),
                            )
                        ):
                            raise ArtifactDenied(503, "Flow resource integrity unavailable")
                        used += len(blob)
                        if used > MAX_EXPORT_TOTAL_BYTES:
                            raise ArtifactDenied(413, "Flow resource export exceeds byte budget")
                        snapshot.append((_metadata(row), blob))
                    return snapshot
        except ArtifactDenied:
            raise
        except Exception as exc:
            raise ArtifactDenied(503, "Durable Flow resource snapshot unavailable") from exc
