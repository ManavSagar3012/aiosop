"""Durable Flow-owned mutable folder metadata, never source bytes or worker sync.

Signed owner+Flow+ROE revision and immutable SHA-verified manifest are checked
before the transaction, again WITHIN the PG Flow write lock, and after commit.
Catalog CAS serializes folder/assignment mutations, including first creation.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Mapping

from sqlalchemy import text

from ai_osop.core.config import settings
from ai_osop.memory.flow_artifact_reviews import (
    ArtifactReviewDenied,
    FlowArtifactReviewStore,
)
from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore
from ai_osop.memory.flow_resource_aliases import FlowResourceAliases, _catalog
from ai_osop.memory.flow_resource_exports import (
    MAX_EXPORT_FILES,
    make_manifest,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_AUTH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z")
_FOLDER_ID = re.compile(r"folder-[0-9a-f]{32}\Z")
_ARTIFACT_ID = re.compile(r"artifact-[0-9a-f]{32}\Z")
_OPERATIONS = frozenset({"create", "rename", "delete", "assign", "unassign"})
MAX_FOLDERS = 32


class FolderDenied(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _sha(value: Any) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _identity(binding: Mapping[str, Any], actor: str, token_sha: str, expires_at: int) -> None:
    if (
        not isinstance(binding, dict)
        or not all(
            type(binding.get(key)) is str and _ID.fullmatch(binding[key])
            for key in ("flow_id", "engagement_id")
        )
        or not type(binding.get("authorization_id")) is str
        or _AUTH.fullmatch(binding["authorization_id"]) is None
        or not _sha(binding.get("authorization_sha256"))
        or not _sha(binding.get("manifest_sha256"))
        or type(binding.get("revision")) is not int
        or binding["revision"] < 0
        or type(binding.get("version")) is not int
        or binding["version"] < 1
        or not type(actor) is str
        or _ID.fullmatch(actor) is None
        or not _sha(token_sha)
        or type(expires_at) is not int
        or expires_at <= int(datetime.now(timezone.utc).timestamp())
    ):
        raise FolderDenied(422, "Explicit current signed Flow and actor binding required")


def _params(binding: Mapping[str, Any], owner: str) -> dict[str, Any]:
    return {
        "fid": binding["flow_id"],
        "sid": binding["engagement_id"],
        "owner": owner,
        "flow_rev": binding["revision"],
        "version": binding["version"],
        "auth_id": binding["authorization_id"],
        "auth_sha": binding["authorization_sha256"],
        "manifest": binding["manifest_sha256"],
    }


class FlowResourceFolders:
    """Exact original immutable SHA source + owner-locked metadata CAS."""

    def __init__(self, artifacts: FlowArtifactStore):
        if type(artifacts) is not FlowArtifactStore:
            raise FolderDenied(503, "Production signed Flow artifact store required")
        self.artifacts = artifacts
        self.aliases = FlowResourceAliases(artifacts)

    def _sessions(self):
        maker = getattr(self.artifacts.session_memory, "_async_session", None)
        if not callable(maker):
            raise FolderDenied(503, "PostgreSQL resource folder catalog unavailable")
        return maker

    async def _current(self, b: Mapping[str, Any], owner: str) -> Dict[str, Any]:
        catalog = await self.aliases._current(b["flow_id"], owner, b["revision"], b["version"])
        if not hmac.compare_digest(catalog["source_manifest_sha256"], b["manifest_sha256"]):
            raise FolderDenied(409, "Signed Flow resource manifest changed")
        return catalog

    @staticmethod
    async def _fence(
        db: Any, b: Mapping[str, Any], actor: str, token_sha: str, expires_at: int, *, writing: bool
    ) -> None:
        await FlowArtifactReviewStore._reviewer_fence(
            db,
            reviewer_sub=actor,
            reviewer_token_sha256=token_sha,
            reviewer_expires_at=expires_at,
        )
        current = await FlowArtifactReviewStore._fence(
            db,
            flow_id=b["flow_id"],
            revision=b["revision"],
            version=b["version"],
            authorization_id=b["authorization_id"],
            authorization_sha256=b["authorization_sha256"],
            writing=writing,
            expected_engagement_id=b["engagement_id"],
        )
        if current["sid"] != b["engagement_id"] or current["owner"] != actor:
            raise FolderDenied(403, "Current durable Flow owner required")

    @staticmethod
    async def _snapshot(db: Any, b: Mapping[str, Any], owner: str) -> Dict[str, Any]:
        """Rehash BYTEA in same transaction/lock as catalog revision update."""
        rows = (
            (
                await db.execute(
                    text(
                        "SELECT id,flow_id,engagement_id,owner_id,name,size_bytes,sha256,flow_revision,"
                        "authorization_version,authorization_sha256,created_at,content "
                        "FROM flow_artifacts WHERE flow_id=:fid AND engagement_id=:sid AND owner_id=:owner "
                        "ORDER BY created_at,id LIMIT :limit"
                    ),
                    {
                        "fid": b["flow_id"],
                        "sid": b["engagement_id"],
                        "owner": owner,
                        "limit": MAX_EXPORT_FILES + 1,
                    },
                )
            )
            .mappings()
            .all()
        )
        if len(rows) > MAX_EXPORT_FILES:
            raise FolderDenied(413, "Flow resource catalog too large")
        snapshot = []
        for row in rows:
            if (
                row["engagement_id"] != b["engagement_id"]
                or row["owner_id"] != owner
                or row["flow_id"] != b["flow_id"]
                or row["flow_revision"] != b["revision"]
                or row["authorization_version"] != b["version"]
                or not _sha(row["authorization_sha256"])
                or not hmac.compare_digest(row["authorization_sha256"], b["authorization_sha256"])
            ):
                raise FolderDenied(409, "Immutable Flow artifact signed identity changed")
            snapshot.append(
                (
                    {
                        "id": row["id"],
                        "flow_id": row["flow_id"],
                        "name": row["name"],
                        "size_bytes": row["size_bytes"],
                        "sha256": row["sha256"],
                        "flow_revision": row["flow_revision"],
                        "authorization_version": row["authorization_version"],
                    },
                    row["content"],
                )
            )
        manifest = make_manifest(b["flow_id"], b["revision"], b["version"], snapshot)
        if not hmac.compare_digest(manifest["manifest_sha256"], b["manifest_sha256"]):
            raise FolderDenied(409, "Flow artifact manifest stale within locked transaction")
        return _catalog(manifest)

    @staticmethod
    async def _catalog_row(
        db: Any, b: Mapping[str, Any], owner: str, *, create: bool
    ) -> Mapping[str, Any] | None:
        p = _params(b, owner)
        if create:
            await db.execute(
                text(
                    "INSERT INTO flow_resource_folder_catalogs "
                    "(flow_id,engagement_id,owner_sub,revision,flow_revision,authorization_version,"
                    "authorization_id,authorization_sha256,manifest_sha256) "
                    "VALUES (:fid,:sid,:owner,0,:flow_rev,:version,:auth_id,:auth_sha,:manifest) "
                    "ON CONFLICT (flow_id) DO NOTHING"
                ),
                p,
            )
        row = (
            (
                await db.execute(
                    text(
                        "SELECT flow_id,engagement_id,owner_sub,revision,flow_revision,authorization_version,"
                        "authorization_id,authorization_sha256,manifest_sha256 "
                        "FROM flow_resource_folder_catalogs WHERE flow_id=:fid AND engagement_id=:sid "
                        "FOR UPDATE"
                    ),
                    p,
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is not None and (
            row["flow_id"] != b["flow_id"]
            or row["engagement_id"] != b["engagement_id"]
            or row["owner_sub"] != owner
            or row["flow_revision"] != b["revision"]
            or row["authorization_version"] != b["version"]
            or row["authorization_id"] != b["authorization_id"]
            or row["authorization_sha256"] != b["authorization_sha256"]
            or row["manifest_sha256"] != b["manifest_sha256"]
        ):
            raise FolderDenied(409, "Stored resource folder catalog authority or manifest stale")
        return row

    @staticmethod
    async def _rows(db: Any, b: Mapping[str, Any]) -> tuple[list[dict], list[dict]]:
        p = {"sid": b["engagement_id"], "fid": b["flow_id"]}
        folders = (
            (
                await db.execute(
                    text(
                        "SELECT id,engagement_id,flow_id,name FROM flow_resource_virtual_folders "
                        "WHERE engagement_id=:sid AND flow_id=:fid ORDER BY name,id LIMIT 33"
                    ),
                    p,
                )
            )
            .mappings()
            .all()
        )
        assignments = (
            (
                await db.execute(
                    text(
                        "SELECT engagement_id,flow_id,folder_id,artifact_id,artifact_sha256 "
                        "FROM flow_resource_folder_assignments WHERE engagement_id=:sid AND flow_id=:fid "
                        "ORDER BY artifact_id LIMIT 17"
                    ),
                    p,
                )
            )
            .mappings()
            .all()
        )
        if len(folders) > MAX_FOLDERS or len(assignments) > MAX_EXPORT_FILES:
            raise FolderDenied(503, "Durable Flow folder metadata exceeds bounds")
        return [dict(r) for r in folders], [dict(r) for r in assignments]

    @staticmethod
    def _representation(
        b: Mapping[str, Any],
        rev: int,
        source: Mapping[str, Any],
        folders: list[dict],
        assignments: list[dict],
    ) -> Dict[str, Any]:
        if type(rev) is not int or rev < 0:
            raise FolderDenied(503, "Invalid durable folder catalog revision")
        resources = {item["artifact_id"]: item for item in source["items"]}
        if len(resources) != len(source["items"]):
            raise FolderDenied(503, "Duplicate signed source artifacts")
        indexed = {}
        seen_names = set()
        for folder in folders:
            if (
                folder["flow_id"] != b["flow_id"]
                or folder["engagement_id"] != b["engagement_id"]
                or not isinstance(folder["id"], str)
                or not _FOLDER_ID.fullmatch(folder["id"])
                or not isinstance(folder["name"], str)
                or not _NAME.fullmatch(folder["name"])
                or folder["name"] in seen_names
                or folder["id"] in indexed
            ):
                raise FolderDenied(503, "Persisted folder identity inconsistent")
            seen_names.add(folder["name"])
            indexed[folder["id"]] = {"folder_id": folder["id"], "name": folder["name"], "items": []}
        assigned = set()
        for row in assignments:
            aid = row["artifact_id"]
            if (
                row["flow_id"] != b["flow_id"]
                or row["engagement_id"] != b["engagement_id"]
                or aid in assigned
                or aid not in resources
                or row["folder_id"] not in indexed
                or not _sha(row["artifact_sha256"])
                or not hmac.compare_digest(row["artifact_sha256"], resources[aid]["sha256"])
            ):
                raise FolderDenied(409, "Resource folder assignment source SHA or owner changed")
            assigned.add(aid)
            indexed[row["folder_id"]]["items"].append(
                FlowResourceFolders._public_item(resources[aid])
            )
        return {
            "format": "ai-osop-flow-resource-folders-v1",
            "flow_id": b["flow_id"],
            "engagement_id": b["engagement_id"],
            "flow_revision": b["revision"],
            "authorization_version": b["version"],
            "authorization_id": b["authorization_id"],
            "authorization_sha256": b["authorization_sha256"],
            "source_manifest_sha256": b["manifest_sha256"],
            "catalog_revision": rev,
            "folders": sorted(indexed.values(), key=lambda f: (f["name"], f["folder_id"])),
            "unassigned": [
                FlowResourceFolders._public_item(item)
                for aid, item in sorted(resources.items())
                if aid not in assigned
            ],
            "metadata_only": True,
            "host_files_created": False,
            "worker_sync_performed": False,
        }

    @staticmethod
    def _public_item(resource: Mapping[str, Any]) -> dict:
        return {
            "artifact_id": resource["artifact_id"],
            "artifact_sha256": resource["sha256"],
            "original_name": resource["original_name"],
            "classification": resource["classification"],
            "size_bytes": resource["size_bytes"],
        }

    async def get(self, b: dict, actor: str, token_sha: str, expires_at: int) -> dict:
        _identity(b, actor, token_sha, expires_at)
        await self._current(b, actor)
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    await self._fence(db, b, actor, token_sha, expires_at, writing=False)
                    source = await self._snapshot(db, b, actor)
                    row = await self._catalog_row(db, b, actor, create=False)
                    folders, assignments = await self._rows(db, b)
                    view = self._representation(
                        b, row["revision"] if row is not None else 0, source, folders, assignments
                    )
            # A source upload or signer rotation outside our snapshot must not
            # escape a GET as a supposedly current mutable folder catalog.
            await self._current(b, actor)
            return view
        except (FolderDenied, ArtifactDenied, ArtifactReviewDenied):
            raise
        except Exception as exc:
            raise FolderDenied(503, "Durable Flow folder read unavailable") from exc

    async def mutate(
        self,
        b: dict,
        actor: str,
        token_sha: str,
        expires_at: int,
        *,
        operation: str,
        expected_catalog_revision: int,
        explicit_human_confirmation: bool,
        folder_id: str | None = None,
        name: str | None = None,
        artifact_id: str | None = None,
        artifact_sha256: str | None = None,
    ) -> dict:
        _identity(b, actor, token_sha, expires_at)
        if (
            operation not in _OPERATIONS
            or type(expected_catalog_revision) is not int
            or expected_catalog_revision < 0
            or explicit_human_confirmation is not True
        ):
            raise FolderDenied(422, "Explicit confirmed bounded folder operation required")
        if (
            (
                operation == "create"
                and (
                    not isinstance(name, str)
                    or not _NAME.fullmatch(name)
                    or any(x is not None for x in (folder_id, artifact_id, artifact_sha256))
                )
            )
            or (
                operation == "rename"
                and (
                    not isinstance(folder_id, str)
                    or not _FOLDER_ID.fullmatch(folder_id)
                    or not isinstance(name, str)
                    or not _NAME.fullmatch(name)
                    or any(x is not None for x in (artifact_id, artifact_sha256))
                )
            )
            or (
                operation == "delete"
                and (
                    not isinstance(folder_id, str)
                    or not _FOLDER_ID.fullmatch(folder_id)
                    or any(x is not None for x in (name, artifact_id, artifact_sha256))
                )
            )
            or (
                operation == "assign"
                and (
                    not isinstance(folder_id, str)
                    or not _FOLDER_ID.fullmatch(folder_id)
                    or not isinstance(artifact_id, str)
                    or not _ARTIFACT_ID.fullmatch(artifact_id)
                    or not _sha(artifact_sha256)
                    or name is not None
                )
            )
            or (
                operation == "unassign"
                and (
                    not isinstance(artifact_id, str)
                    or not _ARTIFACT_ID.fullmatch(artifact_id)
                    or not _sha(artifact_sha256)
                    or any(x is not None for x in (name, folder_id))
                )
            )
        ):
            raise FolderDenied(422, "Invalid resource folder operation fields")
        await self._current(b, actor)
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    # Session, signed authorization, and Flow FOR UPDATE
                    # precede metadata locks. New immutable artifact uploads
                    # use the same Flow row lock and serialize with mutations.
                    await self._fence(db, b, actor, token_sha, expires_at, writing=True)
                    source = await self._snapshot(db, b, actor)
                    row = await self._catalog_row(db, b, actor, create=True)
                    if row is None:
                        raise FolderDenied(503, "Folder metadata migration 0026 unavailable")
                    if row["revision"] != expected_catalog_revision:
                        raise FolderDenied(409, "Flow folder catalog revision changed")
                    folders, assignments = await self._rows(db, b)
                    old_view = self._representation(
                        b, row["revision"], source, folders, assignments
                    )
                    folder_map = {item["id"]: item for item in folders}
                    assign_map = {item["artifact_id"]: item for item in assignments}
                    resource_map = {item["artifact_id"]: item for item in source["items"]}
                    p = _params(b, actor)
                    if operation in {"assign", "unassign"}:
                        matching = resource_map.get(artifact_id)
                        if matching is None:
                            raise FolderDenied(404, "Original Flow artifact not in signed manifest")
                        if not hmac.compare_digest(matching["sha256"], artifact_sha256):
                            raise FolderDenied(409, "Original artifact SHA changed")
                    if operation == "create":
                        if len(folders) >= MAX_FOLDERS:
                            raise FolderDenied(409, "Maximum 32 virtual folders")
                        if name in {item["name"] for item in folders}:
                            raise FolderDenied(409, "Folder name already exists")
                        folder_id = "folder-" + uuid.uuid4().hex
                        await db.execute(
                            text(
                                "INSERT INTO flow_resource_virtual_folders (id,engagement_id,flow_id,name) "
                                "VALUES (:folder,:sid,:fid,:name)"
                            ),
                            {**p, "folder": folder_id, "name": name},
                        )
                    elif operation in {"rename", "delete", "assign"}:
                        if folder_id not in folder_map:
                            raise FolderDenied(404, "Flow resource folder not found")
                        if operation == "rename":
                            if name == folder_map[folder_id]["name"] or name in {
                                x["name"] for x in folders
                            }:
                                raise FolderDenied(409, "Folder name already exists or unchanged")
                            await db.execute(
                                text(
                                    "UPDATE flow_resource_virtual_folders SET name=:name "
                                    "WHERE id=:folder AND flow_id=:fid AND engagement_id=:sid"
                                ),
                                {**p, "folder": folder_id, "name": name},
                            )
                        elif operation == "delete":
                            if any(item["folder_id"] == folder_id for item in assignments):
                                raise FolderDenied(409, "Cannot delete nonempty resource folder")
                            await db.execute(
                                text(
                                    "DELETE FROM flow_resource_virtual_folders WHERE id=:folder "
                                    "AND flow_id=:fid AND engagement_id=:sid"
                                ),
                                {**p, "folder": folder_id},
                            )
                        elif operation == "assign":
                            if artifact_id in assign_map:
                                raise FolderDenied(409, "Artifact already assigned to a folder")
                            await self._approved_review(db, b, actor, artifact_id, artifact_sha256)
                            await db.execute(
                                text(
                                    "INSERT INTO flow_resource_folder_assignments "
                                    "(engagement_id,flow_id,folder_id,artifact_id,artifact_sha256) "
                                    "VALUES (:sid,:fid,:folder,:artifact,:sha)"
                                ),
                                {
                                    **p,
                                    "folder": folder_id,
                                    "artifact": artifact_id,
                                    "sha": artifact_sha256,
                                },
                            )
                    elif operation == "unassign":
                        if artifact_id not in assign_map:
                            raise FolderDenied(404, "Flow artifact was not assigned")
                        await db.execute(
                            text(
                                "DELETE FROM flow_resource_folder_assignments WHERE engagement_id=:sid "
                                "AND flow_id=:fid AND artifact_id=:artifact AND artifact_sha256=:sha"
                            ),
                            {**p, "artifact": artifact_id, "sha": artifact_sha256},
                        )
                        folder_id = assign_map[artifact_id]["folder_id"]
                    updated = (
                        await db.execute(
                            text(
                                "UPDATE flow_resource_folder_catalogs SET revision=revision+1,updated_at=now() "
                                "WHERE flow_id=:fid AND engagement_id=:sid AND owner_sub=:owner "
                                "AND revision=:expected AND flow_revision=:flow_rev AND "
                                "authorization_version=:version AND authorization_id=:auth_id AND "
                                "authorization_sha256=:auth_sha AND manifest_sha256=:manifest RETURNING revision"
                            ),
                            {**p, "expected": expected_catalog_revision},
                        )
                    ).scalar_one_or_none()
                    if updated != expected_catalog_revision + 1:
                        raise FolderDenied(409, "Flow folder catalog CAS changed")
                    event_id = "evt-" + uuid.uuid4().hex
                    await db.execute(
                        text(
                            "INSERT INTO flow_resource_folder_events "
                            "(id,flow_id,engagement_id,actor_sub,operation,catalog_revision,folder_id,folder_name,"
                            "artifact_id,artifact_sha256,manifest_sha256,authorization_id,authorization_sha256) "
                            "VALUES (:evt,:fid,:sid,:owner,:op,:catalog,:folder,:name,:artifact,:sha,:manifest,:auth_id,:auth_sha)"
                        ),
                        {
                            **p,
                            "evt": event_id,
                            "op": operation,
                            "catalog": updated,
                            "folder": folder_id,
                            "name": name,
                            "artifact": artifact_id,
                            "sha": artifact_sha256,
                        },
                    )
                    next_folders, next_assignments = await self._rows(db, b)
                    fresh_view = self._representation(
                        b, updated, source, next_folders, next_assignments
                    )
                    if fresh_view == old_view:
                        raise FolderDenied(503, "Folder state did not change after write")
            # COMMIT has happened. An external source mutation or revocation
            # can make the result UNKNOWN; do NOT imply it rolled back.
            try:
                after = await self.get(b, actor, token_sha, expires_at)
            except Exception as exc:
                raise FolderDenied(503, "Resource folder postcommit readback UNKNOWN") from exc
            if after != fresh_view:
                raise FolderDenied(503, "Resource folder postcommit result UNKNOWN")
            return {**after, "operation": operation, "event_id": event_id}
        except (FolderDenied, ArtifactDenied, ArtifactReviewDenied):
            raise
        except Exception as exc:
            raise FolderDenied(503, "Durable folder write or commit UNKNOWN") from exc

    @staticmethod
    async def _approved_review(
        db: Any, b: Mapping[str, Any], owner: str, artifact_id: str, artifact_sha256: str
    ) -> None:
        review = (
            (
                await db.execute(
                    text(
                        "SELECT r.artifact_id,r.engagement_id,r.flow_id,r.uploader_sub,r.reviewer_sub,"
                        "r.reviewer_role,r.decision,r.artifact_sha256,r.flow_revision,r.authorization_id,"
                        "r.authorization_version,r.authorization_sha256 FROM flow_artifact_reviews r "
                        "WHERE r.artifact_id=:artifact AND r.engagement_id=:sid AND r.flow_id=:fid FOR SHARE"
                    ),
                    {"artifact": artifact_id, "sid": b["engagement_id"], "fid": b["flow_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            review is None
            or review["artifact_id"] != artifact_id
            or review["engagement_id"] != b["engagement_id"]
            or review["flow_id"] != b["flow_id"]
            or review["uploader_sub"] != owner
            or not isinstance(review["reviewer_sub"], str)
            or review["reviewer_sub"] == owner
            or review["reviewer_role"] != "senior_operator"
            or review["decision"] != "approve"
            or review["artifact_sha256"] != artifact_sha256
            or review["flow_revision"] != b["revision"]
            or review["authorization_id"] != b["authorization_id"]
            or review["authorization_version"] != b["version"]
            or review["authorization_sha256"] != b["authorization_sha256"]
        ):
            raise FolderDenied(403, "Current independent senior artifact approval required")
        # A disabled former reviewer may not be used as present authorization.
        if settings.operator_revocation_required:
            disabled = (
                await db.execute(
                    text(
                        "SELECT disabled FROM operator_subject_controls WHERE actor_id=:actor FOR SHARE"
                    ),
                    {"actor": review["reviewer_sub"]},
                )
            ).scalar_one_or_none()
            if disabled is True:
                raise FolderDenied(403, "Senior artifact reviewer revoked")
