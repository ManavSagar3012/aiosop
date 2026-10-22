"""Source-authoritative, Task-pinned 0026 virtual folder staging plan.

No folder or assignment supplied by the requesting native worker is trusted.
The only positive selection is a separately approved Task's precise catalog
revision and canonical assignment SHA, current in PostgreSQL at offer time.
This is a *plan*, never proof a worker mounted or read a filesystem.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from sqlalchemy import text

from ai_osop.memory.native_mcp_execution_grants import _deny

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FOLDER = re.compile(r"[a-z][a-z0-9_-]{0,47}\Z")
_ID = re.compile(r"folder-[0-9a-f]{32}\Z")


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


async def approved_folder_stage_plan(
    db: Any, row: Mapping[str, Any], manifest: dict[str, Any]
) -> dict[str, Any] | None:
    """Require CURRENT immutable approved Task pins for any foldered staging."""
    binding = {"task": row["task_id"], "eng": row["engagement_id"], "flow": row["flow_id"]}
    task = (
        (
            await db.execute(
                text(
                    "SELECT payload FROM tasks WHERE id=:task AND engagement_id=:eng "
                    "AND flow_id=:flow FOR SHARE"
                ),
                binding,
            )
        )
        .mappings()
        .one_or_none()
    )
    if task is None or not isinstance(task["payload"], dict):
        _deny(409, "Original independently approved resource Task unavailable")
    revision = task["payload"].get("mcp_folder_catalog_revision")
    pin = task["payload"].get("mcp_folder_staging_sha256")
    if revision is None and pin is None:
        # Original 0030 RAM-only delivery remains supported, but MUST NOT be
        # interpreted as approval for a folder filesystem stage.
        return None
    if (
        type(revision) is not int
        or revision < 1
        or revision > 1000000
        or not isinstance(pin, str)
        or _SHA.fullmatch(pin) is None
    ):
        _deny(409, "Original approved Task folder binding malformed")
    catalog = (
        (
            await db.execute(
                text(
                    "SELECT revision,engagement_id,flow_id,owner_sub,flow_revision,"
                    "authorization_version,authorization_id,authorization_sha256,"
                    "manifest_sha256 FROM flow_resource_folder_catalogs "
                    "WHERE engagement_id=:eng AND flow_id=:flow FOR SHARE"
                ),
                binding,
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        catalog is None
        or catalog["revision"] != revision
        or catalog["owner_sub"] != row["owner_id"]
        or catalog["flow_revision"] != row["flow_revision"]
        or catalog["authorization_version"] != row["authorization_version"]
        or catalog["authorization_id"] != row["authorization_id"]
        or catalog["authorization_sha256"] != row["authorization_sha256"]
        or catalog["manifest_sha256"] != manifest["manifest_sha256"]
    ):
        _deny(409, "0026 folder revision or signed authorization changed")
    assignments = (
        (
            await db.execute(
                text(
                    "SELECT a.artifact_id,a.artifact_sha256,a.folder_id,f.name "
                    "FROM flow_resource_folder_assignments AS a "
                    "JOIN flow_resource_virtual_folders AS f ON f.id=a.folder_id "
                    "AND f.flow_id=a.flow_id AND f.engagement_id=a.engagement_id "
                    "WHERE a.flow_id=:flow AND a.engagement_id=:eng "
                    "ORDER BY a.artifact_id FOR SHARE OF a,f"
                ),
                binding,
            )
        )
        .mappings()
        .all()
    )
    by_artifact: dict[str, Any] = {}
    for item in assignments:
        if (
            item["artifact_id"] in by_artifact
            or not _ID.fullmatch(item["folder_id"])
            or not _FOLDER.fullmatch(item["name"])
        ):
            _deny(409, "Untrusted or duplicate Flow resource folder assignment")
        by_artifact[item["artifact_id"]] = item
    if not assignments or len(assignments) != len(manifest["items"]):
        _deny(409, "Every approved original resource must be assigned")
    entries = []
    for source in manifest["items"]:
        assignment = by_artifact.get(source["artifact_id"])
        if assignment is None or not hmac.compare_digest(
            assignment["artifact_sha256"], source["sha256"]
        ):
            _deny(409, "Approved original resource assignment SHA changed")
        entries.append(
            {
                "artifact_id": source["artifact_id"],
                "folder_id": assignment["folder_id"],
                "folder_name": assignment["name"],
                "relative_path": "resources/" + assignment["name"] + "/" + source["name"],
                "sha256": source["sha256"],
            }
        )
    entries.sort(key=lambda entry: entry["artifact_id"])
    plan = {
        "format": "ai-osop-readonly-folder-stage-v1",
        "catalog_revision": revision,
        "manifest_sha256": manifest["manifest_sha256"],
        "items": entries,
    }
    digest = hashlib.sha256(_canonical(plan)).hexdigest()
    if not hmac.compare_digest(digest, pin):
        _deny(409, "Original human-approved folder staging digest stale")
    return {**plan, "staging_sha256": digest}
