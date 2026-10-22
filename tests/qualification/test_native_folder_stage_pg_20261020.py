"""Real 0031 PostgreSQL Task-pinned 0026 folder-stage admission.

Uses an exclusively disposable database and original source authority. No
application DB, filesystem writes, target, model or generic MCP scanner.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied
from ai_osop.memory.flow_resource_exports import make_manifest
from ai_osop.memory.native_mcp_folder_stage import _canonical
from ai_osop.memory.native_mcp_resource_delivery import NativeMCPResourceDelivery
from ai_osop.safety.approval_binding import pinned_evidence
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    _OWNER,
    _SERVER,
    _SECRET,
    _case,
    disposable_native_pg,
    initialized_catalog,
    signing_material,
)
from tests.qualification.test_native_reviewed_resource_pg_20261020 import (
    _reviewed_resource,
)


async def _approved_folder_case(
    db_engine: Any, registry: Any, monkeypatch: Any, key: Ed25519PrivateKey
) -> tuple[Any, str, str, dict[str, Any], dict[str, Any]]:
    case = await _case(db_engine, registry, monkeypatch, key, dispatch=False)
    artifact, digest, body = await _reviewed_resource(
        db_engine, case, reviewer="independent-staging-senior"
    )
    sha = hashlib.sha256(body).hexdigest()
    folder_id = "folder-" + uuid.uuid4().hex
    name = "operator_reviewed"
    stage = {
        "format": "ai-osop-readonly-folder-stage-v1",
        "catalog_revision": 1,
        "manifest_sha256": digest,
        "items": [
            {
                "artifact_id": artifact,
                "folder_id": folder_id,
                "folder_name": name,
                "relative_path": "resources/" + name + "/independently_reviewed_notes.txt",
                "sha256": sha,
            }
        ],
    }
    stage_digest = hashlib.sha256(_canonical(stage)).hexdigest()
    b = case.binding
    async with db_engine.begin() as db:
        await db.execute(
            text(
                "INSERT INTO flow_resource_folder_catalogs "
                "(flow_id,engagement_id,owner_sub,revision,flow_revision,"
                "authorization_version,authorization_id,authorization_sha256,manifest_sha256) "
                "VALUES (:flow,:eng,:owner,1,:revision,:version,:auth_id,:auth_sha,:manifest)"
            ),
            {
                "flow": b["flow_id"],
                "eng": b["engagement_id"],
                "owner": _OWNER,
                "revision": b["revision"],
                "version": b["version"],
                "auth_id": b["authorization_id"],
                "auth_sha": b["authorization_sha256"],
                "manifest": digest,
            },
        )
        await db.execute(
            text(
                "INSERT INTO flow_resource_virtual_folders "
                "(id,engagement_id,flow_id,name) VALUES (:id,:eng,:flow,:name)"
            ),
            {"id": folder_id, "eng": b["engagement_id"], "flow": b["flow_id"], "name": name},
        )
        await db.execute(
            text(
                "INSERT INTO flow_resource_folder_assignments "
                "(flow_id,engagement_id,artifact_id,artifact_sha256,folder_id) "
                "VALUES (:flow,:eng,:artifact,:sha,:folder)"
            ),
            {
                "flow": b["flow_id"],
                "eng": b["engagement_id"],
                "artifact": artifact,
                "sha": sha,
                "folder": folder_id,
            },
        )
        task = (
            (
                await db.execute(
                    text("SELECT payload FROM tasks WHERE id=:id FOR UPDATE"),
                    {"id": case.task_id},
                )
            )
            .mappings()
            .one()
        )
        payload = dict(task["payload"])
        payload["mcp_folder_catalog_revision"] = 1
        payload["mcp_folder_staging_sha256"] = stage_digest
        await db.execute(
            text("UPDATE tasks SET payload=CAST(:body AS jsonb) WHERE id=:id"),
            {"id": case.task_id, "body": json.dumps(payload)},
        )
        await db.execute(
            text(
                "UPDATE approval_requests SET evidence=CAST(:evidence AS jsonb) "
                "WHERE id=:approval AND task_id=:task"
            ),
            {
                "approval": case.approval_id,
                "task": case.task_id,
                "evidence": json.dumps(pinned_evidence([], payload)),
            },
        )
    return case, digest, folder_id, stage, {**stage, "staging_sha256": stage_digest}


@pytest.mark.asyncio(scope="module")
async def test_exact_signed_task_and_live_0026_folder_selection_passes_one_0031_offer(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case, digest, _folder, _stage, full_stage = await _approved_folder_case(
        disposable_native_pg, initialized_catalog, monkeypatch, signing_material
    )
    held = await case.original.reserve(case.binding, _OWNER, case.action_id)
    await case.original.mark_dispatched(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        held["reservation_token"],
    )
    token = await case.grants.issue(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        resource_sha256=digest,
    )
    assert (await case.grants.redeem(token["token"], server_id=_SERVER, server_secret=_SECRET))[
        "durably_redeemed"
    ] is True
    delivered = await NativeMCPResourceDelivery(case.original).offer(
        token["token"], server_id=_SERVER, server_secret=_SECRET
    )
    assert delivered["folder_staging"] == full_stage
    assert delivered["manifest_sha256"] == digest
    async with disposable_native_pg.connect() as db:
        row = (
            await db.execute(
                text(
                    "SELECT folder_staging_sha256,status FROM native_mcp_resource_offers "
                    "WHERE grant_id=:id"
                ),
                {"id": token["grant_id"]},
            )
        ).one()
        assert tuple(row) == (full_stage["staging_sha256"], "offered")
    with pytest.raises(MCPActionDenied):
        await NativeMCPResourceDelivery(case.original).offer(
            token["token"], server_id=_SERVER, server_secret=_SECRET
        )


@pytest.mark.asyncio(scope="module")
async def test_change_0026_catalog_revision_after_human_signoff_denies_original_bytes(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case, digest, _folder, _stage, _full_stage = await _approved_folder_case(
        disposable_native_pg, initialized_catalog, monkeypatch, signing_material
    )
    held = await case.original.reserve(case.binding, _OWNER, case.action_id)
    await case.original.mark_dispatched(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        held["reservation_token"],
    )
    token = await case.grants.issue(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        resource_sha256=digest,
    )
    await case.grants.redeem(
        token["token"],
        server_id=_SERVER,
        server_secret=_SECRET,
    )
    async with disposable_native_pg.begin() as db:
        await db.execute(
            text(
                "UPDATE flow_resource_folder_catalogs SET revision=revision+1 "
                "WHERE flow_id=:flow AND engagement_id=:eng"
            ),
            {"flow": case.binding["flow_id"], "eng": case.binding["engagement_id"]},
        )
    with pytest.raises(MCPActionDenied):
        await NativeMCPResourceDelivery(case.original).offer(
            token["token"], server_id=_SERVER, server_secret=_SECRET
        )
    async with disposable_native_pg.connect() as db:
        assert (
            await db.execute(
                text("SELECT count(*) FROM native_mcp_resource_offers WHERE grant_id=:id"),
                {"id": token["grant_id"]},
            )
        ).scalar_one() == 0
