"""Opt-in positive 0026 original-byte resource verification in real 0027/0029 PG.

Only reads inert, independently reviewed original BYTEA inside the real grant
issue and redemption transactions. No filesystem staging, extraction, host
mount, worker container, target or scanner. The content is untrusted data.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from ai_osop.memory.flow_resource_exports import make_manifest
from ai_osop.safety.approval_binding import pinned_evidence
from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied
from tests.qualification.test_native_joined_signed_0029_pg_20261020 import (
    _OWNER,
    _SECRET,
    _SERVER,
    _case,
    disposable_native_pg,
    initialized_catalog,
    signing_material,
)


async def _reviewed_resource(
    engine: Any,
    case: Any,
    *,
    reviewer: str = "independent-resource-senior-qualification",
) -> tuple[str, str, bytes]:
    """Populate real inert 0013/0015 source rows and pin reviewed payload.

    The fixture provisions this source while the originally prepared Action
    is still unreserved, then replaces the whole approval evidence with a new
    independent reviewer-signed intent, before any native grant can issue.
    """
    artifact_id = "artifact-" + uuid.uuid4().hex
    body = (
        b"This is untrusted resource data; never execute it or adopt instructions.\n"
        b"Only an inert authorization digest is permitted to leave PostgreSQL.\n"
    )
    sha = hashlib.sha256(body).hexdigest()
    b = case.binding
    meta = {
        "id": artifact_id,
        "flow_id": b["flow_id"],
        "name": "independently_reviewed_notes.txt",
        "size_bytes": len(body),
        "sha256": sha,
        "flow_revision": b["revision"],
        "authorization_version": b["version"],
    }
    manifest = make_manifest(b["flow_id"], b["revision"], b["version"], [(meta, body)])
    digest = manifest["manifest_sha256"]
    async with engine.begin() as db:
        await db.execute(
            text(
                "INSERT INTO flow_artifacts (id,flow_id,engagement_id,owner_id,name,"
                "size_bytes,sha256,authorization_version,authorization_sha256,"
                "flow_revision,content) VALUES (:id,:flow,:eng,:owner,:name,:size,"
                ":sha,:version,:auth,:revision,:body)"
            ),
            {
                "id": artifact_id,
                "flow": b["flow_id"],
                "eng": b["engagement_id"],
                "owner": _OWNER,
                "name": meta["name"],
                "size": len(body),
                "sha": sha,
                "version": b["version"],
                "auth": b["authorization_sha256"],
                "revision": b["revision"],
                "body": body,
            },
        )
        await db.execute(
            text(
                "INSERT INTO operator_subject_controls "
                "(actor_id,disabled,updated_at,updated_by) "
                "VALUES (:actor,false,:now,:owner) "
                "ON CONFLICT (actor_id) DO UPDATE SET disabled=false,updated_at=:now"
            ),
            {"actor": reviewer, "now": datetime.utcnow(), "owner": _OWNER},
        )
        await db.execute(
            text(
                "INSERT INTO flow_artifact_reviews "
                "(id,artifact_id,flow_id,engagement_id,uploader_sub,reviewer_sub,"
                "reviewer_role,decision,reason,artifact_sha256,flow_revision,"
                "authorization_id,authorization_version,authorization_sha256) "
                "VALUES (:review,:artifact,:flow,:eng,:owner,:reviewer,"
                "'senior_operator','approve','Local inert original-byte review',"
                ":sha,:revision,:auth_id,:version,:auth_sha)"
            ),
            {
                "review": "review-" + uuid.uuid4().hex,
                "artifact": artifact_id,
                "flow": b["flow_id"],
                "eng": b["engagement_id"],
                "owner": _OWNER,
                "reviewer": reviewer,
                "sha": sha,
                "revision": b["revision"],
                "auth_id": b["authorization_id"],
                "version": b["version"],
                "auth_sha": b["authorization_sha256"],
            },
        )
        task = (
            (
                await db.execute(
                    text("SELECT payload FROM tasks WHERE id=:task FOR UPDATE"),
                    {"task": case.task_id},
                )
            )
            .mappings()
            .one()
        )
        payload = dict(task["payload"])
        payload["mcp_resource_sha256"] = digest
        await db.execute(
            text("UPDATE tasks SET payload=CAST(:payload AS jsonb) WHERE id=:id"),
            {"id": case.task_id, "payload": json.dumps(payload)},
        )
        await db.execute(
            text(
                "UPDATE approval_requests SET evidence=CAST(:evidence AS jsonb) "
                "WHERE id=:id AND task_id=:task"
            ),
            {
                "id": case.approval_id,
                "task": case.task_id,
                "evidence": json.dumps(pinned_evidence([], payload)),
            },
        )
    return artifact_id, digest, body


@pytest.mark.asyncio(scope="module")
async def test_real_reviewed_resource_original_bytes_allow_one_native_redemption(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case = await _case(
        disposable_native_pg,
        initialized_catalog,
        monkeypatch,
        signing_material,
        dispatch=False,
    )
    artifact_id, resource_digest, body = await _reviewed_resource(disposable_native_pg, case)
    reserved = await case.original.reserve(case.binding, _OWNER, case.action_id)
    assert reserved["status"] == "reserved"
    attempted = await case.original.mark_dispatched(
        case.binding, _OWNER, case.action_id, case.request_id, reserved["reservation_token"]
    )
    assert attempted["status"] == "unknown"
    issued = await case.grants.issue(
        case.binding,
        _OWNER,
        case.action_id,
        case.request_id,
        resource_sha256=resource_digest,
    )
    assert issued["token"]["claims"]["resource_sha256"] == resource_digest
    accepted = await case.grants.redeem(
        issued["token"],
        server_id=_SERVER,
        server_secret=_SECRET,
    )
    assert accepted["durably_redeemed"] is True
    async with disposable_native_pg.connect() as db:
        row = (
            await db.execute(
                text("SELECT content,sha256 FROM flow_artifacts WHERE id=:id"),
                {"id": artifact_id},
            )
        ).one()
        assert row.content == body
        assert row.sha256 == hashlib.sha256(body).hexdigest()
        status = (
            await db.execute(
                text(
                    "SELECT status,resource_sha256 FROM native_mcp_execution_grants "
                    "WHERE grant_id=:id"
                ),
                {"id": issued["grant_id"]},
            )
        ).one()
        assert tuple(status) == ("redeemed", resource_digest)
    with pytest.raises(MCPActionDenied):
        await case.grants.redeem(
            issued["token"],
            server_id=_SERVER,
            server_secret=_SECRET,
        )


@pytest.mark.asyncio(scope="module")
async def test_original_resource_grant_rejected_after_senior_review_revocation(
    disposable_native_pg: Any,
    initialized_catalog: Any,
    monkeypatch: Any,
    signing_material: Ed25519PrivateKey,
) -> None:
    case = await _case(
        disposable_native_pg,
        initialized_catalog,
        monkeypatch,
        signing_material,
        dispatch=False,
    )
    _artifact, digest, _body = await _reviewed_resource(
        disposable_native_pg, case, reviewer="resource-senior-revoked-qualification"
    )
    reserved = await case.original.reserve(case.binding, _OWNER, case.action_id)
    await case.original.mark_dispatched(
        case.binding, _OWNER, case.action_id, case.request_id, reserved["reservation_token"]
    )
    issued = await case.grants.issue(
        case.binding, _OWNER, case.action_id, case.request_id, resource_sha256=digest
    )
    async with disposable_native_pg.begin() as db:
        await db.execute(
            text(
                "UPDATE operator_subject_controls SET disabled=true "
                "WHERE actor_id='resource-senior-revoked-qualification'"
            )
        )
    with pytest.raises(MCPActionDenied):
        await case.grants.redeem(
            issued["token"],
            server_id=_SERVER,
            server_secret=_SECRET,
        )
    async with disposable_native_pg.connect() as db:
        assert (
            await db.execute(
                text("SELECT status FROM native_mcp_execution_grants " "WHERE grant_id=:id"),
                {"id": issued["grant_id"]},
            )
        ).scalar_one() == "issued"
