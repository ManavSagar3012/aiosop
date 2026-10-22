"""Real mounted ASGI -> 0042 writer -> private nonroot PostgreSQL16.

Explicit opt-in ONLY: OSOP_0042_OPERATOR_MOUNTED_PG_E2E=1. The Windows
FastAPI app uses the existing ephemeral WSL Unix-socket-only PostgreSQL
stdio bridge. Migrations are actual 0009/0014/0019/0038/0039/0041/0042;
Task and Flow parents are minimal disposable SQL fixtures. Four distinct
Ed25519 signer roots and the signed ROE identity are TEST FIXTURES, not
operator-host enrollment or production deployment authority.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from sqlalchemy import text

from ai_osop.api import deps, main
from ai_osop.api.routers import reviewed_library_flow_import as routes
from ai_osop.core.config import settings
from ai_osop.memory.flow_artifacts import FlowArtifactStore
from ai_osop.memory.operator_global_library import OperatorGlobalLibrary
from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
    OperatorReviewedFlowAtomicWriter,
)
from ai_osop.memory.reviewed_library_flow_import import (
    _DOMAIN,
    _ROLES,
    _canonical,
    _scope,
    ReviewedLibraryFlowImport,
)
from tests.qualification import test_unified_knowledge_mounted_pg_integration_20261021 as pg

OPT_IN = "OSOP_0042_OPERATOR_MOUNTED_PG_E2E"
ROOT = Path(__file__).resolve().parents[2]
TASK = "task-reviewed-private-0042"
URI = f"/flows/{pg.FLOW}/reviewed-library-import"
TEXT_ORIGINAL = pg.GLOBAL_TEXT


def _pg_worker_with_current_migrations() -> str:
    """Reuse independently isolated PG bootstrap; change only child test script.

    The actual 0041 and 0042 migration upgrade() functions run in PostgreSQL;
    no production migrations/files or global installed application DB change.
    """
    source = pg._PG_WORKER
    marker = "    load('0039','0039_operator_global_library.py'),\n]"
    assert source.count(marker) == 1, "Parent private PG fixture changed"
    source = source.replace(
        marker,
        "    load('0039','0039_operator_global_library.py'),\n"
        "    load('0041','0041_reviewed_global_flow_citations.py'),\n"
        "    load('0042','0042_reviewed_flow_originals.py'),\n]",
    )
    marker = "            upgrade(db,mods[4])"
    assert source.count(marker) == 1
    source = source.replace(
        marker,
        "            for module in mods[4:]:\n                upgrade(db,module)",
    )
    return source


def _query(bridge: Any, statement: str, **params: Any) -> list[dict[str, Any]]:
    async def run() -> list[dict[str, Any]]:
        async with pg._PgSession(bridge) as db:
            return (await db.execute(text(statement), params)).rows

    return asyncio.run(run())


def _seed_task(bridge: Any) -> None:
    _query(
        bridge,
        "CREATE TABLE tasks (id varchar(64) PRIMARY KEY, engagement_id varchar(64) "
        "REFERENCES session_states(session_id), flow_id varchar(64) "
        "REFERENCES execution_flows(id), status varchar(32) NOT NULL, payload JSONB NOT NULL)",
    )
    _query(
        bridge,
        "INSERT INTO tasks (id,engagement_id,flow_id,status,payload) "
        "VALUES (:task,:eng,:flow,'running',CAST(:body AS JSONB))",
        task=TASK,
        eng=pg.SESSION,
        flow=pg.FLOW,
        body=json.dumps(
            {
                "_authorization_version": pg.AUTH_VERSION,
                "planner_flow_revision": pg.FLOW_REVISION,
            }
        ),
    )


def _test_signer_service(
    library: OperatorGlobalLibrary,
) -> tuple[ReviewedLibraryFlowImport, dict[str, Any]]:
    """Separately signed, nonce-scoped mock attestations, NOT host trust roots."""
    keys = {role: Ed25519PrivateKey.generate() for role in _ROLES}
    state: dict[str, Any] = {
        "forged_reviewer": False,
        "reviewer_revoked": False,
        "swap_second_round": False,
        "expired": False,
        "calls": [],
    }
    extras = {
        "principal": {"principal_authenticated": True, "owner_namespace_verified": True},
        "reviewer": {
            "review_id": "senior-review-0042",
            "reviewer_sub": "independent-senior-0042",
            "uploader_sub": pg.ALICE,
            "reviewer_role": "senior_operator",
            "decision": "approve",
            "review_current": True,
            "source_original_reviewed": True,
        },
        "flow": {
            "flow_status": "running",
            "tenant_owner_verified": True,
            "current_revision_verified": True,
        },
        "roe": {
            "authorization_current": True,
            "task_running": True,
            "task_flow_verified": True,
            "revocation_epoch": 1,
        },
    }

    def reader(role: str) -> Any:
        async def signed(request: Any, nonce: str) -> bytes:
            now = int(time.time())
            state["calls"].append(role)
            _, scope = _scope(request)
            values = dict(extras[role])
            if role == "reviewer":
                if state["reviewer_revoked"]:
                    values["review_current"] = False
                if state["swap_second_round"] and state["calls"].count(role) % 2 == 0:
                    values["review_id"] = "senior-review-changed-0042"
            issued = now - 20 if state["expired"] else now
            claims = {
                "kind": role,
                "nonce": nonce,
                "issued_at": issued,
                "expires_at": issued + 8,
                **scope,
                **values,
            }
            key = keys["principal" if role == "reviewer" and state["forged_reviewer"] else role]
            sig = key.sign(_DOMAIN + role.encode("ascii") + b"\x00" + _canonical(claims))
            return json.dumps(
                {"claims": claims, "signature_b64": base64.b64encode(sig).decode("ascii")},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")

        return signed

    service = ReviewedLibraryFlowImport(
        library=library,
        independently_pinned_public_keys={k: v.public_key() for k, v in keys.items()},
        authority_readers={k: reader(k) for k in _ROLES},
        timeout_seconds=5.0,
    )
    assert service._enrolled_shape
    return service, state


def _assert_safe(reply: Any) -> None:
    if reply.status_code == 200:
        assert reply.headers["cache-control"] == "private, no-store"
        assert reply.headers["x-content-type-options"] == "nosniff"
    assert TEXT_ORIGINAL not in reply.text
    assert "needle global immutable original" not in reply.text
    assert not {"content", "original", "original_text", "api_key", "token"} & set(
        reply.json().keys()
    )
    assert "eyJ" not in reply.text


def _body(digest: str) -> dict[str, Any]:
    return {
        "engagement_id": pg.SESSION,
        "flow_owner": pg.ALICE,
        "expected_flow_revision": pg.FLOW_REVISION,
        "task_id": TASK,
        "authorization_id": pg.AUTH_ID,
        "authorization_version": pg.AUTH_VERSION,
        "authorization_sha256": digest,
        "global_document_id": pg.GLOBAL_ID,
        "global_revision": 1,
        "global_sha256": hashlib.sha256(TEXT_ORIGINAL.encode("utf-8")).hexdigest(),
    }


def test_main_mount_routes_exist_without_trusted_host_enrollment() -> None:
    """No PG opt-in required: production mount must deny before write."""
    for suffix in (
        "/store-reviewed-original",
        "/store-reviewed-original/readback",
        "/record-citation",
        "/record-citation/readback",
    ):
        path = "/flows/{flow_id}/reviewed-library-import" + suffix
        assert len([r for r in main.app.routes if getattr(r, "path", "") == path]) == 1
    assert not hasattr(main.app.state, routes._HOST_SLOT)
    assert not hasattr(main.app.state, routes._LOCKED_SLOT)
    # NO TestClient(main.app) context: that would run the application's live
    # startup/lifespan. The isolated route-only ASGI mount below is safe.


def test_rejected_extra_field_never_echoes_caller_submitted_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prime-owned router's scoped validation-error redaction is verified."""
    from fastapi import FastAPI

    secret = "extra-body-test-" + "z" * 40
    monkeypatch.setattr(settings, "jwt_secret", secret)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "jwt_audience", None)
    app = FastAPI()
    app.include_router(routes.router)
    with TestClient(app) as client:
        response = client.post(
            URI + "/store-reviewed-original",
            json={**_body("a" * 64), "content": TEXT_ORIGINAL},
            headers={"Authorization": "Bearer " + pg._jwt(pg.ALICE, secret)},
        )
    assert response.status_code == 422
    assert TEXT_ORIGINAL not in response.text


def test_ui_flow_import_uses_only_digest_scopes_and_metadata_receipts() -> None:
    """Source assertion only: this is not a rendered-browser/UI E2E test."""
    service = (ROOT / "ui/src/services/reviewedLibraryFlowImport.ts").read_text("utf-8")
    component = (ROOT / "ui/src/components/flows/ReviewedLibraryFlowImportPanel.tsx").read_text(
        "utf-8"
    )
    declared = service.split("export interface StoredReviewedFlowOriginal {", 1)[1].split("}", 1)[0]
    assert "original_utf8_bytes: number" in declared
    assert "source_original_returned: false" in declared
    assert "content:" not in declared and "original_text:" not in declared
    assert "body: JSON.stringify({ ...fields, flow_owner: actor.sub })" in service
    assert "const { flowId, ...fields } = input;" in service
    assert "storeReviewedFlowOriginal(input)" in component
    assert "readbackStoredReviewedFlowOriginal(scope)" in component
    assert "attempted.current.add(key)" in component
    assert "dangerouslySetInnerHTML" not in component
    assert "original.content" not in component


def test_private_pg16_actual_asgi_to_atomic_original_and_deny_races(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.getenv(OPT_IN) != "1":
        pytest.skip(f"Private PostgreSQL16 explicit opt-in requires {OPT_IN}=1")
    # Reuse the current nonroot private 0700 UDS stdio bridge; it creates one
    # fresh cluster under /tmp, never opens a configured app DB connection.
    monkeypatch.setattr(pg, "_PG_WORKER", _pg_worker_with_current_migrations())
    bridge = pg._PgBridge()
    try:
        assert (
            bridge.command(
                "execute",
                sql="SELECT to_regclass('operator_reviewed_flow_originals') AS relation",
            )["rows"][0]["relation"]
            == "operator_reviewed_flow_originals"
        )
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        monkeypatch.setenv(
            "OSOP_ROE_TRUSTED_KEYS_JSON",
            json.dumps({pg.KID: base64.b64encode(public).decode("ascii")}),
        )
        policy, signature, digest = pg._policy(private)
        pg._seed(bridge, policy=policy, signature=signature, digest=digest)
        _seed_task(bridge)

        # Same *callable identity* for the 0039 locked current source and Flow
        # writer; the actual SQL tables and signed ROE verifier are not mocked.
        maker = lambda: pg._PgSession(bridge)
        memory = SimpleNamespace(_async_session=maker)
        service, signer_state = _test_signer_service(OperatorGlobalLibrary(memory))
        writer = OperatorReviewedFlowAtomicWriter(
            preflight=service, flow_artifacts=FlowArtifactStore(memory), timeout_seconds=5.0
        )
        assert writer._trusted_session_maker() is maker

        for field, value in (
            ("environment", "production"),
            ("jwt_secret", "test-only-mount-" + "x" * 48),
            ("jwt_algorithm", "HS256"),
            ("jwt_issuer", None),
            ("jwt_audience", None),
            ("operator_revocation_required", True),
        ):
            monkeypatch.setattr(settings, field, value)
        monkeypatch.setitem(deps.state, "orchestrator", SimpleNamespace(session_memory=memory))
        monkeypatch.setitem(deps.state, "session_store", None)
        # A disposable app with the REAL production router/middleware avoids
        # mutating globally mounted main.app host state.
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(routes.router)
        routes.install_host_reviewed_library_preflight(app, service)
        routes.install_host_locked_reviewed_library_preflight(app, writer)
        token = pg._jwt(pg.ALICE, settings.jwt_secret)
        wrong_token = pg._jwt(pg.BOB, settings.jwt_secret)
        body = _body(digest)

        def post(
            client: TestClient, suffix: str, payload: dict[str, Any] = None, jwt: str = token
        ) -> Any:
            return client.post(
                URI + suffix,
                json=payload or body,
                headers={"Authorization": "Bearer " + jwt},
            )

        with TestClient(app) as client:
            no_auth = client.post(URI + "/store-reviewed-original", json=body)
            assert no_auth.status_code == 401
            wrong_owner = post(client, "/store-reviewed-original", jwt=wrong_token)
            assert wrong_owner.status_code == 403
            _assert_safe(wrong_owner)
            forged_owner = post(client, "/store-reviewed-original", {**body, "flow_owner": pg.BOB})
            assert forged_owner.status_code == 403
            _assert_safe(forged_owner)
            forged_content = post(
                client, "/store-reviewed-original", {**body, "content": TEXT_ORIGINAL}
            )
            assert forged_content.status_code == 422
            # Current prime-owned router redacts unknown body field values;
            # neither caller input nor PostgreSQL original reaches 422 payload.
            assert TEXT_ORIGINAL not in forged_content.text
            _assert_safe(forged_content)

            signer_state["forged_reviewer"] = True
            forged_review = post(client, "/store-reviewed-original")
            assert forged_review.status_code == 409
            _assert_safe(forged_review)
            signer_state["forged_reviewer"] = False
            signer_state["reviewer_revoked"] = True
            rejected = post(client, "/store-reviewed-original")
            assert rejected.status_code == 409
            _assert_safe(rejected)
            signer_state["reviewer_revoked"] = False
            signer_state["swap_second_round"] = True
            changed = post(client, "/store-reviewed-original")
            assert changed.status_code == 409
            _assert_safe(changed)
            signer_state["swap_second_round"] = False
            signer_state["expired"] = True
            expired = post(client, "/store-reviewed-original")
            assert expired.status_code == 409
            _assert_safe(expired)
            signer_state["expired"] = False
            assert _query(bridge, "SELECT citation_id FROM operator_reviewed_flow_originals") == []

            committed = post(client, "/store-reviewed-original")
            assert committed.status_code == 200, committed.text
            _assert_safe(committed)
            receipt = committed.json()
            assert receipt["status"] == "reviewed_flow_original_stored_inert"
            assert receipt["transaction_committed_source_and_citation"] is True
            assert receipt["approved_for_agent_context"] is False
            assert receipt["verified_target_evidence"] is False
            assert receipt["safe_for_execution"] is False
            assert receipt["source_original_returned"] is False
            assert receipt["source_sha256"] == body["global_sha256"]
            assert receipt["original_utf8_bytes"] == len(TEXT_ORIGINAL.encode("utf-8"))
            readback = post(client, "/store-reviewed-original/readback")
            assert readback.status_code == 200
            _assert_safe(readback)
            assert readback.json() == receipt
            assert _query(
                bridge,
                "SELECT content, approved_for_agent_context, "
                "verified_target_evidence FROM operator_reviewed_flow_originals",
            ) == [
                {
                    "content": TEXT_ORIGINAL,
                    "approved_for_agent_context": False,
                    "verified_target_evidence": False,
                }
            ]
            assert (
                len(_query(bridge, "SELECT id FROM operator_reviewed_global_flow_citations")) == 1
            )

            # The same scope can never create a second immutable citation.
            # Its uncertain result is a generic 409; existing receipt remains.
            duplicate = post(client, "/store-reviewed-original")
            assert duplicate.status_code == 409
            _assert_safe(duplicate)
            assert (
                len(_query(bridge, "SELECT citation_id FROM operator_reviewed_flow_originals")) == 1
            )

            # Mutation of signed Task/current Flow between requests prevents
            # readback even though immutable 0042 source remains in PostgreSQL.
            _query(
                bridge,
                "UPDATE tasks SET payload=jsonb_set(payload,'{planner_flow_revision}',"
                " '999'::jsonb) WHERE id=:task",
                task=TASK,
            )
            task_race = post(client, "/store-reviewed-original/readback")
            assert task_race.status_code == 409
            _assert_safe(task_race)
            _query(
                bridge,
                "UPDATE tasks SET payload=jsonb_set(payload,'{planner_flow_revision}',"
                " CAST(:rev AS jsonb)) WHERE id=:task",
                task=TASK,
                rev=str(pg.FLOW_REVISION),
            )

            # Actual 0014 durable operator-subject disable is enforced by the
            # existing signed bearer/revocation boundary (it may DENY before
            # the 0042 writer reaches guard_sql). Never label HTTP 401/403
            # as proof of a committed or attempted writer transaction.
            _query(
                bridge,
                "INSERT INTO operator_subject_controls "
                "(actor_id,disabled,updated_at,updated_by) "
                "VALUES (:owner,true,now(),'fixture-senior')",
                owner=pg.ALICE,
            )
            disabled = post(client, "/store-reviewed-original/readback")
            assert disabled.status_code in (401, 403, 409)
            _assert_safe(disabled)
            _query(
                bridge,
                "UPDATE operator_subject_controls SET disabled=false,updated_at=now() "
                "WHERE actor_id=:owner",
                owner=pg.ALICE,
            )
            reenabled = post(client, "/store-reviewed-original/readback")
            assert reenabled.status_code == 200
            assert reenabled.json() == receipt
            _assert_safe(reenabled)

            # Moving the 0039 current pointer via an immutable new version
            # invalidates previous revision on current, despite old 0042 rows.
            _query(
                bridge,
                "INSERT INTO operator_global_library_versions "
                "(document_id,revision,title,doc_type,content,content_bytes,sha256) "
                "VALUES (:id,2,'Changed','answer',:body,:len,:digest)",
                id=pg.GLOBAL_ID,
                body="revised original",
                len=len("revised original"),
                digest=hashlib.sha256(b"revised original").hexdigest(),
            )
            _query(
                bridge,
                "UPDATE operator_global_library_documents SET current_revision=2 WHERE id=:id",
                id=pg.GLOBAL_ID,
            )
            stale = post(client, "/store-reviewed-original/readback")
            assert stale.status_code == 409
            _assert_safe(stale)
            assert (
                len(_query(bridge, "SELECT citation_id FROM operator_reviewed_flow_originals")) == 1
            )
            _query(
                bridge,
                "UPDATE signed_authorizations SET status='revoked',"
                " revoked_at=now() WHERE authorization_id=:auth",
                auth=pg.AUTH_ID,
            )
            revoked = post(client, "/store-reviewed-original/readback")
            assert revoked.status_code == 409
            _assert_safe(revoked)
            assert (
                len(_query(bridge, "SELECT citation_id FROM operator_reviewed_flow_originals")) == 1
            )
            assert signer_state["calls"], "Synthetic independent-signature readers unused"
    finally:
        bridge.close()
