"""UI manual ACK POST/readback against main.app and worker33 private PG16.

Reuses worker33's unmodified genuine nonroot Unix-socket PG16 fixture; DOES
NOT rerun their generic route tests. Local HS256/Ed25519 keys are fixture
signers, not independently enrolled production trust roots.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
import pytest
from jose import jwt
from sqlalchemy import text

from ai_osop.api import main
from ai_osop.api.routers import durable_supervision_subscriptions as api
from tests.qualification.test_durable_subscriptions_mounted_actual_pg_20261021 import (
    ENG_A,
    ENG_B,
    JWT_SECRET,
    OWNER_A,
    SUB,
    TASK_A,
    PgSession,
    QueryResult,
    mounted_real,
    post,
    private_pg,
    sql,
)

ROOT = Path(__file__).resolve().parents[2]
UI_SERVICE = ROOT / "ui/src/services/durableSupervisionSubscribers.ts"
UI_PANEL = ROOT / "ui/src/components/flows/DurableSupervisionSubscribersPanel.tsx"


def test_ui_exact_manual_ack_envelope_and_mounted_contract_offline() -> None:
    """No database; verify the exact service's request/readback protocol."""
    source = UI_SERVICE.read_text(encoding="utf-8")
    panel = UI_PANEL.read_text(encoding="utf-8")
    for required in (
        "method: 'POST'", "cache: 'no-store'", "credentials: 'omit'",
        "{ replica_id: replicaId, task_id: scope.taskId ?? null }",
        "{ ...binding(scope, lease), limit: 20 }",
        "{ ...binding(scope, lease), expected_cursor: lease.cursor, next_sequence: firstSequence }",
        "replica_id: lease.replica_id, lease_id: lease.lease_id",
        "generation: lease.generation, cursor: lease.cursor, task_id: scope.taskId ?? null",
        "data.acknowledged !== false", "data.acknowledged !== true",
        "updated.cursor !== firstSequence", "event.engagement_id !== scope.engagementId",
        "event.task_id !== scope.taskId", "getRuntimeToken() !== token",
    ):
        assert required in source, required
    assert "lease_until:" not in source.split("function binding(", 1)[1].split("async function post(", 1)[0]
    assert "events[0].sequence" in panel
    assert "displayed only, not acknowledged" in panel
    assert "State UNKNOWN; refresh independent server evidence" in panel
    routes = {
        r.path.rsplit("/", 1)[-1]: r for r in main.app.routes
        if r.path.startswith("/supervision/engagements/") and "/subscriptions/" in r.path
        and r.endpoint.__module__ == api.__name__
    }
    assert set(routes) == {"acquire", "read", "ack", "renew", "release", "revoke", "cursor-readback"}
    assert routes["ack"].endpoint is api.acknowledge


def _binding(lease: dict[str, Any]) -> dict[str, Any]:
    """Literal fields emitted by UI binding(...), omitting lease_until."""
    assert lease["provider_effect"] == "unobserved"
    assert lease["delivery_semantics"] == "at_least_once"
    return {
        "replica_id": lease["replica_id"], "lease_id": lease["lease_id"],
        "generation": lease["generation"], "cursor": lease["cursor"],
        "task_id": TASK_A,
    }


def _lease(response: httpx.Response, subscriber: str, cursor: int) -> dict[str, Any]:
    assert response.status_code == 200, response.text[:550]
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    outer = response.json()
    assert "lease" in outer
    value = outer["lease"]
    assert set(value) == {
        "engagement_id", "subscriber_id", "replica_id", "lease_id",
        "generation", "cursor", "lease_until", "delivery_semantics", "provider_effect",
    }
    assert value["engagement_id"] == ENG_A
    assert value["subscriber_id"] == subscriber and value["cursor"] == cursor
    assert datetime.fromisoformat(value["lease_until"].replace("Z", "+00:00")) > datetime.now(timezone.utc)
    assert value["generation"] >= 1
    return value


async def _cursor(memory: Any, subscriber: str) -> int:
    records = await sql(
        memory, "SELECT cursor_sequence FROM supervision_durable_subscriptions "
        "WHERE engagement_id=:eng AND subscriber_id=:sub",
        eng=ENG_A, sub=subscriber,
    )
    assert len(records) == 1
    return records[0]["cursor_sequence"]


@pytest.mark.asyncio
async def test_ui_mounted_pg16_readback_duplicate_ack_and_cancel_mid_update(
    mounted_real: dict[str, Any],
) -> None:
    world = mounted_real
    memory = world["memory"]
    subscriber = "subscr-" + uuid.uuid4().hex
    # The existing worker33 fixture serializes private PG commands through a
    # single stdio bridge. A concurrent INSERT blocked on a PostgreSQL unique
    # row lock would stall that bridge; test different replicas sequentially
    # here and leave TRUE SQL races to the separate direct-PG qualification.
    valid = await post(world, "acquire", {
        "replica_id": "replica-ui-1", "task_id": TASK_A,
    }, subscriber=subscriber)
    other_replica = await post(world, "acquire", {
        "replica_id": "replica-ui-2", "task_id": TASK_A,
    }, subscriber=subscriber)
    assert other_replica.status_code == 409, other_replica.text[:350]
    initial = _lease(valid, subscriber, 0)
    binding = _binding(initial)
    # Cross-subject, cross-engagement and different senior's identity do not
    # inherit a preexisting subscriber lease, even with correct lease fields.
    assert (await post(world, "read", {**binding, "limit": 20},
                       subject="bob", subscriber=subscriber)).status_code in (403, 409)
    assert (await post(world, "read", {**binding, "limit": 20},
                       subject="bob", engagement=ENG_B, subscriber=subscriber)).status_code in (403, 409)
    assert (await post(world, "read", {**binding, "limit": 20},
                       subject="senior", subscriber=subscriber)).status_code == 409

    read = await post(world, "read", {**binding, "limit": 20}, subscriber=subscriber)
    assert read.status_code == 200, read.text[:400]
    body = read.json()
    assert set(body) == {"events", "cursor", "acknowledged", "delivery_semantics"}
    assert body["cursor"] == 0 and body["acknowledged"] is False
    assert body["delivery_semantics"] == "at_least_once"
    assert [(e["sequence"], e["engagement_id"], e["task_id"]) for e in body["events"]] == [
        (11, ENG_A, TASK_A), (19, ENG_A, TASK_A),
    ]
    assert await _cursor(memory, subscriber) == 0
    assert (await post(world, "ack", {**binding, "expected_cursor": 0,
                                     "next_sequence": 19}, subscriber=subscriber)).status_code == 409
    assert (await post(world, "ack", {**binding, "expected_cursor": 1,
                                     "next_sequence": 11}, subscriber=subscriber)).status_code == 409
    ack_body = {**binding, "expected_cursor": 0, "next_sequence": 11}
    successful = await post(world, "ack", ack_body, subscriber=subscriber)
    duplicate_ack = await post(world, "ack", ack_body, subscriber=subscriber)
    assert successful.status_code == 200, successful.text[:350]
    assert duplicate_ack.status_code == 409, duplicate_ack.text[:350]
    assert successful.json()["acknowledged"] is True
    advanced = _lease(successful, subscriber, 11)
    assert (advanced["generation"], advanced["lease_id"], advanced["replica_id"]) == (
        initial["generation"], initial["lease_id"], initial["replica_id"],
    )
    assert await _cursor(memory, subscriber) == 11
    read_again = await post(world, "read", {**_binding(advanced), "limit": 20},
                            subscriber=subscriber)
    assert read_again.status_code == 200
    assert read_again.json()["acknowledged"] is False
    assert read_again.json()["cursor"] == 11
    assert [e["sequence"] for e in read_again.json()["events"]] == [19]
    assert await _cursor(memory, subscriber) == 11

    # Inject a server-side cancellation immediately AFTER the real 0040 cursor
    # UPDATE returned from PostgreSQL, BEFORE the transaction can commit. A
    # cancelled browser fetch was investigated separately and could leave a
    # live in-process request; it cannot be used to assert HTTP disconnect
    # implies DB rollback. This precisely tests rollback on server cancellation.
    old_factory = memory._async_session
    updates = {"completed": 0}

    class CancelAfterPGUpdate(PgSession):
        async def execute(
            self, stmt: Any, params: Optional[dict[str, Any]] = None
        ) -> QueryResult:
            response = await super().execute(stmt, params)
            if str(stmt).startswith(
                "UPDATE supervision_durable_subscriptions SET cursor_sequence=:next"
            ):
                updates["completed"] += 1
                raise asyncio.CancelledError("Injected server cancel after real UPDATE")
            return response

    memory._async_session = lambda: CancelAfterPGUpdate(
        world["bridge"], "ui-cancel-" + uuid.uuid4().hex
    )
    try:
        try:
            interrupted = await post(
                world, "ack", {**_binding(advanced), "expected_cursor": 11,
                               "next_sequence": 19}, subscriber=subscriber,
            )
        except asyncio.CancelledError:
            pass
        else:
            assert interrupted.status_code != 200, "Server-cancelled ACK returned success"
    finally:
        memory._async_session = old_factory
    assert updates["completed"] == 1
    assert await _cursor(memory, subscriber) == 11
    # This is a NEW human request after independently checking rollback;
    # it is not an automatic retry of an unknown result.
    committed = await post(
        world, "ack", {**_binding(advanced), "expected_cursor": 11,
                       "next_sequence": 19}, subscriber=subscriber,
    )
    assert committed.status_code == 200, committed.text[:350]
    assert committed.json()["acknowledged"] is True
    completed = _lease(committed, subscriber, 19)
    empty = await post(world, "read", {**_binding(completed), "limit": 20},
                       subscriber=subscriber)
    assert empty.status_code == 200 and empty.json()["events"] == []


def _fixture_jwt() -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": "local-jwt", "sub": OWNER_A, "role": "operator", "iat": now,
         "exp": now + 3600, "jti": "ui-" + uuid.uuid4().hex},
        JWT_SECRET, algorithm="HS256",
    )


@pytest.mark.asyncio
async def test_ui_valid_fixture_bearer_then_0014_revocation_insert_blocks_ack(
    mounted_real: dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = mounted_real
    memory = world["memory"]
    world["alice"] = _fixture_jwt()
    original = api._current_signed_roe
    for revocation_type in ("token", "subject"):
        subscriber = "subscr-" + uuid.uuid4().hex
        acquired = await post(world, "acquire", {
            "replica_id": "replica-ui-rev", "task_id": TASK_A,
        }, subscriber=subscriber)
        binding = _binding(_lease(acquired, subscriber, 0))
        injected = {"count": 0}

        async def insert_after_verified_bearer(
            mem: Any, engagement: str, task: Optional[str]
        ) -> Any:
            signed = await original(mem, engagement, task)
            if injected["count"] == 0:
                if revocation_type == "token":
                    await sql(
                        memory, "INSERT INTO operator_token_revocations "
                        "(digest,actor_id,expires_at,revoked_at) VALUES "
                        "(:digest,:actor,now()+interval '2 hours',clock_timestamp())",
                        digest=hashlib.sha256(world["alice"].encode()).hexdigest(),
                        actor=OWNER_A,
                    )
                else:
                    await sql(
                        memory, "INSERT INTO operator_subject_controls "
                        "(actor_id,disabled,updated_at,updated_by) VALUES "
                        "(:actor,true,clock_timestamp(),'fixture-senior')",
                        actor=OWNER_A,
                    )
                injected["count"] += 1
            return signed

        with monkeypatch.context() as patch:
            patch.setattr(api, "_current_signed_roe", insert_after_verified_bearer)
            denied = await post(world, "ack", {
                **binding, "expected_cursor": 0, "next_sequence": 11,
            }, subscriber=subscriber)
        assert injected["count"] == 1, "Revocation was not inserted after bearer verification"
        assert denied.status_code in (401, 409), denied.text[:300]
        assert await _cursor(memory, subscriber) == 0
        assert (await post(world, "read", {**binding, "limit": 20},
                           subscriber=subscriber)).status_code in (401, 409)
        # Another fixture-signed token under the same subject should still
        # work after a token-only revocation, but NOT after subject disable.
        if revocation_type == "token":
            world["alice"] = _fixture_jwt()
    assert (await sql(memory,
                      "SELECT disabled FROM operator_subject_controls WHERE actor_id=:actor",
                      actor=OWNER_A)) == [{"disabled": True}]
