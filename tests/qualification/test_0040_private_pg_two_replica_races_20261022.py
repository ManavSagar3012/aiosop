"""0040 physical two-connection PG16 CAS/ACK/revoke qualification (opt-in).

Reuses the established private WSL Unix-domain-socket-only PostgreSQL stdio
bridge, actual migrations, mounted main.app routes and genuine signed ROE/JWT
from test_durable_subscriptions_mounted_actual_pg_20261021.py. Each SQL client
has its own backend connection and transaction. NO app DB/Docker/TCP/targets.

Two ASGI clients + distinct PostgreSQL sessions are NOT two deployed hosts or
process-isolated replicas. A deliberately discarded successful HTTP response
models a lost ACK; it is not proof of an actual network disconnect.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import text
from starlette.requests import Request

from tests.qualification import (
    test_durable_subscriptions_mounted_actual_pg_20261021 as prior,
)
from tests.qualification.test_durable_subscriptions_mounted_actual_pg_20261021 import (
    mounted_real,  # noqa: F401 - actual signed-ROE + mounted fixture, unchanged
)

OPT_IN = "OSOP_0040_PRIVATE_PG_TWO_REPLICA_RACES"


@pytest.fixture
def private_pg(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Never initialize PG/WSL without this new test's explicit opt-in."""
    if os.environ.get(OPT_IN) != "1":
        pytest.skip(f"Explicit nonroot private PG16 opt-in: {OPT_IN}=1")
    monkeypatch.setenv(prior.OPT_IN, "1")
    bridge = prior.PgBridge()
    try:
        assert bridge.startup == {
            "ready": True,
            "pg": "16",
            "unix_only": True,
            "real_ddl": ["0009", "0014", "0040"],
        }
        yield bridge
    finally:
        bridge.close()


class BoundedPgSession(prior.PgSession):
    """Same physical connection API; cap SQL lock waits for race coverage."""

    async def __aenter__(self) -> "BoundedPgSession":
        await super().__aenter__()
        await super().execute(text("SET LOCAL lock_timeout = '350ms'"))
        await super().execute(text("SET LOCAL statement_timeout = '1600ms'"))
        return self


@asynccontextmanager
async def connection(bridge: prior.PgBridge, label: str) -> Any:
    async with BoundedPgSession(bridge, f"{label}-{uuid.uuid4().hex}") as db:
        yield db


async def _query(memory: Any, sql_text: str, **params: Any) -> list[dict[str, Any]]:
    async with memory._async_session() as db:
        return (await db.execute(text(sql_text), params)).all()


async def _post(
    world: dict[str, Any],
    action: str,
    data: dict[str, Any],
    subscriber: str,
) -> Any:
    # Existing helper constructs an independent httpx.AsyncClient for each
    # invocation and sends to the ACTUAL mounted main.app, no lifespan.
    return await prior.post(world, action, data, subscriber=subscriber)


def _new_subscriber() -> str:
    return "subscr-" + uuid.uuid4().hex


def test_mounted_0040_routes_and_private_opt_in_are_explicit() -> None:
    """Always safe: inspect mount and test opt-in, no database starts."""
    expected = {"acquire", "ack", "cursor-readback", "release", "revoke"}
    actual = {
        route.path.rsplit("/", 1)[-1]
        for route in prior.main.app.routes
        if route.path.startswith("/supervision/engagements/") and "/subscriptions/" in route.path
    }
    assert expected <= actual
    assert OPT_IN != prior.OPT_IN
    assert "listen_addresses=''" in prior._WORKER
    assert "unix_socket_permissions=0700" in prior._WORKER


@pytest.mark.asyncio
async def test_two_physical_connections_lease_ack_release_and_revocation(
    mounted_real: dict[str, Any],  # noqa: F811 - pytest injects imported mounted fixture
) -> None:
    """Two independent backend PIDs, bounded row/revocation lock competition."""
    world = mounted_real
    bridge: prior.PgBridge = world["bridge"]
    memory = world["memory"]
    baseline_factory = memory._async_session
    counter = 0

    def bounded_factory() -> BoundedPgSession:
        nonlocal counter
        counter += 1
        return BoundedPgSession(bridge, f"bounded-0040-{counter}-{uuid.uuid4().hex}")

    memory._async_session = bounded_factory
    try:
        # A and B are distinct genuine PostgreSQL backend connections, both
        # live at the same time. The serialized stdio command channel does not
        # serialize their open transactions or postgres row locks.
        async with connection(bridge, "physical-a") as a:
            async with connection(bridge, "physical-b") as b:
                a_pid = (await a.execute(text("SELECT pg_backend_pid()"))).scalar_one()
                b_pid = (await b.execute(text("SELECT pg_backend_pid()"))).scalar_one()
                assert type(a_pid) is type(b_pid) is int and a_pid != b_pid
                assert (
                    await b.execute(text("SELECT current_setting('transaction_isolation')"))
                ).scalar_one() == "read committed"

        subscriber = _new_subscriber()
        # Two fully independent ASGI clients claim one subscriber; the
        # PostgreSQL PK + live generation/CAS can admit only one.
        replies = await asyncio.wait_for(
            asyncio.gather(
                _post(
                    world,
                    "acquire",
                    {"replica_id": "replica-alpha", "task_id": prior.TASK_A},
                    subscriber,
                ),
                _post(
                    world,
                    "acquire",
                    {"replica_id": "replica-beta", "task_id": prior.TASK_A},
                    subscriber,
                ),
            ),
            timeout=20,
        )
        statuses = sorted(reply.status_code for reply in replies)
        assert statuses == [200, 409], [reply.text[:240] for reply in replies]
        winner = next(reply for reply in replies if reply.status_code == 200)
        lease = prior.lease_body(winner.json())
        assert lease["generation"] == 1 and lease["cursor"] == 0
        assert winner.json()["lease"]["delivery_semantics"] == "at_least_once"
        assert (
            await _query(
                memory,
                "SELECT lease_generation, cursor_sequence, lease_owner "
                "FROM supervision_durable_subscriptions WHERE subscriber_id=:sub",
                sub=subscriber,
            )
        ) == [
            {
                "lease_generation": 1,
                "cursor_sequence": 0,
                "lease_owner": lease["replica_id"],
            }
        ]

        # Explicit held row lock physically fences an ASGI contender: show the
        # locked transaction A backend and a distinct B NOWAIT backend PID.
        async with connection(bridge, "holder") as holder:
            holder_pid = (await holder.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            await holder.execute(
                text(
                    "SELECT subscriber_id FROM supervision_durable_subscriptions "
                    "WHERE engagement_id=:eng AND subscriber_id=:sub FOR UPDATE"
                ),
                {"eng": prior.ENG_A, "sub": subscriber},
            )
            # Separate B would wait for A's PostgreSQL row lock; NOWAIT
            # proves real 55P03 rather than a synthetic Python mutex.
            with pytest.raises(prior.PrivateSqlError) as collision:
                async with connection(bridge, "competing-backend") as competing:
                    second_pid = (
                        await competing.execute(text("SELECT pg_backend_pid()"))
                    ).scalar_one()
                    assert second_pid != holder_pid
                    await competing.execute(
                        text(
                            "SELECT subscriber_id FROM supervision_durable_subscriptions "
                            "WHERE engagement_id=:eng AND subscriber_id=:sub FOR UPDATE NOWAIT"
                        ),
                        {"eng": prior.ENG_A, "sub": subscriber},
                    )
            assert collision.value.sqlstate == "55P03"
            # The unchanged mounted API has a real transaction lock timeout,
            # denying the ACK rather than hanging or reading uncommitted data.
            blocked = await asyncio.wait_for(
                _post(
                    world,
                    "ack",
                    {**lease, "expected_cursor": 0, "next_sequence": 11},
                    subscriber,
                ),
                timeout=12,
            )
            assert blocked.status_code == 409, blocked.text[:220]
        assert (
            await _query(
                memory,
                "SELECT cursor_sequence FROM supervision_durable_subscriptions "
                "WHERE subscriber_id=:sub",
                sub=subscriber,
            )
        )[0]["cursor_sequence"] == 0

        # The real 0040 store accepts a HOST-ONLY bounded disconnect callback.
        # Reconstruct its live JWT/ROE/Task-scoped context from an exact signed
        # fixture bearer; the callback is injected only in this test, not HTTP
        # input. It fires AFTER an actual PG cursor UPDATE and must ROLLBACK it.
        from ai_osop.api import deps
        from ai_osop.api.routers import durable_supervision_subscriptions as mounted
        from ai_osop.memory.durable_supervision_subscriptions import SubscriptionDenied

        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=world["alice"])
        authenticated = await deps.verify_token(credentials=credentials, token=None)
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/supervision/engagements/" + prior.ENG_A,
                "headers": [(b"authorization", ("Bearer " + world["alice"]).encode("ascii"))],
                "query_string": b"",
            }
        )
        principal, store = await mounted._context(
            prior.ENG_A, subscriber, prior.TASK_A, request, authenticated
        )
        bounded_lease = mounted._lease(prior.ENG_A, subscriber, mounted.LeaseBinding(**lease))
        precommit_updates = sum(
            "UPDATE supervision_durable_subscriptions SET cursor_sequence=" in sql
            for sql in bridge.statements
        )

        async def host_observed_disconnection() -> bool:
            return True

        with pytest.raises(SubscriptionDenied, match="connection lost"):
            await store.acknowledge(
                principal,
                bounded_lease,
                expected_cursor=0,
                next_sequence=11,
                precommit_disconnect=host_observed_disconnection,
            )
        assert (
            sum(
                "UPDATE supervision_durable_subscriptions SET cursor_sequence=" in sql
                for sql in bridge.statements
            )
            == precommit_updates + 1
        )
        assert (
            await _query(
                memory,
                "SELECT cursor_sequence FROM supervision_durable_subscriptions "
                "WHERE subscriber_id=:sub",
                sub=subscriber,
            )
        )[0]["cursor_sequence"] == 0

        # Two independent ASGI clients ACK the SAME signed current lease/next
        # event. One real committed CAS wins, the stale rival denies. The
        # ledger cursor is never advanced twice or skips event sequence 11.
        ack_body = {**lease, "expected_cursor": 0, "next_sequence": 11}
        acks = await asyncio.wait_for(
            asyncio.gather(
                _post(world, "ack", ack_body, subscriber),
                _post(world, "ack", ack_body, subscriber),
            ),
            timeout=20,
        )
        assert sorted(resp.status_code for resp in acks) == [200, 409], [
            resp.text[:220] for resp in acks
        ]
        acknowledged = next(reply for reply in acks if reply.status_code == 200)
        assert acknowledged.json()["lease"]["cursor"] == 11
        assert (
            await _query(
                memory,
                "SELECT cursor_sequence,lease_generation FROM "
                "supervision_durable_subscriptions WHERE subscriber_id=:sub",
                sub=subscriber,
            )
        ) == [{"cursor_sequence": 11, "lease_generation": 1}]

        # Simulate client losing the committed ACK response (cannot actually
        # prove an HTTP transport disconnect). DO NOT replay. A new ASGI client
        # reads the exact current signed PostgreSQL cursor with OLD lease body.
        del acknowledged
        prior_updates = sum(
            "UPDATE supervision_durable_subscriptions SET cursor_sequence=" in item
            for item in bridge.statements
        )
        readback = await _post(world, "cursor-readback", lease, subscriber)
        assert readback.status_code == 200, readback.text[:260]
        assert readback.json()["lease"]["cursor"] == 11
        assert (
            sum(
                "UPDATE supervision_durable_subscriptions SET cursor_sequence=" in item
                for item in bridge.statements
            )
            == prior_updates
        )
        stale = await _post(world, "ack", ack_body, subscriber)
        assert stale.status_code == 409

        # Releasing after readback preserves cursor but advances generation.
        committed_lease = prior.lease_body(readback.json())
        released = await _post(world, "release", committed_lease, subscriber)
        assert released.status_code == 200, released.text[:200]
        reacquired = await _post(
            world,
            "acquire",
            {"replica_id": "replica-reacquired", "task_id": prior.TASK_A},
            subscriber,
        )
        assert reacquired.status_code == 200, reacquired.text[:200]
        new_lease = prior.lease_body(reacquired.json())
        assert new_lease["cursor"] == 11
        assert new_lease["generation"] > lease["generation"]
        assert new_lease["lease_id"] != lease["lease_id"]
        assert (await _post(world, "cursor-readback", lease, subscriber)).status_code == 409
        # A late old-generation ACK cannot advance event 19.
        assert (
            await _post(
                world,
                "ack",
                {**lease, "expected_cursor": 11, "next_sequence": 19, "cursor": 11},
                subscriber,
            )
        ).status_code == 409

        # Real 0014 token revoke INSERT on backend A is UNCOMMITTED while
        # ASGI backend B attempts ACK: worker42 SHARE NOWAIT table-lock check
        # must deny before ACK can commit even if A rolls back later.
        digest = hashlib.sha256(world["alice"].encode("utf-8")).hexdigest()

        class AbortRevoke(RuntimeError):
            pass

        try:
            async with connection(bridge, "revoker-a") as revoker:
                revoker_pid = (await revoker.execute(text("SELECT pg_backend_pid()"))).scalar_one()
                await revoker.execute(
                    text(
                        "INSERT INTO operator_token_revocations "
                        "(digest,actor_id,expires_at,revoked_at) "
                        "VALUES (:digest,:actor,now()+interval '2 hours',clock_timestamp())"
                    ),
                    {"digest": digest, "actor": prior.OWNER_A},
                )
                raced = await asyncio.wait_for(
                    _post(
                        world,
                        "ack",
                        {**new_lease, "expected_cursor": 11, "next_sequence": 19},
                        subscriber,
                    ),
                    timeout=12,
                )
                assert raced.status_code == 409, raced.text[:240]
                assert revoker_pid > 0
                raise AbortRevoke()
        except AbortRevoke:
            pass
        assert (
            await _query(
                memory,
                "SELECT cursor_sequence FROM supervision_durable_subscriptions "
                "WHERE subscriber_id=:sub",
                sub=subscriber,
            )
        )[0]["cursor_sequence"] == 11
        # Following rollback of the *uncommitted* revoke, a new signed ACK
        # can commit exactly one successor, but must not replay earlier ACKs.
        current_ack = await _post(
            world,
            "ack",
            {**new_lease, "expected_cursor": 11, "next_sequence": 19},
            subscriber,
        )
        assert current_ack.status_code == 200, current_ack.text[:240]
        assert current_ack.json()["lease"]["cursor"] == 19
        await _query(
            memory,
            "INSERT INTO operator_token_revocations "
            "(digest,actor_id,expires_at,revoked_at) "
            "VALUES (:digest,:actor,now()+interval '2 hours',clock_timestamp())",
            digest=digest,
            actor=prior.OWNER_A,
        )
        now_revoked = await _post(
            world,
            "ack",
            {**prior.lease_body(current_ack.json()), "expected_cursor": 19, "next_sequence": 20},
            subscriber,
        )
        assert now_revoked.status_code in {401, 409}
        assert (
            await _query(
                memory,
                "SELECT cursor_sequence FROM supervision_durable_subscriptions "
                "WHERE subscriber_id=:sub",
                sub=subscriber,
            )
        )[0]["cursor_sequence"] == 19
        assert any(
            "LOCK TABLE operator_token_revocations, operator_subject_controls "
            "IN SHARE MODE NOWAIT" in item
            for item in bridge.statements
        )
        assert any("current_setting('transaction_isolation')" in item for item in bridge.statements)
    finally:
        memory._async_session = baseline_factory
