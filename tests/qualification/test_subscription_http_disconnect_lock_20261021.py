"""Bounded ASGI HTTP-task cancellation versus real 0040 PostgreSQL row lock.

Reuses the genuine disposable nonroot Unix-socket-only PostgreSQL16 and
mounted main.app fixture. No application DB, external server/target, Docker,
Git, or production source edits. The fixture JWT and ROE signing keys are
test-only and do not prove enrolled issuer trust.

IMPORTANT: httpx.ASGITransport cancellation is an in-process client task
cancel, NOT a real TCP close/browser disconnect. The test records the result;
it must not claim that client cancellation necessarily rolls back a server.

The 0040 SQL session is a preexisting test-owned PgSession adapter rather
than production SQLAlchemy AsyncSession. Every paused transaction has
transaction-level idle timeout, test-owned backend PID and bounded forced
ROLLBACK/disconnect cleanup. No cross-test or application PG is touched.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any, Optional

import pytest
from sqlalchemy import text

from tests.qualification.test_durable_subscriptions_mounted_actual_pg_20261021 import (
    ENG_A, TASK_A, PgSession, PrivateSqlError, QueryResult,
    mounted_real, private_pg, post, sql,
)

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "src/ai_osop/memory/durable_supervision_subscriptions.py"
ROUTER = ROOT / "src/ai_osop/api/routers/durable_supervision_subscriptions.py"
BRIDGE = ROOT / "tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py"


def test_real_disconnect_contract_and_unshielded_fixture_seam_without_pg() -> None:
    """Fail-closed source contract; no WSL/PG required."""
    store = STORE.read_text(encoding="utf-8")
    router = ROUTER.read_text(encoding="utf-8")
    bridge = BRIDGE.read_text(encoding="utf-8")
    assert "async with self._maker() as db:" in store
    assert "async with db.begin():" in store
    assert "yield db" in store
    assert "await self._fence_revocation_insert(db)" in store
    assert "cursor_sequence=:next,updated_at=clock_timestamp()" in store
    assert "async def acknowledge(" in router
    assert "return {\"lease\": _lease_response(updated), \"acknowledged\": True}" in router
    # This is not equivalent to proving SQLAlchemy's *real* AsyncSession
    # cancels poorly: worker33's adapter uses cancellable await-to_thread.
    assert 'await asyncio.to_thread(' in bridge
    assert 'self.bridge.command, "end", client=self.client, commit=error is None' in bridge
    assert 'self.bridge.command, "disconnect", client=self.client' in bridge


async def _bridge(
    world: dict[str, Any], operation: str, *, client: str, **kwargs: Any,
) -> dict[str, Any]:
    """Bridge calls are bounded; private PG already has socket-only isolation."""
    return await asyncio.wait_for(
        asyncio.to_thread(
            world["bridge"].command, operation, client=client, **kwargs,
        ),
        timeout=4.0,
    )


async def _pg_probe(
    world: dict[str, Any], *, pid: int, subscriber: str,
) -> dict[str, Any]:
    """Distinct PG session: activity and nonblocking FOR UPDATE lock probe."""
    client = "disconnect-probe-" + uuid.uuid4().hex
    await _bridge(world, "connect", client=client)
    try:
        activity = await _bridge(
            world, "execute", client=client,
            sql="SELECT pid,state,xact_start IS NOT NULL AS in_transaction,"
                "wait_event_type FROM pg_stat_activity WHERE pid=%(pid)s",
            params={"pid": pid},
        )
        # Transaction timeout bounds any row lock contention. Explicitly use
        # NOWAIT so a blocked query cannot wedge the serialized stdio bridge.
        try:
            row = await _bridge(
                world, "execute", client=client,
                sql="SELECT cursor_sequence FROM supervision_durable_subscriptions "
                    "WHERE engagement_id=%(engagement)s AND subscriber_id=%(subscriber)s "
                    "FOR UPDATE NOWAIT",
                params={"engagement": ENG_A, "subscriber": subscriber},
            )
            lock_held = False
            cursor = row["rows"][0]["cursor_sequence"]
        except PrivateSqlError as exc:
            if exc.sqlstate != "55P03":
                raise
            lock_held = True
            cursor = None
        return {
            "activity": activity["rows"],
            "lock_held": lock_held,
            "visible_cursor": cursor,
        }
    finally:
        await _bridge(world, "disconnect", client=client)


async def _force_cleanup(
    world: dict[str, Any], *, client: Optional[str], backend_pid: Optional[int],
    subscriber: str,
) -> dict[str, Any]:
    """Rollback only this new test's tagged client; never mutate another PG."""
    if client is None:
        return {"explicit_rollback": "no tagged client"}
    outcomes: dict[str, Any] = {}
    try:
        await _bridge(world, "end", client=client, commit=False)
        outcomes["explicit_rollback"] = "sent"
    except PrivateSqlError as exc:
        # The adapter may have already rolled back/disconnected itself.
        outcomes["explicit_rollback"] = type(exc).__name__ + ":" + str(exc)[:100]
    try:
        await _bridge(world, "disconnect", client=client)
        outcomes["explicit_disconnect"] = "sent"
    except PrivateSqlError as exc:
        outcomes["explicit_disconnect"] = type(exc).__name__ + ":" + str(exc)[:100]
    if backend_pid is not None:
        verified = await _pg_probe(
            world, pid=backend_pid, subscriber=subscriber,
        )
        outcomes["backend_still_active"] = bool(verified["activity"])
    return outcomes


@pytest.mark.asyncio
@pytest.mark.timeout(80)
async def test_cancel_http_task_after_real_pg_ack_update_has_bounded_cleanup(
    mounted_real: dict[str, Any],
) -> None:
    """Measure, don't promise, rollback on cancelling the ASGI client task."""
    world = mounted_real
    memory = world["memory"]
    subscriber = "subscr-" + uuid.uuid4().hex
    acquired = await post(world, "acquire", {
        "replica_id": "replica-http-cancel", "task_id": TASK_A,
    }, subscriber=subscriber)
    assert acquired.status_code == 200, acquired.text[:250]
    original = acquired.json()["lease"]
    ack = {
        "replica_id": original["replica_id"],
        "lease_id": original["lease_id"],
        "generation": original["generation"],
        "cursor": original["cursor"],
        "task_id": TASK_A,
        "expected_cursor": 0,
        "next_sequence": 11,
    }
    assert ack["cursor"] == 0
    ready = asyncio.Event()
    gate = asyncio.Event()
    telemetry: dict[str, Any] = {
        "after_update": False,
        "exit_started": False,
        "exit_finished": False,
        "cleanup_error": None,
        "tagged_client": None,
        "backend_pid": None,
    }
    old_factory = memory._async_session
    tagged_prefix = "ui-http-disconnect-only-" + uuid.uuid4().hex
    task: Optional[asyncio.Task[Any]] = None

    class TrackedBoundedSession(PgSession):
        async def __aenter__(self) -> "TrackedBoundedSession":
            await super().__aenter__()
            # Only disposable fixture connections, no global db/system config.
            # Even if an ASGI cancellation skips cleanup, PG eventually
            # aborts this idle transaction and frees its row lock.
            await super().execute(text(
                "SET LOCAL idle_in_transaction_session_timeout='3500ms'"
            ))
            await super().execute(text("SET LOCAL statement_timeout='2500ms'"))
            await super().execute(text("SET LOCAL lock_timeout='1000ms'"))
            return self

        async def execute(
            self, statement: Any, params: Optional[dict[str, Any]] = None,
        ) -> QueryResult:
            result = await super().execute(statement, params)
            if str(statement).startswith(
                "UPDATE supervision_durable_subscriptions SET cursor_sequence=:next"
            ):
                telemetry["after_update"] = True
                telemetry["tagged_client"] = self.client
                backend_pid = await super().execute(text("SELECT pg_backend_pid()"))
                telemetry["backend_pid"] = backend_pid.scalar_one()
                ready.set()
                await gate.wait()  # cancellation point AFTER actual UPDATE
            return result

        async def __aexit__(self, error: Any, value: Any, tb: Any) -> None:
            if self.client == telemetry["tagged_client"]:
                telemetry["exit_started"] = True
            try:
                await super().__aexit__(error, value, tb)
            except BaseException as exc:
                if self.client == telemetry["tagged_client"]:
                    telemetry["cleanup_error"] = type(exc).__name__
                raise
            finally:
                if self.client == telemetry["tagged_client"]:
                    telemetry["exit_finished"] = True

    memory._async_session = lambda: TrackedBoundedSession(
        world["bridge"], tagged_prefix + "-" + uuid.uuid4().hex,
    )
    snapshot: Optional[dict[str, Any]] = None
    recovered: Optional[dict[str, Any]] = None
    cleanup: dict[str, Any] = {}
    try:
        task = asyncio.create_task(post(world, "ack", ack, subscriber=subscriber))
        await asyncio.wait_for(ready.wait(), timeout=12.0)
        assert telemetry["after_update"] and telemetry["backend_pid"] is not None
        # Do not query the original row with locking SQL while the server is
        # paused. The probe is its own real PG connection, NOWAIT bounded.
        before = await _pg_probe(
            world, pid=telemetry["backend_pid"], subscriber=subscriber,
        )
        assert before["lock_held"], before
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=4.0)
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("Cancelled in-process HTTP task returned ACK")
        # Give scheduling a bounded chance to complete adapter cleanup.
        await asyncio.sleep(0.15)
        snapshot = await _pg_probe(
            world, pid=telemetry["backend_pid"], subscriber=subscriber,
        )
    finally:
        # A test is NEVER permitted to strand its own PostgreSQL transaction.
        gate.set()
        if task is not None and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        memory._async_session = old_factory
        cleanup = await _force_cleanup(
            world, client=telemetry["tagged_client"],
            backend_pid=telemetry["backend_pid"],
            subscriber=subscriber,
        )
        if telemetry["backend_pid"] is not None:
            recovered = await _pg_probe(
                world, pid=telemetry["backend_pid"], subscriber=subscriber,
            )
    assert snapshot is not None and recovered is not None, telemetry
    assert not recovered["lock_held"], (telemetry, recovered, cleanup)
    visible = await sql(
        memory, "SELECT cursor_sequence FROM supervision_durable_subscriptions "
                "WHERE engagement_id=:engagement AND subscriber_id=:subscriber",
        engagement=ENG_A, subscriber=subscriber,
    )
    assert visible == [{"cursor_sequence": 0}], visible
    # Explicit forced test cleanup happens AFTER the observation. If a lock
    # survived cancel, it is a negative outcome; never reclassify as success.
    assert telemetry["after_update"] is True
    print("HTTP_CANCEL_REAL_PG_OBSERVATION", {
        "after_update": telemetry["after_update"],
        "exit_started": telemetry["exit_started"],
        "exit_finished": telemetry["exit_finished"],
        "cleanup_error": telemetry["cleanup_error"],
        "lock_after_http_cancel_before_forced_cleanup": snapshot["lock_held"],
        "open_transaction_after_http_cancel": bool(snapshot["activity"] and
                                                  snapshot["activity"][0]["in_transaction"]),
        "manual_cleanup": cleanup,
        "final_cursor": visible[0]["cursor_sequence"],
    })


@pytest.mark.asyncio
@pytest.mark.timeout(80)
async def test_asgi_http_disconnect_signal_is_not_equivalent_to_ack_rollback(
    mounted_real: dict[str, Any],
) -> None:
    """Send actual ASGI http.disconnect while ACK UPDATE is held on real PG.

    This is a simulated ASGI transport disconnect, not a real TCP FIN/RST.
    The experiment deliberately accepts either a committed or a rolled-back
    ACK and records exact observed behavior; no exactly-once claim.
    """
    from ai_osop.api import main

    world = mounted_real
    memory = world["memory"]
    subscriber = "subscr-" + uuid.uuid4().hex
    acquired = await post(world, "acquire", {
        "replica_id": "replica-asgi-disconnect", "task_id": TASK_A,
    }, subscriber=subscriber)
    assert acquired.status_code == 200, acquired.text[:250]
    lease = acquired.json()["lease"]
    payload = json.dumps({
        "replica_id": lease["replica_id"],
        "lease_id": lease["lease_id"],
        "generation": lease["generation"],
        "cursor": lease["cursor"],
        "task_id": TASK_A,
        "expected_cursor": 0,
        "next_sequence": 11,
    }, separators=(",", ":")).encode("utf-8")
    url_path = (
        f"/supervision/engagements/{ENG_A}/subscriptions/{subscriber}/ack"
    )
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "root_path": "",
        "path": url_path,
        "raw_path": url_path.encode("ascii"),
        "query_string": b"",
        "headers": [
            (b"host", b"only-disposable.invalid"),
            (b"authorization", b"Bearer " + world["alice"].encode("ascii")),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode("ascii")),
        ],
        "server": ("only-disposable.invalid", 80),
        "client": ("127.0.0.1", 42424),
    }
    first_receive = True
    disconnect = asyncio.Event()
    received_disconnect = {"n": 0}
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal first_receive
        if first_receive:
            first_receive = False
            return {"type": "http.request", "body": payload, "more_body": False}
        await disconnect.wait()
        received_disconnect["n"] += 1
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    updated = asyncio.Event()
    release = asyncio.Event()
    tagged: dict[str, Any] = {"client": None, "pid": None}
    old_factory = memory._async_session
    app_task: Optional[asyncio.Task[Any]] = None
    before: Optional[dict[str, Any]] = None
    after: Optional[dict[str, Any]] = None

    class SignalBoundedSession(PgSession):
        async def __aenter__(self) -> "SignalBoundedSession":
            await super().__aenter__()
            await super().execute(text(
                "SET LOCAL idle_in_transaction_session_timeout='3500ms'"
            ))
            await super().execute(text("SET LOCAL statement_timeout='2500ms'"))
            await super().execute(text("SET LOCAL lock_timeout='1000ms'"))
            return self

        async def execute(
            self, statement: Any, params: Optional[dict[str, Any]] = None,
        ) -> QueryResult:
            result = await super().execute(statement, params)
            if str(statement).startswith(
                "UPDATE supervision_durable_subscriptions SET cursor_sequence=:next"
            ):
                tagged["client"] = self.client
                tagged["pid"] = (await super().execute(
                    text("SELECT pg_backend_pid()")
                )).scalar_one()
                updated.set()
                await release.wait()
            return result

    memory._async_session = lambda: SignalBoundedSession(
        world["bridge"], "asgi-disconnect-only-" + uuid.uuid4().hex,
    )
    error: Optional[str] = None
    try:
        app_task = asyncio.create_task(
            main.app(scope, receive, send),
        )
        await asyncio.wait_for(updated.wait(), timeout=12.0)
        before = await _pg_probe(
            world, pid=tagged["pid"], subscriber=subscriber,
        )
        assert before["lock_held"], before
        # Unlike task.cancel(), this only tells the ASGI receive channel
        # that the client disconnected. The app may or may not observe it.
        disconnect.set()
        await asyncio.sleep(0.1)
        release.set()
        try:
            await asyncio.wait_for(app_task, timeout=8.0)
        except asyncio.CancelledError:
            error = "CancelledError"
        except Exception as exc:
            error = type(exc).__name__ + ":" + str(exc)[:200]
        after = await _pg_probe(
            world, pid=tagged["pid"], subscriber=subscriber,
        )
    finally:
        release.set()
        disconnect.set()
        if app_task is not None and not app_task.done():
            app_task.cancel()
            try:
                await asyncio.wait_for(app_task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        memory._async_session = old_factory
        await _force_cleanup(
            world, client=tagged["client"], backend_pid=tagged["pid"],
            subscriber=subscriber,
        )

    assert before is not None and after is not None
    assert not after["lock_held"], after
    cursor = await sql(
        memory, "SELECT cursor_sequence FROM supervision_durable_subscriptions "
                "WHERE engagement_id=:engagement AND subscriber_id=:subscriber",
        engagement=ENG_A, subscriber=subscriber,
    )
    assert cursor[0]["cursor_sequence"] in {0, 11}
    statuses = [entry["status"] for entry in sent
                if entry.get("type") == "http.response.start"]
    # A disconnection signal alone is not an ACK receipt. The HTTP transport
    # can finish or abort independently from a durably committed cursor.
    print("ASGI_DISCONNECT_REAL_PG_OBSERVATION", {
        "received_disconnect_calls": received_disconnect["n"],
        "http_response_statuses": statuses,
        "server_error": error,
        "cursor_after_disconnect": cursor[0]["cursor_sequence"],
        "backend_transaction_after_response": bool(
            after["activity"] and after["activity"][0]["in_transaction"]
        ),
        "lock_after_response": after["lock_held"],
    })
