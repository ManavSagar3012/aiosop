"""The production outbox publisher must corroborate each leased event source.

Only deterministic PostgreSQL statement emulation is used; no application DB,
target, provider, or external notification service is accessed.
"""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from ai_osop.orchestrator.supervision_outbox import SupervisionOutboxDispatcher
from tests.test_outbox_notification_recovery import (
    PgSession,
    PgStore,
    RecorderBus,
    SqlResult,
    notification,
)


class _SourceFencedSession(PgSession):
    async def execute(self, statement):
        compiled = str(statement.compile(dialect=postgresql.dialect()))
        # The fixture evaluates the SAME mandatory SQL source conditions as
        # the live PostgreSQL statement. A separate Python-only check would
        # make this test pass even if production publishing remained unsafe.
        for required in (
            "EXISTS (SELECT supervision_events.id",
            "supervision_events.id = supervision_outbox.event_id",
            "supervision_events.engagement_id = supervision_outbox.engagement_id",
            "supervision_events.kind = supervision_outbox.topic",
            "supervision_events.task_id IS NOT DISTINCT FROM",
            "supervision_events.payload =",
            "supervision_outbox.payload",
            "FOR SHARE",
            "supervision_outbox.delivered_at IS NULL",
            "supervision_outbox.leased_until >",
            "supervision_outbox.lease_id =",
        ):
            assert required in compiled, f"Missing source-bound lease predicate: {required}"
        params = statement.compile().params
        item_id = next(v for k, v in params.items() if k.startswith("id_"))
        row = self.store.rows[item_id]
        event = self.store.source
        if event is None or not (
            event.id == row["event_id"] == row["payload"].get("event_id")
            and event.engagement_id == row["engagement_id"] == row["payload"].get("engagement_id")
            and event.kind == row["topic"] == row["payload"].get("kind")
            and event.task_id == row["payload"].get("task_id")
            and event.payload == row["payload"].get("metadata")
        ):
            return SqlResult(0)
        return await super().execute(statement)


class _SourceFencedStore(PgStore):
    def __init__(self, item=None):
        item = item if item is not None else notification()
        super().__init__(item)
        self.source = SimpleNamespace(
            id=item["event_id"],
            engagement_id=item["engagement_id"],
            kind=item["topic"],
            task_id=item["payload"]["task_id"],
            payload=deepcopy(item["payload"]["metadata"]),
        )

    def _sessions(self):
        return _SourceFencedSession(self)


@pytest.mark.asyncio
async def test_current_committed_event_can_publish_and_ack():
    store, bus = _SourceFencedStore(), RecorderBus()
    dispatcher = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    assert await dispatcher.flush_once() == 1
    assert [e.payload["event_id"] for e in bus.events] == ["evt-1"]
    assert store.rows["out-1"]["delivered_at"] is not None
    assert all("MUST_NOT_LEAK" not in str(e.payload) for e in bus.events)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    (
        "source_missing",
        "source_tenant",
        "source_topic",
        "source_task",
        "source_metadata",
        "payload_tenant",
        "payload_event",
        "payload_metadata",
    ),
)
async def test_stale_or_cross_tenant_source_never_reaches_bus(tamper):
    store, bus = _SourceFencedStore(), RecorderBus()
    if tamper == "source_missing":
        store.source = None
    elif tamper == "source_tenant":
        store.source.engagement_id = "eng-different"
    elif tamper == "source_topic":
        store.source.kind = "authorization.changed"
    elif tamper == "source_task":
        store.source.task_id = "task-foreign"
    elif tamper == "source_metadata":
        store.source.payload = {"authorization_version": 999}
    elif tamper == "payload_tenant":
        # The payload and row agree superficially but not with the event.
        store.rows["out-1"]["engagement_id"] = "eng-different"
        store.rows["out-1"]["payload"]["engagement_id"] = "eng-different"
    elif tamper == "payload_event":
        store.rows["out-1"]["payload"]["event_id"] = "evt-forged"
    else:
        store.rows["out-1"]["payload"]["metadata"] = {"authorization_version": 999}
    dispatcher = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    assert await dispatcher.flush_once() == 0
    assert bus.events == []
    assert store.rows["out-1"]["delivered_at"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["flow.subtask_dispatch_intent", "replay.pair_admitted"])
async def test_stale_signed_flow_or_replay_source_never_reaches_queue(kind):
    metadata = {"authorization_version": 4, "flow_revision": 2}
    if kind == "replay.pair_admitted":
        metadata.update(source_task_id="task-source", target_task_id="task-target")
    store = _SourceFencedStore(notification(kind=kind, metadata=metadata))
    bus, queue = RecorderBus(), AsyncMock()
    # A redacted delivery payload alone looks valid; the source authority
    # revision has changed underneath that still-live notification claim.
    store.source.payload["authorization_version"] = 5
    dispatcher = SupervisionOutboxDispatcher(
        store,
        bus,
        max_batch=1,
        enqueue_registered_task=queue,
        enqueue_signed_replay_pair=queue,
    )
    assert await dispatcher.flush_once() == 0
    assert bus.events == []
    queue.assert_not_awaited()
    assert store.rows["out-1"]["delivered_at"] is None


@pytest.mark.asyncio
async def test_source_changes_after_publication_must_not_erase_pending_delivery():
    store, bus = _SourceFencedStore(), RecorderBus()

    async def change_source_after_fence():
        store.source.engagement_id = "eng-revoked"

    bus.before_publish = change_source_after_fence
    dispatcher = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    assert await dispatcher.flush_once() == 0
    assert len(bus.events) == 1  # Publication has at-least-once semantics.
    assert store.rows["out-1"]["delivered_at"] is None
    assert store.rows["out-1"]["lease_id"] == "lease-1"
