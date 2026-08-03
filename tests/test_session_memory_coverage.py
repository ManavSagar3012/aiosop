"""Coverage-targeted tests for ai_osop.memory.session_memory.

Uses:
- A real SessionMemory instance wired to an in-memory async SQLite engine
  (matches the pattern from tests/test_outbox_processor_resilience.py) so the
  warm-tier methods execute real SQL against the ORM.
- A hand-rolled in-memory ``FakeRedis`` implementing exactly the async Redis
  client API surface ``SessionMemory`` touches (no external services needed).

The point is real coverage of the hot/warm-tier code paths, not mock-shape
verification. Tests assert behavioural outcomes (read-after-write, lock
contention, pub/sub delivery, queue priority, dedup, etc.).
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from ai_osop.core.enums import AgentType
from ai_osop.core.exceptions import MemoryException
from ai_osop.core.models import ApprovalRequest, ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import Base, SessionMemory


# ---------------------------------------------------------------------------
# In-memory Redis stand-in
# ---------------------------------------------------------------------------


class _FakePubSub:
    """Simple pubsub handle with subscribe/get_message used by subscribe_events."""

    def __init__(self, client: "_FakeRedis") -> None:
        self._client = client
        self._channels: list[str] = []

    async def subscribe(self, channel: str) -> None:
        self._channels.append(channel)
        self._client._subscribers.setdefault(channel, []).append(self)
        # Real redis emits a subscribe confirmation message
        self._client._queue_message(self, {"type": "subscribe", "channel": channel, "data": 1})

    async def unsubscribe(self, channel: str) -> None:
        if channel in self._channels:
            self._channels.remove(channel)

    async def get_message(self, ignore_subscribe_messages: bool = True, timeout: float = 0.1):
        return await self._client._pop_message(self, ignore_subscribe_messages, timeout)

    async def close(self) -> None:
        for ch in list(self._channels):
            subs = self._client._subscribers.get(ch, [])
            if self in subs:
                subs.remove(self)
        self._channels.clear()


class _FakeRedis:
    """In-memory async Redis stand-in implementing the subset SessionMemory uses."""

    def __init__(self) -> None:
        self._kv: Dict[str, tuple[str, Optional[float]]] = {}
        self._sets: Dict[str, set] = {}
        self._lists: Dict[str, list] = {}
        self._zsets: Dict[str, Dict[str, float]] = {}
        self._subscribers: Dict[str, list[_FakePubSub]] = {}
        self._messages: Dict[int, asyncio.Queue] = {}
        self._closed = False
        self._fail_ping = False  # used to simulate a broken redis for _ensure_redis reconnect

    # -- helpers -------------------------------------------------------

    def _purge_expired(self, key: str) -> None:
        if key in self._kv:
            value, expires_at = self._kv[key]
            if expires_at is not None and time.monotonic() >= expires_at:
                del self._kv[key]

    def _queue_message(self, pubsub: _FakePubSub, msg: dict) -> None:
        q = self._messages.setdefault(id(pubsub), asyncio.Queue())
        q.put_nowait(msg)

    async def _pop_message(self, pubsub: _FakePubSub, ignore_subs: bool, timeout: float):
        q = self._messages.setdefault(id(pubsub), asyncio.Queue())
        deadline = time.monotonic() + max(timeout, 0)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                msg = await asyncio.wait_for(q.get(), timeout=remaining)
            except asyncio.TimeoutError:
                return None
            if ignore_subs and msg.get("type") in ("subscribe", "unsubscribe"):
                continue
            return msg

    def _broadcast(self, channel: str, payload: str) -> int:
        subs = list(self._subscribers.get(channel, []))
        for ps in subs:
            self._queue_message(ps, {"type": "message", "channel": channel, "data": payload})
        return len(subs)

    # -- connection / lifecycle ----------------------------------------

    async def ping(self) -> bool:
        if self._fail_ping:
            raise ConnectionError("redis down")
        return True

    async def close(self) -> None:
        self._closed = True

    # -- string K/V -----------------------------------------------------

    async def set(self, key: str, value: str, nx: bool = False, ex: Optional[int] = None):
        self._purge_expired(key)
        if nx and key in self._kv:
            return None
        expires_at = time.monotonic() + ex if ex else None
        self._kv[key] = (value if isinstance(value, str) else str(value), expires_at)
        return True

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        self._kv[key] = (value if isinstance(value, str) else str(value), time.monotonic() + ttl)
        return True

    async def get(self, key: str):
        self._purge_expired(key)
        entry = self._kv.get(key)
        return entry[0] if entry else None

    async def delete(self, *keys: str) -> int:
        removed = 0
        for k in keys:
            self._purge_expired(k)
            if k in self._kv:
                del self._kv[k]
                removed += 1
            if k in self._sets:
                del self._sets[k]
                removed += 1
            if k in self._lists:
                del self._lists[k]
                removed += 1
            if k in self._zsets:
                del self._zsets[k]
                removed += 1
        return removed

    async def keys(self, pattern: str) -> list:
        # minimal glob: "*" suffix / prefix match
        if pattern.endswith("*") and not pattern.startswith("*"):
            prefix = pattern[:-1]
            candidates = list(self._kv.keys()) + list(self._sets.keys())
            return [k for k in candidates if k.startswith(prefix)]
        return [k for k in self._kv if k == pattern]

    # -- Lua eval (used by release_lock) --------------------------------

    async def eval(self, script: str, numkeys: int, *args):
        # The only Lua used by SessionMemory is the lock-release CAS. Match it.
        if "redis.call(\"get\", KEYS[1]) == ARGV[1]" in script or (
            'redis.call("get", KEYS[1]) == ARGV[1]' in script
        ):
            key, expected = args[0], args[1]
            self._purge_expired(key)
            current = self._kv.get(key)
            if current and current[0] == expected:
                del self._kv[key]
                return 1
            return 0
        raise NotImplementedError("unsupported lua script in FakeRedis")

    # -- sets ----------------------------------------------------------

    async def sadd(self, key: str, *members: Any) -> int:
        s = self._sets.setdefault(key, set())
        before = len(s)
        for m in members:
            s.add(m)
        return len(s) - before

    async def srem(self, key: str, *members: Any) -> int:
        s = self._sets.setdefault(key, set())
        removed = 0
        for m in members:
            if m in s:
                s.remove(m)
                removed += 1
        return removed

    async def sismember(self, key: str, member: Any) -> bool:
        return member in self._sets.get(key, set())

    async def smembers(self, key: str) -> set:
        return set(self._sets.get(key, set()))

    # -- sorted sets ----------------------------------------------------

    async def zadd(self, key: str, mapping: Dict[str, float]) -> int:
        z = self._zsets.setdefault(key, {})
        added = 0
        for member, score in mapping.items():
            if member not in z:
                added += 1
            z[member] = float(score)
        return added

    async def zpopmax(self, key: str):
        z = self._zsets.get(key, {})
        if not z:
            return []
        member, score = max(z.items(), key=lambda kv: kv[1])
        del z[member]
        return [(member, score)]

    async def zrange(self, key: str, start: int, end: int, withscores: bool = False):
        z = self._zsets.get(key, {})
        items = sorted(z.items(), key=lambda kv: kv[1])
        if end == -1:
            items = items[start:]
        else:
            items = items[start : end + 1]
        return items if withscores else [m for m, _ in items]

    # -- lists --------------------------------------------------------

    async def rpush(self, key: str, *values: Any) -> int:
        lst = self._lists.setdefault(key, [])
        lst.extend(values)
        return len(lst)

    async def lrange(self, key: str, start: int, end: int) -> list:
        lst = self._lists.get(key, [])
        if end == -1:
            return list(lst[start:])
        return list(lst[start : end + 1])

    # -- pub/sub -------------------------------------------------------

    def pubsub(self) -> _FakePubSub:
        return _FakePubSub(self)

    async def publish(self, channel: str, message: str) -> int:
        return self._broadcast(channel, message)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def fake_redis() -> _FakeRedis:
    return _FakeRedis()


@pytest.fixture
async def sqlite_session_memory(fake_redis):
    """SessionMemory wired to in-memory SQLite + FakeRedis (no external services)."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    sm = SessionMemory()
    sm._pg_engine = engine
    sm._async_session = factory
    sm._redis = fake_redis

    yield sm

    try:
        await engine.dispose()
    except Exception:
        pass


def _make_session(session_id: str = "sess-1", engagement_id: str = "eng-xyz") -> SessionState:
    return SessionState(
        session_id=session_id,
        scope=ScopeDefinition(
            engagement_id=engagement_id,
            domains=["example.com"],
            ips=["127.0.0.1"],
        ),
        roe={"authorized_by": "ops", "window": "anytime"},
        phase="recon",
        agents={"agent-1": {"status": "idle"}},
        checkpoint_id=None,
        audit_log_position="0",
        created_by="tester",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# Hot tier: store/retrieve/delete with TTL
# ---------------------------------------------------------------------------


async def test_store_retrieve_delete_hot_roundtrip(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.store_hot("k1", {"foo": "bar", "n": 1}, ttl=60)
    got = await sm.retrieve_hot("k1")
    assert got == {"foo": "bar", "n": 1}

    await sm.delete_hot("k1")
    assert await sm.retrieve_hot("k1") is None


async def test_store_hot_ttl_expires(sqlite_session_memory, fake_redis):
    sm = sqlite_session_memory
    # Write with a NEGATIVE ttl — already expired by the time we try to read.
    await fake_redis.setex("ephemeral", -1, json.dumps({"x": 1}))
    assert await sm.retrieve_hot("ephemeral") is None


async def test_retrieve_hot_missing_returns_none(sqlite_session_memory):
    assert await sqlite_session_memory.retrieve_hot("no-such-key") is None


async def test_store_hot_json_serializes_datetime(sqlite_session_memory):
    sm = sqlite_session_memory
    payload = {"when": datetime(2026, 1, 2, 3, 4, 5)}
    await sm.store_hot("k-dt", payload, ttl=60)
    got = await sm.retrieve_hot("k-dt")
    # datetime gets serialised via default=str
    assert "2026-01-02" in got["when"]


# ---------------------------------------------------------------------------
# Distributed locks
# ---------------------------------------------------------------------------


async def test_acquire_lock_contention_blocks_second_caller(sqlite_session_memory):
    sm = sqlite_session_memory
    ok1 = await sm.acquire_lock("lock-1", "owner-A", ttl_seconds=30)
    assert ok1 is True
    # Contention: different owner, same key — must be False
    ok2 = await sm.acquire_lock("lock-1", "owner-B", ttl_seconds=30)
    assert ok2 is False
    # Release by the owner, then re-acquire works
    released = await sm.release_lock("lock-1", "owner-A")
    assert released is True
    ok3 = await sm.acquire_lock("lock-1", "owner-B", ttl_seconds=30)
    assert ok3 is True


async def test_release_lock_wrong_value_refuses(sqlite_session_memory):
    sm = sqlite_session_memory
    assert await sm.acquire_lock("lock-2", "A", ttl_seconds=30) is True
    # Wrong owner cannot release
    assert await sm.release_lock("lock-2", "wrong-owner") is False
    # Right owner can
    assert await sm.release_lock("lock-2", "A") is True


async def test_release_lock_on_missing_key_returns_false(sqlite_session_memory):
    sm = sqlite_session_memory
    assert await sm.release_lock("never-acquired", "A") is False


async def test_acquire_lock_with_explicit_ttl_kwarg(sqlite_session_memory):
    sm = sqlite_session_memory
    assert await sm.acquire_lock("lock-3", "owner", ttl=15) is True
    # Second caller blocked while held
    assert await sm.acquire_lock("lock-3", "other", ttl=15) is False


async def test_release_lock_simple_deletes_under_lock_prefix(sqlite_session_memory, fake_redis):
    sm = sqlite_session_memory
    await fake_redis.set("lock:simple-1", "owner")
    await sm.release_lock_simple("simple-1")
    assert await fake_redis.get("lock:simple-1") is None


# ---------------------------------------------------------------------------
# Busy-agent set
# ---------------------------------------------------------------------------


async def test_busy_agents_full_lifecycle(sqlite_session_memory):
    sm = sqlite_session_memory
    # clean
    for a in ("a1", "a2"):
        await sm.remove_busy_agent(a)

    assert await sm.is_busy_agent("a1") is False
    await sm.add_busy_agent("a1")
    await sm.add_busy_agent("a2")
    assert await sm.is_busy_agent("a1") is True
    assert await sm.is_busy_agent("a2") is True

    all_busy = await sm.get_all_busy_agents()
    assert set(all_busy) >= {"a1", "a2"}

    await sm.remove_busy_agent("a1")
    assert await sm.is_busy_agent("a1") is False


# ---------------------------------------------------------------------------
# Session-state Redis round-trip
# ---------------------------------------------------------------------------


async def test_store_and_get_session_state_roundtrip(sqlite_session_memory):
    sm = sqlite_session_memory
    state = _make_session("sess-A", "eng-A")
    await sm.store_session_state(state)
    loaded = await sm.get_session_state("sess-A")
    assert loaded is not None
    assert loaded.session_id == "sess-A"
    assert loaded.scope.engagement_id == "eng-A"
    assert loaded.phase == "recon"
    # canonical_engagement_id property is the scope-derived one
    assert loaded.canonical_engagement_id == "eng-A"


async def test_get_session_state_missing_returns_none(sqlite_session_memory):
    assert await sqlite_session_memory.get_session_state("nope") is None


async def test_engagement_id_mapping_both_id_forms_resolve(sqlite_session_memory):
    sm = sqlite_session_memory
    state = _make_session("sess-long-form-123", "eng-short")
    await sm.store_session_state(state)
    await sm.store_engagement_id_mapping("eng-short", "sess-long-form-123")

    # Look up via the short engagement_id
    got = await sm.get_session_state_by_engagement_id("eng-short")
    assert got is not None
    assert got.session_id == "sess-long-form-123"


async def test_engagement_id_fallback_direct_session_id(sqlite_session_memory):
    """If caller passes the full session_id (mapping missing) -> fallback path."""
    sm = sqlite_session_memory
    state = _make_session("sess-X", "eng-X")
    await sm.store_session_state(state)
    got = await sm.get_session_state_by_engagement_id("sess-X")
    assert got is not None
    assert got.session_id == "sess-X"


async def test_engagement_id_totally_missing_returns_none(sqlite_session_memory):
    sm = sqlite_session_memory
    assert await sm.get_session_state_by_engagement_id("missing-eng") is None


# ---------------------------------------------------------------------------
# Postgres warm tier
# ---------------------------------------------------------------------------


async def test_persist_and_load_session_state_sqlite(sqlite_session_memory):
    sm = sqlite_session_memory
    state = _make_session("sess-pg-1", "eng-pg-1")
    await sm.persist_session_state(state)

    loaded = await sm.load_session_state("sess-pg-1")
    assert loaded is not None
    assert loaded.session_id == "sess-pg-1"
    assert loaded.scope.engagement_id == "eng-pg-1"
    assert loaded.scope.domains == ["example.com"]
    assert loaded.roe == {"authorized_by": "ops", "window": "anytime"}


async def test_persist_session_state_upsert_updates(sqlite_session_memory):
    """Second persist with same session_id does an on_conflict_do_update."""
    sm = sqlite_session_memory
    state = _make_session("sess-pg-2", "eng-pg-2")
    await sm.persist_session_state(state)

    state.phase = "exploitation"
    state.agents = {"agent-2": {"status": "busy"}}
    await sm.persist_session_state(state)

    loaded = await sm.load_session_state("sess-pg-2")
    assert loaded is not None
    assert loaded.phase == "exploitation"
    assert loaded.agents == {"agent-2": {"status": "busy"}}


async def test_load_session_state_missing_returns_none(sqlite_session_memory):
    assert await sqlite_session_memory.load_session_state("missing") is None


async def test_list_sessions_postgres_returns_all(sqlite_session_memory):
    sm = sqlite_session_memory
    for sid in ("sess-list-1", "sess-list-2", "sess-list-3"):
        await sm.persist_session_state(_make_session(sid, f"eng-{sid}"))
    all_sessions = await sm.list_sessions_postgres()
    ids = {s.session_id for s in all_sessions}
    assert {"sess-list-1", "sess-list-2", "sess-list-3"} <= ids


async def test_list_sessions_postgres_skills_malformed(sqlite_session_memory):
    """A row whose scope JSON can't construct ScopeDefinition is skipped, not fatal."""
    from ai_osop.memory.session_memory import SessionStateORM

    sm = sqlite_session_memory
    await sm.persist_session_state(_make_session("good-1", "eng-good"))

    # Insert a malformed row directly (no required fields).
    async with sm._async_session() as s:
        bad = SessionStateORM(
            session_id="bad-1",
            scope={"unexpected": "shape-no-engagement-id"},
            roe={},
            phase="?",
            agents={},
            checkpoint_id=None,
            audit_log_position="0",
            created_by=None,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        s.add(bad)
        await s.commit()

    sessions = await sm.list_sessions_postgres()
    ids = {x.session_id for x in sessions}
    assert "good-1" in ids
    # bad-1 either skipped or raises during ScopeDefinition(...) -> caught
    # the production code logs warning + continue.


# ---------------------------------------------------------------------------
# Pub/Sub
# ---------------------------------------------------------------------------


async def test_publish_and_subscribe_events_roundtrip(sqlite_session_memory):
    sm = sqlite_session_memory
    pubsub = await sm.subscribe_events("chan-x")
    await sm.publish_event("chan-x", {"msg": "hello", "seq": 1})
    msg = await pubsub.get_message(timeout=0.5)
    assert msg is not None
    assert msg["type"] == "message"
    assert json.loads(msg["data"]) == {"msg": "hello", "seq": 1}
    await pubsub.close()


async def test_publish_event_serializes_datetimes(sqlite_session_memory):
    sm = sqlite_session_memory
    pubsub = await sm.subscribe_events("chan-dt")
    await sm.publish_event("chan-dt", {"when": datetime(2026, 1, 1, 0, 0, 0)})
    msg = await pubsub.get_message(timeout=0.5)
    assert msg is not None
    payload = json.loads(msg["data"])
    assert "2026-01-01" in payload["when"]
    await pubsub.close()


async def test_subscribe_only_receives_messages_on_its_channel(sqlite_session_memory):
    sm = sqlite_session_memory
    ps_a = await sm.subscribe_events("chan-a")
    ps_b = await sm.subscribe_events("chan-b")
    await sm.publish_event("chan-a", {"for": "a"})
    msg_a = await ps_a.get_message(timeout=0.5)
    msg_b = await ps_b.get_message(timeout=0.05)
    assert msg_a is not None
    assert msg_b is None
    await ps_a.close()
    await ps_b.close()


# ---------------------------------------------------------------------------
# Task queue (priority + dedup)
# ---------------------------------------------------------------------------


async def test_push_and_pop_task_queue_priority_order(sqlite_session_memory):
    sm = sqlite_session_memory
    # Push three tasks of known priority classes
    await sm.push_task_queue("q1", {"id": "low", "type": "xss_scan"})  # heavy -> 40
    await sm.push_task_queue("q1", {"id": "high", "type": "map_workflow"})  # prereq -> 100
    await sm.push_task_queue("q1", {"id": "mid", "type": "api_discovery"})  # light -> 80
    await sm.push_task_queue(
        "q1", {"id": "default", "type": "other_thing", "priority": 3}
    )  # default 3*10 = 30

    first = await sm.pop_task_queue("q1")
    assert first["id"] == "high"
    assert first["priority"] == 100

    second = await sm.pop_task_queue("q1")
    assert second["id"] == "mid"
    assert second["priority"] == 80

    third = await sm.pop_task_queue("q1")
    assert third["id"] == "low"

    fourth = await sm.pop_task_queue("q1")
    assert fourth["id"] == "default"


async def test_pop_task_queue_empty_returns_none(sqlite_session_memory):
    assert await sqlite_session_memory.pop_task_queue("empty-q") is None


async def test_task_queue_dedup_same_payload(sqlite_session_memory, fake_redis):
    """Identical task payloads hash to the same zset member -> only one entry."""
    sm = sqlite_session_memory
    task = {"id": "t1", "type": "api_discovery", "anything": 1}
    await sm.push_task_queue("q2", task)
    await sm.push_task_queue("q2", dict(task))  # same content -> same member key
    # A sorted set keeps only the latest score for that member, so exactly one pop.
    popped = await sm.pop_task_queue("q2")
    assert popped is not None
    assert popped["id"] == "t1"
    assert await sm.pop_task_queue("q2") is None


async def test_task_queue_prefixed_key_roundtrip(sqlite_session_memory):
    """queue: prefix is not doubled when caller passes prefixed name."""
    sm = sqlite_session_memory
    await sm.push_task_queue("queue:already", {"id": "t9"})
    popped = await sm.pop_task_queue("queue:already")
    assert popped is not None and popped["id"] == "t9"


# ---------------------------------------------------------------------------
# Agent state / heartbeats / lookups
# ---------------------------------------------------------------------------


async def test_agent_state_roundtrip(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.store_agent_state(
        "agent-A", {"status": "busy", "current_task": "task-1"}, ttl=60
    )
    got = await sm.get_agent_state("agent-A")
    assert got == {"status": "busy", "current_task": "task-1"}
    assert await sm.get_agent_state("agent-missing") is None


async def test_update_agent_status_creates_when_missing(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.update_agent_status("agent-new", "idle")
    got = await sm.get_agent_state("agent-new")
    assert got == {"status": "idle"}


async def test_update_agent_status_mutates_existing(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.store_agent_state("agent-B", {"status": "idle", "extra": "x"})
    await sm.update_agent_status("agent-B", "running")
    got = await sm.get_agent_state("agent-B")
    assert got["status"] == "running"
    assert got["extra"] == "x"


async def test_update_agent_heartbeat_sets_last_seen(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.update_agent_heartbeat("agent-H", {"load": 0.5})
    hb = await sm.get_agent_heartbeat("agent-H")
    assert hb is not None
    assert hb["load"] == 0.5
    assert "last_seen" in hb


async def test_get_all_agents_excludes_heartbeat_keys(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.store_agent_state("agent-Y1", {"status": "idle"})
    await sm.update_agent_heartbeat("agent-Y1", {"ok": True})
    all_agents = await sm.get_all_agents()
    # Heartbeat keys must be filtered out
    assert "agent-Y1" in all_agents
    assert "heartbeat:agent-Y1" not in all_agents


async def test_find_tasks_by_agent_filters_on_assignment(sqlite_session_memory, fake_redis):
    sm = sqlite_session_memory
    await sm.store_hot(
        "task:t-1", {"id": "t-1", "assigned_agent_id": "agent-Z"}, ttl=60
    )
    await sm.store_hot(
        "task:t-2", {"id": "t-2", "assigned_agent_id": "agent-other"}, ttl=60
    )
    mine = await sm.find_tasks_by_agent("agent-Z")
    ids = {t["id"] for t in mine}
    assert "t-1" in ids
    assert "t-2" not in ids


# ---------------------------------------------------------------------------
# list_push / list_range list helpers
# ---------------------------------------------------------------------------


async def test_list_push_and_range(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.list_push("mylist", "a")
    await sm.list_push("mylist", "b")
    await sm.list_push("mylist", "c")
    assert await sm.list_range("mylist") == ["a", "b", "c"]
    assert await sm.list_range("mylist", 0, 1) == ["a", "b"]


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------


async def test_create_and_restore_checkpoint(sqlite_session_memory):
    sm = sqlite_session_memory
    state = _make_session("sess-cp", "eng-cp")
    await sm.store_session_state(state)

    cp_id = await sm.create_checkpoint("sess-cp", {"why": "snapshot"})
    assert cp_id.startswith("chk-sess-cp-")

    # Session got the checkpoint reference written back
    sess = await sm.get_session_state("sess-cp")
    assert sess.checkpoint_id == cp_id

    restored = await sm.restore_checkpoint(cp_id)
    assert restored.session_id == "sess-cp"
    assert restored.scope.engagement_id == "eng-cp"


async def test_create_checkpoint_missing_session_raises(sqlite_session_memory):
    sm = sqlite_session_memory
    with pytest.raises(MemoryException):
        await sm.create_checkpoint("no-such-session", {})


async def test_restore_checkpoint_missing_raises(sqlite_session_memory):
    sm = sqlite_session_memory
    with pytest.raises(MemoryException):
        await sm.restore_checkpoint("chk-never-existed")


# ---------------------------------------------------------------------------
# list_all_sessions / list_all_tasks / close
# ---------------------------------------------------------------------------


async def test_list_all_sessions_and_tasks(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.store_session_state(_make_session("s-100", "eng-100"))
    await sm.store_session_state(_make_session("s-101", "eng-101"))
    await sm.store_hot("task:t-100", {"id": "t-100"}, ttl=60)

    sessions = await sm.list_all_sessions()
    tasks = await sm.list_all_tasks()
    assert any(k.startswith("session:") for k in sessions)
    assert any(k.startswith("task:") for k in tasks)


async def test_close_is_safe_when_redis_attached(sqlite_session_memory, fake_redis):
    sm = sqlite_session_memory
    await sm.close()
    assert fake_redis._closed is True


# ---------------------------------------------------------------------------
# _ensure_redis reconnect path
# ---------------------------------------------------------------------------


async def test_ensure_redis_returns_existing_when_healthy(sqlite_session_memory):
    sm = sqlite_session_memory
    r1 = await sm._ensure_redis()
    r2 = await sm._ensure_redis()
    assert r1 is r2  # same object — ping succeeded so no reconnect


# ---------------------------------------------------------------------------
# Approval requests (hot + warm tier)
# ---------------------------------------------------------------------------


def _make_approval(rid: str = "apr-1", status: str = "pending") -> ApprovalRequest:
    return ApprovalRequest(
        id=rid,
        task_id="task-9",
        agent_id="agent-9",
        action_type="scan",
        target="https://example.com",
        payload_summary="scan payload",
        risk_assessment="medium",
        evidence=[{"note": "foo"}],
        status=status,
        operator_id=None,
        operator_notes=None,
        requested_at=datetime.utcnow(),
        responded_at=None,
        engagement_id="eng-apr",
    )


async def test_store_and_load_approval_request_roundtrip(sqlite_session_memory):
    sm = sqlite_session_memory
    apr = _make_approval("apr-rt")
    await sm.store_approval_request(apr)
    loaded = await sm.load_approval_request("apr-rt")
    assert loaded is not None
    assert loaded.id == "apr-rt"
    assert loaded.task_id == "task-9"
    assert loaded.status == "pending"
    assert loaded.engagement_id == "eng-apr"


async def test_approval_request_upsert_updates_status(sqlite_session_memory):
    sm = sqlite_session_memory
    apr = _make_approval("apr-up")
    await sm.store_approval_request(apr)
    # simulate operator approval
    apr.status = "approved"
    apr.operator_id = "op-7"
    apr.operator_notes = "lgtm"
    apr.responded_at = datetime.utcnow()
    # Clear the hot-tier so the second load hits Postgres warm tier.
    await sm.delete_hot(f"approval:{apr.id}")
    await sm.store_approval_request(apr)
    loaded = await sm.load_approval_request("apr-up")
    assert loaded is not None
    assert loaded.status == "approved"
    assert loaded.operator_id == "op-7"


async def test_load_approval_request_missing_returns_none(sqlite_session_memory):
    sm = sqlite_session_memory
    assert await sm.load_approval_request("never-stored") is None


async def test_list_pending_approvals_only_returns_pending(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.store_approval_request(_make_approval("p1", "pending"))
    await sm.store_approval_request(_make_approval("p2", "pending"))
    await sm.store_approval_request(_make_approval("p3", "approved"))
    pending = await sm.list_pending_approvals()
    ids = {p.id for p in pending}
    assert {"p1", "p2"} <= ids
    assert "p3" not in ids


# ---------------------------------------------------------------------------
# Task persistence (hot + warm tier) + recovery queries
# ---------------------------------------------------------------------------


def _make_task(tid: str, status: str = "pending", engagement_id: str = "eng-t") -> Task:
    return Task(
        id=tid,
        type="recon_scan",
        priority=5,
        agent_type=AgentType.RECON,
        payload={"target": "example.com"},
        dependencies=[],
        mcp_requirements=[],
        max_retries=3,
        timeout_seconds=300,
        scope_check=True,
        approval_required=False,
        status=status,
        result=None,
        error=None,
        retry_count=0,
        created_at=datetime.utcnow(),
        started_at=None,
        completed_at=None,
        engagement_id=engagement_id,
        assigned_agent_id=None,
    )


async def test_store_and_load_task_roundtrip(sqlite_session_memory):
    sm = sqlite_session_memory
    task = _make_task("t-rt-1")
    await sm.store_task(task)
    loaded = await sm.load_task("t-rt-1")
    assert loaded is not None
    assert loaded.id == "t-rt-1"
    assert loaded.type == "recon_scan"
    assert loaded.status == "pending"
    assert loaded.agent_type == AgentType.RECON


async def test_load_task_falls_back_to_postgres(sqlite_session_memory):
    """When Redis misses, load_task reads from the warm Postgres tier."""
    sm = sqlite_session_memory
    task = _make_task("t-pg-1", status="running")
    await sm.store_task(task)
    # Simulate Redis cache eviction: pull the task from the hot tier
    await sm.delete_hot(f"task:{task.id}")
    loaded = await sm.load_task("t-pg-1")
    assert loaded is not None
    assert loaded.status == "running"


async def test_load_task_missing_returns_none(sqlite_session_memory):
    assert await sqlite_session_memory.load_task("nope") is None


async def test_load_all_active_tasks_filters_completed(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.store_task(_make_task("t-active-1", status="pending"))
    await sm.store_task(_make_task("t-active-2", status="running"))
    await sm.store_task(_make_task("t-done-1", status="completed"))
    await sm.store_task(_make_task("t-done-2", status="failed"))

    # Redis hot cache must be cleared so the query goes to Postgres
    # (otherwise find via task:{id} keys returns cached dicts).
    active = await sm.load_all_active_tasks()
    ids = {t.id for t in active}
    assert "t-active-1" in ids
    assert "t-active-2" in ids
    assert "t-done-1" not in ids
    assert "t-done-2" not in ids


async def test_load_all_active_tasks_age_cutoff(sqlite_session_memory):
    """Tasks older than recovery_max_age_hours are excluded from resurrection."""
    from ai_osop.core.config import settings

    sm = sqlite_session_memory
    recent = _make_task("t-fresh", status="pending")
    stale = _make_task("t-stale", status="pending")
    stale.created_at = datetime.utcnow() - timedelta(
        hours=settings.recovery_max_age_hours + 1
    )
    await sm.store_task(recent)
    await sm.store_task(stale)

    active = await sm.load_all_active_tasks()
    ids = {t.id for t in active}
    assert "t-fresh" in ids
    assert "t-stale" not in ids


async def test_store_task_enqueues_outbox_row(sqlite_session_memory):
    """store_task is dual-write: task + outbox row in the same transaction."""
    from sqlalchemy import select

    from ai_osop.memory.session_memory import OutboxORM

    sm = sqlite_session_memory
    await sm.store_task(_make_task("t-obx"))
    async with sm._async_session() as s:
        rows = (
            (await s.execute(select(OutboxORM).where(OutboxORM.entity_id == "t-obx")))
            .scalars()
            .all()
        )
        assert len(rows) >= 1
        assert rows[0].entity_type == "task"
        assert rows[0].action == "upsert"


async def test_enqueue_outbox_directly(sqlite_session_memory):
    from sqlalchemy import select

    from ai_osop.memory.session_memory import OutboxORM

    sm = sqlite_session_memory
    await sm.enqueue_outbox("finding", "f-1", {"id": "f-1"}, action="upsert")
    async with sm._async_session() as s:
        row = (
            await s.execute(select(OutboxORM).where(OutboxORM.entity_id == "f-1"))
        ).scalar_one()
        assert row.entity_type == "finding"
        assert row.action == "upsert"
        assert row.payload == {"id": "f-1"}
        assert row.processed is False


# ---------------------------------------------------------------------------
# DLQ (dead letter queue) hot + warm
# ---------------------------------------------------------------------------


def _make_dlq_entry(eid: str, engagement_id: str = "eng-dlq", status: str = "pending_review"):
    from ai_osop.reliability.dlq import DLQEntry

    return DLQEntry(
        id=eid,
        task_id="task-x",
        engagement_id=engagement_id,
        task_type="recon_scan",
        agent_type="recon",
        reason="max_retries_exceeded",
        final_error="boom",
        task_payload={"target": "example.com"},
        status=status,
        operator_notes=None,
        retry_count=3,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


async def test_store_and_get_dlq_entry(sqlite_session_memory):
    sm = sqlite_session_memory
    entry = _make_dlq_entry("dlq-1")
    await sm.store_dlq_entry(entry)
    got = await sm.get_dlq_entry("dlq-1")
    assert got is not None
    assert got.id == "dlq-1"
    assert got.status == "pending_review"
    assert got.reason == "max_retries_exceeded"


async def test_get_dlq_entry_falls_back_to_postgres(sqlite_session_memory):
    sm = sqlite_session_memory
    entry = _make_dlq_entry("dlq-2")
    await sm.store_dlq_entry(entry)
    await sm.delete_hot(f"dlq:{entry.id}")  # evict cache to force warm-tier read
    got = await sm.get_dlq_entry("dlq-2")
    assert got is not None
    assert got.id == "dlq-2"


async def test_get_dlq_entry_missing_returns_none(sqlite_session_memory):
    assert await sqlite_session_memory.get_dlq_entry("nope") is None


async def test_list_dlq_entries_filter_by_engagement_and_status(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.store_dlq_entry(_make_dlq_entry("d-a", engagement_id="eng-A"))
    await sm.store_dlq_entry(_make_dlq_entry("d-b", engagement_id="eng-A", status="requeued"))
    await sm.store_dlq_entry(_make_dlq_entry("d-c", engagement_id="eng-B"))

    # No filter -> all three
    all_entries = await sm.list_dlq_entries()
    ids = {e.id for e in all_entries}
    assert {"d-a", "d-b", "d-c"} <= ids

    # Filtered by engagement
    eng_a = await sm.list_dlq_entries(engagement_id="eng-A")
    assert {e.id for e in eng_a} >= {"d-a", "d-b"}
    assert "d-c" not in {e.id for e in eng_a}

    # Filtered by status
    requeued = await sm.list_dlq_entries(status="requeued")
    assert "d-b" in {e.id for e in requeued}


async def test_get_dlq_stats_counts_by_status(sqlite_session_memory):
    sm = sqlite_session_memory
    await sm.store_dlq_entry(_make_dlq_entry("s-1", status="pending_review"))
    await sm.store_dlq_entry(_make_dlq_entry("s-2", status="pending_review"))
    await sm.store_dlq_entry(_make_dlq_entry("s-3", status="requeued"))
    await sm.store_dlq_entry(_make_dlq_entry("s-4", status="discarded"))

    stats = await sm.get_dlq_stats()
    assert stats["pending"] == 2
    assert stats["requeued"] == 1
    assert stats["discarded"] == 1


# ---------------------------------------------------------------------------
# Corpus findings + historical success rate
# ---------------------------------------------------------------------------


async def test_upsert_and_historical_success_rate(sqlite_session_memory):
    sm = sqlite_session_memory
    base = {"category": "xss", "severity": "high", "engagement_id": "eng-1"}

    await sm.upsert_corpus_finding({**base, "id": "f-1"}, outcome="accepted")
    await sm.upsert_corpus_finding({**base, "id": "f-2"}, outcome="rejected")
    await sm.upsert_corpus_finding({**base, "id": "f-3"}, outcome="duplicate")

    rate = await sm.get_historical_success_rate("xss")
    # accepted + duplicate valid, rejected invalid -> 2/3
    assert rate == pytest.approx(2 / 3, abs=1e-3)


async def test_historical_success_rate_cold_start_neutral(sqlite_session_memory):
    sm = sqlite_session_memory
    rate = await sm.get_historical_success_rate("no-such-category")
    assert rate == 0.5


async def test_historical_outcome_counts(sqlite_session_memory):
    sm = sqlite_session_memory
    base = {"category": "sqli", "severity": "high", "engagement_id": "eng-2"}
    await sm.upsert_corpus_finding({**base, "id": "q-1"}, outcome="accepted")
    await sm.upsert_corpus_finding({**base, "id": "q-2"}, outcome="triaged")
    await sm.upsert_corpus_finding({**base, "id": "q-3"}, outcome="informative")

    n_valid, n_total = await sm.get_historical_outcome_counts("sqli")
    assert n_valid == 2
    assert n_total == 3  # accepted + triaged + informative (informative is invalid but decided)


async def test_historical_outcome_counts_cold_start(sqlite_session_memory):
    sm = sqlite_session_memory
    assert await sm.get_historical_outcome_counts("never") == (0, 0)


async def test_historical_success_rate_returns_neutral_when_no_session(sqlite_session_memory):
    """When _async_session is None (never wired), the API must not crash."""
    sm = sqlite_session_memory
    original = sm._async_session
    sm._async_session = None
    try:
        assert await sm.get_historical_success_rate("any") == 0.5
        assert await sm.get_historical_outcome_counts("any") == (0, 0)
    finally:
        sm._async_session = original


async def test_upsert_corpus_finding_updates_outcome_on_conflict(sqlite_session_memory):
    sm = sqlite_session_memory
    finding = {"id": "ups-1", "category": "ssrf", "severity": "high", "engagement_id": "eng-1"}
    await sm.upsert_corpus_finding(finding, outcome="triaged")
    # Later the same finding is ground-truthed as accepted — the upsert path
    # must update the outcome rather than create a duplicate row.
    await sm.upsert_corpus_finding(finding, outcome="accepted")
    n_valid, n_total = await sm.get_historical_outcome_counts("ssrf")
    assert (n_valid, n_total) == (1, 1)
