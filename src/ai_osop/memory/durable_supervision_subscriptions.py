"""Durable, fenced subscribers for PostgreSQL supervision event sequences.

This isolated store is NOT wired into supervision SSE yet. It needs the 0040
schema and a caller-supplied live, signed-identity verifier. Polling SSE with a
Last-Event-ID header is not a durable multi-replica subscriber acknowledgement.

All mutations use one PostgreSQL transaction: live principal verification,
signed ROE guard_sql, exact engagement/task ownership, and row/lease fences.
The published cursor only advances when the owner ACKs the *next* committed
tenant event. It therefore supports at-least-once delivery after a crash;
no exactly-once delivery or independently observed client receipt is claimed.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional

from sqlalchemy import text

_ENG = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_SUBSCRIBER = re.compile(r"subscr-[0-9a-f]{32}\Z")
_REPLICA = re.compile(r"replica-[A-Za-z0-9._-]{1,90}\Z")
_TASK = re.compile(r"task-[A-Za-z0-9._:-]{1,59}\Z")  # existing tasks.id VARCHAR(64)
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_LEASE = re.compile(r"lease-[0-9a-f]{32}\Z")
_MAX_CURSOR = 9223372036854775807

# Required 0040 table: PK(engagement_id, subscriber_id), principal_issuer,
# principal_subject, task_id, authorization_version, authorization_sha256,
# cursor_sequence BIGINT, lease_owner, lease_id, lease_generation BIGINT,
# lease_until TIMESTAMPTZ, revoked_at TIMESTAMPTZ, created_at, updated_at.
# No CREATE TABLE at runtime: absent/unmigrated PG schema must fail closed.


class SubscriptionDenied(RuntimeError):
    """Missing/expired authority, stale CAS, revoked subscriber or database."""


@dataclass(frozen=True)
class SubscriberPrincipal:
    engagement_id: str
    subscriber_id: str
    issuer: str
    subject: str
    role: str
    expires_at: int
    authorization_version: int
    authorization_sha256: str
    task_id: Optional[str] = None


@dataclass(frozen=True)
class SubscriberLease:
    engagement_id: str
    subscriber_id: str
    replica_id: str
    lease_id: str
    generation: int
    cursor: int
    lease_until: datetime


# Must validate the CURRENT cryptographically authenticated bearer and its
# issuer/subject/role/expiry/revocation against the exact principal INSIDE the
# passed caller-owned transaction; caller must never use a cached login flag.
LiveCredentialGuard = Callable[[Any, SubscriberPrincipal], Awaitable[bool]]
SignedROEGuard = Callable[..., Awaitable[Any]]
PrecommitDisconnectGuard = Callable[[], Awaitable[bool]]


def _validate_principal(value: SubscriberPrincipal) -> None:
    if (
        not isinstance(value, SubscriberPrincipal)
        or type(value.engagement_id) is not str
        or not _ENG.fullmatch(value.engagement_id)
        or type(value.subscriber_id) is not str
        or not _SUBSCRIBER.fullmatch(value.subscriber_id)
        or type(value.issuer) is not str
        or not 1 <= len(value.issuer) <= 128
        or type(value.subject) is not str
        or not 1 <= len(value.subject) <= 128
        or any(ord(c) < 33 or ord(c) > 126 for c in value.issuer + value.subject)
        or value.role not in {"operator", "senior_operator"}
        or type(value.expires_at) is not int
        or value.expires_at <= int(datetime.now(timezone.utc).timestamp())
        or type(value.authorization_version) is not int
        or value.authorization_version < 1
        or type(value.authorization_sha256) is not str
        or not _SHA.fullmatch(value.authorization_sha256)
        or (
            value.task_id is not None
            and (type(value.task_id) is not str or not _TASK.fullmatch(value.task_id))
        )
    ):
        raise SubscriptionDenied("Authenticated, scoped subscriber identity required")


def _validate_cursor(value: int) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_CURSOR:
        raise SubscriptionDenied("Bounded supervision cursor required")


def _validate_replica(value: str) -> None:
    if type(value) is not str or not _REPLICA.fullmatch(value):
        raise SubscriptionDenied("Exact replica identity required")


def _lease_params(lease: SubscriberLease) -> Dict[str, Any]:
    if (
        not isinstance(lease, SubscriberLease)
        or type(lease.lease_id) is not str
        or not _LEASE.fullmatch(lease.lease_id)
        or type(lease.generation) is not int
        or not 1 <= lease.generation < _MAX_CURSOR
    ):
        raise SubscriptionDenied("Valid fenced lease required")
    _validate_replica(lease.replica_id)
    _validate_cursor(lease.cursor)
    return {"replica": lease.replica_id, "lease_id": lease.lease_id, "generation": lease.generation}


def _base(principal: SubscriberPrincipal) -> Dict[str, Any]:
    return {
        "engagement": principal.engagement_id,
        "subscriber": principal.subscriber_id,
        "issuer": principal.issuer,
        "subject": principal.subject,
        "task": principal.task_id,
        "auth_version": principal.authorization_version,
        "auth_sha": principal.authorization_sha256,
    }


class DurableSupervisionSubscriptions:
    """PostgreSQL-backed replica-fenced subscription state, never an SSE handler."""

    def __init__(
        self,
        session_memory: Any,
        *,
        credential_guard: LiveCredentialGuard,
        roe_guard: Optional[SignedROEGuard] = None,
    ) -> None:
        self._maker = getattr(session_memory, "_async_session", None)
        if not callable(credential_guard):
            raise SubscriptionDenied("Live cryptographic operator verifier required")
        self._credential_guard = credential_guard
        if roe_guard is None:
            from ai_osop.memory.authorization_store import guard_sql

            roe_guard = guard_sql
        self._roe_guard = roe_guard

    @asynccontextmanager
    async def _transaction(
        self,
        principal: SubscriberPrincipal,
        *,
        precommit_disconnect: Optional[PrecommitDisconnectGuard] = None,
    ) -> AsyncIterator[Any]:
        _validate_principal(principal)
        if precommit_disconnect is not None and not callable(precommit_disconnect):
            raise SubscriptionDenied("Trusted server disconnect check required")
        if not callable(self._maker):
            raise SubscriptionDenied("Durable PostgreSQL subscription store unavailable")
        try:
            async with self._maker() as db:
                async with db.begin():
                    # The signed ROE guard locks the engagement row FOR SHARE
                    # in this SAME PG transaction. A revocation must serialize.
                    await self._authorize(db, principal)
                    yield db
                    # The 0014 token/subject revocation tables can have no row
                    # for an *active* principal. SELECT ... FOR SHARE on a
                    # missing digest/subject takes NO PostgreSQL row lock. A
                    # concurrent revoke_token()/disable_subject() can INSERT
                    # after a credential check and commit before our cursor or
                    # lease transaction commits. Lock BOTH tables in SHARE mode
                    # NOWAIT before the final check, to fence those INSERTs
                    # without relying on cooperation from revocation writers.
                    # This remains a bounded admission point: a busy writer
                    # denies the operation rather than waiting or retrying.
                    await self._fence_revocation_insert(db)
                    # Under READ COMMITTED the final check sees every earlier
                    # committed revocation. The table locks then prevent a new
                    # revocation from committing until this transaction ends.
                    await self._authorize(db, principal)
                    if precommit_disconnect is not None:
                        # This callback must be supplied by the host HTTP
                        # Request, never a client body/caller-signed assertion.
                        # After SQL UPDATE and current credential/ROE fencing,
                        # deny+ROLLBACK a disconnect already observed by ASGI.
                        # This is best effort: the final check/COMMIT/socket
                        # publication window remains inherently non-atomic.
                        disconnected = await asyncio.wait_for(precommit_disconnect(), timeout=0.5)
                        if type(disconnected) is not bool or disconnected:
                            raise SubscriptionDenied(
                                "Subscriber HTTP connection lost before ACK commit"
                            )
        except SubscriptionDenied:
            raise
        except Exception as exc:
            raise SubscriptionDenied("Current durable subscription state unavailable") from exc

    @staticmethod
    async def _fence_revocation_insert(db: Any) -> None:
        """Prevent the absent-row PostgreSQL revocation phantom at commit.

        0014 revocation writers INSERT/UPDATE their own tables with ordinary
        ROW EXCLUSIVE locks. SHARE NOWAIT conflicts with those writes even if
        the digest or subject did not exist at admission time. READ COMMITTED
        is essential: REPEATABLE READ could use a pre-lock stale snapshot.
        Sessions without a PostgreSQL dialect deny; test fakes must explicitly
        model the lock SQL and cannot establish actual PostgreSQL guarantees.
        """
        bind = getattr(db, "bind", None)
        if bind is None:
            raise SubscriptionDenied("Bound PostgreSQL revocation transaction required")
        if getattr(getattr(bind, "dialect", None), "name", None) != "postgresql":
            raise SubscriptionDenied("Durable operator revocation requires PostgreSQL")
        isolation = (
            await db.execute(text("SELECT current_setting('transaction_isolation')"))
        ).scalar_one_or_none()
        if isolation != "read committed":
            raise SubscriptionDenied("Current revocation snapshot isolation unavailable")
        await db.execute(
            text(
                "LOCK TABLE operator_token_revocations, operator_subject_controls "
                "IN SHARE MODE NOWAIT"
            )
        )

    async def _authorize(self, db: Any, principal: SubscriberPrincipal) -> None:
        _validate_principal(principal)
        if await self._credential_guard(db, principal) is not True:
            raise SubscriptionDenied("Live subscriber bearer revoked or changed")
        verified = await self._roe_guard(
            db,
            principal.engagement_id,
            expected_version=principal.authorization_version,
            expected_digest=principal.authorization_sha256,
        )
        if verified is None:
            raise SubscriptionDenied("Current signed supervision ROE unavailable")
        parent = (
            (
                await db.execute(
                    text(
                        "SELECT created_by FROM session_states "
                        "WHERE session_id=:engagement FOR SHARE"
                    ),
                    {"engagement": principal.engagement_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if parent is None or (
            principal.role != "senior_operator" and parent.get("created_by") != principal.subject
        ):
            raise SubscriptionDenied("Engagement is not owned by subscriber principal")
        if principal.task_id is not None:
            owner = (
                await db.execute(
                    text(
                        "SELECT id FROM tasks WHERE id=:task AND engagement_id=:engagement FOR SHARE"
                    ),
                    {"task": principal.task_id, "engagement": principal.engagement_id},
                )
            ).scalar_one_or_none()
            if owner != principal.task_id:
                raise SubscriptionDenied("Subscribed Task does not belong to engagement")

    @staticmethod
    async def _locked(db: Any, principal: SubscriberPrincipal) -> Dict[str, Any]:
        row = (
            (
                await db.execute(
                    text(
                        "SELECT cursor_sequence,lease_owner,lease_id,lease_generation,"
                        "lease_until,revoked_at FROM supervision_durable_subscriptions "
                        "WHERE engagement_id=:engagement AND subscriber_id=:subscriber "
                        "AND principal_issuer=:issuer AND principal_subject=:subject "
                        "AND task_id IS NOT DISTINCT FROM :task "
                        "AND authorization_version=:auth_version AND authorization_sha256=:auth_sha "
                        "FOR UPDATE"
                    ),
                    _base(principal),
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None or row.get("revoked_at") is not None:
            raise SubscriptionDenied("Subscription absent, rebound or revoked")
        _validate_cursor(row.get("cursor_sequence"))
        if type(row.get("lease_generation")) is not int or row["lease_generation"] < 0:
            raise SubscriptionDenied("Invalid durable lease generation")
        return dict(row)

    @staticmethod
    def _projection(
        principal: SubscriberPrincipal, replica: str, row: Dict[str, Any]
    ) -> SubscriberLease:
        if (
            row.get("lease_owner") != replica
            or type(row.get("lease_id")) is not str
            or not _LEASE.fullmatch(row["lease_id"])
            or not isinstance(row.get("lease_until"), datetime)
            or type(row.get("lease_generation")) is not int
            or row["lease_generation"] < 1
        ):
            raise SubscriptionDenied("Current durable lease cannot be proven")
        _validate_cursor(row.get("cursor_sequence"))
        return SubscriberLease(
            principal.engagement_id,
            principal.subscriber_id,
            replica,
            row["lease_id"],
            row["lease_generation"],
            row["cursor_sequence"],
            row["lease_until"],
        )

    async def acquire(
        self, principal: SubscriberPrincipal, replica_id: str, *, lease_seconds: int = 30
    ) -> SubscriberLease:
        """Create inert cursor=0 once, then atomically claim an expired/empty lease."""
        _validate_replica(replica_id)
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 120:
            raise SubscriptionDenied("Bounded subscription lease required")
        async with self._transaction(principal) as db:
            params = {
                **_base(principal),
                "replica": replica_id,
                "lease_id": "lease-" + uuid.uuid4().hex,
                "ttl": lease_seconds,
            }
            await db.execute(
                text(
                    "INSERT INTO supervision_durable_subscriptions "
                    "(engagement_id,subscriber_id,principal_issuer,principal_subject,task_id,"
                    "authorization_version,authorization_sha256,cursor_sequence,lease_generation) "
                    "VALUES (:engagement,:subscriber,:issuer,:subject,:task,:auth_version,:auth_sha,0,0) "
                    "ON CONFLICT (engagement_id,subscriber_id) DO NOTHING"
                ),
                params,
            )
            before = await self._locked(db, principal)
            updated = (
                (
                    await db.execute(
                        text(
                            "UPDATE supervision_durable_subscriptions SET "
                            "lease_owner=:replica,lease_id=:lease_id,lease_generation=lease_generation+1,"
                            "lease_until=clock_timestamp()+(:ttl * INTERVAL '1 second'),"
                            "updated_at=clock_timestamp() "
                            "WHERE engagement_id=:engagement AND subscriber_id=:subscriber "
                            "AND principal_issuer=:issuer AND principal_subject=:subject "
                            "AND task_id IS NOT DISTINCT FROM :task "
                            "AND authorization_version=:auth_version AND authorization_sha256=:auth_sha "
                            "AND lease_generation=:prior AND revoked_at IS NULL "
                            "AND (lease_id IS NULL OR lease_until<=clock_timestamp()) "
                            "RETURNING cursor_sequence,lease_owner,lease_id,lease_generation,lease_until"
                        ),
                        {**params, "prior": before["lease_generation"]},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if updated is None:
                raise SubscriptionDenied("Subscriber already leased or fenced by another replica")
            return self._projection(principal, replica_id, dict(updated))

    async def _active(
        self, db: Any, principal: SubscriberPrincipal, lease: SubscriberLease
    ) -> Dict[str, Any]:
        if (lease.engagement_id, lease.subscriber_id) != (
            principal.engagement_id,
            principal.subscriber_id,
        ):
            raise SubscriptionDenied("Foreign subscriber lease")
        fence = _lease_params(lease)
        row = await self._locked(db, principal)
        if (
            row.get("lease_owner") != fence["replica"]
            or row.get("lease_id") != fence["lease_id"]
            or row.get("lease_generation") != fence["generation"]
        ):
            raise SubscriptionDenied("Replica lease was replaced")
        live = (
            await db.execute(
                text(
                    "SELECT 1 FROM supervision_durable_subscriptions "
                    "WHERE engagement_id=:engagement AND subscriber_id=:subscriber "
                    "AND principal_issuer=:issuer AND principal_subject=:subject "
                    "AND task_id IS NOT DISTINCT FROM :task "
                    "AND authorization_version=:auth_version AND authorization_sha256=:auth_sha "
                    "AND lease_owner=:replica AND lease_id=:lease_id "
                    "AND lease_generation=:generation AND revoked_at IS NULL "
                    "AND lease_until>clock_timestamp()"
                ),
                {**_base(principal), **fence},
            )
        ).scalar_one_or_none()
        if live != 1:
            raise SubscriptionDenied("Subscription lease expired or revoked")
        return row

    async def read_committed_cursor(
        self, principal: SubscriberPrincipal, lease: SubscriberLease
    ) -> SubscriberLease:
        """Read ONLY current committed cursor after ambiguous HTTP ACK.

        The provided lease.cursor is the caller's old observed cursor, not an
        assertion that PostgreSQL still has that value. A lost HTTP response
        can leave an ACK committed. Require the SAME current signed principal,
        replica owner, lease ID and generation while independently returning
        the durable cursor, without attempting another ACK or Tool invocation.
        A changed/expired/revoked lease denies, never guesses an ACK outcome.
        """
        async with self._transaction(principal) as db:
            row = await self._active(db, principal, lease)
            # _active locks the exact subscriber row, rejects revoked/expired
            # leases and validates same replica; no cursor write occurs.
            return self._projection(principal, lease.replica_id, row)

    async def renew(
        self, principal: SubscriberPrincipal, lease: SubscriberLease, *, lease_seconds: int = 30
    ) -> SubscriberLease:
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 120:
            raise SubscriptionDenied("Bounded renewal deadline required")
        async with self._transaction(principal) as db:
            await self._active(db, principal, lease)
            new = (
                (
                    await db.execute(
                        text(
                            "UPDATE supervision_durable_subscriptions SET "
                            "lease_until=clock_timestamp()+(:ttl * INTERVAL '1 second'),"
                            "updated_at=clock_timestamp() "
                            "WHERE engagement_id=:engagement AND subscriber_id=:subscriber "
                            "AND principal_issuer=:issuer AND principal_subject=:subject "
                            "AND task_id IS NOT DISTINCT FROM :task "
                            "AND authorization_version=:auth_version AND authorization_sha256=:auth_sha "
                            "AND lease_owner=:replica AND lease_id=:lease_id "
                            "AND lease_generation=:generation AND revoked_at IS NULL "
                            "AND lease_until>clock_timestamp() "
                            "RETURNING cursor_sequence,lease_owner,lease_id,lease_generation,lease_until"
                        ),
                        {**_base(principal), **_lease_params(lease), "ttl": lease_seconds},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if new is None:
                raise SubscriptionDenied("Renewal lost lease fence")
            return self._projection(principal, lease.replica_id, dict(new))

    async def read_batch(
        self, principal: SubscriberPrincipal, lease: SubscriberLease, *, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Read committed events for the current owner; caller rechecks before SSE emit."""
        if type(limit) is not int or not 1 <= limit <= 100:
            raise SubscriptionDenied("Bounded subscriber batch required")
        async with self._transaction(principal) as db:
            active = await self._active(db, principal, lease)
            # A leased replica must not silently read a newer cursor after
            # another ACK committed. Otherwise the API would return events
            # from the NEW position while labelling them with its OLD cursor.
            # UNKNOWN HTTP ACKs use the separate read_committed_cursor route.
            if active["cursor_sequence"] != lease.cursor:
                raise SubscriptionDenied("Replica read cursor changed; use explicit readback")
            rows = (
                (
                    await db.execute(
                        text(
                            "SELECT sequence,id,engagement_id,task_id,kind,actor_id,payload,created_at "
                            "FROM supervision_events WHERE engagement_id=:engagement "
                            "AND sequence>:cursor AND (CAST(:task AS VARCHAR(64)) IS NULL "
                            "OR task_id=CAST(:task AS VARCHAR(64))) "
                            "ORDER BY sequence ASC LIMIT :limit"
                        ),
                        {
                            "engagement": principal.engagement_id,
                            "cursor": active["cursor_sequence"],
                            "task": principal.task_id,
                            "limit": limit,
                        },
                    )
                )
                .mappings()
                .all()
            )
            previous = active["cursor_sequence"]
            for row in rows:
                sequence = row.get("sequence")
                _validate_cursor(sequence)
                if (
                    sequence <= previous
                    or row.get("engagement_id") != principal.engagement_id
                    or (principal.task_id is not None and row.get("task_id") != principal.task_id)
                    or type(row.get("payload")) is not dict
                    or type(row.get("id")) is not str
                    or not 1 <= len(row["id"]) <= 64
                    or type(row.get("kind")) is not str
                    or not 1 <= len(row["kind"]) <= 64
                    or type(row.get("actor_id")) is not str
                    or not 1 <= len(row["actor_id"]) <= 64
                ):
                    raise SubscriptionDenied("Untrusted supervision event tenant/sequence")
                try:
                    encoded = json.dumps(
                        dict(row),
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=False,
                        default=lambda value: (
                            value.isoformat()
                            if isinstance(value, datetime)
                            else (_ for _ in ()).throw(TypeError("Unsupported event timestamp"))
                        ),
                    ).encode("utf-8")
                except (ValueError, TypeError, OverflowError) as exc:
                    raise SubscriptionDenied("Invalid committed event envelope") from exc
                if len(encoded) > 8192:
                    raise SubscriptionDenied("Oversized committed supervision event")
                previous = sequence
            # The API still must recheck live identity and this lease before
            # publishing each SSE row; a batch is only a bounded DB snapshot.
            latest = await self._active(db, principal, lease)
            if latest["cursor_sequence"] != lease.cursor:
                raise SubscriptionDenied("Replica read cursor changed before publication")
            return [dict(row) for row in rows]

    async def acknowledge(
        self,
        principal: SubscriberPrincipal,
        lease: SubscriberLease,
        *,
        expected_cursor: int,
        next_sequence: int,
        precommit_disconnect: Optional[PrecommitDisconnectGuard] = None,
    ) -> SubscriberLease:
        """CAS ACK one next committed matching event; no skipped event or stale owner."""
        _validate_cursor(expected_cursor)
        _validate_cursor(next_sequence)
        if next_sequence <= expected_cursor:
            raise SubscriptionDenied("Cursor ACK must advance to next committed event")
        async with self._transaction(principal, precommit_disconnect=precommit_disconnect) as db:
            active = await self._active(db, principal, lease)
            if active["cursor_sequence"] != expected_cursor or lease.cursor != expected_cursor:
                raise SubscriptionDenied("Stale subscriber cursor")
            # Same advisory lock held by supervision_store._append_event: no
            # earlier uncommitted event can become visible after ACK commits.
            await db.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:engagement, 8044))"),
                {"engagement": principal.engagement_id},
            )
            successor = (
                await db.execute(
                    text(
                        "SELECT sequence FROM supervision_events "
                        "WHERE engagement_id=:engagement AND sequence>:cursor "
                        "AND (CAST(:task AS VARCHAR(64)) IS NULL "
                        "OR task_id=CAST(:task AS VARCHAR(64))) "
                        "ORDER BY sequence ASC LIMIT 1"
                    ),
                    {
                        "engagement": principal.engagement_id,
                        "cursor": expected_cursor,
                        "task": principal.task_id,
                    },
                )
            ).scalar_one_or_none()
            if successor != next_sequence:
                raise SubscriptionDenied("ACK skipped or forged committed supervision event")
            new = (
                (
                    await db.execute(
                        text(
                            "UPDATE supervision_durable_subscriptions SET "
                            "cursor_sequence=:next,updated_at=clock_timestamp() "
                            "WHERE engagement_id=:engagement AND subscriber_id=:subscriber "
                            "AND principal_issuer=:issuer AND principal_subject=:subject "
                            "AND task_id IS NOT DISTINCT FROM :task "
                            "AND authorization_version=:auth_version AND authorization_sha256=:auth_sha "
                            "AND lease_owner=:replica AND lease_id=:lease_id "
                            "AND lease_generation=:generation AND revoked_at IS NULL "
                            "AND lease_until>clock_timestamp() AND cursor_sequence=:cursor "
                            "RETURNING cursor_sequence,lease_owner,lease_id,lease_generation,lease_until"
                        ),
                        {
                            **_base(principal),
                            **_lease_params(lease),
                            "cursor": expected_cursor,
                            "next": next_sequence,
                        },
                    )
                )
                .mappings()
                .one_or_none()
            )
            if new is None:
                raise SubscriptionDenied("Concurrent cursor/lease ACK was rejected")
            return self._projection(principal, lease.replica_id, dict(new))

    async def release(self, principal: SubscriberPrincipal, lease: SubscriberLease) -> None:
        """Give up lease without deleting the durable cursor; fence old owner."""
        async with self._transaction(principal) as db:
            await self._active(db, principal, lease)
            updated = (
                await db.execute(
                    text(
                        "UPDATE supervision_durable_subscriptions SET "
                        "lease_owner=NULL,lease_id=NULL,lease_until=NULL,"
                        "lease_generation=lease_generation+1,updated_at=clock_timestamp() "
                        "WHERE engagement_id=:engagement AND subscriber_id=:subscriber "
                        "AND principal_issuer=:issuer AND principal_subject=:subject "
                        "AND task_id IS NOT DISTINCT FROM :task "
                        "AND authorization_version=:auth_version AND authorization_sha256=:auth_sha "
                        "AND lease_owner=:replica AND lease_id=:lease_id "
                        "AND lease_generation=:generation AND revoked_at IS NULL "
                        "AND lease_until>clock_timestamp() RETURNING lease_generation"
                    ),
                    {**_base(principal), **_lease_params(lease)},
                )
            ).scalar_one_or_none()
            if type(updated) is not int or updated <= lease.generation:
                raise SubscriptionDenied("Release lost current lease fence")

    async def revoke(self, principal: SubscriberPrincipal) -> None:
        """Permanent tombstone for this identity; a stale replica cannot resume."""
        async with self._transaction(principal) as db:
            await self._locked(db, principal)
            updated = (
                await db.execute(
                    text(
                        "UPDATE supervision_durable_subscriptions SET "
                        "revoked_at=clock_timestamp(),lease_owner=NULL,lease_id=NULL,"
                        "lease_until=NULL,lease_generation=lease_generation+1,"
                        "updated_at=clock_timestamp() "
                        "WHERE engagement_id=:engagement AND subscriber_id=:subscriber "
                        "AND principal_issuer=:issuer AND principal_subject=:subject "
                        "AND task_id IS NOT DISTINCT FROM :task "
                        "AND authorization_version=:auth_version AND authorization_sha256=:auth_sha "
                        "AND revoked_at IS NULL RETURNING lease_generation"
                    ),
                    _base(principal),
                )
            ).scalar_one_or_none()
            if type(updated) is not int or updated < 1:
                raise SubscriptionDenied("Subscriber revocation not durable")
