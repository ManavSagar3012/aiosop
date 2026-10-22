"""Senior-authorized, owner-fenced DLQ disposition without execution replay.

This intentionally supports *discard only*. A historical failed task may
have produced an irreversible remote effect; requeuing it requires a separate
verified remote-outcome reconciliation and fresh, signed human approval.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from sqlalchemy import select

from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.session_memory import DLQEntryORM, SessionStateORM
from ai_osop.memory.supervision_store import SupervisionStore

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}\Z")


class DLQResolutionDenied(RuntimeError):
    """No independently authorized, current durable disposition is possible."""


class DLQResolutionStore:
    """Real PostgreSQL signed owner/entry lock and audit in one transaction."""

    def __init__(self, memory: Any):
        self._memory = memory

    async def discard(self, engagement_id: str, entry_id: str, actor_id: str, reason: str) -> str:
        if (
            not isinstance(engagement_id, str)
            or not _ID.fullmatch(engagement_id)
            or not isinstance(entry_id, str)
            or not entry_id.startswith("dlq-")
            or not _ID.fullmatch(entry_id)
            or not isinstance(actor_id, str)
            # Verified OIDC subjects may contain a provider delimiter, e.g.
            # auth0|abc. Do not reinterpret or rewrite the verified subject:
            # compare its complete original bytes to session.created_by.
            or not 1 <= len(actor_id) <= 64
            or not actor_id.isascii()
            or any(ord(char) < 33 or ord(char) > 126 for char in actor_id)
            or not isinstance(reason, str)
            or not 10 <= len(reason.strip()) <= 500
            or any(ord(char) < 32 and char not in "\n\t" for char in reason)
        ):
            raise DLQResolutionDenied("Signed DLQ disposition fields invalid")
        sessions = getattr(self._memory, "_async_session", None)
        if not callable(sessions):
            raise DLQResolutionDenied("Authoritative DLQ database unavailable")
        async with sessions() as db:
            async with db.begin():
                # The same owner lock is taken by signed engagement policy
                # revocation. No stale authorization from Redis or from the
                # preceding HTTP read may permit a post-revocation discard.
                owner = (
                    await db.execute(
                        select(SessionStateORM.created_by)
                        .where(SessionStateORM.session_id == engagement_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if owner != actor_id:
                    raise DLQResolutionDenied("Current engagement owner required")
                await guard_sql(db, engagement_id)
                entry = (
                    await db.execute(
                        select(DLQEntryORM)
                        .where(
                            DLQEntryORM.id == entry_id,
                            DLQEntryORM.engagement_id == engagement_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if entry is None:
                    return "not_found"
                if entry.status != "pending_review":
                    return "conflict"
                entry.status = "discarded"
                entry.resolved_at = datetime.utcnow()
                entry.operator_notes = reason.strip()
                await SupervisionStore._append_event(
                    db,
                    engagement_id,
                    entry.task_id,
                    "dlq.discarded",
                    actor_id,
                    {"entry_id": entry_id, "status": "discarded"},
                    idempotency_key="dlq-discard:" + entry_id,
                )
        return "discarded"
