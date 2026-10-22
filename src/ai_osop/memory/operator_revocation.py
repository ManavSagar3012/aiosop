"""Cross-process operator bearer revocation, backed by authoritative PostgreSQL.

No token, JWT payload, signing key or IdP credential is stored. The database
is read on every signed-bearer admission when explicit enforcement is enabled.
This protects against a Redis outage and avoids stale per-worker allow caches.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime
from typing import Any, Dict

from sqlalchemy import Boolean, Column, DateTime, String, select

from ai_osop.memory.session_memory import Base

_ACTOR = re.compile(r"[A-Za-z0-9_.:@-]{1,64}\Z")


class OperatorTokenRevocationORM(Base):
    __tablename__ = "operator_token_revocations"
    digest = Column(String(64), primary_key=True)
    actor_id = Column(String(64), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=False)


class OperatorSubjectControlORM(Base):
    __tablename__ = "operator_subject_controls"
    actor_id = Column(String(64), primary_key=True)
    disabled = Column(Boolean, nullable=False, default=False)
    updated_at = Column(DateTime, nullable=False)
    updated_by = Column(String(64), nullable=False)


class OperatorAuthEventORM(Base):
    __tablename__ = "operator_auth_events"
    id = Column(String(64), primary_key=True)
    actor_id = Column(String(64), nullable=False)
    subject_id = Column(String(64), nullable=False)
    kind = Column(String(32), nullable=False)
    reason = Column(String(500), nullable=False)
    created_at = Column(DateTime, nullable=False)


class OperatorRevocationUnavailable(RuntimeError):
    """Durable token status could not be determined."""


class OperatorRevoked(PermissionError):
    """Token or subject is explicitly revoked."""


class OperatorRevocationLedger:
    def __init__(self, memory: Any) -> None:
        self.memory = memory

    @staticmethod
    def _digest(token: str) -> str:
        if not isinstance(token, str) or not 0 < len(token) <= 16384:
            raise ValueError("Invalid bearer token")
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _actor(principal: Dict[str, Any]) -> str:
        actor = principal.get("sub")
        if not isinstance(actor, str) or _ACTOR.fullmatch(actor) is None:
            raise ValueError("Invalid actor")
        return actor

    def _sessions(self) -> Any:
        factory = getattr(self.memory, "_async_session", None)
        if not callable(factory):
            raise OperatorRevocationUnavailable("Durable revocation ledger unavailable")
        return factory

    async def assert_active(self, token: str, principal: Dict[str, Any]) -> None:
        actor = self._actor(principal)
        digest = self._digest(token)
        try:
            async with self._sessions()() as db:
                revoked = (await db.execute(
                    select(OperatorTokenRevocationORM.digest).where(
                        OperatorTokenRevocationORM.digest == digest,
                    )
                )).scalar_one_or_none()
                disabled = (await db.execute(
                    select(OperatorSubjectControlORM.disabled).where(
                        OperatorSubjectControlORM.actor_id == actor,
                    )
                )).scalar_one_or_none()
        except OperatorRevocationUnavailable:
            raise
        except Exception as exc:
            raise OperatorRevocationUnavailable("Durable revocation check unavailable") from exc
        if revoked is not None or disabled is True:
            raise OperatorRevoked("Operator credential revoked")

    async def revoke_token(self, token: str, principal: Dict[str, Any]) -> bool:
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        actor = self._actor(principal)
        claims = principal.get("claims")
        expires = claims.get("exp") if isinstance(claims, dict) else None
        from datetime import timezone
        if type(expires) is not int or expires <= int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("Signed, unexpired token required")
        digest = self._digest(token)
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    result = await db.execute(
                        pg_insert(OperatorTokenRevocationORM).values(
                            digest=digest,
                            actor_id=actor,
                            expires_at=datetime.utcfromtimestamp(expires),
                            revoked_at=datetime.utcnow(),
                        ).on_conflict_do_nothing(
                            index_elements=[OperatorTokenRevocationORM.digest],
                        ).returning(OperatorTokenRevocationORM.digest)
                    )
                    inserted = result.scalar_one_or_none() is not None
                    if inserted:
                        db.add(OperatorAuthEventORM(
                            id="authevt-" + uuid.uuid4().hex,
                            actor_id=actor, subject_id=actor,
                            kind="credential_revoked", reason="self_logout",
                            created_at=datetime.utcnow(),
                        ))
        except Exception as exc:
            raise OperatorRevocationUnavailable("Credential revocation could not be committed") from exc
        return inserted

    async def disable_subject(
        self, subject: str, *, actor_id: str, disabled: bool, reason: str,
    ) -> None:
        """Emergency account block persists until explicit senior reenable.

        Applies to already-issued JWTs across all workers; unlike a JWT iat
        cutoff, even older local tokens without an iat are invalidated.
        """
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        if not isinstance(subject, str) or _ACTOR.fullmatch(subject) is None:
            raise ValueError("Invalid operator subject")
        if not isinstance(actor_id, str) or _ACTOR.fullmatch(actor_id) is None:
            raise ValueError("Invalid supervisor")
        if type(disabled) is not bool:
            raise ValueError("Invalid block state")
        if not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 500:
            raise ValueError("Meaningful operator status reason required")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    await db.execute(
                        pg_insert(OperatorSubjectControlORM).values(
                            actor_id=subject, disabled=disabled,
                            updated_by=actor_id, updated_at=datetime.utcnow(),
                        ).on_conflict_do_update(
                            index_elements=[OperatorSubjectControlORM.actor_id],
                            set_={
                                "disabled": disabled, "updated_by": actor_id,
                                "updated_at": datetime.utcnow(),
                            },
                        )
                    )
                    db.add(OperatorAuthEventORM(
                        id="authevt-" + uuid.uuid4().hex,
                        actor_id=actor_id, subject_id=subject,
                        kind="subject_disabled" if disabled else "subject_enabled",
                        reason=reason.strip(), created_at=datetime.utcnow(),
                    ))
        except Exception as exc:
            raise OperatorRevocationUnavailable("Operator status could not be committed") from exc
