"""
SessionStore — durable + cached user-session storage for bug-bounty engagements.

Architecture (per Phase 1 spec):
    Postgres ─── durable source of truth (UserSessionORM table)
                 - cookies (list of dicts)
                 - bearer_token (str)
                 - local_storage (dict)
                 - session_storage (dict)
                 - csrf_token (str)
                 - extra_headers (dict)
                 - captured_at, expires_at

    Redis ─── hot cache keyed by f"usersession:{engagement_id}:{user_label}"
              TTL = derived from expires_at (or default 3600s)

Key API:
    await store.save_session(engagement_id, user_label, session_dict)
    sess = await store.get_session(engagement_id, user_label)
    await store.delete_session(engagement_id, user_label)
    async with store.as_user(engagement_id, "user_a") as client:
        await client.get("https://api.target.com/me")

The `as_user(...)` context manager returns a SessionClient (defined in
session_client.py) that automatically injects cookies + Authorization header +
CSRF token. No agent should ever read raw credentials and inject them by hand.
"""

from __future__ import annotations

import base64
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy import JSON, Column, DateTime, String, Text
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_osop.core.config import settings
from ai_osop.memory.session_memory import Base, SessionMemory

if TYPE_CHECKING:  # avoid circular import at runtime
    from ai_osop.memory.graph_memory import GraphMemory


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Session Encryption (Fernet)
# ─────────────────────────────────────────────────────────────────────────────


class SessionEncryption:
    """Encrypt/decrypt sensitive session fields at rest using Fernet.

    Falls back to no-op if OSOP_SESSION_ENCRYPTION_KEY is not configured,
    so development environments continue to work without a key.
    """

    _warned_missing_key = False

    SENSITIVE_FIELDS = {
        "cookies",
        "bearer_token",
        "local_storage",
        "session_storage",
        "csrf_token",
        "extra_headers",
    }

    def __init__(self, key: Optional[str] = None):

        self._fernet = None
        raw = key or settings.session_encryption_key
        if raw:
            try:
                # Derive a 32-byte URL-safe base64 key from the provided string
                import hashlib

                from cryptography.fernet import Fernet

                key_bytes = hashlib.sha256(raw.encode("utf-8")).digest()
                b64_key = base64.urlsafe_b64encode(key_bytes)
                self._fernet = Fernet(b64_key)
            except Exception as exc:
                logger.warning("session_encryption_init_failed", error=str(exc))
        else:
            # P1: fail hard in production when session encryption key is missing
            if settings.environment != "development":
                raise RuntimeError(
                    "OSOP_SESSION_ENCRYPTION_KEY is required in production. "
                    "Set it in your environment or .env file."
                )
            if not SessionEncryption._warned_missing_key:
                logger.warning("session_encryption_key_missing: plaintext storage in dev mode")
                SessionEncryption._warned_missing_key = True

    def encrypt(self, plaintext: str) -> str:
        if self._fernet is None:
            return plaintext
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        if self._fernet is None:
            return ciphertext
        try:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            logger.warning("session_decryption_failed", error=str(exc))
            return ciphertext

    def encrypt_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        if self._fernet is None:
            return d
        return {
            k: self.encrypt(json.dumps(v)) if k in self.SENSITIVE_FIELDS else v
            for k, v in d.items()
        }

    def decrypt_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        if self._fernet is None:
            return d
        result = {}
        for k, v in d.items():
            if k in self.SENSITIVE_FIELDS and isinstance(v, str):
                try:
                    decrypted = self.decrypt(v)
                    result[k] = json.loads(decrypted)
                except (json.JSONDecodeError, TypeError):
                    result[k] = v  # fallback to raw value if not encrypted
            else:
                result[k] = v
        return result


# ─────────────────────────────────────────────────────────────────────────────
#  ORM
# ─────────────────────────────────────────────────────────────────────────────


class UserSessionORM(Base):
    """Durable storage for captured user sessions per engagement."""

    __tablename__ = "user_sessions"

    # composite key (engagement_id, user_label) — represented as joined str pk
    pk = Column(String(160), primary_key=True)  # f"{engagement_id}:{user_label}"
    engagement_id = Column(String(80), index=True, nullable=False)
    user_label = Column(String(64), nullable=False)
    cookies = Column(JSON, default=list)  # list of {name, value, domain, path, ...}
    bearer_token = Column(Text, default="")
    local_storage = Column(JSON, default=dict)
    session_storage = Column(JSON, default=dict)
    csrf_token = Column(String(512), default="")
    extra_headers = Column(JSON, default=dict)  # arbitrary headers to inject
    user_agent = Column(String(512), default="")
    # `timezone=True` so asyncpg accepts tz-aware datetimes (we always pass UTC).
    captured_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # None = no known expiry
    metadata_blob = Column(JSON, default=dict)  # free-form (capture method, source URL, …)


# ─────────────────────────────────────────────────────────────────────────────
#  Errors + DTO
# ─────────────────────────────────────────────────────────────────────────────


class UserSessionNotFound(Exception):
    """Raised when get_session has no matching record."""


@dataclass
class UserSession:
    """In-memory DTO for a captured session.

    Used by agents and the SessionClient. Serializes to/from JSON for Redis
    and to/from ORM for Postgres.

    ``refresh_token`` is an opaque credential that the ``token_refresh_callback``
    (see :class:`SessionClient`) can exchange for a new ``bearer_token`` when the
    original token expires mid-scan. Populated by the caller at capture time;
    consumed by the callback registered in ``SessionStore.as_user``.
    """

    engagement_id: str
    user_label: str
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    bearer_token: str = ""
    refresh_token: str = ""  # opaque IdP refresh token for credential rotation
    local_storage: Dict[str, Any] = field(default_factory=dict)
    session_storage: Dict[str, Any] = field(default_factory=dict)
    csrf_token: str = ""
    extra_headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    metadata_blob: Dict[str, Any] = field(default_factory=dict)

    # -- serialization helpers -------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # datetime → ISO so JSON can round-trip
        d["captured_at"] = self.captured_at.isoformat() if self.captured_at else None
        d["expires_at"] = self.expires_at.isoformat() if self.expires_at else None
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "UserSession":
        captured = d.get("captured_at")
        expires = d.get("expires_at")
        return cls(
            engagement_id=d["engagement_id"],
            user_label=d["user_label"],
            cookies=d.get("cookies") or [],
            bearer_token=d.get("bearer_token") or "",
            refresh_token=d.get("refresh_token") or "",
            local_storage=d.get("local_storage") or {},
            session_storage=d.get("session_storage") or {},
            csrf_token=d.get("csrf_token") or "",
            extra_headers=d.get("extra_headers") or {},
            user_agent=d.get("user_agent") or "",
            captured_at=(
                datetime.fromisoformat(captured)
                if isinstance(captured, str)
                else (captured or datetime.now(timezone.utc))
            ),
            expires_at=(datetime.fromisoformat(expires) if isinstance(expires, str) else expires),
            metadata_blob=d.get("metadata_blob") or {},
        )

    # -- Playwright storage_state interop --------------------------------------
    #
    # Playwright's BrowserContext.add_cookies / new_context(storage_state=...)
    # uses this exact shape:
    #   {"cookies": [...], "origins": [{"origin": "...", "localStorage": [...]}]}

    def to_playwright_storage_state(self) -> Dict[str, Any]:
        """Convert to Playwright's `storage_state` format for context import."""
        origins: List[Dict[str, Any]] = []
        if self.local_storage:
            # Playwright wants per-origin breakdown; if caller only gave us a flat
            # dict, place it under a synthetic origin so import still works.
            raw_origin = self.metadata_blob.get("origin") or "https://localhost"
            # Playwright applies localStorage PER ORIGIN, matched on the bare
            # scheme://host[:port]. A full URL with a path/fragment (e.g. the SPA's
            # post-login "http://localhost:3000/#/search") never matches the page
            # origin, so the JWT is silently NOT seeded and the replayed context
            # stays anonymous — the real cause of "storage_state doesn't apply
            # localStorage" and why authenticated IDOR replay only ever saw public
            # data. Normalise to the bare origin. (AIOSOP-STORAGE-ORIGIN-001)
            _p = urlparse(raw_origin)
            origin = f"{_p.scheme}://{_p.netloc}" if _p.scheme and _p.netloc else raw_origin
            origins.append(
                {
                    "origin": origin,
                    "localStorage": [
                        {"name": k, "value": str(v)} for k, v in self.local_storage.items()
                    ],
                }
            )
        return {"cookies": self.cookies, "origins": origins}

    def is_expired(self, *, now: Optional[datetime] = None, skew_seconds: int = 30) -> bool:
        """True if expires_at is in the past (allowing for clock skew)."""
        if self.expires_at is None:
            return False
        now = now or datetime.now(timezone.utc)
        # tolerate tz-naive expires_at (treat as UTC)
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp <= now - timedelta(seconds=skew_seconds)

    def ttl_seconds(self, *, default: int = 3600, max_ttl: int = 86400) -> int:
        """Seconds until expiry, clamped. Used for Redis SETEX."""
        if self.expires_at is None:
            return default
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = (exp - datetime.now(timezone.utc)).total_seconds()
        if delta <= 0:
            return 1  # let Redis evict on next pass
        return min(int(delta), max_ttl)


# ─────────────────────────────────────────────────────────────────────────────
#  Store
# ─────────────────────────────────────────────────────────────────────────────


class SessionStore:
    """Durable (Postgres) + hot-cache (Redis) user-session store.

    Constructor takes a connected SessionMemory instance — we piggyback on its
    SQLAlchemy engine + Redis client so we don't double-connect.
    """

    REDIS_PREFIX = "usersession"

    def __init__(
        self,
        session_memory: SessionMemory,
        graph_memory: Optional[GraphMemory] = None,
    ):
        self.sm = session_memory
        self.gm = graph_memory
        self._encryption = SessionEncryption()

    # -- key helpers -----------------------------------------------------------

    @staticmethod
    def _pk(engagement_id: str, user_label: str) -> str:
        return f"{engagement_id}:{user_label}"

    def _redis_key(self, engagement_id: str, user_label: str) -> str:
        return f"{self.REDIS_PREFIX}:{engagement_id}:{user_label}"

    # -- public API ------------------------------------------------------------

    async def save_session(
        self,
        engagement_id: str,
        user_label: str,
        *,
        cookies: Optional[List[Dict[str, Any]]] = None,
        bearer_token: str = "",
        local_storage: Optional[Dict[str, Any]] = None,
        session_storage: Optional[Dict[str, Any]] = None,
        csrf_token: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        user_agent: str = "",
        expires_at: Optional[datetime] = None,
        metadata_blob: Optional[Dict[str, Any]] = None,
    ) -> UserSession:
        """Persist a captured session. Returns the stored DTO."""
        sess = UserSession(
            engagement_id=engagement_id,
            user_label=user_label,
            cookies=cookies or [],
            bearer_token=bearer_token,
            local_storage=local_storage or {},
            session_storage=session_storage or {},
            csrf_token=csrf_token,
            extra_headers=extra_headers or {},
            user_agent=user_agent,
            captured_at=datetime.now(timezone.utc),
            expires_at=expires_at or self._infer_expiry(bearer_token, cookies or []),
            metadata_blob=metadata_blob or {},
        )

        # 1. durable write — UPSERT (encrypt sensitive fields at rest)
        enc = self._encryption
        async with self.sm._async_session() as db:
            stmt = pg_insert(UserSessionORM).values(
                pk=self._pk(engagement_id, user_label),
                engagement_id=engagement_id,
                user_label=user_label,
                cookies=self._encrypt_field(enc, sess.cookies),
                bearer_token=self._encrypt_field(enc, sess.bearer_token),
                local_storage=self._encrypt_field(enc, sess.local_storage),
                session_storage=self._encrypt_field(enc, sess.session_storage),
                csrf_token=self._encrypt_field(enc, sess.csrf_token),
                extra_headers=self._encrypt_field(enc, sess.extra_headers),
                user_agent=sess.user_agent,
                captured_at=sess.captured_at,
                expires_at=sess.expires_at,
                metadata_blob=sess.metadata_blob,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[UserSessionORM.pk],
                set_={
                    "cookies": self._encrypt_field(enc, sess.cookies),
                    "bearer_token": self._encrypt_field(enc, sess.bearer_token),
                    "local_storage": self._encrypt_field(enc, sess.local_storage),
                    "session_storage": self._encrypt_field(enc, sess.session_storage),
                    "csrf_token": self._encrypt_field(enc, sess.csrf_token),
                    "extra_headers": self._encrypt_field(enc, sess.extra_headers),
                    "user_agent": sess.user_agent,
                    "captured_at": sess.captured_at,
                    "expires_at": sess.expires_at,
                    "metadata_blob": sess.metadata_blob,
                },
            )
            await db.execute(stmt)
            await db.commit()

        # 2. hot cache
        await self._cache_set(sess)

        if self.gm:
            try:
                await self.gm.sync_user_session(sess)
            except Exception as e:
                logger.error("Failed to sync session to GraphMemory: %s", e)

        logger.info(
            "session.saved engagement=%s user=%s cookies=%d has_bearer=%s expires_at=%s",
            engagement_id,
            user_label,
            len(sess.cookies),
            bool(sess.bearer_token),
            sess.expires_at,
        )
        return sess

    async def get_session(self, engagement_id: str, user_label: str) -> UserSession:
        """Retrieve session. Tries Redis first, falls back to Postgres."""
        cached = await self._cache_get(engagement_id, user_label)
        if cached is not None:
            return cached

        async with self.sm._async_session() as db:
            row = (
                await db.execute(
                    select(UserSessionORM).where(
                        UserSessionORM.pk == self._pk(engagement_id, user_label)
                    )
                )
            ).scalar_one_or_none()

        if row is None:
            raise UserSessionNotFound(
                f"no session for engagement={engagement_id} user={user_label}"
            )

        sess = self._orm_to_dto(row, self._encryption)
        # warm the cache for next caller
        await self._cache_set(sess)
        return sess

    async def get_session_or_none(
        self, engagement_id: str, user_label: str
    ) -> Optional[UserSession]:
        try:
            return await self.get_session(engagement_id, user_label)
        except UserSessionNotFound:
            return None

    async def list_sessions(self, engagement_id: str) -> List[UserSession]:
        async with self.sm._async_session() as db:
            rows = (
                (
                    await db.execute(
                        select(UserSessionORM).where(UserSessionORM.engagement_id == engagement_id)
                    )
                )
                .scalars()
                .all()
            )
        return [self._orm_to_dto(r, self._encryption) for r in rows]

    async def delete_session(self, engagement_id: str, user_label: str) -> bool:
        async with self.sm._async_session() as db:
            result = await db.execute(
                sa_delete(UserSessionORM).where(
                    UserSessionORM.pk == self._pk(engagement_id, user_label)
                )
            )
            await db.commit()
        await self.sm._redis.delete(self._redis_key(engagement_id, user_label))
        if self.gm:
            try:
                await self.gm.delete_user_session_node(engagement_id, user_label)
            except Exception as e:
                logger.error("Failed to delete session in GraphMemory: %s", e)
        return result.rowcount > 0

    # -- as_user context manager ----------------------------------------------

    @asynccontextmanager
    async def as_user(
        self, engagement_id: str, user_label: str, *, base_url: str = "",
        governance_hook: Any = None,
    ):
        """Yield a SessionClient pre-configured with the user's credentials.

        Usage:
            async with store.as_user(eng, "user_a") as client:
                r = await client.get("https://api.target.com/me")

        Auto-persists any new cookies the response Set-Cookie-d back to us.
        If the captured session includes a ``refresh_token``, the client will
        automatically attempt a credential refresh on 401/403 responses.

        ``governance_hook`` (M1), when supplied, is attached to the yielded
        client so every authenticated request is scope-checked, rate-limited,
        and research-tagged.
        """
        from ai_osop.auth.session_client import SessionClient  # lazy to break cycle

        sess = await self.get_session(engagement_id, user_label)

        # Build a token refresh callback that exchanges the refresh_token
        # for a new bearer_token. Agents can override this by setting an
        # explicit refresh_callback on the session metadata.
        async def _default_refresh(session_dict: Dict[str, Any]) -> Dict[str, Any]:
            """Default token refresh: re-fetch from store and return fresh creds.

            In the common case the session is still valid and we just need to
            re-apply it. Operators with a custom IdP can hook a real refresh
            endpoint here via session.extra_headers['refresh_callback'].
            """
            try:
                refreshed = await self.get_session(engagement_id, user_label)
                return {
                    "bearer_token": refreshed.bearer_token,
                    "cookies": refreshed.cookies,
                }
            except Exception:
                return {"bearer_token": sess.bearer_token, "cookies": sess.cookies}

        # Allow operators to provide a custom refresh implementation via metadata
        custom_refresh = getattr(sess, "metadata_blob", {}).get("refresh_callback")
        callback = custom_refresh if callable(custom_refresh) else _default_refresh

        client = SessionClient(
            session=sess,
            base_url=base_url,
            store=self,
            token_refresh_callback=callback if sess.refresh_token else None,
            governance_hook=governance_hook,
        )
        try:
            yield client
        finally:
            if client.cookies_dirty:
                await self.save_session(
                    engagement_id,
                    user_label,
                    cookies=sess.cookies,
                    bearer_token=sess.bearer_token,
                    local_storage=sess.local_storage,
                    session_storage=sess.session_storage,
                    csrf_token=sess.csrf_token,
                    extra_headers=sess.extra_headers,
                    user_agent=sess.user_agent,
                    expires_at=sess.expires_at,
                    metadata_blob=sess.metadata_blob,
                )
            await client.aclose()

    # -- internals -------------------------------------------------------------

    async def _cache_set(self, sess: UserSession) -> None:
        key = self._redis_key(sess.engagement_id, sess.user_label)
        d = sess.to_dict()
        # Encrypt sensitive fields before writing to Redis
        enc = self._encryption
        for field in SessionEncryption.SENSITIVE_FIELDS:
            if field in d:
                d[field] = self._encrypt_field(enc, d[field])
        payload = json.dumps(d, default=str)
        await self.sm._redis.setex(key, sess.ttl_seconds(), payload)

    async def _cache_get(self, engagement_id: str, user_label: str) -> Optional[UserSession]:
        raw = await self.sm._redis.get(self._redis_key(engagement_id, user_label))
        if raw is None:
            return None
        try:
            d = json.loads(raw)
            # Decrypt sensitive fields after reading from Redis
            enc = self._encryption
            for field in SessionEncryption.SENSITIVE_FIELDS:
                if field in d:
                    d[field] = self._decrypt_field(enc, d[field])
            return UserSession.from_dict(d)
        except Exception as e:
            logger.warning(
                "session.cache_parse_fail key=%s err=%s",
                self._redis_key(engagement_id, user_label),
                e,
            )
            return None

    @staticmethod
    def _encrypt_field(encryption: SessionEncryption, value: Any) -> Any:
        if encryption._fernet is None:
            return value
        return encryption.encrypt(json.dumps(value))

    @staticmethod
    def _decrypt_field(encryption: SessionEncryption, value: Any) -> Any:
        if not isinstance(value, str) or not value.startswith("gAAAAA"):
            return value
        decrypted = encryption.decrypt(value)
        try:
            return json.loads(decrypted)
        except (json.JSONDecodeError, TypeError):
            return decrypted

    @staticmethod
    def _orm_to_dto(row: UserSessionORM, encryption: SessionEncryption) -> UserSession:
        return UserSession(
            engagement_id=row.engagement_id,
            user_label=row.user_label,
            cookies=SessionStore._decrypt_field(encryption, row.cookies) or [],
            bearer_token=SessionStore._decrypt_field(encryption, row.bearer_token) or "",
            local_storage=SessionStore._decrypt_field(encryption, row.local_storage) or {},
            session_storage=SessionStore._decrypt_field(encryption, row.session_storage) or {},
            csrf_token=SessionStore._decrypt_field(encryption, row.csrf_token) or "",
            extra_headers=SessionStore._decrypt_field(encryption, row.extra_headers) or {},
            user_agent=row.user_agent or "",
            captured_at=row.captured_at,
            expires_at=row.expires_at,
            metadata_blob=row.metadata_blob or {},
        )

    @staticmethod
    def _infer_expiry(bearer_token: str, cookies: List[Dict[str, Any]]) -> Optional[datetime]:
        """Derive an `expires_at` from JWT exp claim or cookie max expiry.

        Best-effort. Returns None if nothing inferable.
        """
        # JWT exp
        if bearer_token and bearer_token.count(".") == 2:
            try:
                payload_b64 = bearer_token.split(".")[1]
                # base64 padding fix
                padded = payload_b64 + "=" * (-len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(padded))
                exp = payload.get("exp")
                if isinstance(exp, (int, float)) and exp > 0:
                    return datetime.fromtimestamp(exp, tz=timezone.utc)
            except Exception:
                pass

        # cookie expires (Playwright format uses 'expires' as unix epoch float; -1 = session cookie)
        best_exp: Optional[float] = None
        for c in cookies:
            e = c.get("expires") or c.get("expiry")
            if isinstance(e, (int, float)) and e > 0:
                if best_exp is None or e > best_exp:
                    best_exp = e
        if best_exp is not None:
            return datetime.fromtimestamp(best_exp, tz=timezone.utc)

        return None
