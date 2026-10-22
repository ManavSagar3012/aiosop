"""Authoritative PostgreSQL signed-ROE authorization ledger.

Use only after signed_roe.verify_signed_roe has returned VerifiedPolicy.
In particular, the unverified envelope/dict is NEVER accepted here.

The database session row is the serializing lock for create/register/revoke.
guard_sql holds a FOR SHARE lock through the caller's existing transaction,
so a scope update or revocation cannot race past an authorized dispatch.
Do not use this as a substitute for the gateway's operator authentication.
"""

from __future__ import annotations

import hashlib
import base64
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Union

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_osop.core.models import SessionState

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}\Z")
_AUTHORIZATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SCOPE_KEYS = (
    "domains", "ips", "exclusions", "allowed_techniques", "restrictions",
    "approval_required_for", "testing_window_start", "testing_window_end",
)
_READ_SESSION = text(
    "SELECT session_id, scope, roe, created_by FROM session_states "
    "WHERE session_id = :sid FOR SHARE"
)
_LOCK_SESSION = text(
    "SELECT session_id, scope, roe, created_by FROM session_states "
    "WHERE session_id = :sid FOR UPDATE"
)
_LATEST = text(
    "SELECT authorization_id, session_id, version, kid, policy_sha256, "
    "canonical_policy, signature, status, verified_at, revoked_at "
    "FROM signed_authorizations WHERE session_id = :sid "
    "ORDER BY version DESC LIMIT 1 FOR SHARE"
)
_LATEST_LOCKED = text(
    "SELECT authorization_id, session_id, version, kid, policy_sha256, "
    "canonical_policy, signature, status, verified_at, revoked_at "
    "FROM signed_authorizations WHERE session_id = :sid "
    "ORDER BY version DESC LIMIT 1 FOR UPDATE"
)
# Emergency subject disable is a durable execution admission fence. API
# bearer checks alone do not protect headless Temporal and agent workers.
_ACTIVE_EXECUTION_OPERATOR = text(
    "SELECT disabled FROM operator_subject_controls "
    "WHERE actor_id = :actor FOR SHARE"
)


class AuthorizationDenied(RuntimeError):
    """Missing/stale/revoked or unverifiable signed authorization (fail closed)."""


@dataclass(frozen=True)
class VerifiedAuthorization:
    """Persisted *binding*, not a fresh cryptographic verification result."""

    session_id: str
    authorization_id: str
    version: int
    kid: str
    policy_sha256: str
    policy: Dict[str, Any]

    @property
    def digest(self) -> str:
        return self.policy_sha256


def _canonical_bytes(policy: Dict[str, Any]) -> bytes:
    serialized = json.dumps(
        policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    # The verifier's canonical byte stream is the signing authority; use the
    # same implementation when installed, not an independent approximation.
    try:
        from ai_osop.safety.signed_roe import canonical_json_bytes
    except ImportError as exc:
        raise AuthorizationDenied("Signed ROE verifier unavailable") from exc
    if not callable(canonical_json_bytes):
        raise AuthorizationDenied("Signed ROE canonicalization unavailable")
    try:
        authoritative = canonical_json_bytes(policy)
    except (TypeError, ValueError) as exc:
        raise AuthorizationDenied("Signed authorization canonicalization invalid") from exc
    if not isinstance(authoritative, bytes) or authoritative != serialized:
        # Avoid silently accepting a second serialization format.
        raise AuthorizationDenied("Signed authorization canonicalization mismatch")
    return authoritative


def _verify_persisted_signature(
    policy: Dict[str, Any], signature: Any, kid: Any,
) -> None:
    """Reverify with CURRENT trusted keys on every dispatch (incl key removal)."""
    if (
        not isinstance(kid, str) or not kid
        or not isinstance(signature, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{86}", signature)
    ):
        raise AuthorizationDenied("Signed authorization signature unavailable")
    try:
        trusted = json.loads(os.environ.get("OSOP_ROE_TRUSTED_KEYS_JSON", ""))
        if not isinstance(trusted, dict) or kid not in trusted:
            raise ValueError("Trusted key unavailable")
        key_encoded = trusted[kid]
        if not isinstance(key_encoded, str):
            raise ValueError("Invalid key entry")
        key_bytes = base64.b64decode(key_encoded, validate=True)
        if len(key_bytes) != 32:
            raise ValueError("Invalid Ed25519 public key")
        signature_bytes = base64.urlsafe_b64decode(signature + "==")
        if len(signature_bytes) != 64:
            raise ValueError("Invalid Ed25519 signature")
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(
            signature_bytes, _canonical_bytes(policy),
        )
    except (ValueError, TypeError, InvalidSignature, UnicodeError) as exc:
        raise AuthorizationDenied("Signed authorization signature not trusted") from exc


def _rfc3339(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
        if dt.tzinfo is None:
            if isinstance(value, datetime):
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                raise ValueError("Missing timezone")
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError) as exc:
        raise AuthorizationDenied("Invalid authoritative time boundary") from exc


def _policy_binding_matches(
    policy: Mapping[str, Any],
    session_id: str,
    scope: Any,
    roe: Any,
    owner: Any,
) -> bool:
    if not isinstance(policy, dict) or not isinstance(scope, dict):
        return False
    if not isinstance(roe, dict) or not isinstance(owner, str) or not owner:
        return False
    if scope.get("engagement_id") != session_id:
        return False
    if policy.get("engagement_id") != session_id or policy.get("created_by") != owner:
        return False
    if scope.get("authorization_ref") not in (None, policy.get("authorization_id")):
        return False
    for key in _SCOPE_KEYS:
        scope_value = scope.get(key)
        signed_value = policy.get(key)
        if key in ("testing_window_start", "testing_window_end"):
            try:
                if _rfc3339(scope_value) != _rfc3339(signed_value):
                    return False
            except AuthorizationDenied:
                return False
        elif scope_value != signed_value:
            return False
    return policy.get("roe") == roe


def _validated_policy_window(policy: Dict[str, Any]) -> None:
    """Every dispatch must re-evaluate current time, not registration time."""
    now = datetime.now(timezone.utc)
    for name in ("issued_at", "not_before", "expires_at", "testing_window_start", "testing_window_end"):
        timestamp = policy.get(name)
        if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
            raise AuthorizationDenied("Signed authorization time boundary unavailable")
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuthorizationDenied("Signed authorization time boundary invalid") from exc
        if parsed.tzinfo is None:
            raise AuthorizationDenied("Signed authorization missing timezone")
        if (
            name in {"issued_at", "not_before", "testing_window_start"}
            and now < parsed
        ) or (
            name in {"expires_at", "testing_window_end"} and now >= parsed
        ):
            raise AuthorizationDenied("Signed authorization outside valid time window")


async def guard_sql(
    db: AsyncSession,
    session_id: str,
    expected_version: Optional[int] = None,
    expected_digest: Optional[str] = None,
) -> VerifiedAuthorization:
    """Authoritative guard INSIDE a caller-owned transaction.

    The session row FOR SHARE prevents a concurrent version revocation or
    modification from committing while the caller holds this transaction.
    The guard must be called on the SAME AsyncSession as dispatch/claim.
    This method does not commit or release the transaction.
    """
    if not isinstance(session_id, str) or not _ID.fullmatch(session_id):
        raise AuthorizationDenied("Invalid engagement authorization binding")
    if expected_version is not None and (
        type(expected_version) is not int or expected_version <= 0
    ):
        raise AuthorizationDenied("Invalid expected authorization version")
    if expected_digest is not None and (
        not isinstance(expected_digest, str) or not _DIGEST.fullmatch(expected_digest)
    ):
        raise AuthorizationDenied("Invalid expected authorization digest")
    try:
        parent = (await db.execute(_READ_SESSION, {"sid": session_id})).mappings().one_or_none()
        if parent is None:
            raise AuthorizationDenied("Engagement authorization unavailable")
        from ai_osop.core.config import settings

        if settings.operator_revocation_required:
            # Every signed admission, including worker/scheduler/MCP paths,
            # now checks the signer-linked engagement owner. Migration 0014
            # must be present before enabling this across replicas. Missing
            # control ledger is a denial, never implicit 'active' status.
            owner = parent.get("created_by")
            if not isinstance(owner, str) or not _ID.fullmatch(owner):
                raise AuthorizationDenied("Signed execution operator identity unavailable")
            disabled = (
                await db.execute(_ACTIVE_EXECUTION_OPERATOR, {"actor": owner})
            ).scalar_one_or_none()
            if disabled is True:
                raise AuthorizationDenied("Signed execution owner is disabled")
        current = (await db.execute(_LATEST, {"sid": session_id})).mappings().one_or_none()
        if current is None or current["status"] != "active":
            raise AuthorizationDenied("No active verified signed authorization")
        policy = current["canonical_policy"]
        if not isinstance(policy, dict):
            raise AuthorizationDenied("Signed authorization policy unavailable")
        digest = current["policy_sha256"]
        if (
            not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
            or hashlib.sha256(_canonical_bytes(policy)).hexdigest() != digest
        ):
            raise AuthorizationDenied("Signed authorization policy integrity mismatch")
        if not _policy_binding_matches(
            policy, session_id, parent["scope"], parent["roe"], parent["created_by"]
        ):
            raise AuthorizationDenied("Signed authorization scope or owner mismatch")
        if policy.get("version") != current["version"] or (
            policy.get("authorization_id") != current["authorization_id"]
        ) or policy.get("key_id") != current["kid"]:
            raise AuthorizationDenied("Signed authorization version binding mismatch")
        _verify_persisted_signature(policy, current["signature"], current["kid"])
        # The canonical signer/verifier also checks the complete policy schema,
        # current trust-store, scope, ROE, ownership, time windows, and signature.
        from ai_osop.safety.signed_roe import verify_signed_roe, SignedROEError
        try:
            verified_now = verify_signed_roe(
                {
                    "version": current["version"],
                    "policy": policy,
                    "signature": current["signature"],
                },
                expected_engagement_id=session_id,
                expected_owner=parent["created_by"],
                expected_scope=parent["scope"],
                expected_roe=parent["roe"],
                now=datetime.now(timezone.utc),
            )
        except SignedROEError as exc:
            raise AuthorizationDenied("Signed authorization no longer verifies") from exc
        if verified_now.policy_digest != digest:
            raise AuthorizationDenied("Verified policy digest changed")
        _validated_policy_window(policy)
        if expected_version is not None and current["version"] != expected_version:
            raise AuthorizationDenied("Signed authorization version fence changed")
        if expected_digest is not None and digest != expected_digest:
            raise AuthorizationDenied("Signed authorization digest fence changed")
        return VerifiedAuthorization(
            session_id=session_id,
            authorization_id=current["authorization_id"],
            version=current["version"],
            kid=current["kid"],
            policy_sha256=digest,
            policy=policy.copy(),
        )
    except AuthorizationDenied:
        raise
    except Exception as exc:
        # Missing 0009 migration, broken database, revoked access, etc. all deny.
        raise AuthorizationDenied("Authoritative signed authorization unavailable") from exc


def _trusted_verified(verified: Any) -> tuple[Dict[str, Any], str, str]:
    """Accept ONLY worker-3's in-process VerifiedPolicy; reject raw dicts."""
    try:
        from ai_osop.safety.signed_roe import VerifiedPolicy
    except ImportError as exc:
        raise AuthorizationDenied("Signed ROE verification contract unavailable") from exc
    if not isinstance(verified, VerifiedPolicy):
        raise AuthorizationDenied("Signed ROE must be verified before registration")
    canonical = getattr(verified, "canonical_bytes", None)
    if not isinstance(canonical, bytes):
        raise AuthorizationDenied("Invalid verified policy")
    try:
        policy = json.loads(canonical)
    except (ValueError, UnicodeError) as exc:
        raise AuthorizationDenied("Invalid verified canonical policy") from exc
    if not isinstance(policy, dict) or _canonical_bytes(policy) != canonical:
        raise AuthorizationDenied("Invalid verified canonical policy")
    if (
        policy.get("engagement_id") != verified.engagement_id
        or policy.get("created_by") != verified.created_by
        or policy.get("authorization_id") != verified.authorization_id
        or policy.get("key_id") != verified.kid
        or policy.get("version") != verified.version
    ):
        raise AuthorizationDenied("Verified signed binding mismatch")
    return policy, getattr(verified, "signature", ""), verified.policy_digest


def _actor_id(actor: Union[str, Mapping[str, Any]], owner: Any) -> str:
    if isinstance(actor, str):
        name = actor
        elevated = False
    elif isinstance(actor, Mapping):
        name = actor.get("sub")
        elevated = actor.get("role") == "senior_operator"
    else:
        raise AuthorizationDenied("Authorized operator required")
    if not isinstance(name, str) or not name or len(name) > 64:
        raise AuthorizationDenied("Authorized operator required")
    if name != owner and not elevated:
        raise AuthorizationDenied("Engagement owner authorization required")
    return name


async def _event(
    db: AsyncSession,
    sid: str,
    version: int,
    digest: str,
    action: str,
    actor_id: str,
) -> None:
    """Atomically append a redacted supervision timeline event and deliverable."""
    event_id = f"evt-{uuid.uuid4().hex}"
    payload = {
        "authorization_version": version,
        "policy_sha256": digest,
        "status": action,
    }
    await db.execute(
        text(
            "INSERT INTO supervision_events "
            "(id, engagement_id, kind, actor_id, payload, idempotency_key) "
            "VALUES (:id, :sid, :kind, :actor, CAST(:payload AS jsonb), :idem)"
        ),
        {
            "id": event_id, "sid": sid, "kind": f"signed_roe_{action}",
            "actor": actor_id, "payload": json.dumps(payload),
            "idem": f"signed_roe_{action}:{version}",
        },
    )
    await db.execute(
        text(
            "INSERT INTO supervision_outbox (id, event_id, engagement_id, topic, payload) "
            "VALUES (:id, :event, :sid, :topic, CAST(:payload AS jsonb))"
        ),
        {
            "id": f"out-{uuid.uuid4().hex}", "event": event_id, "sid": sid,
            "topic": "authorization.changed", "payload": json.dumps(payload),
        },
    )


class AuthorizationStore:
    """Use SessionMemory._async_session; never access hot/Redis cached state."""

    def __init__(self, session_memory: Any):
        self.session_memory = session_memory

    def _factory(self) -> Any:
        factory = getattr(self.session_memory, "_async_session", None)
        if not callable(factory):
            raise AuthorizationDenied("Authoritative PostgreSQL session unavailable")
        return factory

    @staticmethod
    def _prepare(
        sid: str, verified: Any, actor: Union[str, Mapping[str, Any]],
        scope: Any, roe: Any, owner: Any,
    ) -> Dict[str, Any]:
        policy, signature, supplied_digest = _trusted_verified(verified)
        version, aid, kid = (
            policy.get("version"), policy.get("authorization_id"), policy.get("key_id")
        )
        if (
            type(version) is not int or version <= 0
            or not isinstance(aid, str) or not _AUTHORIZATION_ID.fullmatch(aid)
            or not isinstance(kid, str) or not kid or len(kid) > 128
            or not signature or len(signature) > 512
            or not _policy_binding_matches(policy, sid, scope, roe, owner)
        ):
            raise AuthorizationDenied("Signed authorization does not match engagement")
        # Worker-3's verifier has already checked the signature. The ledger
        # additionally binds and recomputes the canonical policy digest.
        digest = hashlib.sha256(_canonical_bytes(policy)).hexdigest()
        if supplied_digest and supplied_digest != digest:
            raise AuthorizationDenied("Signed authorization canonical digest mismatch")
        _validated_policy_window(policy)
        _verify_persisted_signature(policy, signature, kid)
        actor_id = _actor_id(actor, owner)
        return {
            "sid": sid, "authorization_id": aid, "version": version,
            "kid": kid, "digest": digest,
            "policy": json.dumps(policy, allow_nan=False, ensure_ascii=False),
            "signature": signature, "actor": actor_id,
        }

    @staticmethod
    async def _insert(db: AsyncSession, prepared: Dict[str, Any]) -> None:
        await db.execute(
            text(
                "INSERT INTO signed_authorizations "
                "(authorization_id, session_id, version, kid, policy_sha256, "
                "canonical_policy, signature, status, actor_id, verified_at) "
                "VALUES (:authorization_id, :sid, :version, :kid, :digest, "
                "CAST(:policy AS jsonb), :signature, 'active', :actor, now())"
            ),
            prepared,
        )
        await _event(
            db, prepared["sid"], prepared["version"], prepared["digest"],
            "active", prepared["actor"],
        )

    async def create_authorized_session(
        self,
        session: SessionState,
        verified: Any,
        actor: Union[str, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Insert session+verified policy+outbox atomically, never an UPSERT."""
        if not isinstance(session, SessionState):
            raise AuthorizationDenied("Invalid authorized engagement")
        sid = session.session_id
        prepared = self._prepare(
            sid, verified, actor, session.scope.model_dump(mode="json"),
            session.roe, session.created_by,
        )
        if prepared["version"] != 1:
            raise AuthorizationDenied("New authorization must start at version 1")
        factory = self._factory()
        async with factory() as db, db.begin():
            inserted = (
                await db.execute(
                    text(
                        "INSERT INTO session_states "
                        "(session_id, scope, roe, phase, agents, checkpoint_id, "
                        "audit_log_position, created_by, created_at, updated_at) "
                        "VALUES (:sid, CAST(:scope AS jsonb), CAST(:roe AS jsonb), "
                        ":phase, CAST(:agents AS jsonb), :checkpoint, :audit, "
                        ":owner, :created, :updated) "
                        "ON CONFLICT (session_id) DO NOTHING RETURNING session_id"
                    ),
                    {
                        "sid": sid,
                        "scope": json.dumps(session.scope.model_dump(mode="json")),
                        "roe": json.dumps(session.roe), "phase": session.phase,
                        "agents": json.dumps(session.agents),
                        "checkpoint": session.checkpoint_id,
                        "audit": session.audit_log_position, "owner": session.created_by,
                        "created": session.created_at, "updated": session.updated_at,
                    },
                )
            ).scalar_one_or_none()
            if inserted != sid:
                raise AuthorizationDenied("Engagement already exists")
            await self._insert(db, prepared)
        return {
            "session_id": sid, "authorization_id": prepared["authorization_id"],
            "version": 1, "policy_sha256": prepared["digest"], "status": "active",
        }

    async def register_verified(
        self,
        session_id: str,
        verified: Any,
        actor: Union[str, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Register next signed version for a previously revoked ledger only.

        No grandfathering of old sessions without a signed ledger. New
        engagement creation must use create_authorized_session instead.
        """
        factory = self._factory()
        async with factory() as db, db.begin():
            row = (await db.execute(_LOCK_SESSION, {"sid": session_id})).mappings().one_or_none()
            if row is None:
                raise AuthorizationDenied("Engagement authorization unavailable")
            latest = (await db.execute(
                _LATEST_LOCKED, {"sid": session_id}
            )).mappings().one_or_none()
            if latest is None:
                raise AuthorizationDenied("Legacy engagement has no signed authorization")
            scope = row["scope"]
            if not isinstance(scope, dict) or scope.get("authorization_ref") not in (
                None, latest["authorization_id"]
            ):
                raise AuthorizationDenied("Legacy authorization reference changed")
            # The only metadata transition permitted during signed rotation
            # is the authorization reference; scope lists, ROE and owner
            # remain locked and must match the newly verified policy.
            replacement_scope = {**scope, "authorization_ref": verified.authorization_id}
            prepared = self._prepare(
                session_id, verified, actor, replacement_scope, row["roe"],
                row["created_by"],
            )
            if latest["status"] != "revoked" or prepared["version"] != latest["version"] + 1:
                raise AuthorizationDenied("Signed authorization rotation requires revoked predecessor")
            await db.execute(
                text(
                    "UPDATE session_states SET scope = CAST(:scope AS jsonb), updated_at = now() "
                    "WHERE session_id = :sid"
                ),
                {"sid": session_id, "scope": json.dumps(replacement_scope)},
            )
            await self._insert(db, prepared)
        return {
            "session_id": session_id,
            "authorization_id": prepared["authorization_id"],
            "version": prepared["version"], "policy_sha256": prepared["digest"],
            "status": "active",
        }

    async def assert_active(
        self,
        session_id: str,
        expected_version: Optional[int] = None,
        expected_digest: Optional[str] = None,
    ) -> VerifiedAuthorization:
        factory = self._factory()
        async with factory() as db, db.begin():
            return await guard_sql(db, session_id, expected_version, expected_digest)

    async def revoke(
        self,
        session_id: str,
        actor: Union[str, Mapping[str, Any]],
        expected_version: int,
        reason: str,
    ) -> bool:
        if (
            type(expected_version) is not int or expected_version <= 0
            or not isinstance(reason, str) or not reason.strip()
            or len(reason) > 512
        ):
            raise AuthorizationDenied("Expected version and bounded reason required")
        factory = self._factory()
        async with factory() as db, db.begin():
            row = (await db.execute(
                _LOCK_SESSION, {"sid": session_id}
            )).mappings().one_or_none()
            if row is None:
                return False
            actor_id = _actor_id(actor, row["created_by"])
            latest = (await db.execute(
                _LATEST_LOCKED, {"sid": session_id}
            )).mappings().one_or_none()
            if (
                latest is None or latest["status"] != "active"
                or latest["version"] != expected_version
            ):
                return False
            updated = await db.execute(
                text(
                    "UPDATE signed_authorizations SET status = 'revoked', "
                    "revoked_at = now(), revoked_by = :actor, "
                    "revocation_reason = :reason "
                    "WHERE session_id = :sid AND version = :version "
                    "AND status = 'active' RETURNING authorization_id"
                ),
                {
                    "sid": session_id, "version": expected_version,
                    "actor": actor_id,
                    # An arbitrary operator reason may contain a credential.
                    # Store only its digest; never save that raw text.
                    "reason": "operator_revocation:sha256:" + hashlib.sha256(
                        reason.strip().encode("utf-8")
                    ).hexdigest(),
                },
            )
            if updated.scalar_one_or_none() is None:
                return False
            await _event(
                db, session_id, latest["version"], latest["policy_sha256"],
                "revoked", actor_id,
            )
        return True
