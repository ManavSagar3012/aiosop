"""Durable NONSECRET provider credential *reference* review, not credential storage.

The only permitted slots are fixed server-understood symbolic labels, never
client supplied credential keys, secret values, env variable names or paths.
Nothing in this ledger is consulted by LiteLLM, ProviderRoutes or a vault.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text

from ai_osop.core.config import settings
from ai_osop.core.provider_routing import _PROVIDER_CREDENTIALS
from ai_osop.memory.flow_artifact_reviews import FlowArtifactReviewStore
from ai_osop.memory.provider_route_policy_reviews import canonical_policy
from ai_osop.memory.session_memory import SessionMemory

_REF = re.compile(r"pcref-[0-9a-f]{32}\Z")
_OP = re.compile(r"pcop-[0-9a-f]{32}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._:-]{1,59}\Z")
_ENG = re.compile(r"eng-[A-Za-z0-9._:-]{1,60}\Z")
_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}\Z")
_AUTH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REVIEW = re.compile(r"provider-review-[0-9a-f]{32}\Z")
_SLOTS = frozenset({"primary", "backup"})
_OPS = frozenset({"register", "rotate", "approve", "revoke"})
_COLUMNS = (
    "id,engagement_id,flow_id,owner_sub,provider,slot,policy_review_id,"
    "policy_sha256,reference_sha256,reference_revision,generation,status,senior_sub,"
    "flow_revision,authorization_version,authorization_id,authorization_sha256,"
    "created_at,updated_at"
)
_REASON = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .,:;()_-]{9,159}\Z")
_SECRET_WORDS = re.compile(
    r"(?i)\b(?:bearer|password|credential|secret|token|api[_-]?key|authorization|"
    r"private[_-]?key|http|sk[_-]?live|env|path|vault|key)\b"
)


class CredentialProfileDenied(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status


def _require(value: Any, pattern: re.Pattern[str], message: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise CredentialProfileDenied(422, message)
    return value


def _sha(value: Any) -> str:
    return _require(value, _SHA, "Bounded nonsecret SHA-256 required")


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode("ascii")
    except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
        raise CredentialProfileDenied(422, "Invalid canonical nonsecret metadata") from exc
    if len(encoded) > 2048:
        raise CredentialProfileDenied(422, "Nonsecret metadata too large")
    return encoded


def _digest(domain: str, data: Any) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + _canonical(data)).hexdigest()


def _binding(
    flow_id: Any,
    engagement_id: Any,
    revision: Any,
    version: Any,
    authorization_id: Any,
    authorization_sha256: Any,
) -> Dict[str, Any]:
    _require(flow_id, _FLOW, "Bounded Flow identity required")
    _require(engagement_id, _ENG, "Bounded tenant identity required")
    _require(authorization_id, _AUTH, "Signed authorization identity required")
    _sha(authorization_sha256)
    if (
        type(revision) is not int
        or not 0 <= revision <= 2147483647
        or type(version) is not int
        or not 1 <= version <= 2147483647
    ):
        raise CredentialProfileDenied(422, "Current signed Flow revision required")
    return {
        "flow_id": flow_id,
        "engagement_id": engagement_id,
        "flow_revision": revision,
        "authorization_version": version,
        "authorization_id": authorization_id,
        "authorization_sha256": authorization_sha256,
    }


def _public(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ref_id": row["id"],
        "engagement_id": row["engagement_id"],
        "flow_id": row["flow_id"],
        "provider": row["provider"],
        "slot": row["slot"],
        "policy_review_id": row["policy_review_id"],
        "policy_sha256": row["policy_sha256"],
        "reference_sha256": row["reference_sha256"],
        "reference_revision": row["reference_revision"],
        "generation": row["generation"],
        "status": row["status"],
        "flow_revision": row["flow_revision"],
        "authorization_version": row["authorization_version"],
        "authorization_id": row["authorization_id"],
        "authorization_sha256": row["authorization_sha256"],
        "senior_reviewed": row["senior_sub"] is not None,
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat(),
        "credentials_stored": False,
        "credential_available_verified": False,
        "credential_rotated": False,
        "execution_enabled": False,
        "provider_contacted": False,
        "route_activated": False,
        "server_reference_only": True,
        "status_is_historical_review_only": True,
        "policy_current_approval_verified": False,
    }


class ProviderCredentialProfileRefStore:
    """Signed PostgreSQL CAS lifecycle; a reference cannot enable a provider."""

    def __init__(self, memory: SessionMemory) -> None:
        if not isinstance(memory, SessionMemory):
            raise CredentialProfileDenied(
                503, "Durable signed provider reference store unavailable"
            )
        self.memory = memory

    def _sessions(self) -> Any:
        maker = getattr(self.memory, "_async_session", None)
        if not callable(maker):
            raise CredentialProfileDenied(503, "Durable provider reference PostgreSQL unavailable")
        return maker

    @staticmethod
    async def _fence(
        db: Any,
        b: Dict[str, Any],
        actor: str,
        role: str,
        delegated_tenants: Any,
        token_sha256: Optional[str],
        token_expires_at: Optional[int],
        *,
        senior: bool,
        read_access: bool = False,
    ) -> Dict[str, Any]:
        if senior and (
            role != "senior_operator"
            or type(delegated_tenants) is not list
            or len(delegated_tenants) > 32
            or b["engagement_id"] not in delegated_tenants
            or any(type(eid) is not str or _ENG.fullmatch(eid) is None for eid in delegated_tenants)
        ):
            raise CredentialProfileDenied(403, "Explicit tenant-delegated senior reviewer required")
        if not senior and role not in {"operator", "senior_operator"}:
            raise CredentialProfileDenied(403, "Signed Flow operator required")
        if type(token_expires_at) is not int or token_expires_at <= int(
            datetime.now(timezone.utc).timestamp()
        ):
            raise CredentialProfileDenied(401, "Current signed bearer required")
        if settings.operator_revocation_required and (
            type(token_sha256) is not str or _SHA.fullmatch(token_sha256) is None
        ):
            raise CredentialProfileDenied(403, "Signed bearer SHA proof required")
        # Holding this signed Flow/ROE lock serializes registration and ROE
        # revision/revocation for the entire SQL transaction.
        current = await FlowArtifactReviewStore._fence(
            db,
            flow_id=b["flow_id"],
            revision=b["flow_revision"],
            version=b["authorization_version"],
            authorization_id=b["authorization_id"],
            authorization_sha256=b["authorization_sha256"],
            writing=True,
            expected_engagement_id=b["engagement_id"],
        )
        await FlowArtifactReviewStore._reviewer_fence(
            db,
            reviewer_sub=actor,
            reviewer_token_sha256=token_sha256,
            reviewer_expires_at=token_expires_at,
        )
        if settings.operator_revocation_required:
            active = (
                await db.execute(
                    text(
                        "SELECT disabled FROM operator_subject_controls "
                        "WHERE actor_id=:actor FOR SHARE"
                    ),
                    {"actor": actor},
                )
            ).scalar_one_or_none()
            if active is not False:
                raise CredentialProfileDenied(403, "Current signed operator subject unavailable")
        if not senior and current["owner"] != actor:
            # A senior can review already-persisted reference metadata only
            # with explicit signed delegation for this exact engagement.
            if not (
                read_access
                and role == "senior_operator"
                and type(delegated_tenants) is list
                and len(delegated_tenants) <= 32
                and b["engagement_id"] in delegated_tenants
                and all(type(eid) is str and _ENG.fullmatch(eid) for eid in delegated_tenants)
            ):
                raise CredentialProfileDenied(403, "Current owner or delegated senior required")
        if senior and current["owner"] == actor:
            raise CredentialProfileDenied(403, "Senior approval must be independent of Flow owner")
        return current

    @staticmethod
    async def _policy(
        db: Any, b: Dict[str, Any], owner: str, review_id: str, digest: str, provider: str
    ) -> None:
        policy = (
            (
                await db.execute(
                    text(
                        "SELECT id,engagement_id,flow_id,creator_sub,policy,policy_sha256,status,"
                        "senior_sub,flow_revision,authorization_version,authorization_id,"
                        "authorization_sha256 FROM provider_route_policy_reviews "
                        "WHERE id=:id AND engagement_id=:eng AND flow_id=:flow FOR SHARE"
                    ),
                    {"id": review_id, "eng": b["engagement_id"], "flow": b["flow_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            policy is None
            or policy["creator_sub"] != owner
            or policy["status"] != "approved"
            or not isinstance(policy["senior_sub"], str)
            or policy["senior_sub"] == owner
            or policy["flow_revision"] != b["flow_revision"]
            or policy["authorization_version"] != b["authorization_version"]
            or policy["authorization_id"] != b["authorization_id"]
            or not hmac.compare_digest(policy["authorization_sha256"], b["authorization_sha256"])
            or not hmac.compare_digest(policy["policy_sha256"], digest)
        ):
            raise CredentialProfileDenied(
                403, "Independent approved signed provider intent required"
            )
        validated, checked = canonical_policy(policy["policy"])
        if checked != digest or validated != policy["policy"] or validated["provider"] != provider:
            raise CredentialProfileDenied(403, "Approved provider policy SHA or provider changed")
        if settings.operator_revocation_required:
            active = (
                await db.execute(
                    text(
                        "SELECT disabled FROM operator_subject_controls "
                        "WHERE actor_id=:actor FOR SHARE"
                    ),
                    {"actor": policy["senior_sub"]},
                )
            ).scalar_one_or_none()
            if active is not False:
                raise CredentialProfileDenied(
                    403, "Original provider policy senior reviewer unavailable"
                )

    @staticmethod
    async def _row(db: Any, b: Dict[str, Any], ref_id: str) -> Optional[Dict[str, Any]]:
        return (
            (
                await db.execute(
                    text(
                        f"SELECT {_COLUMNS} FROM provider_credential_profile_refs "
                        "WHERE id=:id AND engagement_id=:eng AND flow_id=:flow FOR UPDATE"
                    ),
                    {"id": ref_id, "eng": b["engagement_id"], "flow": b["flow_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )

    @staticmethod
    def _same(row: Dict[str, Any], b: Dict[str, Any], owner: str) -> None:
        if row["owner_sub"] != owner or any(
            row[key] != b[key]
            for key in (
                "engagement_id",
                "flow_id",
                "flow_revision",
                "authorization_version",
                "authorization_id",
                "authorization_sha256",
            )
        ):
            raise CredentialProfileDenied(409, "Reference bound to different signed Flow")
        expected = _digest(
            "ai-osop-provider-credential-reference-v1",
            {
                "engagement_id": row["engagement_id"],
                "flow_id": row["flow_id"],
                "provider": row["provider"],
                "slot": row["slot"],
                "policy_review_id": row["policy_review_id"],
                "policy_sha256": row["policy_sha256"],
                "generation": row["generation"],
                "owner": row["owner_sub"],
                "flow_revision": row["flow_revision"],
                "authorization_version": row["authorization_version"],
                "authorization_id": row["authorization_id"],
                "authorization_sha256": row["authorization_sha256"],
            },
        )
        if not hmac.compare_digest(expected, row["reference_sha256"]):
            raise CredentialProfileDenied(503, "Durable provider reference integrity unavailable")

    @staticmethod
    async def _event(
        db: Any,
        b: Dict[str, Any],
        row: Dict[str, Any],
        operation: str,
        operation_id: str,
        actor: str,
        request_sha: str,
    ) -> None:
        await db.execute(
            text(
                "INSERT INTO provider_credential_profile_ref_events "
                "(operation_id,ref_id,engagement_id,flow_id,actor_sub,operation,"
                "reference_revision,generation,status,reference_sha256,request_sha256) "
                "VALUES (:op,:ref,:eng,:flow,:actor,:operation,:revision,:generation,"
                ":status,:reference_sha,:request_sha)"
            ),
            {
                "op": operation_id,
                "ref": row["id"],
                "eng": b["engagement_id"],
                "flow": b["flow_id"],
                "actor": actor,
                "operation": operation,
                "revision": row["reference_revision"],
                "generation": row["generation"],
                "status": row["status"],
                "reference_sha": row["reference_sha256"],
                "request_sha": request_sha,
            },
        )

    async def perform(
        self,
        *,
        operation: str,
        flow_id: str,
        engagement_id: str,
        flow_revision: int,
        version: int,
        authorization_id: str,
        authorization_sha256: str,
        actor: str,
        role: str,
        delegated_tenants: Optional[list[str]] = None,
        token_sha256: Optional[str] = None,
        token_expires_at: Optional[int] = None,
        operation_id: Optional[str] = None,
        ref_id: Optional[str] = None,
        expected_ref_revision: Optional[int] = None,
        provider: Optional[str] = None,
        slot: Optional[str] = None,
        policy_review_id: Optional[str] = None,
        policy_sha256: Optional[str] = None,
        reason: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Dict[str, Any]:
        b = _binding(
            flow_id, engagement_id, flow_revision, version, authorization_id, authorization_sha256
        )
        _require(actor, _ACTOR, "Signed operator identity required")
        if operation not in _OPS | {"list", "detail"}:
            raise CredentialProfileDenied(422, "Unsupported nonsecret reference operation")
        if operation in _OPS:
            _require(operation_id, _OP, "Explicit idempotency operation ID required")
        if operation in {"detail", "rotate", "approve", "revoke"}:
            _require(ref_id, _REF, "Nonsecret profile reference ID required")
        if operation in {"rotate", "approve", "revoke"} and (
            type(expected_ref_revision) is not int or not 1 <= expected_ref_revision <= 2147483647
        ):
            raise CredentialProfileDenied(422, "Exact reference CAS revision required")
        if operation in {"register", "rotate"}:
            if type(provider) is not str or provider not in _PROVIDER_CREDENTIALS:
                raise CredentialProfileDenied(422, "Server-allowlisted provider identity required")
            if type(slot) is not str or slot not in _SLOTS:
                raise CredentialProfileDenied(
                    422, "Server-managed symbolic primary/backup slot required"
                )
            _require(policy_review_id, _REVIEW, "Approved route policy review ID required")
            _sha(policy_sha256)
        if operation in {"approve", "revoke"}:
            if (
                type(reason) is not str
                or _REASON.fullmatch(reason) is None
                or _SECRET_WORDS.search(reason) is not None
            ):
                raise CredentialProfileDenied(422, "Nonsecret senior review reason required")
        if operation == "list" and (
            type(limit) is not int
            or not 1 <= limit <= 50
            or type(offset) is not int
            or not 0 <= offset <= 1000
        ):
            raise CredentialProfileDenied(422, "Bounded reference pagination required")
        senior = operation in {"approve", "revoke"}
        request_sha = (
            _digest(
                "ai-osop-provider-credential-operation-v1",
                {
                    "operation": operation,
                    "operation_id": operation_id,
                    "flow": b,
                    "actor": actor,
                    "ref_id": ref_id,
                    "revision": expected_ref_revision,
                    "provider": provider,
                    "slot": slot,
                    "policy_review_id": policy_review_id,
                    "policy_sha256": policy_sha256,
                    "reason": reason,
                },
            )
            if operation in _OPS
            else None
        )
        # Registration ID is generated server-side deterministically from the
        # opaque operation ID; an ambiguous commit cannot create another ref.
        proposed_id = (
            (
                "pcref-"
                + _digest(
                    "ai-osop-provider-credential-ref-id-v1",
                    {"tenant": engagement_id, "flow": flow_id, "op": operation_id},
                )[:32]
            )
            if operation == "register"
            else ref_id
        )
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    signed = await self._fence(
                        db,
                        b,
                        actor,
                        role,
                        delegated_tenants,
                        token_sha256,
                        token_expires_at,
                        senior=senior,
                        read_access=operation in {"list", "detail"},
                    )
                    owner = signed["owner"]
                    # Cross-replica idempotency: exact committed audit event is
                    # an immutable readback. No repeat UPDATE/INSERT on retry.
                    if operation in _OPS:
                        recorded = (
                            (
                                await db.execute(
                                    text(
                                        "SELECT operation_id,ref_id,engagement_id,flow_id,actor_sub,"
                                        "operation,request_sha256,reference_revision,generation,status "
                                        "FROM provider_credential_profile_ref_events "
                                        "WHERE operation_id=:op FOR SHARE"
                                    ),
                                    {"op": operation_id},
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if recorded is not None:
                            if (
                                recorded["engagement_id"] != engagement_id
                                or recorded["flow_id"] != flow_id
                                or recorded["actor_sub"] != actor
                                or recorded["operation"] != operation
                                or not hmac.compare_digest(recorded["request_sha256"], request_sha)
                            ):
                                raise CredentialProfileDenied(
                                    409, "Idempotency operation ID already bound"
                                )
                            observed = await self._row(db, b, recorded["ref_id"])
                            if observed is None:
                                raise CredentialProfileDenied(
                                    503, "Committed reference readback unavailable"
                                )
                            self._same(observed, b, owner)
                            return {
                                **_public(observed),
                                "operation_recorded": True,
                                "idempotent_replay": True,
                                "replayed_event_revision": recorded["reference_revision"],
                                "replayed_event_status": recorded["status"],
                                "current_state_may_have_advanced": (
                                    observed["reference_revision"] != recorded["reference_revision"]
                                ),
                            }
                    if operation == "list":
                        rows = (
                            (
                                await db.execute(
                                    text(
                                        f"SELECT {_COLUMNS} FROM provider_credential_profile_refs "
                                        "WHERE engagement_id=:eng AND flow_id=:flow "
                                        "ORDER BY created_at DESC,id LIMIT :limit OFFSET :offset FOR SHARE"
                                    ),
                                    {
                                        "eng": engagement_id,
                                        "flow": flow_id,
                                        "limit": limit + 1,
                                        "offset": offset,
                                    },
                                )
                            )
                            .mappings()
                            .all()
                        )
                        for row in rows:
                            self._same(row, b, owner)
                        return {
                            "items": [_public(row) for row in rows[:limit]],
                            "has_more": len(rows) > limit,
                        }
                    if operation == "register":
                        await self._policy(db, b, owner, policy_review_id, policy_sha256, provider)
                        count = (
                            await db.execute(
                                text(
                                    "SELECT count(*) FROM provider_credential_profile_refs "
                                    "WHERE engagement_id=:eng AND flow_id=:flow"
                                ),
                                {"eng": engagement_id, "flow": flow_id},
                            )
                        ).scalar_one()
                        if type(count) is not int or count >= 16:
                            raise CredentialProfileDenied(409, "Provider reference quota reached")
                        digest = _digest(
                            "ai-osop-provider-credential-reference-v1",
                            {
                                "engagement_id": engagement_id,
                                "flow_id": flow_id,
                                "provider": provider,
                                "slot": slot,
                                "policy_review_id": policy_review_id,
                                "policy_sha256": policy_sha256,
                                "generation": 1,
                                "owner": owner,
                                **b,
                            },
                        )
                        row = (
                            (
                                await db.execute(
                                    text(
                                        f"INSERT INTO provider_credential_profile_refs "
                                        "(id,engagement_id,flow_id,owner_sub,provider,slot,"
                                        "policy_review_id,policy_sha256,reference_sha256,"
                                        "reference_revision,generation,status,flow_revision,"
                                        "authorization_version,authorization_id,authorization_sha256) "
                                        "VALUES (:id,:eng,:flow,:owner,:provider,:slot,:review,:policy_sha,"
                                        ":reference_sha,1,1,'pending',:revision,:version,:auth_id,:auth_sha) "
                                        f"RETURNING {_COLUMNS}"
                                    ),
                                    {
                                        "id": proposed_id,
                                        "eng": engagement_id,
                                        "flow": flow_id,
                                        "owner": owner,
                                        "provider": provider,
                                        "slot": slot,
                                        "review": policy_review_id,
                                        "policy_sha": policy_sha256,
                                        "reference_sha": digest,
                                        "revision": flow_revision,
                                        "version": version,
                                        "auth_id": authorization_id,
                                        "auth_sha": authorization_sha256,
                                    },
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if row is None:
                            raise CredentialProfileDenied(
                                503, "Durable reference registration UNKNOWN"
                            )
                    else:
                        row = await self._row(db, b, ref_id)
                        if row is None:
                            raise CredentialProfileDenied(
                                404, "Nonsecret provider reference not found"
                            )
                        self._same(row, b, owner)
                        if operation == "detail":
                            return _public(row)
                        if row["reference_revision"] != expected_ref_revision:
                            raise CredentialProfileDenied(409, "Reference CAS revision changed")
                        if operation == "rotate":
                            if row["status"] != "approved":
                                raise CredentialProfileDenied(
                                    409, "Only approved references may propose rotation"
                                )
                            if (
                                row["provider"] != provider
                                or row["slot"] != slot
                                or row["policy_review_id"] != policy_review_id
                                or row["policy_sha256"] != policy_sha256
                            ):
                                raise CredentialProfileDenied(
                                    409, "Immutable managed reference identity changed"
                                )
                            await self._policy(
                                db, b, owner, policy_review_id, policy_sha256, provider
                            )
                            generation = row["generation"] + 1
                            new_status, new_senior = "pending", None
                        else:
                            if actor == owner:
                                raise CredentialProfileDenied(
                                    403, "Independent senior decision required"
                                )
                            if operation == "approve" and row["status"] != "pending":
                                raise CredentialProfileDenied(
                                    409, "Only pending reference may be approved"
                                )
                            if operation == "revoke" and row["status"] not in {
                                "pending",
                                "approved",
                            }:
                                raise CredentialProfileDenied(409, "Reference already revoked")
                            # Revalidate the earlier independent approved 0025
                            # policy before any newly approved reference status.
                            if operation == "approve":
                                await self._policy(
                                    db,
                                    b,
                                    owner,
                                    row["policy_review_id"],
                                    row["policy_sha256"],
                                    row["provider"],
                                )
                            generation = row["generation"]
                            new_status = "approved" if operation == "approve" else "revoked"
                            new_senior = actor
                        digest = _digest(
                            "ai-osop-provider-credential-reference-v1",
                            {
                                "engagement_id": engagement_id,
                                "flow_id": flow_id,
                                "provider": row["provider"],
                                "slot": row["slot"],
                                "policy_review_id": row["policy_review_id"],
                                "policy_sha256": row["policy_sha256"],
                                "generation": generation,
                                "owner": owner,
                                **b,
                            },
                        )
                        updated = (
                            (
                                await db.execute(
                                    text(
                                        f"UPDATE provider_credential_profile_refs SET "
                                        "status=:status,senior_sub=:senior,generation=:generation,"
                                        "reference_sha256=:sha,reference_revision=reference_revision+1,"
                                        "updated_at=now() WHERE id=:id AND engagement_id=:eng AND "
                                        "flow_id=:flow AND reference_revision=:expected AND status=:prior "
                                        f"RETURNING {_COLUMNS}"
                                    ),
                                    {
                                        "status": new_status,
                                        "senior": new_senior,
                                        "generation": generation,
                                        "sha": digest,
                                        "id": ref_id,
                                        "eng": engagement_id,
                                        "flow": flow_id,
                                        "expected": expected_ref_revision,
                                        "prior": row["status"],
                                    },
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if updated is None:
                            raise CredentialProfileDenied(
                                409, "Concurrent provider reference transition"
                            )
                        row = updated
                    await self._event(db, b, row, operation, operation_id, actor, request_sha)
                    return {**_public(row), "operation_recorded": True, "idempotent_replay": False}
        except CredentialProfileDenied:
            raise
        except Exception as exc:
            # Commit ACK loss is UNKNOWN. Never transparently retry a mutation.
            raise CredentialProfileDenied(
                503, "Provider reference outcome UNKNOWN; read back operation ID before retry"
            ) from exc
