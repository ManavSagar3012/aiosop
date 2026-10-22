"""PostgreSQL-only, non-executable provider routing *intent* review lifecycle.

PentAGI manages configured providers; this intentionally does NOT. The operator
declaration is inert and never influences ProviderRoutes, LiteLLM or budgets.
Every read/write is fenced by signed ROE and active Flow in the SAME SQL tx.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import text

from ai_osop.core.config import AgentType
from ai_osop.core.provider_routing import (
    _BUDGET_SOURCE,
    _CAPABILITIES,
    _LABEL,
    _OPERATIONS,
    _PROVIDER_CREDENTIALS,
)
from ai_osop.memory.flow_artifact_reviews import (
    ArtifactReviewDenied,
    FlowArtifactReviewStore,
)

_REVIEW_ID = re.compile(r"provider-review-[0-9a-f]{32}\Z")
_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_KEYS = frozenset(
    {
        "provider",
        "model",
        "operations",
        "allowed_roles",
        "capabilities",
        "max_output_tokens",
        "budget_source",
    }
)
_COLUMNS = (
    "id,engagement_id,flow_id,creator_sub,policy,policy_sha256,policy_revision,"
    "status,senior_sub,decision_reason,flow_revision,authorization_version,"
    "authorization_id,authorization_sha256,created_at,updated_at"
)
_MAX_REVIEWS = 32


class ProviderPolicyDenied(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status


def canonical_policy(candidate: Any) -> tuple[Dict[str, Any], str]:
    """Mirror ProviderRoutes v2 allowlist, WITHOUT credential/env/endpoint data.

    No env writing, model resolution, network probing or served-model assertion.
    Canonical sorted tuple choices yield the same SHA for equivalent intents.
    """
    if type(candidate) is not dict or set(candidate) != _POLICY_KEYS:
        raise ProviderPolicyDenied(422, "Non-secret provider policy fields required")
    provider, model = candidate["provider"], candidate["model"]
    ops = candidate["operations"]
    roles = candidate["allowed_roles"]
    caps = candidate["capabilities"]
    maximum = candidate["max_output_tokens"]
    if (
        type(provider) is not str
        or provider not in _PROVIDER_CREDENTIALS
        or type(model) is not str
        or not _LABEL.fullmatch(model)
        or re.search(
            r"(?i)(?:sk[-_](?:live|test)|gh[pousr]_|bearer|password|"
            r"credential|secret|token|api[_-]?key)",
            model,
        )
        is not None
        or any(part in {"", ".", ".."} for part in model.split("/"))
        or ("/" in model and model.split("/", 1)[0] != provider)
        or ("/" not in model and provider != "openai")
        or type(ops) is not list
        or not 1 <= len(ops) <= 2
        or any(type(op) is not str or op not in _OPERATIONS for op in ops)
        or len(set(ops)) != len(ops)
        or type(roles) is not list
        or not 1 <= len(roles) <= 24
        or any(type(role) is not str or role not in {r.value for r in AgentType} for role in roles)
        or len(set(roles)) != len(roles)
        or type(caps) is not list
        or not 1 <= len(caps) <= len(_CAPABILITIES)
        or any(type(cap) is not str or cap not in _CAPABILITIES for cap in caps)
        or len(set(caps)) != len(caps)
        or ("completion" in ops and "text_completion" not in caps)
        or ("embedding" in ops and "embeddings" not in caps)
        or ("embedding" not in ops and "embeddings" in caps)
        or (
            "completion" not in ops
            and any(
                cap in caps for cap in ("text_completion", "tool_calls", "json_mode", "reasoning")
            )
        )
        or type(maximum) is not int
        or not 1 <= maximum <= 16384
        or candidate["budget_source"] != _BUDGET_SOURCE
    ):
        raise ProviderPolicyDenied(422, "Invalid bounded provider route intent")
    policy = {
        "provider": provider,
        "model": model,
        "operations": sorted(ops),
        "allowed_roles": sorted(roles),
        "capabilities": sorted(caps),
        "max_output_tokens": maximum,
        "budget_source": _BUDGET_SOURCE,
    }
    raw = json.dumps(policy, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > 2048:
        raise ProviderPolicyDenied(422, "Provider intent exceeds byte limit")
    return policy, hashlib.sha256(b"ai-osop-provider-review-intent-v1\0" + raw).hexdigest()


def _metadata(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "review_id": row["id"],
        "engagement_id": row["engagement_id"],
        "flow_id": row["flow_id"],
        "policy_revision": row["policy_revision"],
        "policy_sha256": row["policy_sha256"],
        "policy": row["policy"],
        "status": row["status"],
        "flow_revision": row["flow_revision"],
        "authorization_version": row["authorization_version"],
        "authorization_id": row["authorization_id"],
        "authorization_sha256": row["authorization_sha256"],
        "senior_reviewed": row["senior_sub"] is not None,
        "purpose": "operator_declared_policy_only",
        "provider_served_model_verified": False,
        "provider_capability_verified": False,
        "callable_remotely": False,
        "execution_enabled": False,
        "budget_reserved": False,
        "credentials_stored": False,
        "created_at": row["created_at"].isoformat(),
        "updated_at": row["updated_at"].isoformat(),
    }


def _identity(
    review_id: Optional[str],
    actor: str,
    revision: int,
    version: int,
    authorization_id: str,
    authorization_sha256: str,
    engagement_id: str,
) -> None:
    if (
        (
            review_id is not None
            and (type(review_id) is not str or not _REVIEW_ID.fullmatch(review_id))
        )
        or type(actor) is not str
        or not _ACTOR.fullmatch(actor)
        or type(revision) is not int
        or not 0 <= revision <= 2**31 - 1
        or type(version) is not int
        or not 1 <= version <= 2**31 - 1
        or type(authorization_id) is not str
        or not 1 <= len(authorization_id) <= 128
        or any(
            ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:@-"
            for ch in authorization_id
        )
        or type(authorization_sha256) is not str
        or not _DIGEST.fullmatch(authorization_sha256)
        or type(engagement_id) is not str
        or not re.fullmatch(r"eng-[A-Za-z0-9._:-]{1,60}", engagement_id)
    ):
        raise ProviderPolicyDenied(422, "Invalid signed policy-review identity")


class ProviderRoutePolicyReviewStore:
    """Only bound inert SQL reads, guarded CAS revisions, and immutable audit."""

    def __init__(self, session_memory: Any):
        self.memory = session_memory

    def _sessions(self) -> Any:
        from ai_osop.memory.session_memory import SessionMemory

        maker = getattr(self.memory, "_async_session", None)
        if not isinstance(self.memory, SessionMemory) or not callable(maker):
            raise ProviderPolicyDenied(503, "Signed provider policy review storage unavailable")
        return maker

    @staticmethod
    async def _fence(
        db: Any,
        *,
        flow_id: str,
        actor: str,
        role: str,
        engagement_id: str,
        flow_revision: int,
        version: int,
        authorization_id: str,
        authorization_sha256: str,
        owner_only: bool,
    ) -> Dict[str, str]:
        try:
            binding = await FlowArtifactReviewStore._fence(
                db,
                flow_id=flow_id,
                revision=flow_revision,
                version=version,
                authorization_id=authorization_id,
                authorization_sha256=authorization_sha256,
                writing=True,
                expected_engagement_id=engagement_id,
            )
        except ArtifactReviewDenied as exc:
            raise ProviderPolicyDenied(exc.status, str(exc)) from exc
        if owner_only and actor != binding["owner"]:
            raise ProviderPolicyDenied(403, "Signed Flow owner required")
        if not owner_only and role != "senior_operator":
            raise ProviderPolicyDenied(403, "Signed senior reviewer required")
        return binding

    @staticmethod
    async def _one(db: Any, sid: str, flow_id: str, review_id: str) -> Optional[Dict[str, Any]]:
        result = await db.execute(
            text(
                f"SELECT {_COLUMNS} FROM provider_route_policy_reviews "
                "WHERE id=:id AND engagement_id=:sid AND flow_id=:fid FOR UPDATE"
            ),
            {"id": review_id, "sid": sid, "fid": flow_id},
        )
        return result.mappings().one_or_none()

    @staticmethod
    def _matching(
        row: Dict[str, Any],
        *,
        sid: str,
        flow_id: str,
        owner: str,
        version: int,
        flow_revision: int,
        authorization_id: str,
        authorization_sha256: str,
    ) -> None:
        if (
            row["engagement_id"] != sid
            or row["flow_id"] != flow_id
            or row["creator_sub"] != owner
            or row["authorization_version"] != version
            or row["flow_revision"] != flow_revision
            or row["authorization_id"] != authorization_id
            or not hmac.compare_digest(row["authorization_sha256"], authorization_sha256)
        ):
            raise ProviderPolicyDenied(409, "Provider policy review signed origin changed")
        policy, digest = canonical_policy(row["policy"])
        if policy != row["policy"] or not hmac.compare_digest(digest, row["policy_sha256"]):
            raise ProviderPolicyDenied(503, "Durable provider intent integrity unavailable")

    @staticmethod
    async def _audit(db: Any, row: Dict[str, Any], actor: str, event: str) -> None:
        await db.execute(
            text(
                "INSERT INTO provider_route_policy_review_events "
                "(id,review_id,engagement_id,flow_id,actor_sub,event,policy_revision,policy_sha256) "
                "VALUES (:id,:review_id,:sid,:fid,:actor,:event,:revision,:sha)"
            ),
            {
                "id": "prevt-" + uuid.uuid4().hex,
                "review_id": row["id"],
                "sid": row["engagement_id"],
                "fid": row["flow_id"],
                "actor": actor,
                "event": event,
                "revision": row["policy_revision"],
                "sha": row["policy_sha256"],
            },
        )

    async def perform(
        self,
        *,
        action: str,
        flow_id: str,
        actor: str,
        role: str,
        engagement_id: str,
        flow_revision: int,
        version: int,
        authorization_id: str,
        authorization_sha256: str,
        review_id: Optional[str] = None,
        expected_policy_revision: Optional[int] = None,
        policy: Optional[Dict[str, Any]] = None,
        decision_reason: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
        delegated_tenants: Optional[list[str]] = None,
        token_sha256: Optional[str] = None,
        token_expires_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        _identity(
            review_id,
            actor,
            flow_revision,
            version,
            authorization_id,
            authorization_sha256,
            engagement_id,
        )
        if type(flow_id) is not str or not re.fullmatch(r"flow-[A-Za-z0-9._:-]{1,59}", flow_id):
            raise ProviderPolicyDenied(422, "Invalid review Flow")
        if action not in {"create", "list", "detail", "update", "approve", "revoke"}:
            raise ProviderPolicyDenied(422, "Invalid provider review transition")
        if action in {"detail", "update", "approve", "revoke"} and review_id is None:
            raise ProviderPolicyDenied(422, "Provider review identity required")
        if action in {"update", "approve", "revoke"} and (
            type(expected_policy_revision) is not int or expected_policy_revision < 1
        ):
            raise ProviderPolicyDenied(422, "Expected provider policy CAS revision required")
        if action in {"create", "update"}:
            policy, digest = canonical_policy(policy)
        else:
            digest = None
        if action == "list" and (
            type(limit) is not int
            or not 1 <= limit <= 50
            or type(offset) is not int
            or not 0 <= offset <= 1000
        ):
            raise ProviderPolicyDenied(422, "Invalid review pagination")
        is_senior_action = action in {"approve", "revoke"}
        delegated_senior = (
            role == "senior_operator"
            and type(delegated_tenants) is list
            and len(delegated_tenants) <= 32
            and engagement_id in delegated_tenants
        )
        if is_senior_action and (role != "senior_operator" or not delegated_senior):
            # A global senior JWT never automatically grants access to all
            # tenant Flow policies. The JWT must explicitly delegate THIS
            # engagement ID; the senior must also differ from the creator.
            raise ProviderPolicyDenied(403, "Scoped senior delegation required")
        if is_senior_action and (
            type(decision_reason) is not str
            or not 10 <= len(decision_reason) <= 256
            or decision_reason.strip() != decision_reason
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .,:;()_-]{9,255}", decision_reason)
            or re.search(
                r"(?i)\b(?:bearer|password|credential|secret|token|api[_-]?key|"
                r"authorization|private[_-]?key|http|sk[_-]?live)\b",
                decision_reason,
            )
            is not None
        ):
            raise ProviderPolicyDenied(422, "Bounded senior review reason required")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    review_access = is_senior_action or (
                        action in {"list", "detail"} and delegated_senior
                    )
                    binding = await self._fence(
                        db,
                        flow_id=flow_id,
                        actor=actor,
                        role=role,
                        engagement_id=engagement_id,
                        flow_revision=flow_revision,
                        version=version,
                        authorization_id=authorization_id,
                        authorization_sha256=authorization_sha256,
                        owner_only=not review_access,
                    )
                    if review_access:
                        try:
                            await FlowArtifactReviewStore._reviewer_fence(
                                db,
                                reviewer_sub=actor,
                                reviewer_token_sha256=token_sha256,
                                reviewer_expires_at=token_expires_at,
                            )
                        except ArtifactReviewDenied as exc:
                            raise ProviderPolicyDenied(exc.status, str(exc)) from exc
                    common = {"sid": engagement_id, "fid": flow_id}
                    if action == "create":
                        result = await db.execute(
                            text(
                                "SELECT count(*) FROM provider_route_policy_reviews "
                                "WHERE engagement_id=:sid AND flow_id=:fid"
                            ),
                            common,
                        )
                        count = result.scalar_one()
                        if type(count) is not int or count >= _MAX_REVIEWS:
                            raise ProviderPolicyDenied(409, "Provider policy review limit reached")
                        result = await db.execute(
                            text(
                                f"INSERT INTO provider_route_policy_reviews "
                                "(id,engagement_id,flow_id,creator_sub,policy,policy_sha256,"
                                "policy_revision,status,flow_revision,authorization_version,"
                                "authorization_id,authorization_sha256) "
                                "VALUES (:id,:sid,:fid,:actor,CAST(:policy AS jsonb),:sha,1,'pending',"
                                ":flow_revision,:version,:authorization_id,:authorization_sha256) "
                                f"RETURNING {_COLUMNS}"
                            ),
                            {
                                **common,
                                "id": "provider-review-" + uuid.uuid4().hex,
                                "actor": actor,
                                "policy": json.dumps(policy, sort_keys=True),
                                "sha": digest,
                                "flow_revision": flow_revision,
                                "version": version,
                                "authorization_id": authorization_id,
                                "authorization_sha256": authorization_sha256,
                            },
                        )
                        row = result.mappings().one()
                        await self._audit(db, row, actor, "created")
                        return _metadata(row)
                    if action == "list":
                        rows = (
                            (
                                await db.execute(
                                    text(
                                        f"SELECT {_COLUMNS} FROM provider_route_policy_reviews "
                                        "WHERE engagement_id=:sid AND flow_id=:fid "
                                        "ORDER BY created_at DESC,id LIMIT :limit OFFSET :offset FOR SHARE"
                                    ),
                                    {**common, "limit": limit + 1, "offset": offset},
                                )
                            )
                            .mappings()
                            .all()
                        )
                        for row in rows:
                            self._matching(
                                row,
                                sid=engagement_id,
                                flow_id=flow_id,
                                owner=binding["owner"],
                                version=version,
                                flow_revision=flow_revision,
                                authorization_id=authorization_id,
                                authorization_sha256=authorization_sha256,
                            )
                        return {
                            "items": [_metadata(row) for row in rows[:limit]],
                            "has_more": len(rows) > limit,
                        }
                    row = await self._one(db, engagement_id, flow_id, review_id)
                    if row is None:
                        raise ProviderPolicyDenied(404, "Provider policy review not found")
                    self._matching(
                        row,
                        sid=engagement_id,
                        flow_id=flow_id,
                        owner=binding["owner"],
                        version=version,
                        flow_revision=flow_revision,
                        authorization_id=authorization_id,
                        authorization_sha256=authorization_sha256,
                    )
                    if action == "detail":
                        return _metadata(row)
                    if row["policy_revision"] != expected_policy_revision:
                        raise ProviderPolicyDenied(409, "Provider policy CAS revision changed")
                    if action == "update":
                        if row["status"] != "pending":
                            raise ProviderPolicyDenied(
                                409, "Approved/revoked policy cannot be edited"
                            )
                        if hmac.compare_digest(digest, row["policy_sha256"]):
                            raise ProviderPolicyDenied(
                                409, "Identical policy revision is not a change"
                            )
                        params = {
                            "id": review_id,
                            **common,
                            "revision": expected_policy_revision,
                            "policy": json.dumps(policy),
                            "sha": digest,
                        }
                        result = await db.execute(
                            text(
                                f"UPDATE provider_route_policy_reviews SET "
                                "policy=CAST(:policy AS jsonb),policy_sha256=:sha,"
                                "policy_revision=policy_revision+1,updated_at=now() "
                                "WHERE id=:id AND engagement_id=:sid AND flow_id=:fid "
                                "AND policy_revision=:revision AND status='pending' "
                                f"RETURNING {_COLUMNS}"
                            ),
                            params,
                        )
                        updated = result.mappings().one_or_none()
                        event = "updated"
                    else:
                        if actor == row["creator_sub"]:
                            raise ProviderPolicyDenied(403, "Independent senior reviewer required")
                        if action == "approve" and row["status"] != "pending":
                            raise ProviderPolicyDenied(409, "Only pending intents may be approved")
                        if action == "revoke" and row["status"] not in {"pending", "approved"}:
                            raise ProviderPolicyDenied(409, "Intent already revoked")
                        result = await db.execute(
                            text(
                                f"UPDATE provider_route_policy_reviews SET "
                                "status=:decision,senior_sub=:senior,decision_reason=:reason,"
                                "policy_revision=policy_revision+1,updated_at=now() "
                                "WHERE id=:id AND engagement_id=:sid AND flow_id=:fid "
                                "AND policy_revision=:revision AND status=:prior "
                                f"RETURNING {_COLUMNS}"
                            ),
                            {
                                "id": review_id,
                                **common,
                                "revision": expected_policy_revision,
                                "decision": "approved" if action == "approve" else "revoked",
                                "prior": row["status"],
                                "senior": actor,
                                "reason": decision_reason,
                            },
                        )
                        updated = result.mappings().one_or_none()
                        event = "approved" if action == "approve" else "revoked"
                    if updated is None:
                        raise ProviderPolicyDenied(409, "Concurrent provider review transition")
                    await self._audit(db, updated, actor, event)
                    return _metadata(updated)
        except ProviderPolicyDenied:
            raise
        except Exception as exc:
            raise ProviderPolicyDenied(503, "Durable signed provider review unavailable") from exc
