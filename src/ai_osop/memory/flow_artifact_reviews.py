"""Independent, immutable senior review of PostgreSQL Flow artifact bytes.

A checksum from an upload is NOT review. Only a separately authenticated
senior's explicit, one-time decision, bound to CURRENT signed authorization
and a byte-verified snapshot, may become a review receipt. No tool execution,
model invocation, remote fetch or filesystem operation occurs here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text

from ai_osop.core.config import settings
from ai_osop.memory.authorization_store import AuthorizationDenied, guard_sql
from ai_osop.memory.flow_artifacts import MAX_BYTES

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SUBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+:-]{0,63}\Z")
_AUTH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
_ARTIFACT = re.compile(r"artifact-[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class ArtifactReviewDenied(Exception):
    """Safe denial from the durable, fail-closed review boundary."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _identifier(value: Any, pattern: re.Pattern[str] = _ID) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ArtifactReviewDenied(422, "Invalid review identity")
    return value


def _expected(
    *,
    flow_id: str,
    artifact_id: str,
    revision: int,
    version: int,
    sha256: str,
    authorization_id: str,
    authorization_sha256: str,
) -> None:
    _identifier(flow_id)
    _identifier(artifact_id, _ARTIFACT)
    _identifier(authorization_id, _AUTH_ID)
    if (
        type(revision) is not int
        or revision < 0
        or type(version) is not int
        or version < 1
        or not isinstance(sha256, str)
        or _SHA.fullmatch(sha256) is None
        or not isinstance(authorization_sha256, str)
        or _SHA.fullmatch(authorization_sha256) is None
    ):
        raise ArtifactReviewDenied(422, "Invalid signed review fence")


def _validated_bytes(row: Dict[str, Any], expected_sha256: str) -> None:
    blob = row.get("content")
    digest = row.get("sha256")
    if (
        not isinstance(blob, bytes)
        or not 0 < len(blob) <= MAX_BYTES
        or row.get("size_bytes") != len(blob)
        or not isinstance(digest, str)
        or _SHA.fullmatch(digest) is None
        or not hmac.compare_digest(digest, hashlib.sha256(blob).hexdigest())
    ):
        raise ArtifactReviewDenied(503, "Immutable artifact integrity unavailable")
    if not hmac.compare_digest(digest, expected_sha256):
        raise ArtifactReviewDenied(409, "Artifact checksum changed")


class FlowArtifactReviewStore:
    """Review and approved-only read path over one PostgreSQL transaction."""

    def __init__(self, session_memory: Any):
        self._session_memory = session_memory

    def _sessions(self) -> Any:
        maker = getattr(self._session_memory, "_async_session", None)
        if not callable(maker):
            raise ArtifactReviewDenied(503, "Durable Flow review storage unavailable")
        return maker

    @staticmethod
    async def _reviewer_fence(
        db: Any,
        *,
        reviewer_sub: Optional[str],
        reviewer_token_sha256: Optional[str],
        reviewer_expires_at: Optional[int],
    ) -> None:
        """Recheck a signed senior identity *inside* the source transaction.

        Header verification happens before the DB transaction and can become
        stale while awaiting its locks or BYTEA read. When the deployment has
        durable token revocation enabled, never rely on the earlier API check
        for the final human review/source delivery. The token is not persisted,
        logged, or supplied to SQL, only its one-way SHA-256 digest.
        """
        if reviewer_sub is None:
            if reviewer_token_sha256 is not None or reviewer_expires_at is not None:
                raise ArtifactReviewDenied(403, "Reviewer identity binding unavailable")
            return  # Internal agent reads have a separate signed Task/ROE fence.
        _identifier(reviewer_sub, _SUBJECT)
        if type(reviewer_expires_at) is not int or reviewer_expires_at <= int(
            datetime.now(timezone.utc).timestamp()
        ):
            raise ArtifactReviewDenied(401, "Senior reviewer credential expired")
        if not settings.operator_revocation_required:
            return
        if (
            not isinstance(reviewer_token_sha256, str)
            or _SHA.fullmatch(reviewer_token_sha256) is None
        ):
            raise ArtifactReviewDenied(403, "Durable reviewer credential proof required")
        # Use this SAME db transaction; a separate connection loses the Flow
        # authorization snapshot and leaves a larger auth-vs-download gap.
        revoked = (
            await db.execute(
                text(
                    "SELECT digest FROM operator_token_revocations "
                    "WHERE digest=:digest FOR SHARE"
                ),
                {"digest": reviewer_token_sha256},
            )
        ).scalar_one_or_none()
        disabled = (
            await db.execute(
                text(
                    "SELECT disabled FROM operator_subject_controls "
                    "WHERE actor_id=:actor FOR SHARE"
                ),
                {"actor": reviewer_sub},
            )
        ).scalar_one_or_none()
        if revoked is not None or disabled is True:
            raise ArtifactReviewDenied(401, "Senior reviewer credential revoked")

    @staticmethod
    async def _fence(
        db: Any,
        *,
        flow_id: str,
        revision: int,
        version: int,
        authorization_id: str,
        authorization_sha256: str,
        writing: bool,
        expected_engagement_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Hold session+Flow locks in the same order as FlowArtifactStore.

        Revocation and Flow revisions serialize against this transaction.
        Upload digest is checked against the actual BYTEA independently.
        """
        resolved = (
            (
                await db.execute(
                    text("SELECT engagement_id FROM execution_flows WHERE id=:fid"),
                    {"fid": flow_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if resolved is None:
            raise ArtifactReviewDenied(404, "Flow not found")
        sid = resolved["engagement_id"]
        if expected_engagement_id is not None and expected_engagement_id != sid:
            raise ArtifactReviewDenied(403, "Review tenant binding differs")
        session = (
            (
                await db.execute(
                    text(
                        "SELECT created_by,phase FROM session_states "
                        "WHERE session_id=:sid FOR SHARE"
                    ),
                    {"sid": sid},
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            session is None
            or not isinstance(session.get("created_by"), str)
            or not session["created_by"]
        ):
            raise ArtifactReviewDenied(403, "Flow tenant owner unavailable")
        try:
            signed = await guard_sql(db, sid, expected_version=version)
        except AuthorizationDenied as exc:
            raise ArtifactReviewDenied(403, "Active signed authorization required") from exc
        if (
            signed.authorization_id != authorization_id
            or not hmac.compare_digest(signed.policy_sha256, authorization_sha256)
            or signed.policy.get("created_by") != session["created_by"]
        ):
            raise ArtifactReviewDenied(409, "Current signed authorization differs")
        locked = (
            (
                await db.execute(
                    text(
                        "SELECT id,engagement_id,revision,status FROM execution_flows "
                        f"WHERE id=:fid AND engagement_id=:sid "
                        f"{'FOR UPDATE' if writing else 'FOR SHARE'}"
                    ),
                    {"fid": flow_id, "sid": sid},
                )
            )
            .mappings()
            .one_or_none()
        )
        if locked is None:
            raise ArtifactReviewDenied(404, "Flow not found")
        if (
            locked["revision"] != revision
            or locked["status"] not in {"pending", "running"}
            or session["phase"] in {"halted", "completed"}
        ):
            raise ArtifactReviewDenied(409, "Flow state or revision changed")
        return {"sid": sid, "owner": session["created_by"]}

    @staticmethod
    async def _snapshot(
        db: Any,
        *,
        flow_id: str,
        artifact_id: str,
        revision: int,
        version: int,
        sha256: str,
        authorization_id: str,
        authorization_sha256: str,
        writing: bool,
        expected_engagement_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        binding = await FlowArtifactReviewStore._fence(
            db,
            flow_id=flow_id,
            revision=revision,
            version=version,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
            writing=writing,
            expected_engagement_id=expected_engagement_id,
        )
        sid, owner = binding["sid"], binding["owner"]
        row = (
            (
                await db.execute(
                    text(
                        "SELECT id,flow_id,engagement_id,owner_id,name,sha256,size_bytes,"
                        "flow_revision,authorization_version,authorization_sha256,content "
                        "FROM flow_artifacts WHERE id=:id AND flow_id=:fid AND "
                        "engagement_id=:sid"
                    ),
                    {"id": artifact_id, "fid": flow_id, "sid": sid},
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise ArtifactReviewDenied(404, "Artifact not found")
        if (
            row["owner_id"] != owner
            or row["flow_revision"] != revision
            or row["authorization_version"] != version
            or not isinstance(row["authorization_sha256"], str)
            or not hmac.compare_digest(row["authorization_sha256"], authorization_sha256)
        ):
            raise ArtifactReviewDenied(409, "Artifact owner or signed lineage changed")
        _validated_bytes(row, sha256)
        return {**binding, "row": row}

    @staticmethod
    def _receipt(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "review_id": row["id"],
            "artifact_id": row["artifact_id"],
            "flow_id": row["flow_id"],
            "engagement_id": row["engagement_id"],
            "artifact_sha256": row["artifact_sha256"],
            "flow_revision": row["flow_revision"],
            "authorization_id": row["authorization_id"],
            "authorization_version": row["authorization_version"],
            "authorization_sha256": row["authorization_sha256"],
            "uploader_sub": row["uploader_sub"],
            "reviewer_sub": row["reviewer_sub"],
            "reviewer_role": row["reviewer_role"],
            "decision": row["decision"],
            "reviewed_at": row["created_at"].isoformat(),
            "verified_review": True,
            "approved": row["decision"] == "approve",
        }

    async def decide(
        self,
        *,
        flow_id: str,
        artifact_id: str,
        revision: int,
        version: int,
        sha256: str,
        authorization_id: str,
        authorization_sha256: str,
        reviewer_sub: str,
        reviewer_role: str,
        decision: str,
        reason: str,
        reviewer_token_sha256: Optional[str] = None,
        reviewer_expires_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        _expected(
            flow_id=flow_id,
            artifact_id=artifact_id,
            revision=revision,
            version=version,
            sha256=sha256,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
        )
        _identifier(reviewer_sub, _SUBJECT)
        if reviewer_role != "senior_operator":
            raise ArtifactReviewDenied(403, "Independent senior review required")
        if decision not in {"approve", "reject"}:
            raise ArtifactReviewDenied(422, "Explicit approval or rejection required")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 512:
            raise ArtifactReviewDenied(422, "Bounded human review reason required")
        review_id = "review-" + uuid.uuid4().hex
        event_id = "evt-" + uuid.uuid4().hex
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    snapshot = await self._snapshot(
                        db,
                        flow_id=flow_id,
                        artifact_id=artifact_id,
                        revision=revision,
                        version=version,
                        sha256=sha256,
                        authorization_id=authorization_id,
                        authorization_sha256=authorization_sha256,
                        writing=True,
                    )
                    sid, owner = snapshot["sid"], snapshot["owner"]
                    if reviewer_sub == owner or reviewer_sub == snapshot["row"]["owner_id"]:
                        raise ArtifactReviewDenied(403, "Uploader cannot review own artifact")
                    if reviewer_expires_at is not None or settings.operator_revocation_required:
                        await self._reviewer_fence(
                            db,
                            reviewer_sub=reviewer_sub,
                            reviewer_token_sha256=reviewer_token_sha256,
                            reviewer_expires_at=reviewer_expires_at,
                        )
                    duplicate = (
                        await db.execute(
                            text("SELECT id FROM flow_artifact_reviews " "WHERE artifact_id=:id"),
                            {"id": artifact_id},
                        )
                    ).scalar_one_or_none()
                    if duplicate:
                        raise ArtifactReviewDenied(409, "Artifact already reviewed")
                    inserted = (
                        (
                            await db.execute(
                                text(
                                    "INSERT INTO flow_artifact_reviews "
                                    "(id,artifact_id,flow_id,engagement_id,uploader_sub,"
                                    "reviewer_sub,reviewer_role,decision,reason,artifact_sha256,"
                                    "flow_revision,authorization_id,authorization_version,"
                                    "authorization_sha256) "
                                    "VALUES (:id,:artifact,:fid,:sid,:uploader,:reviewer,"
                                    "'senior_operator',"
                                    ":decision,:reason,:sha,:revision,:auth_id,:version,:auth_sha) "
                                    "RETURNING id,artifact_id,flow_id,engagement_id,uploader_sub,"
                                    "reviewer_sub,reviewer_role,decision,artifact_sha256,flow_revision,"
                                    "authorization_id,authorization_version,authorization_sha256,"
                                    "created_at"
                                ),
                                {
                                    "id": review_id,
                                    "artifact": artifact_id,
                                    "fid": flow_id,
                                    "sid": sid,
                                    "uploader": owner,
                                    "reviewer": reviewer_sub,
                                    "decision": decision,
                                    "reason": reason.strip(),
                                    "sha": sha256,
                                    "revision": revision,
                                    "auth_id": authorization_id,
                                    "version": version,
                                    "auth_sha": authorization_sha256,
                                },
                            )
                        )
                        .mappings()
                        .one()
                    )
                    # Notification carries identities and decision only, never
                    # source bytes, raw snippets or human reason.
                    event = {
                        "kind": "flow.artifact_reviewed",
                        "event_id": event_id,
                        "engagement_id": sid,
                        "flow_id": flow_id,
                        "artifact_id": artifact_id,
                        "review_id": review_id,
                        "decision": decision,
                        "flow_revision": revision,
                        "authorization_version": version,
                    }
                    await db.execute(
                        text(
                            "INSERT INTO supervision_events "
                            "(id,engagement_id,kind,actor_id,payload,idempotency_key) "
                            "VALUES (:event,:sid,'flow.artifact_reviewed',:actor,"
                            "CAST(:payload AS jsonb),:dedupe)"
                        ),
                        {
                            "event": event_id,
                            "sid": sid,
                            "actor": reviewer_sub,
                            "payload": json.dumps(event),
                            "dedupe": "review:" + artifact_id,
                        },
                    )
                    await db.execute(
                        text(
                            "INSERT INTO supervision_outbox "
                            "(id,event_id,engagement_id,topic,payload) "
                            "VALUES (:id,:event,:sid,'flow.artifact_reviewed',"
                            "CAST(:payload AS jsonb))"
                        ),
                        {
                            "id": "out-" + uuid.uuid4().hex,
                            "event": event_id,
                            "sid": sid,
                            "payload": json.dumps(event),
                        },
                    )
                    if reviewer_expires_at is not None or settings.operator_revocation_required:
                        await self._reviewer_fence(
                            db,
                            reviewer_sub=reviewer_sub,
                            reviewer_token_sha256=reviewer_token_sha256,
                            reviewer_expires_at=reviewer_expires_at,
                        )
                    return self._receipt(inserted)
        except ArtifactReviewDenied:
            raise
        except Exception as exc:
            raise ArtifactReviewDenied(503, "Durable artifact review unavailable") from exc

    async def read_verified(
        self,
        *,
        flow_id: str,
        artifact_id: str,
        revision: int,
        version: int,
        sha256: str,
        authorization_id: str,
        authorization_sha256: str,
        include_approved_text: bool = False,
        reviewer_sub: Optional[str] = None,
        reviewer_token_sha256: Optional[str] = None,
        reviewer_expires_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return current signed, SHA-verified receipt metadata, or UNKNOWN.

        This is the internal agent-facing trust contract. It returns no model
        text by default and does not promote an uploaded digest into approval.
        An explicit private text request may return a short reviewed UTF-8
        value as *inert data*, never as a trusted instruction or finding.
        """
        _expected(
            flow_id=flow_id,
            artifact_id=artifact_id,
            revision=revision,
            version=version,
            sha256=sha256,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
        )
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    snapshot = await self._snapshot(
                        db,
                        flow_id=flow_id,
                        artifact_id=artifact_id,
                        revision=revision,
                        version=version,
                        sha256=sha256,
                        authorization_id=authorization_id,
                        authorization_sha256=authorization_sha256,
                        writing=False,
                    )
                    if reviewer_sub is not None:
                        await self._reviewer_fence(
                            db,
                            reviewer_sub=reviewer_sub,
                            reviewer_token_sha256=reviewer_token_sha256,
                            reviewer_expires_at=reviewer_expires_at,
                        )
                    row = (
                        (
                            await db.execute(
                                text(
                                    "SELECT id,artifact_id,flow_id,engagement_id,"
                                    "uploader_sub,reviewer_sub,reviewer_role,decision,artifact_sha256,"
                                    "flow_revision,authorization_id,authorization_version,"
                                    "authorization_sha256,created_at FROM flow_artifact_reviews "
                                    "WHERE artifact_id=:id AND flow_id=:fid AND engagement_id=:sid"
                                ),
                                {"id": artifact_id, "fid": flow_id, "sid": snapshot["sid"]},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if row is None:
                        if reviewer_sub is not None:
                            await self._reviewer_fence(
                                db,
                                reviewer_sub=reviewer_sub,
                                reviewer_token_sha256=reviewer_token_sha256,
                                reviewer_expires_at=reviewer_expires_at,
                            )
                        return {
                            "verified_review": False,
                            "approved": False,
                            "decision": "UNKNOWN",
                            "artifact_id": artifact_id,
                        }
                    if (
                        row["uploader_sub"] != snapshot["owner"]
                        or row["reviewer_sub"] == snapshot["owner"]
                        or row["reviewer_role"] != "senior_operator"
                        or row["artifact_sha256"] != sha256
                        or row["authorization_id"] != authorization_id
                        or row["authorization_version"] != version
                        or row["flow_revision"] != revision
                        or row["authorization_sha256"] != authorization_sha256
                    ):
                        raise ArtifactReviewDenied(409, "Artifact review provenance changed")
                    receipt = self._receipt(row)
                    if include_approved_text and receipt["approved"]:
                        artifact = snapshot["row"]
                        content = artifact["content"]
                        name = artifact["name"]
                        if (
                            isinstance(name, str)
                            and name.lower().endswith((".txt", ".md"))
                            and len(content) <= 4096
                        ):
                            try:
                                decoded = content.decode("utf-8", errors="strict")
                            except UnicodeDecodeError:
                                decoded = ""
                            if decoded and all(
                                ord(char) >= 32 or char in "\n\t" for char in decoded
                            ):
                                receipt["untrusted_reviewed_text"] = decoded
                                receipt["text_trust_boundary"] = "inert_reviewed_data_only"
                                receipt["security_evidence_verified"] = False
                    if reviewer_sub is not None:
                        await self._reviewer_fence(
                            db,
                            reviewer_sub=reviewer_sub,
                            reviewer_token_sha256=reviewer_token_sha256,
                            reviewer_expires_at=reviewer_expires_at,
                        )
                    return receipt
        except ArtifactReviewDenied:
            raise
        except Exception as exc:
            raise ArtifactReviewDenied(
                503, "Durable artifact review verification unavailable"
            ) from exc

    async def read_verified_approval(self, **expected: Any) -> Optional[Dict[str, Any]]:
        """Explicit approval-only gate for future inert knowledge retrieval."""
        receipt = await self.read_verified(**expected)
        return receipt if receipt.get("verified_review") and receipt.get("approved") else None

    async def read_approved_inert_text(self, **expected: Any) -> Optional[Dict[str, Any]]:
        """Bounded source data with independently rechecked approval provenance.

        Does not instruct or invoke a model. A caller must separately isolate
        this untrusted text at its own supervised inference boundary.
        """
        receipt = await self.read_verified(**expected, include_approved_text=True)
        if (
            receipt.get("verified_review")
            and receipt.get("approved")
            and "untrusted_reviewed_text" in receipt
        ):
            return receipt
        return None

    async def list_review_candidates(
        self,
        *,
        flow_id: str,
        engagement_id: str,
        revision: int,
        version: int,
        authorization_id: str,
        authorization_sha256: str,
        reviewer_sub: str,
        reviewer_role: str,
        limit: int = 10,
        offset: int = 0,
        reviewer_token_sha256: Optional[str] = None,
        reviewer_expires_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Independent senior-only tenant/Flow inventory; no raw file content."""
        _identifier(flow_id)
        _identifier(engagement_id)
        _identifier(authorization_id, _AUTH_ID)
        _identifier(reviewer_sub, _SUBJECT)
        if (
            reviewer_role != "senior_operator"
            or type(revision) is not int
            or revision < 0
            or type(version) is not int
            or version < 1
            or not isinstance(authorization_sha256, str)
            or _SHA.fullmatch(authorization_sha256) is None
            or type(limit) is not int
            or not 1 <= limit <= 10
            or type(offset) is not int
            or not 0 <= offset <= 64
        ):
            raise ArtifactReviewDenied(422, "Invalid bounded review inventory request")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    binding = await self._fence(
                        db,
                        flow_id=flow_id,
                        revision=revision,
                        version=version,
                        authorization_id=authorization_id,
                        authorization_sha256=authorization_sha256,
                        writing=False,
                        expected_engagement_id=engagement_id,
                    )
                    if reviewer_sub == binding["owner"]:
                        raise ArtifactReviewDenied(403, "Uploader cannot review own artifacts")
                    if reviewer_expires_at is not None or settings.operator_revocation_required:
                        await self._reviewer_fence(
                            db,
                            reviewer_sub=reviewer_sub,
                            reviewer_token_sha256=reviewer_token_sha256,
                            reviewer_expires_at=reviewer_expires_at,
                        )
                    records = (
                        (
                            await db.execute(
                                text(
                                    "SELECT a.id,a.flow_id,a.engagement_id,a.owner_id,a.name,"
                                    "a.size_bytes,a.sha256,a.flow_revision,"
                                    "a.authorization_version,a.authorization_sha256,"
                                    "a.content,r.decision AS review_decision,"
                                    "r.uploader_sub AS review_uploader_sub,"
                                    "r.reviewer_sub AS review_reviewer_sub,"
                                    "r.reviewer_role AS review_reviewer_role,"
                                    "r.artifact_sha256 AS review_artifact_sha256,"
                                    "r.flow_revision AS review_flow_revision,"
                                    "r.authorization_id AS review_authorization_id,"
                                    "r.authorization_version AS review_authorization_version,"
                                    "r.authorization_sha256 AS review_authorization_sha256,"
                                    "r.flow_id AS review_flow_id,"
                                    "r.engagement_id AS review_engagement_id "
                                    "FROM flow_artifacts AS a "
                                    "LEFT JOIN flow_artifact_reviews AS r ON r.artifact_id=a.id "
                                    "WHERE a.flow_id=:fid AND a.engagement_id=:sid "
                                    "AND a.owner_id=:owner ORDER BY a.id "
                                    "LIMIT :limit OFFSET :offset"
                                ),
                                {
                                    "fid": flow_id,
                                    "sid": engagement_id,
                                    "owner": binding["owner"],
                                    "limit": limit,
                                    "offset": offset,
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if len(records) > limit:
                        raise ArtifactReviewDenied(503, "Review inventory is unbounded")
                    items = []
                    for row in records:
                        if (
                            row["engagement_id"] != binding["sid"]
                            or row["flow_id"] != flow_id
                            or row["owner_id"] != binding["owner"]
                            or row["flow_revision"] != revision
                            or row["authorization_version"] != version
                            or row["authorization_sha256"] != authorization_sha256
                        ):
                            raise ArtifactReviewDenied(409, "Review inventory lineage changed")
                        _validated_bytes(row, row["sha256"])
                        if row["review_decision"] is not None and (
                            row["review_decision"] not in {"approve", "reject"}
                            or row["review_uploader_sub"] != binding["owner"]
                            or row["review_reviewer_sub"] == binding["owner"]
                            or row["review_reviewer_role"] != "senior_operator"
                            or row["review_artifact_sha256"] != row["sha256"]
                            or row["review_flow_revision"] != revision
                            or row["review_authorization_id"] != authorization_id
                            or row["review_authorization_version"] != version
                            or row["review_authorization_sha256"] != authorization_sha256
                            or row["review_flow_id"] != flow_id
                            or row["review_engagement_id"] != binding["sid"]
                        ):
                            # Never show an old/forged 'approve' or 'reject'
                            # when the originally reviewed source was swapped
                            # or its signed tenant/Flow lineage has changed.
                            raise ArtifactReviewDenied(
                                409, "Review decision source provenance changed"
                            )
                        items.append(
                            {
                                "artifact_id": row["id"],
                                "name": row["name"],
                                "size_bytes": row["size_bytes"],
                                "sha256": row["sha256"],
                                "flow_revision": revision,
                                "authorization_version": version,
                                "review_decision": row["review_decision"] or "UNKNOWN",
                                "verified_bytes": True,
                                "approved": False,  # candidate list never asserts release
                            }
                        )
                    if reviewer_expires_at is not None or settings.operator_revocation_required:
                        await self._reviewer_fence(
                            db,
                            reviewer_sub=reviewer_sub,
                            reviewer_token_sha256=reviewer_token_sha256,
                            reviewer_expires_at=reviewer_expires_at,
                        )
                    return {
                        "engagement_id": binding["sid"],
                        "flow_id": flow_id,
                        "items": items,
                        "limit": limit,
                        "offset": offset,
                        "next_offset": (
                            offset + len(items)
                            if len(items) == limit and offset + len(items) <= 64
                            else None
                        ),
                    }
        except ArtifactReviewDenied:
            raise
        except Exception as exc:
            raise ArtifactReviewDenied(503, "Durable review inventory unavailable") from exc

    async def read_review_source(
        self,
        *,
        flow_id: str,
        engagement_id: str,
        artifact_id: str,
        revision: int,
        version: int,
        sha256: str,
        authorization_id: str,
        authorization_sha256: str,
        reviewer_sub: str,
        reviewer_role: str,
        reviewer_token_sha256: Optional[str] = None,
        reviewer_expires_at: Optional[int] = None,
    ) -> tuple[Dict[str, Any], bytes]:
        """Verified 2-MiB-max bytes for a different signed senior reviewer.

        An independent review needs to inspect the original artifact. This
        method gives NO approval status and never routes bytes to execution.
        """
        _expected(
            flow_id=flow_id,
            artifact_id=artifact_id,
            revision=revision,
            version=version,
            sha256=sha256,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
        )
        _identifier(engagement_id)
        _identifier(reviewer_sub, _SUBJECT)
        if reviewer_role != "senior_operator":
            raise ArtifactReviewDenied(403, "Signed senior reviewer required")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    binding = await self._snapshot(
                        db,
                        flow_id=flow_id,
                        artifact_id=artifact_id,
                        revision=revision,
                        version=version,
                        sha256=sha256,
                        authorization_id=authorization_id,
                        authorization_sha256=authorization_sha256,
                        expected_engagement_id=engagement_id,
                        writing=False,
                    )
                    if reviewer_sub == binding["owner"]:
                        raise ArtifactReviewDenied(403, "Uploader cannot review own artifact")
                    if reviewer_expires_at is not None or settings.operator_revocation_required:
                        await self._reviewer_fence(
                            db,
                            reviewer_sub=reviewer_sub,
                            reviewer_token_sha256=reviewer_token_sha256,
                            reviewer_expires_at=reviewer_expires_at,
                        )
                    return (
                        {
                            "artifact_id": artifact_id,
                            "sha256": sha256,
                            "size_bytes": binding["row"]["size_bytes"],
                            "verified_bytes": True,
                            "approved": False,
                        },
                        binding["row"]["content"],
                    )
        except ArtifactReviewDenied:
            raise
        except Exception as exc:
            raise ArtifactReviewDenied(503, "Durable review source unavailable") from exc
