"""Post-commit-only, one-shot SourceMap 0035/0029 provenance binding.

This unmounted central service does NOT mint/redeem a grant, issue 0035
preflights, deliver files, stage mounts, assert 0033 worker activity, or replay
0027 UNKNOWN. Both *independently signed and already committed* capabilities
must exist before a binding can be recorded. Native 0029 verification STILL
denies SourceMap, so current production admission deliberately fails closed.

0037 bindings are immutable evidence, NEVER permission to invoke a provider.
This post-commit design avoids making either issuer depend on a future row.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
import uuid
from typing import Any, Mapping

from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_execution_grants import _verify as _verify_native
from ai_osop.memory.sourcemap_source_authority import (
    CLAIM_FIELDS,
    DOMAIN as SOURCE_DOMAIN,
    SourceMapSourceAuthorityStore,
    canonical,
    validate_request,
)
from ai_osop.memory.sourcemap_status_authority import SourceMapStatusAuthorityStore
from ai_osop.orchestrator.sourcemap_original_stage import _roots, _signed_claims

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"artifact-[0-9a-f]{32}\Z")
_GRANT = re.compile(r"ngr-[0-9a-f]{32}\Z")
_PREFLIGHT = re.compile(r"nsp-[0-9a-f]{32}\Z")
_COMPARE = (
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "approval_id",
    "lease_id",
    "authorization_version",
    "authorization_sha256",
    "server_id",
    "tool_name",
)
_GRANT_COMPARE = (
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "approval_id",
    "lease_id",
    "lease_owner_id",
    "flow_revision",
    "authorization_id",
    "authorization_version",
    "authorization_sha256",
    "server_id",
    "tool_name",
    "side_effect_class",
    "parameters_sha256",
    "intent_sha256",
)


class SourceMapNativeGrantBindingDenied(ValueError):
    """All failed admissions are non-consuming and do not create a 0037 row."""


def _deny(reason: str = "Original SourceMap signed grant join unavailable") -> None:
    raise SourceMapNativeGrantBindingDenied(reason)


def _same(a: Mapping[str, Any], b: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    return all(
        type(a.get(field)) is type(b.get(field)) and a.get(field) == b.get(field)
        for field in fields
    )


def _hash(value: Any) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _join_snapshot(
    original: Mapping[str, Any],
    preflight: Mapping[str, Any],
    grant: Mapping[str, Any],
    source_claims: Mapping[str, Any],
    native_claims: Mapping[str, Any],
    task_payload: Mapping[str, Any],
    review: Mapping[str, Any],
    *,
    artifact_sha256: str,
    manifest_sha256: str,
    source_kid: str,
    native_kid: str,
    source_signature_sha256: str,
    native_signature_sha256: str,
    native_claims_sha256: str,
    now: int,
) -> dict[str, Any]:
    """Compare *complete* current sources; never infer success from a digest.

    Trusted caller MUST first independently verify BOTH Ed25519 tokens and
    revalidate SourceMap current Flow/ROE/Task/reviewer/0013 BYTEA in the SAME
    PostgreSQL transaction. This routine only produces an inert DB row, not an
    authorization token. No hidden row repair/defaulting is allowed.
    """
    if (
        any(
            not isinstance(row, Mapping)
            for row in (
                original,
                preflight,
                grant,
                source_claims,
                native_claims,
                task_payload,
                review,
            )
        )
        or type(now) is not int
        or now <= 0
        or original.get("status") != "unknown"
        or original.get("cancel_requested") is not False
        or original.get("receipt_sha256") is not None
        or original.get("server_id") != "source-map-mcp"
        or original.get("tool_name") != "inspect_local_original_sourcemap"
        or original.get("side_effect_class") != "READ_ONLY"
        or not _same(original, preflight, _COMPARE)
        or not _same(original, source_claims, _COMPARE)
        or not _same(original, grant, _GRANT_COMPARE)
        or not _same(
            original,
            native_claims,
            (
                "request_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "action_id",
                "server_id",
                "tool_name",
                "authorization_version",
                "authorization_sha256",
                "lease_id",
                "parameters_sha256",
                "side_effect_class",
            ),
        )
        or preflight.get("preflight_id") != source_claims.get("preflight_id")
        or grant.get("grant_id") != native_claims.get("grant_id")
        or type(grant.get("grant_id")) is not str
        or _GRANT.fullmatch(grant["grant_id"]) is None
        or type(preflight.get("preflight_id")) is not str
        or _PREFLIGHT.fullmatch(preflight["preflight_id"]) is None
        or source_claims.get("version") != 1
        or native_claims.get("version") != 1
        or preflight.get("version") != 1
        or preflight.get("kid") != source_kid
        or grant.get("kid") != native_kid
        or grant.get("status") != "issued"
        or type(grant.get("revision")) is not int
        or grant["revision"] != 1
        or type(grant.get("issued_at")) is not int
        or type(grant.get("expires_at")) is not int
        or not grant["issued_at"] <= now < grant["expires_at"]
        or not 0 < grant["expires_at"] - grant["issued_at"] <= 60
        or not _same(
            grant, native_claims, ("issued_at", "expires_at", "resource_sha256", "manifest_sha256")
        )
        or type(preflight.get("issued_at")) is not int
        or type(preflight.get("expires_at")) is not int
        or not preflight["issued_at"] <= now < preflight["expires_at"]
        or not 0 < preflight["expires_at"] - preflight["issued_at"] <= 10
        or not _same(
            preflight,
            source_claims,
            ("issued_at", "expires_at", "artifact_sha256", "manifest_sha256"),
        )
        or grant.get("manifest_sha256") != original.get("declaration_sha256")
        or grant.get("parameters_sha256") != original.get("parameters_sha256")
        or native_claims.get("resource_sha256") != manifest_sha256
        or preflight.get("manifest_sha256") != manifest_sha256
        or preflight.get("artifact_sha256") != artifact_sha256
        or task_payload.get("resource_artifact_sha256") != artifact_sha256
        or task_payload.get("resource_manifest_sha256") != manifest_sha256
        or task_payload.get("resource_authorization_sha256") != original.get("authorization_sha256")
        or task_payload.get("resource_command_sha256") != original.get("parameters_sha256")
        or type(task_payload.get("resource_artifact_id")) is not str
        or _ARTIFACT.fullmatch(task_payload["resource_artifact_id"]) is None
        or review.get("artifact_id") != task_payload["resource_artifact_id"]
        or review.get("artifact_sha256") != artifact_sha256
        or review.get("reviewer_role") != "senior_operator"
        or review.get("decision") != "approve"
        or review.get("uploader_sub") != original.get("owner_id")
        or review.get("reviewer_sub") in (None, "", original.get("owner_id"))
        or not _same(
            review,
            original,
            (
                "engagement_id",
                "flow_id",
                "flow_revision",
                "authorization_id",
                "authorization_version",
                "authorization_sha256",
            ),
        )
        or any(
            not _hash(value)
            for value in (
                artifact_sha256,
                manifest_sha256,
                original.get("declaration_sha256"),
                original.get("parameters_sha256"),
                original.get("authorization_sha256"),
                source_signature_sha256,
                native_signature_sha256,
                native_claims_sha256,
                preflight.get("claims_sha256"),
                preflight.get("signature_sha256"),
                grant.get("claims_sha256"),
                grant.get("signature_sha256"),
            )
        )
        or not hmac.compare_digest(source_signature_sha256, preflight["signature_sha256"])
        or not hmac.compare_digest(native_signature_sha256, grant["signature_sha256"])
        or not hmac.compare_digest(native_claims_sha256, grant["claims_sha256"])
        or not hmac.compare_digest(
            hashlib.sha256(canonical(source_claims)).hexdigest(), preflight["claims_sha256"]
        )
    ):
        _deny("Original 0035/0029 grant, artifact, reviewer or signed lease does not join")

    immutable = {
        "action_id": original["action_id"],
        "request_id": original["request_id"],
        "preflight_id": preflight["preflight_id"],
        "grant_id": grant["grant_id"],
        "artifact_id": task_payload["resource_artifact_id"],
        **{
            name: original[name]
            for name in (
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "owner_id",
                "approval_id",
                "lease_id",
                "lease_owner_id",
                "flow_revision",
                "authorization_id",
                "authorization_version",
                "authorization_sha256",
            )
        },
        "reviewer_id": review["reviewer_sub"],
        "artifact_sha256": artifact_sha256,
        "resource_manifest_sha256": manifest_sha256,
        "declaration_sha256": original["declaration_sha256"],
        "parameters_sha256": original["parameters_sha256"],
        "preflight_claims_sha256": preflight["claims_sha256"],
        "preflight_signature_sha256": source_signature_sha256,
        "grant_claims_sha256": native_claims_sha256,
        "grant_signature_sha256": native_signature_sha256,
        "status": "bound_only",
    }
    immutable["join_sha256"] = hashlib.sha256(canonical(immutable)).hexdigest()
    return immutable


class SourceMapNativeGrantBindingStore:
    """Single-transaction witness of pre-existing authority, never an issuer."""

    def __init__(self, actions: FlowMCPActionStore) -> None:
        if not isinstance(actions, FlowMCPActionStore):
            _deny("Central original 0027 Action store required")
        self.actions = actions
        self.sources = SourceMapSourceAuthorityStore(actions)

    async def bind_existing(
        self, *, source_proof: dict[str, Any], native_grant_token: dict[str, Any]
    ) -> dict[str, Any]:
        """Record immutable 0037 post-commit join only after two valid proofs.

        No 0037 row is a prerequisite for either issuer (no circular dependency).
        Native `_verify` currently denies SourceMap by design; accordingly the
        real method cannot yet reach SQL and MUST NOT report success.
        """
        try:
            # Only centrally enrolled immutable issuer roots; no request roots.
            roots = _roots("OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
            source_claims, _ = _signed_claims(
                source_proof, roots, SOURCE_DOMAIN, CLAIM_FIELDS, int(time.time())
            )
            native_claims, native_kid, native_digest, native_signature_digest = _verify_native(
                native_grant_token
            )
            request = validate_request(
                {
                    key: source_claims[key]
                    for key in (
                        "request_id",
                        "engagement_id",
                        "task_id",
                        "server_id",
                        "tool_name",
                        "artifact_sha256",
                    )
                }
            )
            if (
                native_claims.get("server_id") != "source-map-mcp"
                or native_claims.get("tool_name") != "inspect_local_original_sourcemap"
            ):
                _deny("Exact SourceMap native grant identity missing")

            source_signature = base64.urlsafe_b64decode(source_proof["signature"] + "==")
            source_signature_digest = hashlib.sha256(source_signature).hexdigest()
            async with self.actions._sessions()() as db:
                async with db.begin():
                    # _source rechecks current 0027 UNKNOWN, signed Task,
                    # actual 0013 BYTEA, independent 0015 reviewer enabled,
                    # ROE/Flow/approval/lease and durable dispatch event.
                    original, manifest = await self.sources._source(db, request)
                    clock = await self.sources._now(db)
                    preflight = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_sourcemap_source_preflights "
                                    "WHERE action_id=:action AND request_id=:request FOR SHARE"
                                ),
                                {
                                    "action": original["action_id"],
                                    "request": original["request_id"],
                                },
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    SourceMapStatusAuthorityStore._verify_issued(
                        preflight,
                        original,
                        manifest,
                        request["artifact_sha256"],
                        current_kid=source_proof["kid"],
                        now=clock,
                    )
                    grant = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_mcp_execution_grants "
                                    "WHERE grant_id=:grant FOR SHARE"
                                ),
                                {"grant": native_claims["grant_id"]},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    task = (
                        (
                            await db.execute(
                                text(
                                    "SELECT payload FROM tasks WHERE id=:task "
                                    "AND engagement_id=:eng AND flow_id=:flow FOR SHARE"
                                ),
                                {
                                    "task": original["task_id"],
                                    "eng": original["engagement_id"],
                                    "flow": original["flow_id"],
                                },
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    payload = task.get("payload") if isinstance(task, Mapping) else None
                    if type(payload) is not dict:
                        _deny("Current original reviewed Task payload missing")
                    review = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM flow_artifact_reviews WHERE artifact_id=:id "
                                    "AND engagement_id=:eng AND flow_id=:flow FOR SHARE"
                                ),
                                {
                                    "id": payload.get("resource_artifact_id"),
                                    "eng": original["engagement_id"],
                                    "flow": original["flow_id"],
                                },
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    row = _join_snapshot(
                        original,
                        preflight,
                        grant,
                        source_claims,
                        native_claims,
                        payload,
                        review,
                        artifact_sha256=request["artifact_sha256"],
                        manifest_sha256=manifest,
                        source_kid=source_proof["kid"],
                        native_kid=native_kid,
                        source_signature_sha256=source_signature_digest,
                        native_signature_sha256=native_signature_digest,
                        native_claims_sha256=native_digest,
                        now=clock,
                    )
                    # No 0030 offer/0033 supervisor may precede this post-commit
                    # provenance fence. It still does not authorize either.
                    for table in ("native_mcp_resource_offers", "native_mcp_worker_supervisions"):
                        existing = (
                            await db.execute(
                                text(
                                    f"SELECT 1 FROM {table} WHERE grant_id=:grant LIMIT 1 FOR SHARE"
                                ),
                                {"grant": row["grant_id"]},
                            )
                        ).scalar_one_or_none()
                        if existing is not None:
                            _deny("Existing resource offer or worker cannot be retroactively bound")
                    row["binding_id"] = "snb-" + uuid.uuid4().hex
                    inserted = (
                        await db.execute(
                            text(
                                "INSERT INTO native_sourcemap_grant_bindings ("
                                + ",".join(row)
                                + ") VALUES ("
                                + ",".join(":" + k for k in row)
                                + ") ON CONFLICT DO NOTHING RETURNING binding_id"
                            ),
                            row,
                        )
                    ).scalar_one_or_none()
                    if inserted != row["binding_id"]:
                        _deny("Original SourceMap Action/request already joined or UNKNOWN")
                    return {
                        "binding_id": inserted,
                        "status": "bound_only",
                        "authorizes_execution": False,
                        "authorizes_staging": False,
                    }
        except SourceMapNativeGrantBindingDenied:
            raise
        except Exception as exc:
            raise SourceMapNativeGrantBindingDenied(
                "Independent signed SourceMap native binding unavailable"
            ) from exc
