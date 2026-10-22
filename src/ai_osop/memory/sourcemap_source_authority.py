"""One-use PostgreSQL source authority for an ORIGINAL reviewed SourceMap artifact.

Only central durable facts grant access. No byte body, source text or path
leaves the issuer. The native SourceMap process must separately SHA-read its
own immutable, content-addressed original before inspecting it. This module
requires the future 0035 one-shot table; missing migration fails closed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import uuid
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from ai_osop.core.models import ScopeDefinition
from ai_osop.mcp.protocol import SideEffectClass
from ai_osop.memory.flow_mcp_action_dispatch import (
    FlowMCPActionStore,
    MCPActionDenied,
    _ACTION,
    _DIGEST_DOMAIN,
    _SHA,
    _binding,
    _digest,
    _safe_parameters,
)
from ai_osop.memory.flow_artifacts import safe_filename
from ai_osop.memory.flow_resource_exports import _TEXT_TYPES
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

DOMAIN = b"ai-osop/sourcemap-original-preflight/v1\x00"
REQUEST = re.compile(r"req-[a-f0-9]{48}\Z")
ARTIFACT = re.compile(r"artifact-[a-f0-9]{32}\Z")
KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
REQUEST_FIELDS = frozenset(
    {
        "request_id",
        "engagement_id",
        "task_id",
        "server_id",
        "tool_name",
        "artifact_sha256",
    }
)
CLAIM_FIELDS = frozenset(
    {
        "version",
        "preflight_id",
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "owner_id",
        "server_id",
        "tool_name",
        "artifact_sha256",
        "manifest_sha256",
        "approval_id",
        "lease_id",
        "authorization_version",
        "authorization_sha256",
        "issued_at",
        "expires_at",
    }
)


class SourceMapSourceDenied(MCPActionDenied):
    """Redacted source denial: the issuer never returns artifact bytes."""


def _deny(status: int = 409) -> None:
    raise SourceMapSourceDenied(status, "Current original SourceMap authority unavailable")


def canonical(value: Any) -> bytes:
    try:
        data = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        if len(data) > 4096:
            _deny(403)
        return data
    except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
        raise SourceMapSourceDenied(403, "Signed SourceMap metadata unavailable") from exc


def validate_request(value: Any) -> dict[str, str]:
    if type(value) is not dict or set(value) != REQUEST_FIELDS:
        _deny(422)
    if (
        type(value["request_id"]) is not str
        or REQUEST.fullmatch(value["request_id"]) is None
        or type(value["engagement_id"]) is not str
        or not value["engagement_id"].startswith("eng-")
        or IDENTITY.fullmatch(value["engagement_id"]) is None
        or type(value["task_id"]) is not str
        or not value["task_id"].startswith("task-")
        or IDENTITY.fullmatch(value["task_id"]) is None
        or type(value["artifact_sha256"]) is not str
        or _SHA.fullmatch(value["artifact_sha256"]) is None
        or value["server_id"] != "source-map-mcp"
        or value["tool_name"] != "inspect_local_original_sourcemap"
    ):
        _deny(422)
    return dict(value)


def signer() -> tuple[str, Ed25519PrivateKey]:
    """The signer is independently deployed; never sourced from the request."""
    try:
        kid = os.environ["OSOP_SOURCEMAP_SOURCE_SIGNING_KID"]
        encoded = os.environ["OSOP_SOURCEMAP_SOURCE_SIGNING_PRIVATE_KEY_B64"]
        if (
            type(kid) is not str
            or KID.fullmatch(kid) is None
            or type(encoded) is not str
            or not 43 <= len(encoded) <= 44
        ):
            raise ValueError("key metadata")
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if len(raw) != 32 or encoded not in {
            base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
            base64.b64encode(raw).decode("ascii"),
        }:
            raise ValueError("signing key")
        return kid, Ed25519PrivateKey.from_private_bytes(raw)
    except (KeyError, ValueError, TypeError, base64.binascii.Error) as exc:
        raise SourceMapSourceDenied(503, "Independent SourceMap issuer unavailable") from exc


class SourceMapSourceAuthorityStore:
    """A single DB transaction fences immutable Action, senior review and bytes."""

    def __init__(self, actions: FlowMCPActionStore) -> None:
        if not isinstance(actions, FlowMCPActionStore):
            _deny(503)
        self.actions = actions

    @staticmethod
    async def _now(db: Any) -> int:
        moment = (
            await db.execute(text("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint"))
        ).scalar_one()
        if type(moment) is not int or moment <= 0:
            _deny(503)
        return moment

    @staticmethod
    def _intent(row: Mapping[str, Any]) -> None:
        b = {
            "engagement_id": row["engagement_id"],
            "flow_id": row["flow_id"],
            "revision": row["flow_revision"],
            "version": row["authorization_version"],
            "authorization_id": row["authorization_id"],
            "authorization_sha256": row["authorization_sha256"],
        }
        original = {
            **b,
            **{
                field: row[field]
                for field in (
                    "task_id",
                    "subtask_id",
                    "action_id",
                    "owner_id",
                    "approval_id",
                    "lease_id",
                    "lease_owner_id",
                    "server_id",
                    "tool_name",
                    "side_effect_class",
                    "declaration_sha256",
                    "parameters_sha256",
                )
            },
        }
        digest = _digest(_DIGEST_DOMAIN, original, 4096)
        if row.get("intent_sha256") != digest or row.get("request_id") != "req-" + digest[:48]:
            _deny()

    @staticmethod
    def _metadata_manifest(
        flow: str, revision: int, version: int, rows: list[dict[str, Any]]
    ) -> str:
        """Reconstruct immutable signed manifest SHA WITHOUT reading BYTEA.

        The *trusted original* reviewed Task must independently pin this
        digest. Classification follows the inert export's name-derived type;
        this method does not claim to have interpreted or validated source
        content (that was required when the reviewed manifest was created).
        All original BYTEA sizes/hashes are verified INSIDE PostgreSQL.
        """
        source_extensions = {
            ".py",
            ".go",
            ".rs",
            ".java",
            ".c",
            ".h",
            ".cpp",
            ".hpp",
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".sql",
            ".css",
        }
        if len(rows) > 16:
            _deny()
        files = []
        total = 0
        names: set[str] = set()
        for file in rows:
            name = safe_filename(file["name"])
            suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if name.startswith(".") or suffix not in _TEXT_TYPES or name in names:
                _deny()
            names.add(name)
            total += file["size_bytes"]
            if total > 4 * 1024 * 1024:
                _deny()
            files.append(
                {
                    "artifact_id": file["id"],
                    "name": name,
                    "resource_path": "resources/" + name,
                    "size_bytes": file["size_bytes"],
                    "sha256": file["sha256"],
                    "classification": (
                        "utf8_inert_source" if suffix in source_extensions else "utf8_inert_text"
                    ),
                }
            )
        files.sort(key=lambda item: item["resource_path"])
        base = {
            "format": "ai-osop-inert-flow-resources-v1",
            "flow_id": flow,
            "flow_revision": revision,
            "authorization_version": version,
            "count": len(files),
            "total_size_bytes": total,
            "items": files,
            "read_only": True,
            "content_executed": False,
            "host_files_created": False,
            "archive_compression": "stored",
            "artifact_bytes_untrusted": True,
        }
        return hashlib.sha256(canonical(base)).hexdigest()

    @staticmethod
    async def _original_manifest(
        db: Any,
        row: Mapping[str, Any],
        artifact_sha256: str,
    ) -> tuple[str, str]:
        """Rebuild whole resource manifest and review *in one source transaction*.

        Reading a checksum column alone would trust a caller and cannot prove
        original 0013 BYTEA bytes or the distinct 0015 senior review.
        """
        originals = (
            (
                await db.execute(
                    text(
                        "SELECT id,flow_id,engagement_id,owner_id,name,size_bytes,sha256,"
                        "flow_revision,authorization_version,authorization_sha256,"
                        "octet_length(content) AS original_bytes_len,"
                        "encode(sha256(content),'hex') AS original_bytes_sha256 "
                        "FROM flow_artifacts WHERE engagement_id=:eng AND flow_id=:flow "
                        "AND owner_id=:owner ORDER BY id LIMIT 17 FOR SHARE"
                    ),
                    {"eng": row["engagement_id"], "flow": row["flow_id"], "owner": row["owner_id"]},
                )
            )
            .mappings()
            .all()
        )
        if not originals or len(originals) > 16:
            _deny()
        metadata: list[dict[str, Any]] = []
        selected: list[dict[str, Any]] = []
        for raw in originals:
            file = dict(raw)
            original_bytes_len = file.pop("original_bytes_len", None)
            original_bytes_sha256 = file.pop("original_bytes_sha256", None)
            if (
                file.get("engagement_id") != row["engagement_id"]
                or file.get("flow_id") != row["flow_id"]
                or file.get("owner_id") != row["owner_id"]
                or file.get("flow_revision") != row["flow_revision"]
                or file.get("authorization_version") != row["authorization_version"]
                or file.get("authorization_sha256") != row["authorization_sha256"]
                or type(original_bytes_len) is not int
                or file.get("size_bytes") != original_bytes_len
                or not 0 < original_bytes_len <= 2 * 1024 * 1024
                or type(file.get("sha256")) is not str
                or _SHA.fullmatch(file["sha256"]) is None
                or type(original_bytes_sha256) is not str
                or not hmac.compare_digest(original_bytes_sha256, file["sha256"])
            ):
                _deny()
            metadata.append(file)
            if hmac.compare_digest(file["sha256"], artifact_sha256):
                selected.append(file)
        if len(selected) != 1:
            # Ambiguous same-digest artifacts must not select an arbitrary owner.
            _deny()
        digest = SourceMapSourceAuthorityStore._metadata_manifest(
            row["flow_id"],
            row["flow_revision"],
            row["authorization_version"],
            metadata,
        )
        if (
            _SHA.fullmatch(digest) is None
            or len(
                [
                    file
                    for file in metadata
                    if (file["id"] == selected[0]["id"] and file["sha256"] == artifact_sha256)
                ]
            )
            != 1
        ):
            _deny()
        reviewed = (
            (
                await db.execute(
                    text(
                        "SELECT id,artifact_id,flow_id,engagement_id,uploader_sub,"
                        "reviewer_sub,reviewer_role,decision,artifact_sha256,flow_revision,"
                        "authorization_id,authorization_version,authorization_sha256 "
                        "FROM flow_artifact_reviews WHERE artifact_id=:artifact "
                        "AND flow_id=:flow AND engagement_id=:eng FOR SHARE"
                    ),
                    {
                        "artifact": selected[0]["id"],
                        "flow": row["flow_id"],
                        "eng": row["engagement_id"],
                    },
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            reviewed is None
            or reviewed.get("artifact_id") != selected[0]["id"]
            or reviewed.get("flow_id") != row["flow_id"]
            or reviewed.get("engagement_id") != row["engagement_id"]
            or reviewed.get("uploader_sub") != row["owner_id"]
            or reviewed.get("reviewer_sub") in (None, "", row["owner_id"])
            or reviewed.get("reviewer_role") != "senior_operator"
            or reviewed.get("decision") != "approve"
            or reviewed.get("artifact_sha256") != artifact_sha256
            or reviewed.get("flow_revision") != row["flow_revision"]
            or reviewed.get("authorization_id") != row["authorization_id"]
            or reviewed.get("authorization_version") != row["authorization_version"]
            or reviewed.get("authorization_sha256") != row["authorization_sha256"]
        ):
            _deny()
        disabled = (
            await db.execute(
                text(
                    "SELECT disabled FROM operator_subject_controls "
                    "WHERE actor_id=:actor FOR SHARE"
                ),
                {"actor": reviewed["reviewer_sub"]},
            )
        ).scalar_one_or_none()
        if disabled is not False:
            # Missing reviewer controls are not independently current proof.
            _deny()
        return digest, selected[0]["id"]

    async def _source(self, db: Any, request: Mapping[str, str]) -> tuple[dict[str, Any], str]:
        candidate = (
            (
                await db.execute(
                    text("SELECT * FROM flow_mcp_action_dispatches WHERE request_id=:request"),
                    {"request": request["request_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if candidate is None:
            _deny()
        original = dict(candidate)
        if (
            original.get("request_id") != request["request_id"]
            or original.get("engagement_id") != request["engagement_id"]
            or original.get("task_id") != request["task_id"]
            or original.get("server_id") != "source-map-mcp"
            or original.get("tool_name") != "inspect_local_original_sourcemap"
            or original.get("side_effect_class") != SideEffectClass.READ_ONLY.value
            or type(original.get("action_id")) is not str
            or _ACTION.fullmatch(original["action_id"]) is None
        ):
            _deny()
        binding = _binding(
            {
                "engagement_id": original["engagement_id"],
                "flow_id": original["flow_id"],
                "revision": original["flow_revision"],
                "version": original["authorization_version"],
                "authorization_id": original["authorization_id"],
                "authorization_sha256": original["authorization_sha256"],
            }
        )
        session = await self.actions._authority(db, binding, original["owner_id"], dispatch=True)
        current = await self.actions._row(db, original["action_id"], lock=True)
        if current is None or current != original:
            _deny()
        self.actions._same(current, binding, original["owner_id"])
        if (
            current.get("status") != "unknown"
            or current.get("cancel_requested") is not False
            or current.get("receipt_sha256") is not None
        ):
            _deny()
        self._intent(current)
        attempt = (
            await db.execute(
                text(
                    "SELECT 1 FROM flow_mcp_action_dispatch_events "
                    "WHERE action_id=:action AND engagement_id=:eng AND flow_id=:flow "
                    "AND kind='dispatch_attempted' AND status='unknown' "
                    "AND intent_sha256=:intent LIMIT 1 FOR SHARE"
                ),
                {
                    "action": current["action_id"],
                    "eng": current["engagement_id"],
                    "flow": current["flow_id"],
                    "intent": current["intent_sha256"],
                },
            )
        ).scalar_one_or_none()
        if attempt != 1:
            _deny()
        definition = self.actions._declaration("source-map-mcp", "inspect_local_original_sourcemap")
        if (
            definition.side_effect_class is not SideEffectClass.READ_ONLY
            or definition.requires_approval is not True
            or definition.scope_check is not True
            or self.actions.declaration_sha256(definition, "source-map-mcp")
            != current["declaration_sha256"]
        ):
            _deny()
        parameters = _safe_parameters(
            current["safe_parameters"],
            definition,
            server_id="source-map-mcp",
        )
        if (
            set(parameters) != {"artifact_sha256"}
            or parameters["artifact_sha256"] != request["artifact_sha256"]
            or self.actions.parameters_sha256(parameters) != current["parameters_sha256"]
        ):
            _deny()
        scope = ScopeEnforcer(ScopeDefinition.model_validate(session["scope"]))
        scope.validate_time_window()
        validate_payload_targets(scope, parameters, require_target=False)
        # READ_ONLY never grants a target fetch, scanner invocation, or new
        # budget debit. No 0030 Go resource delivery token is accepted here.
        roe = (
            (
                await db.execute(
                    text("SELECT roe FROM session_states WHERE session_id=:eng FOR SHARE"),
                    {"eng": current["engagement_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if roe is None or type(roe.get("roe")) is not dict:
            _deny()
        if (
            roe["roe"].get("allow_read_only") is False
            or roe["roe"].get("allow_source_map_inspection") is False
        ):
            _deny()
        approved = await self.actions._approved_task(
            db,
            binding,
            current["owner_id"],
            current["task_id"],
            current["subtask_id"],
            current["server_id"],
            current["tool_name"],
            current["declaration_sha256"],
            current["parameters_sha256"],
            current["side_effect_class"],
            scope,
        )
        if any(
            approved.get(field) != current[field]
            for field in ("action_id", "approval_id", "lease_id", "lease_owner_id")
        ):
            _deny()
        task = (
            (
                await db.execute(
                    text(
                        "SELECT payload FROM tasks WHERE id=:task AND engagement_id=:eng FOR UPDATE"
                    ),
                    {"task": current["task_id"], "eng": current["engagement_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        payload = task.get("payload") if task is not None else None
        if (
            type(payload) is not dict
            or type(payload.get("resource_artifact_id")) is not str
            or ARTIFACT.fullmatch(payload["resource_artifact_id"]) is None
            or payload.get("resource_artifact_sha256") != request["artifact_sha256"]
            or payload.get("resource_authorization_sha256") != current["authorization_sha256"]
            or type(payload.get("resource_command_sha256")) is not str
            or _SHA.fullmatch(payload["resource_command_sha256"]) is None
            or payload["resource_command_sha256"] != current["parameters_sha256"]
        ):
            _deny()
        manifest_digest, selected_artifact = await self._original_manifest(
            db,
            current,
            request["artifact_sha256"],
        )
        if (
            selected_artifact != payload["resource_artifact_id"]
            or type(payload.get("resource_manifest_sha256")) is not str
            or _SHA.fullmatch(payload["resource_manifest_sha256"]) is None
            or not hmac.compare_digest(payload["resource_manifest_sha256"], manifest_digest)
        ):
            # Recomputed current manifest cannot substitute for the manifest
            # originally signed into the independently reviewed Task. This
            # extra 0027 Task field is a PRIME-owned schema/admission change.
            _deny()
        return current, manifest_digest

    async def admit(self, claimed: Any) -> dict[str, Any]:
        request = validate_request(claimed)
        kid, private = signer()  # Deny before any SQL lock/write if unconfigured.
        try:
            async with self.actions._sessions()() as db:
                async with db.begin():
                    row, manifest_sha256 = await self._source(db, request)
                    now = await self._now(db)
                    claims = {
                        "version": 1,
                        "preflight_id": "nsp-" + uuid.uuid4().hex,
                        **{
                            name: row[name]
                            for name in (
                                "request_id",
                                "engagement_id",
                                "flow_id",
                                "task_id",
                                "subtask_id",
                                "action_id",
                                "owner_id",
                                "server_id",
                                "tool_name",
                                "approval_id",
                                "lease_id",
                                "authorization_version",
                                "authorization_sha256",
                            )
                        },
                        "artifact_sha256": request["artifact_sha256"],
                        "manifest_sha256": manifest_sha256,
                        "issued_at": now,
                        "expires_at": now + 10,
                    }
                    if set(claims) != CLAIM_FIELDS:
                        _deny(503)
                    encoded = canonical(claims)
                    signature = private.sign(DOMAIN + encoded)
                    saved = {
                        **claims,
                        "kid": kid,
                        "claims_sha256": hashlib.sha256(encoded).hexdigest(),
                        "signature_sha256": hashlib.sha256(signature).hexdigest(),
                    }
                    inserted = (
                        await db.execute(
                            text(
                                "INSERT INTO native_sourcemap_source_preflights ("
                                + ",".join(saved)
                                + ") VALUES ("
                                + ",".join(":" + key for key in saved)
                                + ") ON CONFLICT DO NOTHING RETURNING preflight_id"
                            ),
                            saved,
                        )
                    ).scalar_one_or_none()
                    if inserted != claims["preflight_id"]:
                        _deny()
                    token = {
                        "claims": claims,
                        "kid": kid,
                        "signature": base64.urlsafe_b64encode(signature)
                        .decode("ascii")
                        .rstrip("="),
                    }
            # Only AFTER successful commit, never during an open transaction.
            return token
        except SourceMapSourceDenied:
            raise
        except MCPActionDenied as exc:
            raise SourceMapSourceDenied(409, "Original signed Action unavailable") from exc
        except Exception as exc:
            # Also covers missing 0035 migration or ambiguous commit/ACK.
            raise SourceMapSourceDenied(503, "Durable SourceMap source unavailable") from exc
