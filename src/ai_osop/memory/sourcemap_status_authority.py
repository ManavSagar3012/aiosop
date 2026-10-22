"""Fresh non-consuming original SourceMap status authority.

This is an independent read-only status permission, NOT another execution
grant and never a SourceMap byte-delivery mechanism. An original 0027 UNKNOWN
Action and its immutable, globally one-use 0035 source preflight must already
exist. Current signed Flow/ROE/Task/reviewer/lease and independently reviewed
0013 original-byte SHA are rechecked in the same PostgreSQL transaction.

Even a signed native completion is provider testimony, not an independently
verified target effect. No original Action is replayed or settled here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import uuid
from typing import Any, Mapping

from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore, MCPActionDenied
from ai_osop.memory.sourcemap_source_authority import (
    CLAIM_FIELDS,
    SourceMapSourceAuthorityStore,
    SourceMapSourceDenied,
    _deny,
    canonical,
    signer,
    validate_request,
)

STATUS_DOMAIN = b"ai-osop/sourcemap-original-status/v1\x00"
STATUS_FIELDS = CLAIM_FIELDS | frozenset({"status_id"})
_SHA_FIELDS = ("artifact_sha256", "manifest_sha256", "authorization_sha256")
_IDENTITY_FIELDS = (
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
    "approval_id",
    "lease_id",
    "authorization_version",
    "authorization_sha256",
    "artifact_sha256",
    "manifest_sha256",
)


class SourceMapStatusAuthorityStore:
    """Re-read authorized original source identity; issue a 5-second status permit."""

    def __init__(self, actions: FlowMCPActionStore) -> None:
        self.sources = SourceMapSourceAuthorityStore(actions)

    @staticmethod
    def _verify_issued(
        preflight: Mapping[str, Any],
        original: Mapping[str, Any],
        manifest_sha256: str,
        requested_sha256: str,
        *,
        current_kid: str,
        now: int,
    ) -> dict[str, Any]:
        if not isinstance(preflight, Mapping):
            _deny()
        try:
            original_issued = {field: preflight[field] for field in CLAIM_FIELDS}
        except KeyError:
            _deny()
        expected = {
            "request_id": original["request_id"],
            "engagement_id": original["engagement_id"],
            "flow_id": original["flow_id"],
            "task_id": original["task_id"],
            "subtask_id": original["subtask_id"],
            "action_id": original["action_id"],
            "owner_id": original["owner_id"],
            "server_id": original["server_id"],
            "tool_name": original["tool_name"],
            "approval_id": original["approval_id"],
            "lease_id": original["lease_id"],
            "authorization_version": original["authorization_version"],
            "authorization_sha256": original["authorization_sha256"],
            "artifact_sha256": requested_sha256,
            "manifest_sha256": manifest_sha256,
        }
        if (
            preflight.get("version") != 1
            or preflight.get("kid") != current_kid
            or preflight.get("committed_at") is None
            or any(preflight.get(k) != value for k, value in expected.items())
            or type(preflight.get("issued_at")) is not int
            or type(preflight.get("expires_at")) is not int
            or not 0 < preflight["expires_at"] - preflight["issued_at"] <= 10
            or preflight["issued_at"] > now
            or type(preflight.get("claims_sha256")) is not str
            or type(preflight.get("signature_sha256")) is not str
            or len(preflight["signature_sha256"]) != 64
            or not all(c in "0123456789abcdef" for c in preflight["signature_sha256"])
            or not hmac.compare_digest(
                hashlib.sha256(canonical(original_issued)).hexdigest(),
                preflight["claims_sha256"],
            )
        ):
            _deny()
        return original_issued

    async def admit(self, supplied: Any) -> dict[str, Any]:
        request = validate_request(supplied)
        kid, key = signer()
        try:
            async with self.sources.actions._sessions()() as db:
                async with db.begin():
                    row, manifest_sha256 = await self.sources._source(db, request)
                    preflight = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_sourcemap_source_preflights "
                                    "WHERE action_id=:action AND request_id=:request "
                                    "AND engagement_id=:eng AND task_id=:task FOR SHARE"
                                ),
                                {
                                    "action": row["action_id"],
                                    "request": row["request_id"],
                                    "eng": row["engagement_id"],
                                    "task": row["task_id"],
                                },
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    now = await self.sources._now(db)
                    issued = self._verify_issued(
                        preflight,
                        row,
                        manifest_sha256,
                        request["artifact_sha256"],
                        current_kid=kid,
                        now=now,
                    )
                    claims = {
                        **issued,
                        "status_id": "nss-" + uuid.uuid4().hex,
                        "issued_at": now,
                        "expires_at": now + 5,
                    }
                    if set(claims) != STATUS_FIELDS:
                        _deny(503)
                    signature = key.sign(STATUS_DOMAIN + canonical(claims))
                    response = {
                        "claims": claims,
                        "kid": kid,
                        "signature": base64.urlsafe_b64encode(signature)
                        .decode("ascii")
                        .rstrip("="),
                    }
            # No UPDATE/INSERT and no resurrected execution after commit.
            return response
        except SourceMapSourceDenied:
            raise
        except MCPActionDenied as exc:
            raise SourceMapSourceDenied(409, "Current original SourceMap status denied") from exc
        except Exception as exc:
            raise SourceMapSourceDenied(503, "Signed SourceMap status unavailable") from exc
