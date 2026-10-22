"""One-use, byte-safe original Flow artifact offer to an authenticated native MCP.

The native process receives the *data* only after redemption of its separately
signed 0029 grant.  A PostgreSQL CAS offer is committed before bytes cross the
network.  A lost response is UNKNOWN and MUST NOT cause replay.  The offer is
not proof of native receipt, staging, interpretation, target contact or effects.

No host paths, filenames supplied by a request, mounts or filesystem writes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any

from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied, FlowMCPActionStore
from ai_osop.memory.flow_resource_exports import MAX_EXPORT_FILES, make_manifest
from ai_osop.memory.native_mcp_folder_stage import approved_folder_stage_plan
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPExecutionGrantStore,
    NativeMCPGrantDenied,
    _authenticate_server,
    _verify,
    _deny,
)


class NativeMCPResourceDelivery:
    """Transactional issuer; never reuse a grant to fetch the resource twice."""

    def __init__(self, action_store: FlowMCPActionStore) -> None:
        if not isinstance(action_store, FlowMCPActionStore):
            raise NativeMCPGrantDenied(503, "Source authority unavailable")
        self.grants = NativeMCPExecutionGrantStore(action_store)

    async def offer(
        self, token: dict[str, Any], *, server_id: str, server_secret: str
    ) -> dict[str, Any]:
        _authenticate_server(server_id, server_secret)
        claims, kid, claims_digest, signature_digest = _verify(token)
        if claims["server_id"] != server_id or claims["resource_sha256"] is None:
            _deny(403, "A redeemed native reviewed-resource authority is required")
        try:
            async with self.grants.actions._sessions()() as db:
                async with db.begin():
                    # Identity discovery does NOT lock the grant first: the
                    # original Action lock must precede the grant lock, using
                    # exactly the same ordering as redemption.
                    observed = await self.grants._grant(db, claims["grant_id"], lock=False)
                    if observed is None or observed["status"] != "redeemed":
                        _deny(409, "Durably redeemed resource grant unavailable")
                    self.grants._signed(claims, observed)
                    if (
                        observed["server_id"] != server_id
                        or observed["kid"] != kid
                        or observed["claims_sha256"] != claims_digest
                        or observed["signature_sha256"] != signature_digest
                    ):
                        _deny(403, "Native reviewed resource identity changed")
                    from ai_osop.memory.native_mcp_execution_grants import _binding

                    b = _binding(
                        {
                            "engagement_id": observed["engagement_id"],
                            "flow_id": observed["flow_id"],
                            "revision": observed["flow_revision"],
                            "version": observed["authorization_version"],
                            "authorization_id": observed["authorization_id"],
                            "authorization_sha256": observed["authorization_sha256"],
                        }
                    )
                    original = await self.grants._source(
                        db, b, observed["owner_id"], observed["action_id"]
                    )
                    locked = await self.grants._grant(db, claims["grant_id"], lock=True)
                    if locked is None or locked["status"] != "redeemed":
                        _deny(409, "Native reviewed resource state changed")
                    self.grants._same(locked, original)
                    self.grants._signed(claims, locked)
                    if (
                        locked["kid"] != kid
                        or locked["claims_sha256"] != claims_digest
                        or locked["signature_sha256"] != signature_digest
                    ):
                        _deny(403, "Native resource signer changed")
                    now = await self.grants._now(db)
                    if now < locked["issued_at"] or now >= locked["expires_at"]:
                        _deny(409, "Resource grant expired before original bytes offered")
                    # Revalidate actual senior-reviewed, task-pinned original
                    # BYTEA; NEVER trust the hash in an untrusted token alone.
                    await self.grants._resources(db, original, locked["resource_sha256"])
                    snapshot_rows = (
                        (
                            await db.execute(
                                text(
                                    "SELECT id,flow_id,name,size_bytes,sha256,"
                                    "flow_revision,authorization_version,content "
                                    "FROM flow_artifacts WHERE engagement_id=:eng "
                                    "AND flow_id=:flow AND owner_id=:owner "
                                    "ORDER BY created_at,id LIMIT :limit FOR SHARE"
                                ),
                                {
                                    "eng": original["engagement_id"],
                                    "flow": original["flow_id"],
                                    "owner": original["owner_id"],
                                    "limit": MAX_EXPORT_FILES + 1,
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if not 1 <= len(snapshot_rows) <= MAX_EXPORT_FILES:
                        _deny(409, "Bounded reviewed original bytes unavailable")
                    snapshot = [(dict(item), item["content"]) for item in snapshot_rows]
                    manifest = make_manifest(
                        original["flow_id"],
                        original["flow_revision"],
                        original["authorization_version"],
                        snapshot,
                    )
                    digest = manifest["manifest_sha256"]
                    if not hmac.compare_digest(digest, locked["resource_sha256"]):
                        _deny(409, "Original byte manifest differs from signed Task")
                    # The approved Task may optionally pin a mutable 0026
                    # virtual-folder catalog. It must still match exactly NOW.
                    # A missing Task pin is RAM-only, NOT filesystem approval.
                    folder_stage = await approved_folder_stage_plan(db, original, manifest)
                    # The manifest verifies bytes/filenames/permissions already;
                    # order by deterministic artifact_id, not user filenames.
                    by_id = {metadata["id"]: body for metadata, body in snapshot}
                    if len(by_id) != len(snapshot):
                        _deny(409, "Duplicate original artifact identity")
                    files = [
                        {
                            "artifact_id": item["artifact_id"],
                            "sha256": item["sha256"],
                            "content_b64": base64.b64encode(by_id[item["artifact_id"]]).decode(
                                "ascii"
                            ),
                        }
                        for item in manifest["items"]
                    ]
                    # Durable one-use point: commit the offering before the
                    # HTTPS response can reach any worker. No second offer.
                    inserted = (
                        await db.execute(
                            text(
                                "INSERT INTO native_mcp_resource_offers "
                                "(grant_id,engagement_id,flow_id,action_id,request_id,"
                                "server_id,manifest_sha256,claims_sha256,file_count,"
                                "total_size_bytes,folder_staging_sha256,status) VALUES "
                                "(:grant,:eng,:flow,:action,:request,:server,:manifest,"
                                ":claims,:count,:size,:folder_sha,'offered') "
                                "ON CONFLICT DO NOTHING RETURNING grant_id"
                            ),
                            {
                                "grant": locked["grant_id"],
                                "eng": locked["engagement_id"],
                                "flow": locked["flow_id"],
                                "action": locked["action_id"],
                                "request": locked["request_id"],
                                "server": locked["server_id"],
                                "manifest": digest,
                                "claims": claims_digest,
                                "count": manifest["count"],
                                "size": manifest["total_size_bytes"],
                                "folder_sha": (
                                    folder_stage["staging_sha256"]
                                    if folder_stage is not None
                                    else None
                                ),
                            },
                        )
                    ).scalar_one_or_none()
                    if inserted != locked["grant_id"]:
                        _deny(409, "Reviewed resource bytes already offered; outcome UNKNOWN")
                    envelope = {
                        "grant_id": locked["grant_id"],
                        "request_id": locked["request_id"],
                        "manifest_sha256": digest,
                        "manifest": manifest,
                        "files": files,
                    }
                    if folder_stage is not None:
                        envelope["folder_staging"] = folder_stage
                    return envelope
        except MCPActionDenied:
            raise
        except NativeMCPGrantDenied:
            raise
        except Exception as exc:
            # May be a post-COMMIT ACK loss. NEVER auto-retry.
            raise NativeMCPGrantDenied(503, "Reviewed resource delivery outcome UNKNOWN") from exc
