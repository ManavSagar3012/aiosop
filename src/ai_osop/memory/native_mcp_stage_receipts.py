"""Worker Ed25519 self-attestation for genuine 0031 staged original bytes.

Source verifies a distinct server-owned public key, original signed 0029
grant, current ROE/reviewer/lease, precise 0026 folder assignment and 0030
offering, and records an immutable global one-shot worker-reported receipt.
This is *worker testimony*, not independent sandbox-orchestrator attestation
or target-owner evidence, and cannot close an original UNKNOWN Action.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import text

from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied, FlowMCPActionStore
from ai_osop.memory.flow_resource_exports import MAX_EXPORT_FILES, make_manifest
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPExecutionGrantStore,
    NativeMCPGrantDenied,
    _authenticate_server,
    _binding,
    _deny,
    _verify,
)
from ai_osop.memory.native_mcp_folder_stage import approved_folder_stage_plan

DOMAIN = b"ai-osop/native-stage-receipt/v1\x00"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_KID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,47}\Z")
_FIELDS = frozenset(
    {
        "version",
        "grant_id",
        "request_id",
        "server_id",
        "resource_sha256",
        "folder_staging_sha256",
        "readback_sha256",
        "verified_at",
    }
)


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _public_key(server_id: str, kid: str) -> Ed25519PublicKey:
    configured = os.environ.get("OSOP_NATIVE_STAGE_RECEIPT_TRUST_JSON", "")
    if not 1 <= len(configured) <= 8192:
        _deny(503, "Independent native worker receipt trust is unavailable")
    try:
        keys = json.loads(configured)
        if (
            not isinstance(keys, dict)
            or len(keys) > 8
            or server_id not in keys
            or not isinstance(keys[server_id], dict)
            or set(keys[server_id]) != {"kid", "public_key"}
            or keys[server_id]["kid"] != kid
        ):
            raise ValueError("Untrusted native worker receipt issuer")
        encoded = keys[server_id]["public_key"]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded:
            raise ValueError("Native worker public key invalid")
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise NativeMCPGrantDenied(503, "Native worker trust unavailable") from exc


def _verified_stage_receipt(
    receipt: dict[str, Any], server_id: str
) -> tuple[dict[str, Any], str, str]:
    if (
        type(receipt) is not dict
        or set(receipt) != {"claims", "kid", "signature"}
        or type(receipt["claims"]) is not dict
        or set(receipt["claims"]) != _FIELDS
        or type(receipt["kid"]) is not str
        or not _KID.fullmatch(receipt["kid"])
        or type(receipt["signature"]) is not str
    ):
        _deny(403, "Malformed independently signed worker receipt")
    claims = receipt["claims"]
    if (
        type(claims["version"]) is not int
        or claims["version"] != 1
        or claims["server_id"] != server_id
        or any(
            type(claims[key]) is not str or not _SHA.fullmatch(claims[key])
            for key in ("resource_sha256", "folder_staging_sha256", "readback_sha256")
        )
        or type(claims["verified_at"]) is not int
    ):
        _deny(403, "Invalid worker stage receipt claims")
    canonical = _canonical(claims)
    if len(canonical) > 2048 or len(receipt["signature"]) != 86:
        _deny(403, "Worker receipt exceeds limits")
    try:
        raw = base64.urlsafe_b64decode(
            receipt["signature"] + "=" * (-len(receipt["signature"]) % 4)
        )
        if (
            len(raw) != 64
            or base64.urlsafe_b64encode(raw).decode().rstrip("=") != receipt["signature"]
        ):
            raise ValueError("Canonical signature missing")
        _public_key(server_id, receipt["kid"]).verify(raw, DOMAIN + canonical)
    except (ValueError, TypeError, Exception) as exc:
        # Never reveal if a particular stage receipt key exists.
        raise NativeMCPGrantDenied(403, "Native worker receipt signature denied") from exc
    return claims, hashlib.sha256(canonical).hexdigest(), hashlib.sha256(raw).hexdigest()


def readback_digest(grant_id: str, request_id: str, plan: dict[str, Any]) -> str:
    parts = {
        "grant_id": grant_id,
        "request_id": request_id,
        "folder_staging_sha256": plan["staging_sha256"],
        "files": [
            {
                "artifact_id": item["artifact_id"],
                "relative_path": item["relative_path"],
                "sha256": item["sha256"],
            }
            for item in plan["items"]
        ],
    }
    return hashlib.sha256(b"ai-osop/native-stage-readback/v1\x00" + _canonical(parts)).hexdigest()


class NativeStageReceiptStore:
    def __init__(self, action_store: FlowMCPActionStore) -> None:
        if not isinstance(action_store, FlowMCPActionStore):
            _deny(503, "Current independent native Action authority unavailable")
        self.grants = NativeMCPExecutionGrantStore(action_store)

    async def record(
        self,
        token: dict[str, Any],
        receipt: dict[str, Any],
        *,
        server_id: str,
        server_secret: str,
    ) -> dict[str, Any]:
        _authenticate_server(server_id, server_secret)
        token_claims, kid, token_digest, token_signature_sha = _verify(token)
        claims, receipt_digest, receipt_signature_sha = _verified_stage_receipt(receipt, server_id)
        if (
            token_claims["server_id"] != server_id
            or token_claims["resource_sha256"] is None
            or claims["grant_id"] != token_claims["grant_id"]
            or claims["request_id"] != token_claims["request_id"]
            or claims["resource_sha256"] != token_claims["resource_sha256"]
        ):
            _deny(403, "Native stage receipt not bound to original grant")
        try:
            async with self.grants.actions._sessions()() as db:
                async with db.begin():
                    # Preserve 0027/0029 lock order: original Action BEFORE
                    # 0029 grant BEFORE 0030 offer and this 0032 insert.
                    observed = await self.grants._grant(db, token_claims["grant_id"], lock=False)
                    if observed is None or observed["status"] != "redeemed":
                        _deny(409, "Native original grant not durably redeemed")
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
                    locked = await self.grants._grant(db, token_claims["grant_id"], lock=True)
                    if locked is None or locked["status"] != "redeemed":
                        _deny(409, "Native stage source grant changed")
                    self.grants._same(locked, original)
                    self.grants._signed(token_claims, locked)
                    if any(
                        (
                            locked["server_id"] != server_id,
                            locked["kid"] != kid,
                            locked["claims_sha256"] != token_digest,
                            locked["signature_sha256"] != token_signature_sha,
                        )
                    ):
                        _deny(403, "Signed grant source and worker identity changed")
                    now = await self.grants._now(db)
                    if (
                        now < locked["issued_at"]
                        or now >= locked["expires_at"]
                        or not now - 20 <= claims["verified_at"] <= now + 2
                    ):
                        _deny(409, "Worker stage verification or lease expired")
                    await self.grants._resources(db, original, locked["resource_sha256"])
                    snapshot = (
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
                                    "eng": locked["engagement_id"],
                                    "flow": locked["flow_id"],
                                    "owner": locked["owner_id"],
                                    "limit": MAX_EXPORT_FILES + 1,
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    manifest = make_manifest(
                        locked["flow_id"],
                        locked["flow_revision"],
                        locked["authorization_version"],
                        [(dict(item), item["content"]) for item in snapshot],
                    )
                    folder = await approved_folder_stage_plan(db, original, manifest)
                    if (
                        folder is None
                        or claims["folder_staging_sha256"] != folder["staging_sha256"]
                        or claims["readback_sha256"]
                        != readback_digest(locked["grant_id"], locked["request_id"], folder)
                    ):
                        _deny(409, "Native stage readback not original Task approved")
                    offer = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM native_mcp_resource_offers "
                                    "WHERE grant_id=:grant FOR SHARE"
                                ),
                                {"grant": locked["grant_id"]},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if (
                        offer is None
                        or offer["status"] != "offered"
                        or any(
                            offer[key] != locked[key]
                            for key in (
                                "engagement_id",
                                "flow_id",
                                "action_id",
                                "request_id",
                                "server_id",
                            )
                        )
                        or offer["manifest_sha256"] != manifest["manifest_sha256"]
                        or offer["folder_staging_sha256"] != folder["staging_sha256"]
                    ):
                        _deny(409, "Original immutable source offer does not match worker")
                    inserted = (
                        await db.execute(
                            text(
                                "INSERT INTO native_mcp_stage_receipts "
                                "(grant_id,request_id,engagement_id,flow_id,action_id,"
                                "server_id,resource_sha256,folder_staging_sha256,"
                                "readback_sha256,claims_sha256,signature_sha256,"
                                "worker_key_id,verified_at,status) VALUES "
                                "(:grant,:request,:eng,:flow,:action,:server,"
                                ":resource,:folder,:readback,:claims,:signature,"
                                ":kid,:verified,'worker_reported') "
                                "ON CONFLICT DO NOTHING RETURNING grant_id"
                            ),
                            {
                                "grant": locked["grant_id"],
                                "request": locked["request_id"],
                                "eng": locked["engagement_id"],
                                "flow": locked["flow_id"],
                                "action": locked["action_id"],
                                "server": locked["server_id"],
                                "resource": locked["resource_sha256"],
                                "folder": folder["staging_sha256"],
                                "readback": claims["readback_sha256"],
                                "claims": receipt_digest,
                                "signature": receipt_signature_sha,
                                "kid": receipt["kid"],
                                "verified": claims["verified_at"],
                            },
                        )
                    ).scalar_one_or_none()
                    if inserted != locked["grant_id"]:
                        _deny(409, "Worker stage receipt already recorded; outcome UNKNOWN")
                    return {
                        "grant_id": locked["grant_id"],
                        "request_id": locked["request_id"],
                        "receipt_sha256": receipt_digest,
                        "worker_stage_report_durable": True,
                        "independent_target_effect_verified": False,
                    }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise NativeMCPGrantDenied(503, "Native worker stage receipt outcome UNKNOWN") from exc
