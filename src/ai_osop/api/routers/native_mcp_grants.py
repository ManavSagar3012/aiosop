"""Read-only, owner-scoped historical native MCP grant redemption ledger.

No capability signature, nonce, bearer, approved Task target, parameters,
private evidence, tool operation or provider result leaves this endpoint.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import text

from ai_osop.api.routers.flow_mcp_actions import (
    _binding,
    _executor,
    _headers,
    _operator,
)

router = APIRouter(prefix="/flows", tags=["native-mcp-grant-ledger"])

_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{2,95}\Z")
_ACTION = re.compile(r"action-[0-9a-f]{32}\Z")
_GRANT = re.compile(r"ngr-[0-9a-f]{32}\Z")
_REQUEST = re.compile(r"req-[0-9a-f]{32,64}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SERVER = frozenset(
    {
        "recon-mcp",
        "payload-mcp",
        "nuclei-mcp",
        "shodan-mcp",
        "threat-intel-mcp",
        "security-bridge",
    }
)
_STATUSES = frozenset({"issued", "redeemed", "unknown", "revoked"})
_SUPERVISOR_STATES = frozenset(
    {"provisioned", "running", "terminating", "terminated", "unknown", "reaped"}
)


def _public(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        raise ValueError("Invalid signed native grant row")
    if (
        not isinstance(row.get("grant_id"), str)
        or not _GRANT.fullmatch(row["grant_id"])
        or not isinstance(row.get("action_id"), str)
        or not _ACTION.fullmatch(row["action_id"])
        or not isinstance(row.get("request_id"), str)
        or not _REQUEST.fullmatch(row["request_id"])
        or row.get("server_id") not in _SERVER
        or row.get("tool_name") != "authority_status"
        or row.get("status") not in _STATUSES
        or type(row.get("issued_at")) is not int
        or type(row.get("expires_at")) is not int
        or not 0 < row["expires_at"] - row["issued_at"] <= 60
        or (
            row.get("resource_sha256") is not None
            and (
                not isinstance(row.get("resource_sha256"), str)
                or _SHA.fullmatch(row["resource_sha256"]) is None
            )
        )
        or row.get("resource_offer_status") not in (None, "offered")
        or (
            row.get("folder_staging_sha256") is not None
            and (
                not isinstance(row.get("folder_staging_sha256"), str)
                or _SHA.fullmatch(row["folder_staging_sha256"]) is None
                or row.get("resource_offer_status") != "offered"
            )
        )
        or row.get("stage_receipt_status") not in (None, "worker_reported")
        or row.get("supervisor_state") not in (None, *_SUPERVISOR_STATES)
        or type(row.get("supervisor_recovery_intent_pending", False)) is not bool
        or (
            row.get("supervisor_recovery_intent_pending") is True
            and row.get("supervisor_state") not in {"unknown", "terminating"}
        )
        or (row.get("supervisor_state") is None and row.get("supervisor_revision") is not None)
        or (
            row.get("supervisor_state") is not None
            and (
                type(row.get("supervisor_revision")) is not int
                or not 1 <= row["supervisor_revision"] < 2**31
            )
        )
        or (
            row.get("supervisor_state") is not None
            and row.get("status") == "issued"
            and row["supervisor_state"] not in {"provisioned", "unknown", "terminated", "reaped"}
        )
        or (
            row.get("stage_receipt_status") == "worker_reported"
            and row.get("folder_staging_sha256") is None
        )
        or (
            row.get("resource_offer_status") == "offered"
            and (row.get("resource_sha256") is None or row["status"] != "redeemed")
        )
    ):
        raise ValueError("Untrusted native MCP grant status metadata")
    result = {
        key: row[key]
        for key in (
            "grant_id",
            "action_id",
            "request_id",
            "server_id",
            "tool_name",
            "status",
            "issued_at",
            "expires_at",
        )
    }
    # Return only historic verification *flags*, NEVER raw artifact bytes,
    # digest, privileged source paths, authorization or a native grant token.
    # A redeemed row with an immutable resource SHA proves source byte checks
    # occurred during PostgreSQL redemption; it is NOT worker staging, target
    # execution or proof of the resource being used by an external scanner.
    result["reviewed_resource_bound"] = row.get("resource_sha256") is not None
    result["resource_bytes_checked_at_redemption"] = (
        result["reviewed_resource_bound"] and row["status"] == "redeemed"
    )
    # An immutable one-shot source OFFER is not proof that the worker actually
    # received bytes; never release token, file content, path or artifact SHA.
    result["original_resource_bytes_offered_once"] = row.get("resource_offer_status") == "offered"
    # Separate, independently keyed *worker testimony* is not outside-the-
    # worker sandbox attestation or target-owner evidence. Never leak a
    # receipt signature, private key, file path, artifact or stage digest.
    result["approved_folder_staging_bound"] = row.get("folder_staging_sha256") is not None
    result["worker_stage_receipt_reported"] = row.get("stage_receipt_status") == "worker_reported"
    # Current independent Docker supervisor evidence stays separate from a
    # worker-signature receipt. A reaped lifecycle confirms an externally
    # observed owned worker teardown only, NOT independent target effects.
    result["supervisor_lifecycle_observed"] = row.get("supervisor_state") is not None
    result["supervisor_state"] = row.get("supervisor_state")
    result["supervisor_revision"] = row.get("supervisor_revision")
    result["supervisor_cleanup_observed"] = row.get("supervisor_state") == "reaped"
    result["supervisor_recovery_required"] = row.get("supervisor_state") == "unknown"
    result["supervisor_recovery_intent_pending"] = row.get(
        "supervisor_recovery_intent_pending", False
    )
    return result


@router.get("/{flow_id}/native-mcp-grants")
async def read_native_mcp_grant_ledger(
    flow_id: str,
    response: Response,
    expected_engagement_id: str = Query(min_length=5, max_length=64),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    _headers(response)
    binding = _binding(
        flow_id, expected_engagement_id, expected_revision, expected_authorization_version
    )
    try:
        service = _executor()
        await service._authority(binding, operator)
        maker = service.store._sessions()
        async with maker() as db:
            async with db.begin():
                query = await db.execute(
                    text(
                        "SELECT g.grant_id,g.action_id,g.request_id,g.server_id,g.tool_name,"
                        "g.status,g.issued_at,g.expires_at,g.resource_sha256,"
                        "o.status AS resource_offer_status,"
                        "o.folder_staging_sha256,s.status AS stage_receipt_status,"
                        "w.state AS supervisor_state,w.revision AS supervisor_revision,"
                        "EXISTS (SELECT 1 FROM native_mcp_worker_recovery_intents AS ri "
                        "WHERE ri.grant_id=w.grant_id AND ri.expected_revision=w.revision "
                        "AND ri.engagement_id=g.engagement_id AND ri.flow_id=g.flow_id "
                        "AND ri.action_id=g.action_id) AS supervisor_recovery_intent_pending "
                        "FROM native_mcp_execution_grants AS g "
                        "LEFT JOIN native_mcp_resource_offers AS o "
                        "ON o.grant_id=g.grant_id AND o.engagement_id=g.engagement_id "
                        "AND o.flow_id=g.flow_id AND o.action_id=g.action_id "
                        "AND o.request_id=g.request_id AND o.server_id=g.server_id "
                        "LEFT JOIN native_mcp_stage_receipts AS s "
                        "ON s.grant_id=g.grant_id AND s.engagement_id=g.engagement_id "
                        "AND s.flow_id=g.flow_id AND s.action_id=g.action_id "
                        "AND s.request_id=g.request_id AND s.server_id=g.server_id "
                        "LEFT JOIN native_mcp_worker_supervisions AS w "
                        "ON w.grant_id=g.grant_id AND w.engagement_id=g.engagement_id "
                        "AND w.flow_id=g.flow_id AND w.action_id=g.action_id "
                        "AND w.request_id=g.request_id AND w.server_id=g.server_id "
                        "WHERE g.engagement_id=:eng AND g.flow_id=:flow AND g.owner_id=:owner "
                        "AND g.flow_revision=:revision AND g.authorization_id=:auth "
                        "AND g.authorization_version=:version AND g.authorization_sha256=:sha "
                        "ORDER BY g.issued_at DESC,g.grant_id DESC LIMIT 101 FOR SHARE OF g"
                    ),
                    {
                        "eng": expected_engagement_id,
                        "flow": flow_id,
                        "owner": operator["sub"],
                        "revision": expected_revision,
                        "auth": binding["authorization_id"],
                        "version": expected_authorization_version,
                        "sha": binding["authorization_sha256"],
                    },
                )
                rows = [dict(row) for row in query.mappings().all()]
        if len(rows) > 100:
            raise ValueError("Native MCP grant ledger exceeds bound")
        grants = [_public(row) for row in rows]
        if len({entry["grant_id"] for entry in grants}) != len(grants):
            raise ValueError("Duplicate durable native grant identity")
        await service._authority(binding, operator)
        return {
            "engagement_id": expected_engagement_id,
            "flow_id": flow_id,
            "flow_revision": expected_revision,
            "authorization_version": expected_authorization_version,
            "source": "durable_native_grants",
            "server_side_signed_authorization_verified": False,
            "independent_target_effect_verified": False,
            "grants": grants,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Current signed native MCP ledger unavailable") from exc
