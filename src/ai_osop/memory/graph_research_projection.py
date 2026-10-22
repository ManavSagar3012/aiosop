"""Signed-source graph projection, never an authorization or exploit success."""

import hashlib
import hmac
import re
import json
import os
import base64
import binascii
from typing import Any

from ai_osop.core.models import Task
from ai_osop.memory.graph_research_context import (
    GraphResearchDenied,
    _TOOL_KINDS,
    _fingerprint_result,
)
from ai_osop.orchestrator.context_compaction import (
    source_sha256,
    task_assignment_sha256,
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


def _provider_key_fingerprint(server_id: str, kid: str) -> str:
    """Return the current enrolled signer public-key digest, fail closed.

    The original full Ed25519 receipt was independently verified by the
    PostgreSQL event writer. Its digest-only audit event cannot reverify that
    signature; pinning the exact original enrolled key in the graph prevents
    an old graph projection from surviving a same-KID key replacement.
    """
    if not isinstance(server_id, str) or not isinstance(kid, str):
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,96}", kid):
        return ""
    try:
        trust_text = os.environ.get("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "")
        if len(trust_text) > 16384:
            return ""
        trust = json.loads(trust_text)
        if not isinstance(trust, dict) or len(trust) > 128:
            return ""
        source = trust.get(server_id)
        if not isinstance(source, dict) or len(source) > 32:
            return ""
        pub = source.get(kid)
        if not isinstance(pub, str) or len(pub) > 128:
            return ""
        decoded = base64.b64decode(pub, validate=True)
        if len(decoded) != 32:
            return ""
        return hashlib.sha256(decoded).hexdigest()
    except (TypeError, ValueError, UnicodeError, binascii.Error):
        return ""


def _provider_key_current(server_id: str, kid: str) -> bool:
    """Retained helper for current signed-event admission."""
    return bool(_provider_key_fingerprint(server_id, kid))


async def verify_signed_action_event(
    *,
    supervision: Any,
    engagement_id: str,
    task_id: str,
    event_id: str,
    provider_receipt_sha256: str,
    authorization_version: int,
) -> bool:
    """Check a projected action against the actual PostgreSQL signed receipt.

    Both the producer and reader can use this independently of Neo4j contents.
    A graph node containing copied authorization hashes cannot forge this
    event or the original durable signed-version-bound MCP dispatch identity.
    """
    if (
        not isinstance(event_id, str)
        or not event_id.startswith("evt-")
        or len(event_id) > 64
        or not isinstance(provider_receipt_sha256, str)
        or not _SHA.fullmatch(provider_receipt_sha256)
        or type(authorization_version) is not int
        or authorization_version < 1
    ):
        raise GraphResearchDenied("Invalid signed graph action event binding")
    try:
        events = await supervision.list_events(
            engagement_id,
            task_id=task_id,
            limit=100,
        )
        if not isinstance(events, list) or len(events) > 100:
            raise GraphResearchDenied("Signed action event history unbounded")
        matches = [e for e in events if isinstance(e, dict) and e.get("id") == event_id]
        if len(matches) != 1:
            raise GraphResearchDenied("Signed action event missing or replayed")
        event = matches[0]
        body = event.get("payload")
        if (
            event.get("engagement_id") != engagement_id
            or event.get("task_id") != task_id
            or event.get("kind")
            not in {
                "agent.mcp.reconciliation_result",
                "agent.mcp.execution_finished",
            }
            or not isinstance(body, dict)
            or body.get("status") != "confirmed_finished"
            or body.get("provider_receipt_status") != "succeeded"
            or not hmac.compare_digest(
                str(body.get("provider_receipt_sha256", "")),
                provider_receipt_sha256,
            )
            or not isinstance(body.get("provider_signing_kid"), str)
            or not 1 <= len(body["provider_signing_kid"]) <= 128
            or not isinstance(body.get("request_id"), str)
            or not _REQUEST.fullmatch(body["request_id"])
        ):
            raise GraphResearchDenied("Signed action event lacks independent success proof")
        dispatches = await supervision.list_mcp_dispatches(
            engagement_id,
            task_id=task_id,
            limit=100,
        )
        matched = [
            row
            for row in dispatches
            if row.get("request_id") == body["request_id"]
            and row.get("status") == "confirmed_finished"
            and row.get("authorization_version") == authorization_version
        ]
        if len(matched) != 1:
            raise GraphResearchDenied("Signed action dispatch ambiguous")
        dispatch = matched[0]
        if not _provider_key_current(
            dispatch.get("server_id"), body["provider_signing_kid"],
        ):
            raise GraphResearchDenied("Signed action provider key retired or unavailable")
        original = await supervision.get_mcp_dispatch(
            engagement_id,
            task_id,
            dispatch["server_id"],
            dispatch["request_id"],
        )
        if (
            not isinstance(original, dict)
            or original.get("engagement_id") != engagement_id
            or original.get("task_id") != task_id
            or original.get("server_id") != dispatch["server_id"]
            or original.get("request_id") != body["request_id"]
            or original.get("authorization_version") != authorization_version
            or original.get("status") != "confirmed_finished"
        ):
            raise GraphResearchDenied("Signed action dispatch changed")
        return True
    except GraphResearchDenied:
        raise
    except Exception as exc:
        raise GraphResearchDenied("Signed action receipt verification unavailable") from exc


async def _boundary(memory: Any, sid: str, task_id: str) -> Any:
    """Reload PostgreSQL Task, current signed authority and Flow, not Redis."""
    try:
        task = await memory.load_task_authoritative(task_id)
        if (
            not isinstance(task, Task)
            or task.id != task_id
            or task.engagement_id != sid
            or task.status != "completed"
            or not task.flow_id
            or not isinstance(task.payload, dict)
            or type(task.payload.get("_authorization_version")) is not int
            or not isinstance(task.result, dict)
            or task.result.get("status") not in {"success", "succeeded"}
        ):
            return None
        signed = await memory.assert_signed_authorization(
            sid,
            expected_version=task.payload["_authorization_version"],
        )
        flow = await memory.load_flow(task.flow_id)
        if (
            flow is None
            or flow.id != task.flow_id
            or flow.engagement_id != sid
            or flow.status not in {"running", "pending"}
            or type(flow.revision) is not int
            or signed.version != task.payload["_authorization_version"]
            or not isinstance(signed.policy_sha256, str)
            or not _SHA.fullmatch(signed.policy_sha256)
        ):
            raise GraphResearchDenied("Signed graph source Flow unavailable")
        return task, signed, flow, _fingerprint_result(task.result)
    except GraphResearchDenied:
        raise
    except Exception as exc:
        raise GraphResearchDenied("Durable graph source unavailable") from exc


async def project_verified_mcp_action(
    *,
    memory: Any,
    supervision: Any,
    graph: Any,
    engagement_id: str,
    task_id: str,
) -> bool:
    """Project only an independently signed successful MCP event plus Task.

    Existing terminal callback effect ledger fences this idempotent Neo4j write.
    No target, raw receipt, command, model response or secret is projected.
    A provider-signed assertion is not physical proof of external effects.
    """
    initial = await _boundary(memory, engagement_id, task_id)
    if initial is None:
        return False
    task, signed, flow, result_sha = initial
    try:
        events = await supervision.list_events(
            engagement_id,
            task_id=task_id,
            limit=100,
        )
    except Exception as exc:
        raise GraphResearchDenied("Signed MCP receipt history unavailable") from exc
    if not isinstance(events, list) or len(events) > 100:
        raise GraphResearchDenied("MCP receipt history unbounded")
    qualified = None
    for event in reversed(events):
        if (
            not isinstance(event, dict)
            or event.get("engagement_id") != engagement_id
            or event.get("task_id") != task_id
        ):
            raise GraphResearchDenied("Cross-tenant MCP receipt history")
        if event.get("kind") not in {
            "agent.mcp.reconciliation_result",
            "agent.mcp.execution_finished",
        }:
            continue
        body = event.get("payload")
        if not isinstance(body, dict) or body.get("status") != "confirmed_finished":
            continue
        # A signed FAILED, COMPLETED or FINISHED claim is not a success proof.
        if body.get("provider_receipt_status") != "succeeded":
            continue
        digest, request_id = body.get("provider_receipt_sha256"), body.get("request_id")
        if (
            not isinstance(digest, str)
            or not _SHA.fullmatch(digest)
            or not isinstance(request_id, str)
            or not _REQUEST.fullmatch(request_id)
            or not isinstance(body.get("provider_signing_kid"), str)
            or not 1 <= len(body["provider_signing_kid"]) <= 128
            or not isinstance(event.get("id"), str)
            or not event["id"].startswith("evt-")
            or len(event["id"]) > 64
        ):
            raise GraphResearchDenied("Malformed signed MCP receipt provenance")
        qualified = event, body
        break
    if qualified is None:
        return False
    event, body = qualified
    try:
        dispatches = await supervision.list_mcp_dispatches(
            engagement_id,
            task_id=task_id,
            limit=100,
        )
        matches = [
            item
            for item in dispatches
            if item.get("request_id") == body["request_id"]
            and item.get("status") == "confirmed_finished"
            and item.get("authorization_version") == signed.version
        ]
        if len(matches) != 1:
            raise GraphResearchDenied("MCP dispatch identity ambiguous")
        match = matches[0]
        signer_key_sha256 = _provider_key_fingerprint(
            match.get("server_id"), body["provider_signing_kid"],
        )
        if not signer_key_sha256:
            raise GraphResearchDenied("Signed MCP provider key retired or unavailable")
        direct = await supervision.get_mcp_dispatch(
            engagement_id,
            task_id,
            match["server_id"],
            match["request_id"],
        )
        if (
            not isinstance(direct, dict)
            or direct.get("task_id") != task_id
            or direct.get("engagement_id") != engagement_id
            or direct.get("server_id") != match["server_id"]
            or direct.get("request_id") != body["request_id"]
            or direct.get("status") != "confirmed_finished"
            or direct.get("authorization_version") != signed.version
        ):
            raise GraphResearchDenied("Signed MCP dispatch changed")
    except GraphResearchDenied:
        raise
    except Exception as exc:
        raise GraphResearchDenied("Durable MCP dispatch unavailable") from exc
    renewed = await _boundary(memory, engagement_id, task_id)
    if renewed is None:
        raise GraphResearchDenied("Graph source invalidated")
    current, next_signed, next_flow, next_digest = renewed
    if (
        source_sha256(current.model_dump(mode="json"))
        != source_sha256(task.model_dump(mode="json"))
        or next_signed.authorization_id != signed.authorization_id
        or next_signed.policy_sha256 != signed.policy_sha256
        or next_flow.revision != flow.revision
        or not hmac.compare_digest(next_digest, result_sha)
    ):
        raise GraphResearchDenied("Graph source changed before projection")
    stable_id = (
        "action-"
        + hashlib.sha256(
            (engagement_id + ":" + task_id + ":" + event["id"]).encode("utf-8")
        ).hexdigest()[:48]
    )
    projection = {
        "id": stable_id,
        "engagement_id": engagement_id,
        "flow_id": flow.id,
        "flow_revision": flow.revision,
        "authorization_version": signed.version,
        "authorization_sha256": signed.policy_sha256,
        "source_task_id": task.id,
        "source_task_sha256": task_assignment_sha256(task),
        # Most real agent Task results do not contain a tool_kind field.
        # A confirmed, pinned MCP source still conveys the safe generic
        # taxonomy 'mcp'; specific allowlisted category is optional.
        "tool_kind": (
            task.result.get("tool_kind") if task.result.get("tool_kind") in _TOOL_KINDS else "mcp"
        ),
        "receipt_sha256": result_sha,
        "provider_receipt_sha256": body["provider_receipt_sha256"],
        "provider_server_id": match["server_id"],
        "provider_signing_kid": body["provider_signing_kid"],
        "provider_signer_key_sha256": signer_key_sha256,
        "source_event_id": event["id"],
        "outcome": "succeeded",
    }
    try:
        if not await graph.project_signed_tool_action(projection):
            raise GraphResearchDenied("Graph projection identity collision")
    except GraphResearchDenied:
        raise
    except Exception as exc:
        raise GraphResearchDenied("Signed graph projection unavailable") from exc
    return True
