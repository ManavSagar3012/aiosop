"""Conservative comparison of two signed, separately approved GET observations.

This is an *adjudication of provider testimony*, not a vulnerability validator.
It never receives or returns raw authenticated HTTP bodies, cookies or headers.
Only an independently corroborated target-side ownership/authorization oracle
could promote a candidate to a verified finding; none is assumed here.
"""

import hashlib
import json
import re
from typing import Any, Dict, Optional

from ai_osop.core.models import Task


def observation_task_id(
    engagement_id: str,
    parent_id: str,
    flow_id: str,
    workflow_id: str,
    step_id: str,
    user_label: str,
    version: int,
) -> str:
    """Stable TaskORM identity shared by admission and independent readback."""
    if (
        not all(
            isinstance(x, str) and 1 <= len(x) <= 96 and re.fullmatch(r"[A-Za-z0-9_.-]+", x)
            for x in (engagement_id, parent_id, flow_id, workflow_id, step_id, user_label)
        )
        or type(version) is not int
        or version < 1
    ):
        raise ValueError("Invalid immutable replay observation identity")
    key = json.dumps(
        [engagement_id, parent_id, flow_id, workflow_id, step_id, user_label, version],
        separators=(",", ":"),
    )
    return "task-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def observation_subtask_id(task_id: str) -> str:
    """Stable Flow subtask for an approved observation, never a fresh random ID."""
    if not isinstance(task_id, str) or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,59}", task_id):
        raise ValueError("Invalid signed replay observation Task identity")
    return (
        "subtask-"
        + hashlib.sha256(("signed-replay-subtask-v1:" + task_id).encode("utf-8")).hexdigest()[:32]
    )


def _usable(task: Optional[Task], role: str, identity: str, *, version: int) -> bool:
    if not isinstance(task, Task) or not isinstance(task.payload, dict):
        return False
    payload, result = task.payload, task.result
    return bool(
        task.type == "navigate"
        and task.status == "completed"
        and task.approval_required
        and task.max_retries == 0
        and isinstance(result, dict)
        and payload.get("_comparison_role") == role
        and payload.get("user_label") == identity
        and payload.get("_authorization_version") == version
        and payload.get("operator_approved") is True
        and isinstance(payload.get("approval_id"), str)
        and result.get("status") == "success"
        and result.get("verification_status") == "provider_testimony_only"
        and result.get("authorization_violation_verified") is False
        and result.get("remote_effect_verified") is False
        and isinstance(result.get("provider_evidence"), dict)
        and result["provider_evidence"].get("source_authenticity_verified") is False
        and result["provider_evidence"].get("target_effect_verified") is False
        and result["provider_evidence"].get("finding_verified") is False
        and isinstance(result["provider_evidence"].get("provider_event_id"), str)
        and re.fullmatch(
            r"evt-[A-Za-z0-9._-]{1,60}",
            result["provider_evidence"]["provider_event_id"],
        )
        is not None
        and isinstance(result["provider_evidence"].get("provider_receipt_sha256"), str)
        and re.fullmatch(
            r"[a-f0-9]{64}",
            result["provider_evidence"]["provider_receipt_sha256"],
        )
        is not None
        and type(result.get("http_status_code")) is int
        and 100 <= result["http_status_code"] <= 599
    )


def classify_signed_observation_pair(
    source: Optional[Task],
    target: Optional[Task],
    *,
    engagement_id: str,
    parent_id: str,
    flow_id: str,
    workflow_id: str,
    step_id: str,
    source_identity: str,
    target_identity: str,
    version: int,
    flow_revision: int,
    original_source_task_id: str,
) -> Dict[str, Any]:
    """Return secret-free, non-promotable comparison with immutable lineage."""
    verdict: Dict[str, Any] = {
        "step_id": step_id,
        "status": "inconclusive",
        "reason": "signed_pair_incomplete_or_unverified",
        "source_observed": False,
        "target_observed": False,
        "provider_testimony_only": True,
        "source_authenticity_verified": False,
        "target_effect_verified": False,
        "authorization_violation_verified": False,
        "findings_count": 0,
    }
    if (
        source_identity == target_identity
        or not isinstance(source, Task)
        or not isinstance(target, Task)
    ):
        return verdict
    expected_common = {
        "engagement_id": engagement_id,
        "flow_id": flow_id,
        "parent_task_id": parent_id,
        "dependencies": [parent_id],
    }
    for obj in (source, target):
        if any(getattr(obj, key) != value for key, value in expected_common.items()):
            return verdict
        if not isinstance(obj.payload, dict) or any(
            obj.payload.get(key) != value
            for key, value in {
                "step_id": step_id,
                "workflow_id": workflow_id,
                "source_user_label": source_identity,
                "target_user_label": target_identity,
                "_flow_revision": flow_revision,
                "method": "GET",
            }.items()
        ):
            return verdict
    if (
        not _usable(source, "source", source_identity, version=version)
        or not _usable(target, "target", target_identity, version=version)
        or (source.subtask_id is None) != (target.subtask_id is None)
        or (
            source.subtask_id is not None
            and (
                source.subtask_id != observation_subtask_id(source.id)
                or target.subtask_id != observation_subtask_id(target.id)
            )
        )
        or source.id
        != observation_task_id(
            engagement_id, parent_id, flow_id, workflow_id, step_id, source_identity, version
        )
        or target.id
        != observation_task_id(
            engagement_id, parent_id, flow_id, workflow_id, step_id, target_identity, version
        )
        or source.payload.get("url") != target.payload.get("url")
        or source.result.get("source_task_id") != original_source_task_id
        or target.result.get("source_task_id") != original_source_task_id
        or source.result.get("replay_parent_task_id") != parent_id
        or target.result.get("replay_parent_task_id") != parent_id
        or source.result.get("comparison_role") != "source"
        or target.result.get("comparison_role") != "target"
    ):
        return verdict
    verdict["source_observed"] = True
    verdict["target_observed"] = True
    status_a, status_b = source.result["http_status_code"], target.result["http_status_code"]
    if (
        source.result.get("redirected") is not False
        or target.result.get("redirected") is not False
        or status_a in range(300, 400)
        or status_b in range(300, 400)
    ):
        verdict["reason"] = "redirect_or_authentication_context_unverified"
    elif status_a in range(200, 300) and status_b in (401, 403):
        verdict.update(status="expected_denial_observed", reason="cross_identity_access_rejected")
    elif status_a in range(200, 300) and status_b in range(200, 300):
        digest_a = source.result.get("response_body_sha256")
        digest_b = target.result.get("response_body_sha256")
        if (
            isinstance(digest_a, str)
            and isinstance(digest_b, str)
            and re.fullmatch(r"[a-f0-9]{64}", digest_a)
            and re.fullmatch(r"[a-f0-9]{64}", digest_b)
        ):
            verdict.update(
                status=(
                    "candidate_needs_independent_review" if digest_a == digest_b else "inconclusive"
                ),
                reason=(
                    "matching_provider_body_digest_not_ownership_proof"
                    if digest_a == digest_b
                    else "different_provider_body_digest_not_auth_failure"
                ),
            )
        else:
            verdict["reason"] = "no_comparable_bounded_body_digest"
    else:
        verdict["reason"] = "source_or_target_response_not_comparable"
    # Stable, redacted artifact identity. Do not persist/expose either raw body
    # or body digest; an unkeyed digest can itself leak low-entropy content.
    evidence = json.dumps(
        [
            engagement_id,
            parent_id,
            flow_id,
            workflow_id,
            step_id,
            source.id,
            target.id,
            status_a,
            status_b,
            source.result.get("response_body_sha256"),
            target.result.get("response_body_sha256"),
            source.result["provider_evidence"]["provider_receipt_sha256"],
            target.result["provider_evidence"]["provider_receipt_sha256"],
        ],
        separators=(",", ":"),
    )
    verdict["comparison_sha256"] = hashlib.sha256(evidence.encode()).hexdigest()
    return verdict


async def persist_verified_replay_comparison(
    *,
    memory: Any,
    supervision: Any,
    graph: Any,
    engagement_id: str,
    terminal_task_id: str,
) -> bool:
    """Real terminal callback consumer: append only a bounded PG action receipt.

    One child can finish before its peer. In that case this does nothing; the
    peer's separately fenced terminal callback will attempt the comparison.
    This has no browser/tool calls, and cannot create a Vulnerability node.
    The audit receipt is non-authoritative: reads and report release must
    independently reverify the signed original source and both MCP events.
    """
    from ai_osop.core.models import ExecutionActionRecord
    from ai_osop.memory.graph_research_projection import verify_signed_action_event
    from ai_osop.memory.session_memory import SessionMemory
    from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

    if not isinstance(memory, SessionMemory):
        return False
    task = await memory.load_task_authoritative(terminal_task_id)
    if (
        not isinstance(task, Task)
        or task.engagement_id != engagement_id
        or task.type != "navigate"
        or task.status != "completed"
        or not isinstance(task.payload, dict)
        or task.payload.get("_comparison_role") not in {"source", "target"}
        or not isinstance(task.parent_task_id, str)
        or not isinstance(task.flow_id, str)
    ):
        return False
    parent = await memory.load_task_authoritative(task.parent_task_id)
    version = task.payload.get("_authorization_version")
    flow_revision = task.payload.get("_flow_revision")
    if (
        not isinstance(parent, Task)
        or parent.type != "replay_for_diff_auth"
        or parent.status != "completed"
        or parent.engagement_id != engagement_id
        or parent.flow_id != task.flow_id
        or not isinstance(parent.payload, dict)
        or type(version) is not int
        or version < 1
        or type(flow_revision) is not int
        or flow_revision < 0
        or parent.payload.get("_authorization_version") != version
        or parent.payload.get("_flow_revision") != flow_revision
        or parent.payload.get("operator_approved") is not True
        or not isinstance(parent.payload.get("approval_id"), str)
        or not await memory.is_task_approved(
            parent.id, engagement_id, parent.payload["approval_id"]
        )
    ):
        return False
    flow = await memory.load_flow(task.flow_id)
    session = await memory.load_session_state(engagement_id)
    if (
        flow is None
        or flow.engagement_id != engagement_id
        or flow.status not in {"pending", "running"}
        or flow.revision != flow_revision
        or session is None
        or session.phase in {"completed", "halted"}
        or session.scope.engagement_id != engagement_id
    ):
        return False
    original = await memory.load_task_authoritative(parent.parent_task_id)
    if (
        not isinstance(original, Task)
        or original.type != "map_workflow"
        or original.status != "completed"
        or original.engagement_id != engagement_id
        or original.flow_id not in {None, flow.id}
        or not isinstance(original.payload, dict)
        or original.payload.get("_authorization_version") != version
        or not isinstance(original.result, dict)
    ):
        return False
    source_label, target_label = (
        parent.payload.get("source_user_label"),
        parent.payload.get("target_user_label"),
    )
    wid, step_id = task.payload.get("workflow_id"), task.payload.get("step_id")
    if (
        not isinstance(source_label, str)
        or not isinstance(target_label, str)
        or not isinstance(wid, str)
        or not isinstance(step_id, str)
        or source_label == target_label
        or original.payload.get("user_label") != source_label
        or original.result.get("workflow_id") != wid
        or parent.payload.get("workflow_id") != wid
    ):
        return False
    enforcer = ScopeEnforcer(session.scope)
    enforcer.validate_time_window()
    await memory.assert_signed_authorization(engagement_id, expected_version=version)
    validate_payload_targets(enforcer, {"url": original.payload.get("url")}, require_target=True)
    source_id = observation_task_id(
        engagement_id,
        parent.id,
        task.flow_id,
        wid,
        step_id,
        source_label,
        version,
    )
    target_id = observation_task_id(
        engagement_id,
        parent.id,
        task.flow_id,
        wid,
        step_id,
        target_label,
        version,
    )
    source = await memory.load_task_authoritative(source_id)
    target = await memory.load_task_authoritative(target_id)
    if not isinstance(source, Task) or not isinstance(target, Task):
        return False
    # Treat graph as a provenance cross-check, not an authorization authority.
    query = (
        "MATCH (w:Workflow {id:$wid,engagement_id:$eid})-[:HAS_STEP]->"
        "(s:Step {id:$sid,engagement_id:$eid,workflow_id:$wid})"
        "-[:TARGETS_ENDPOINT]->(e:Endpoint {engagement_id:$eid}) "
        "WHERE s.endpoint_id=e.id "
        "RETURN w.role AS role,e.url AS url,e.method AS method LIMIT 2"
    )
    async with graph._driver.session() as db:
        rows = await db.run(
            query,
            {"wid": wid, "eid": engagement_id, "sid": step_id},
        )
        links = [dict(row) async for row in rows]
    if (
        len(links) != 1
        or links[0].get("role") != source_label
        or links[0].get("method") != "GET"
        or source.payload.get("url") != links[0].get("url")
        or target.payload.get("url") != links[0].get("url")
    ):
        return False
    validate_payload_targets(enforcer, {"url": links[0]["url"]}, require_target=True)
    for observation in (source, target):
        details = observation.result if isinstance(observation.result, dict) else {}
        proof = details.get("provider_evidence")
        approval = observation.payload.get("approval_id")
        if (
            not isinstance(proof, dict)
            or not isinstance(approval, str)
            or not await memory.is_task_approved(observation.id, engagement_id, approval)
            or not await verify_signed_action_event(
                supervision=supervision,
                engagement_id=engagement_id,
                task_id=observation.id,
                event_id=proof.get("provider_event_id"),
                provider_receipt_sha256=proof.get("provider_receipt_sha256"),
                authorization_version=version,
            )
        ):
            return False
    decision = classify_signed_observation_pair(
        source,
        target,
        engagement_id=engagement_id,
        parent_id=parent.id,
        flow_id=flow.id,
        workflow_id=wid,
        step_id=step_id,
        source_identity=source_label,
        target_identity=target_label,
        version=version,
        flow_revision=flow_revision,
        original_source_task_id=original.id,
    )
    if not decision["source_observed"] or not decision["target_observed"]:
        return False
    await memory.assert_signed_authorization(engagement_id, expected_version=version)
    check = await memory.load_flow(flow.id)
    if (
        check is None
        or check.revision != flow.revision
        or check.status not in {"pending", "running"}
    ):
        return False
    outcome = {
        "candidate_needs_independent_review": "candidate_review",
        "expected_denial_observed": "expected_denial",
    }.get(decision["status"], "inconclusive")
    digest = decision["comparison_sha256"]
    await memory.record_action(
        ExecutionActionRecord(
            id="action-"
            + hashlib.sha256((engagement_id + ":" + parent.id + ":" + digest).encode()).hexdigest()[
                :48
            ],
            engagement_id=engagement_id,
            flow_id=flow.id,
            task_id=parent.id,
            subtask_id=target.subtask_id,
            tool_name="signed_diff_auth_compare",
            outcome=outcome,
            safe_metadata={
                "comparison_sha256": digest,
                "source_task_id": original.id,
                "source_observation_task_id": source.id,
                "target_observation_task_id": target.id,
            },
        )
    )
    return True
