"""Prevent stale approved Flow knowledge across asynchronous receipt reads.

All tests use the actual BaseAgent.think boundary and deterministic mocked
review/PG read contracts: no application database or model provider requests.
"""

import json

import pytest

from ai_osop.memory.reviewed_flow_knowledge import (
    ReviewedFlowKnowledgeDenied,
    verified_reviewed_flow_knowledge,
)
from tests.test_agent_compacted_context_consumption import signed_flow
from tests.test_reviewed_flow_knowledge_inference_20261016 import (
    ARTIFACT_A,
    ARTIFACT_B,
    SHA_B,
    approved_flow,
)


@pytest.mark.asyncio
async def test_approval_disappears_after_first_read_before_inference(approved_flow):
    case, read_review, receipt = approved_flow
    read_review.side_effect = [receipt(), None]
    assert await case.consumer.think("Current signed Flow", []) == ""
    case.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert read_review.await_count == 2


@pytest.mark.asyncio
async def test_first_review_revoked_while_second_source_is_read(approved_flow):
    case, read_review, receipt = approved_flow
    case.current.payload["_reviewed_knowledge_artifacts"].append(
        {
            "artifact_id": ARTIFACT_B,
            "sha256": SHA_B,
        }
    )
    calls = []

    async def read_current(**kwargs):
        artifact_id = kwargs["artifact_id"]
        calls.append(artifact_id)
        if artifact_id == ARTIFACT_A and calls.count(ARTIFACT_A) > 1:
            return None  # approval withdrawn after B's first read
        if artifact_id == ARTIFACT_B:
            return receipt(artifact_id=ARTIFACT_B, artifact_sha256=SHA_B)
        return receipt()

    read_review.side_effect = read_current
    assert await case.consumer.think("Current signed Flow", []) == ""
    case.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert calls == [ARTIFACT_A, ARTIFACT_B, ARTIFACT_A]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,updated",
    [
        ("review_id", "review-" + "d" * 32),
        ("reviewer_sub", "replacement-senior-reviewer"),
        ("reviewed_at", "2026-10-16T09:10:00"),
        ("uploader_sub", "replacement-uploader"),
    ],
)
async def test_replaced_review_provenance_cannot_promote_prior_facts(
    approved_flow,
    field,
    updated,
):
    case, read_review, receipt = approved_flow
    read_review.side_effect = [receipt(), receipt(**{field: updated})]
    assert await case.consumer.think("Current signed Flow", []) == ""
    case.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert read_review.await_count == 2


@pytest.mark.asyncio
async def test_changed_source_text_cannot_reuse_earlier_review_snapshot(approved_flow):
    case, read_review, receipt = approved_flow
    altered = json.dumps(
        {
            "schema": "ai-osop-reviewed-flow-facts-v1",
            "facts": [{"type": "technology", "value": "Redis 7"}],
        }
    )
    read_review.side_effect = [receipt(), receipt(text=altered)]
    assert await case.consumer.think("Current signed Flow", []) == ""
    case.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert read_review.await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"verified_review": False, "approved": False, "decision": "UNKNOWN"},
        {"approved": False, "decision": "reject"},
        {"authorization_sha256": "f" * 64},
        {"flow_revision": 888},
    ],
)
async def test_second_review_check_refuses_revoked_or_stale_receipt(approved_flow, change):
    case, read_review, receipt = approved_flow
    read_review.side_effect = [receipt(), receipt(**change)]
    assert await case.consumer.think("Current signed Flow", []) == ""
    case.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert read_review.await_count == 2


@pytest.mark.asyncio
async def test_revocation_during_final_task_read_requires_post_task_signer_check(
    approved_flow,
):
    case, read_review, receipt = approved_flow
    signer_live = True
    original_auth = case.memory.assert_signed_authorization.side_effect
    original_task = case.memory.load_task_authoritative.side_effect
    reads = 0

    async def fresh_task(task_id):
        nonlocal reads, signer_live
        reads += 1
        if reads == 6:
            # BaseAgent's existing two preflight fences each read the Task
            # twice. The helper's initial and final Task reads are #5 and #6.
            # Revoke after the final signer read but during final Task fetch.
            signer_live = False
        return original_task(task_id)

    async def fresh_authorization(*args, **kwargs):
        if not signer_live:
            raise PermissionError("signed ROE was revoked while fetching last task")
        return await original_auth(*args, **kwargs)

    case.memory.load_task_authoritative.side_effect = fresh_task
    case.memory.assert_signed_authorization.side_effect = fresh_authorization
    read_review.side_effect = [receipt(), receipt()]
    assert await case.consumer.think("Current signed Flow", []) == ""
    case.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert read_review.await_count == 2


@pytest.mark.asyncio
async def test_database_review_outage_during_second_check_denies_before_provider(approved_flow):
    case, read_review, receipt = approved_flow
    read_review.side_effect = [
        receipt(),
        ConnectionError("postgres password must not enter model context"),
    ]
    assert await case.consumer.think("Current signed Flow", []) == ""
    assert read_review.await_count == 2
    case.consumer.ctx.llm_client.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_direct_retrieval_rejects_mutation_between_authority_and_receipts(approved_flow):
    case, read_review, receipt = approved_flow

    async def shift_policy(**kwargs):
        # Poison source objects in place while retaining a seemingly valid
        # returned receipt; the original signed authority tuple must win.
        case.signed.authorization_id = "auth-replaced"
        case.flow.revision += 1
        return receipt(
            flow_revision=case.flow.revision,
            authorization_id=case.signed.authorization_id,
        )

    read_review.side_effect = shift_policy
    with pytest.raises(ReviewedFlowKnowledgeDenied):
        await verified_reviewed_flow_knowledge(
            memory=case.memory,
            current_task=case.current,
            engagement_id=case.current.engagement_id,
        )
    case.consumer.ctx.llm_client.complete.assert_not_awaited()
