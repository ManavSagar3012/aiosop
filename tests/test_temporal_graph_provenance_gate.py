"""Restart, signer rotation and read-after-await fences in the live model path.

These deterministic tests use Neo4j/PostgreSQL doubles. A graph-validated
Vulnerability is not independently source authenticated by its Task digest.
"""

import base64
import copy
import hashlib
import json
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.graph_research_context import (
    GraphResearchDenied,
    verified_graph_research_context,
)
from ai_osop.memory.graph_research_projection import _provider_key_fingerprint
from tests.test_agent_compacted_context_consumption import seed, signed_flow
from tests.test_tenant_graph_research_context import graph_case


async def _read(case):
    fx = case.fixture
    return await verified_graph_research_context(
        memory=fx.memory,
        graph=case.graph,
        current_task=fx.current,
        engagement_id=fx.current.engagement_id,
        topic="MCP signed checks",
    )


@pytest.mark.asyncio
async def test_authenticated_graph_action_rechecked_after_all_source_reads(graph_case):
    fx = graph_case.fixture
    text = await _read(graph_case)
    assert "action:http:receipt-sha256=" in text
    assert "finding:" not in text
    assert fx.memory.verify_signed_graph_action.await_count == 2


@pytest.mark.asyncio
async def test_source_verified_finding_claim_is_quarantined_even_with_matching_digest(
    graph_case,
):
    graph_case.graph.read_signed_research_candidates.return_value = [
        copy.deepcopy(graph_case.finding)
    ]
    with pytest.raises(GraphResearchDenied, match="stale graph provenance"):
        await _read(graph_case)
    assert graph_case.fixture.memory.verify_signed_graph_action.await_count == 0


@pytest.mark.asyncio
async def test_same_kid_reenrollment_rejects_persisted_graph_across_restart(
    graph_case,
    monkeypatch,
):
    assert "action:http:" in await _read(graph_case)
    graph_case.fixture.memory.verify_signed_graph_action.reset_mock()
    graph_case.graph.read_signed_research_candidates.reset_mock()
    # A provider replaced its Ed25519 public key but reused the old KID.
    # The old graph node survives the restart: it must not survive validation.
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps(
            {
                "mock-mcp": {
                    "pinned-ed25519-kid": base64.b64encode(bytes([24]) * 32).decode(),
                },
            }
        ),
    )
    with pytest.raises(GraphResearchDenied, match="signer changed or retired"):
        await _read(graph_case)
    graph_case.fixture.memory.verify_signed_graph_action.assert_not_awaited()


@pytest.mark.asyncio
async def test_signer_rotation_during_replay_blocks_real_agent_model_call(
    graph_case,
    monkeypatch,
):
    fx = graph_case.fixture
    await seed(fx)
    checked = 0
    unchanged_verifier = fx.memory.verify_signed_graph_action

    async def rotated_after_first_check(*args):
        nonlocal checked
        checked += 1
        if checked == 1:
            monkeypatch.setenv(
                "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
                json.dumps(
                    {
                        "mock-mcp": {
                            "pinned-ed25519-kid": base64.b64encode(bytes([84]) * 32).decode(),
                        },
                    }
                ),
            )
        return True

    unchanged_verifier.side_effect = rotated_after_first_check
    assert await fx.consumer.think("MCP checks", []) == ""
    fx.consumer.ctx.llm_client.complete.assert_not_awaited()
    assert checked == 1


@pytest.mark.asyncio
async def test_dispatch_revoked_after_initial_receipt_check_never_reaches_llm(graph_case):
    fx = graph_case.fixture
    await seed(fx)
    fx.memory.verify_signed_graph_action.side_effect = [True, False]
    assert await fx.consumer.think("MCP checks", []) == ""
    assert fx.memory.verify_signed_graph_action.await_count == 2
    fx.consumer.ctx.llm_client.complete.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "broken",
    [
        "missing_key_fingerprint",
        "copied_other_server",
        "changed_kid",
        "wrong_key_fingerprint",
    ],
)
async def test_graph_node_signer_provenance_immutable_and_unforgeable(
    graph_case,
    broken,
):
    action = graph_case.action
    if broken == "missing_key_fingerprint":
        action.pop("provider_signer_key_sha256")
    elif broken == "copied_other_server":
        action["provider_server_id"] = "foreign-mcp"
    elif broken == "changed_kid":
        action["provider_signing_kid"] = "foreign-key-id"
    elif broken == "wrong_key_fingerprint":
        action["provider_signer_key_sha256"] = "f" * 64
    with pytest.raises(GraphResearchDenied):
        await _read(graph_case)


def test_provider_signer_fingerprint_requires_bounded_enrolled_key(
    graph_case,
    monkeypatch,
):
    assert (
        _provider_key_fingerprint("mock-mcp", "pinned-ed25519-kid")
        == hashlib.sha256(bytes([42]) * 32).hexdigest()
    )
    for configured in ('{"mock-mcp":{"pinned-ed25519-kid":"Z"}}', "{", "x" * 20000):
        monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", configured)
        assert not _provider_key_fingerprint("mock-mcp", "pinned-ed25519-kid")
