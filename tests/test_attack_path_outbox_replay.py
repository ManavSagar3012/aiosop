"""AIOSOP-ATTACK-OUTBOX: attack-path replay must not self-DLQ.

Regression: ``add_attack_path_from_outbox`` validated the minimal outbox payload
with a strict ``AttackPath.model_validate``. The producer (``add_attack_path``)
enqueues ONLY ``{id, node_ids, confidence, total_time_estimate, detection_risk,
edges}`` — none of ``entry_node_id``/``goal_node_id``/``edge_ids``/``risk_score``
— so the validation raised on every replay, the entry was marked a failed
attempt 10 times, and the processor DLQ'd it even though the LEADS_TO edge
projection (the actual graph-shaping work) had already succeeded. This pins the
lenient validation (construct a model from the carried fields; malformed rows
still fail loudly).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.memory.graph_memory import GraphMemory


def _make_gm():
    """GraphMemory with a mocked driver whose session returns a FakeResult-like
    object (only ``run`` is used by add_attack_path_from_outbox)."""
    gm = GraphMemory()

    class _FakeResult:
        async def single(self):
            return None

        async def data(self):
            return []

    session = MagicMock()
    session.run = AsyncMock(return_value=_FakeResult())
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    driver = MagicMock()
    driver.session = MagicMock(return_value=ctx)
    driver.close = AsyncMock()
    gm._driver = driver
    return gm, session


@pytest.mark.asyncio
async def test_minimal_outbox_payload_replays_without_dlq():
    """The producer's minimal payload (no entry_node_id/goal_node_id/edge_ids/
    risk_score) must replay the LEADS_TO edges and NOT raise — a strict model
    round-trip previously DLQ'd every attack-path row after 10 attempts."""
    payload = {
        "id": "path-abc",
        "node_ids": ["vuln-1", "vuln-2", "vuln-3"],
        "confidence": 0.8,
        "total_time_estimate": 60,
        "detection_risk": 0.2,
        "edges": [
            {"from_id": "vuln-1", "to_id": "vuln-2", "type": "exploit_chain"},
            {"from_id": "vuln-2", "to_id": "vuln-3", "type": "exploit_chain"},
        ],
    }
    gm, session = _make_gm()
    await gm.add_attack_path_from_outbox(payload)  # must not raise

    session.run.assert_awaited_once()
    cypher, params = session.run.await_args.args
    assert "LEADS_TO" in cypher
    assert params["edges"] == payload["edges"]


@pytest.mark.asyncio
async def test_malformed_outbox_payload_still_fails_loudly():
    """A payload that cannot run the edge projection must still raise so a
    broken producer surfaces as a DLQ entry instead of a silent no-op."""
    gm, session = _make_gm()
    # node_ids present but edges missing -> the projection runs with an empty
    # edge list, which we now tolerate (the edges are the durable fact; a row
    # with zero edges is a legitimate no-op path). Instead assert the loud
    # failure for a payload whose node_ids is not even a list — that cannot be
    # the producer's shape and must not be silently accepted.
    with pytest.raises(Exception):
        await gm.add_attack_path_from_outbox({"id": "path-bad", "node_ids": None})
