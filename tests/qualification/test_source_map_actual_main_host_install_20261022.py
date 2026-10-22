"""Original mounted FastAPI SourceMap host reader enrollment join.

Fixture Ed25519 public roots and a *stubbed* corroborator are not a real 0033
process/mount witness, host issuer, 0029 grant or production certification.
"""

from typing import Any

import httpx
import pytest

from ai_osop.api import main
from ai_osop.api import source_map_host_witness_operator as source
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from tests.qualification.test_source_map_host_witness_operator_20261022 import (
    ENGAGEMENT,
    IDENTITY,
    REQUEST,
    _bearer,
    _proofs,
    api,
)


_SLOT = "_independently_host_enrolled_source_map_witness_20261022"


@pytest.mark.asyncio
async def test_actual_main_uses_explicit_host_enrollment_with_only_metadata(
    api: dict[str, Any],
) -> None:
    calls = []

    class SyntheticCorroborator:
        def __init__(self, actions: FlowMCPActionStore) -> None:
            assert isinstance(actions, FlowMCPActionStore)

        async def corroborate(self, **proofs: Any) -> dict[str, Any]:
            calls.append(proofs)
            return {
                "status": "corroborated_read_only",
                "0033_epoch": 2,
                "0033_revision": 8,
                "observed_mount_read_only": True,
                "authorizes_execution": False,
                "authorizes_mount_or_replay": False,
            }

    api["monkeypatch"].setattr(source, "SourceMap0033CurrentWitness", SyntheticCorroborator)

    async def host_reader(engagement: str, original: str, operator: str):
        assert (engagement, original, operator) == (
            ENGAGEMENT,
            REQUEST,
            "independently-signed-operator",
        )
        return source.HostPinnedSourceMapReadback(dict(IDENTITY), _proofs())

    service = source.SourceMapHostWitnessOperator(
        independently_enrolled=True,
        host_pinned_reader=host_reader,
        actions=object.__new__(FlowMCPActionStore),
    )
    assert not hasattr(main.app.state, _SLOT)
    source.install_host_source_map_witness_operator(main.app, service)
    with pytest.raises(ValueError, match="enrollment"):
        source.install_host_source_map_witness_operator(main.app, service)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app, client=("127.0.0.1", 8181)),
            base_url="http://original-host.test",
        ) as client:
            reply = await client.post(
                "/system/source-map/host-witness/readback",
                json={"engagement_id": ENGAGEMENT, "request_id": REQUEST},
                headers={"Authorization": "Bearer " + _bearer()},
            )
        assert reply.status_code == 200, reply.text
        answer = reply.json()
        assert answer["status"] == "CURRENT_ORIGINAL_HOST_WITNESS_VERIFIED"
        assert answer["authorizes_execution"] is False
        assert answer["original_action_replayed"] is False
        assert answer["target_effect_verified"] is False
        assert answer["production_certified"] is False
        assert len(calls) == 1
        assert "signature" not in reply.text and "private" not in reply.text
    finally:
        delattr(main.app.state, _SLOT)


def test_unenrolled_host_cannot_install_operator_service() -> None:
    assert not hasattr(main.app.state, _SLOT)
    with pytest.raises(ValueError, match="enrollment"):
        source.install_host_source_map_witness_operator(
            main.app, source.SourceMapHostWitnessOperator()
        )
    assert not hasattr(main.app.state, _SLOT)
