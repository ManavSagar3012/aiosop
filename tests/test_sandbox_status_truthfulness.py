"""The operator console must never present placeholder sandbox metrics as facts."""

import asyncio

from ai_osop.api.routers.system import get_sandbox_status


def test_sandbox_status_distinguishes_configuration_from_runtime_evidence():
    result = asyncio.run(get_sandbox_status(operator={"role": "operator"}))

    assert isinstance(result["runtime"], str)
    assert result["telemetry_available"] is False
    assert result["network_guard_status"] == "unknown"
    for field in (
        "ebpf_filter_active",
        "tetragon_policy",
        "active_blocks",
        "cpu_load",
        "memory_usage",
    ):
        assert result[field] is None
