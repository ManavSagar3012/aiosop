"""Task/lease revocation during the signed artifact-to-Docker handoff.

Production SignedFlowTaskResources, PostgresApprovedTaskResourceVerifier and
SandboxManager are exercised with deterministic SQL/Docker test doubles from
the existing signed resource suite. NO application DB, Docker daemon, host
filesystem, network, provider, or assessment target is accessed.
"""

import hashlib
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.exceptions import SandboxException
from ai_osop.memory.flow_resource_materialization import ResourceAdmissionDenied
from ai_osop.safety.approval_binding import pinned_evidence
from ai_osop.safety.scope import SandboxManager
from tests.test_signed_sandbox_resource_delivery_20261016 import sandbox, source


def _race_after_artifact_read(reader, mutate):
    """Switch the authoritative Task/lease after the real artifact await."""
    original = reader.artifacts.read

    async def race(*args):
        result = await original(*args)
        mutate()
        return result

    reader.artifacts.read = race


@pytest.mark.asyncio
async def test_unrevoked_resource_returns_same_immutable_bytes_after_two_checks(sandbox):
    _, _, reader, binding, _, _ = sandbox
    original_verifier = reader.verify_approved_task
    checks = []

    async def counted(item):
        current = await original_verifier(item)
        checks.append(current["approved_command_sha256"])
        return current

    reader.verify_approved_task = counted
    metadata, original = await reader.read(binding)
    assert original == b"safe reference notes\n"
    assert metadata["sha256"] == hashlib.sha256(original).hexdigest()
    assert metadata["approved_for_agent_instructions"] is False
    assert len(checks) == 2
    assert checks[0] == checks[1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "table,key,value",
    [
        ("approval_requests", "status", "revoked"),
        ("tasks", "status", "cancelled"),
        ("session_states", "phase", "halted"),
        ("execution_flows", "revision", 11),
        ("supervision_execution_leases", "state", "released"),
        ("supervision_execution_leases", "owner_id", ""),
        ("session_states", "created_by", "foreign-owner"),
    ],
)
async def test_revocation_or_identity_swap_during_artifact_read_fails_closed(
    sandbox, table, key, value
):
    _, container, reader, binding, rows, _ = sandbox
    _race_after_artifact_read(reader, lambda: rows[table].__setitem__(key, value))
    with pytest.raises(ResourceAdmissionDenied, match="admission changed"):
        await reader.read(binding)
    assert container.archive == b""  # No daemon transfer occurred.


@pytest.mark.asyncio
async def test_docker_provision_denies_before_bytes_cross_daemon_on_approval_revocation(
    sandbox,
):
    manager, container, reader, binding, rows, removed = sandbox
    _race_after_artifact_read(
        reader,
        lambda: rows["approval_requests"].__setitem__("status", "revoked"),
    )
    with pytest.raises(SandboxException, match="Signed sandbox materialization"):
        await manager.provision_approved_flow_resource("sb-1", binding, reader)
    assert container.archive == b""  # Old code transferred before denying.
    assert removed == ["sb-1"]
    assert "sb-1" not in manager._active_sandboxes


@pytest.mark.asyncio
async def test_approved_command_digest_rotation_during_artifact_read_is_denied(sandbox):
    manager, container, reader, binding, rows, removed = sandbox
    payload = rows["tasks"]["payload"]

    def legitimately_reapprove_different_argv():
        payload["resource_command_sha256"] = SandboxManager._command_sha256(
            ["cat", "/run/ai-osop/resources/replacement.txt"]
        )
        rows["approval_requests"]["evidence"] = pinned_evidence([], payload)

    _race_after_artifact_read(reader, legitimately_reapprove_different_argv)
    with pytest.raises(SandboxException, match="Signed sandbox materialization"):
        await manager.provision_approved_flow_resource("sb-1", binding, reader)
    assert container.archive == b""
    assert removed == ["sb-1"]


@pytest.mark.asyncio
async def test_second_verifier_outage_after_successful_signed_artifact_read_denied(sandbox):
    _, container, reader, binding, _, _ = sandbox
    original_verifier = reader.verify_approved_task
    calls = 0

    async def fail_second(item):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected PostgreSQL readback failure")
        return await original_verifier(item)

    reader.verify_approved_task = fail_second
    with pytest.raises(ResourceAdmissionDenied, match="admission changed"):
        await reader.read(binding)
    assert calls == 2
    assert container.archive == b""


@pytest.mark.asyncio
@pytest.mark.parametrize("digest", [None, True, "A" * 64, "invalid", 0])
async def test_malformed_approved_argv_digest_fails_before_artifact_fetch(sandbox, digest):
    _, container, reader, binding, _, _ = sandbox
    original_verifier = reader.verify_approved_task
    reader.artifacts.read = AsyncMock(side_effect=AssertionError("should not fetch bytes"))

    async def malformed(item):
        result = dict(await original_verifier(item))
        result["approved_command_sha256"] = digest
        return result

    reader.verify_approved_task = malformed
    with pytest.raises(ResourceAdmissionDenied, match="command digest unavailable"):
        await reader.read(binding)
    reader.artifacts.read.assert_not_awaited()
    assert container.archive == b""
