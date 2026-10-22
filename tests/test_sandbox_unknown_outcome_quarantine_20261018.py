"""Sandbox transport ambiguity must never leave an automatically reusable worker."""

import asyncio

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.safety.scope import SandboxException, SandboxManager


@pytest.mark.asyncio
async def test_failed_exec_transport_quarantines_before_returning_unknown():
    manager = SandboxManager()
    manager._active_sandboxes["sb-1"] = {"container_id": "cont-1"}
    manager.destroy_sandbox = AsyncMock()
    docker = MagicMock()
    docker.containers.get.return_value.exec_run.side_effect = RuntimeError("lost ack")

    with patch("docker.from_env", return_value=docker):
        result = await manager.execute_in_sandbox("sb-1", ["echo", "test"])

    assert result["status"] == "UNKNOWN"
    assert result["error"] == "sandbox_execution_outcome_unknown"
    manager.destroy_sandbox.assert_awaited_once_with("sb-1")


@pytest.mark.asyncio
async def test_failed_quarantine_does_not_claim_remote_outcome_is_known():
    manager = SandboxManager()
    manager._active_sandboxes["sb-1"] = {"container_id": "cont-1"}
    manager.destroy_sandbox = AsyncMock(
        side_effect=SandboxException("Sandbox still present; firewall retained")
    )
    docker = MagicMock()
    docker.containers.get.return_value.exec_run.side_effect = RuntimeError("ack missing")

    with patch("docker.from_env", return_value=docker):
        with pytest.raises(SandboxException, match="firewall retained"):
            await manager.execute_in_sandbox("sb-1", ["echo", "test"])

    manager.destroy_sandbox.assert_awaited_once_with("sb-1")


@pytest.mark.asyncio
async def test_cancelled_remote_exec_quarantines_and_propagates_cancellation():
    manager = SandboxManager()
    manager._active_sandboxes["sb-1"] = {"container_id": "cont-1"}
    manager.destroy_sandbox = AsyncMock()
    docker = MagicMock()

    with (
        patch("docker.from_env", return_value=docker),
        patch("asyncio.to_thread", new=AsyncMock(side_effect=asyncio.CancelledError())),
    ):
        with pytest.raises(asyncio.CancelledError):
            await manager.execute_in_sandbox("sb-1", ["echo", "test"])

    manager.destroy_sandbox.assert_awaited_once_with("sb-1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_command",
    [[], [""], ["echo", "x" * 4097], ["echo", "a\x00b"], ["ls"] * 33, "echo test"],
)
async def test_legacy_sandbox_argv_is_bounded_before_docker(invalid_command):
    manager = SandboxManager()
    manager._active_sandboxes["sb-1"] = {"container_id": "cont-1"}
    with patch("docker.from_env") as docker:
        with pytest.raises(SandboxException, match="(Invalid bounded|exceeds approved)"):
            await manager.execute_in_sandbox("sb-1", invalid_command)
    docker.assert_not_called()


@pytest.mark.asyncio
async def test_valid_manual_sandbox_argv_remains_supported():
    manager = SandboxManager()
    manager._active_sandboxes["sb-1"] = {"container_id": "cont-1"}
    docker = MagicMock()
    docker.containers.get.return_value.exec_run.return_value = MagicMock(
        exit_code=0, output=(b"ok", b"")
    )
    with patch("docker.from_env", return_value=docker):
        result = await manager.execute_in_sandbox("sb-1", ["echo", "ok"])
    assert result["status"] == "success"
    assert result["stdout"] == "ok"
