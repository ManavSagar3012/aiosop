"""Replayability Truth Engine — honesty contract tests.

The engine must NEVER fabricate a replay result. Previously execute_replay
hardcoded success=True (fabricated proof); these tests lock in that it now:
  - returns 'unverified' with no replay script,
  - fails closed to 'unverified' when no real sandbox runtime is configured,
  - reports the TRUE exit status when a real sandbox runs,
  - treats a sandbox error as 'unverified' (never success).
All hermetic: an injected fake SandboxManager, no Docker.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core import evidence_vault as ev_mod
from ai_osop.core.evidence_vault import ReplayabilityTruthEngine
from ai_osop.core.models import EvidencePackage


def _pkg(**kw):
    return EvidencePackage(finding_id="f-1", engagement_id="e-1", **kw)


def _fake_sandbox(exec_result):
    sb = MagicMock()
    sb.create_sandbox = AsyncMock()
    sb.execute_in_sandbox = AsyncMock(return_value=exec_result)
    sb.destroy_sandbox = AsyncMock()
    return sb


@pytest.mark.asyncio
async def test_no_replay_script_is_unverified():
    engine = ReplayabilityTruthEngine(sandbox_manager=_fake_sandbox({}))
    out = await engine.execute_replay(_pkg(replay_script=[]))
    assert out["verified"] is False
    assert out["provenance"] == "unverified"


@pytest.mark.asyncio
async def test_mock_runtime_fails_closed_never_fabricates(monkeypatch):
    # Even with a replay script, a 'mock' runtime must NOT run and must NOT claim success.
    monkeypatch.setattr(ev_mod.settings, "sandbox_runtime", "mock", raising=False)
    sb = _fake_sandbox({"status": "success", "exit_code": 0})
    engine = ReplayabilityTruthEngine(sandbox_manager=sb)

    out = await engine.execute_replay(_pkg(replay_script=["curl", "http://x"]))

    assert out["verified"] is False
    assert out["provenance"] == "unverified"
    sb.execute_in_sandbox.assert_not_awaited()  # never even attempted


@pytest.mark.asyncio
async def test_real_runtime_reports_true_success(monkeypatch):
    monkeypatch.setattr(ev_mod.settings, "sandbox_runtime", "docker", raising=False)
    sb = _fake_sandbox(
        {"status": "success", "exit_code": 0, "stdout": "PWNED", "execution_time": 0.4}
    )
    engine = ReplayabilityTruthEngine(sandbox_manager=sb)

    out = await engine.execute_replay(_pkg(replay_script=["curl", "http://x"]))

    assert out["verified"] is True
    assert out["provenance"] == "live"
    assert out["exit_code"] == 0
    sb.create_sandbox.assert_awaited_once()
    sb.destroy_sandbox.assert_awaited_once()  # cleanup always runs


@pytest.mark.asyncio
async def test_real_runtime_reports_true_failure(monkeypatch):
    # A non-zero exit is an honest failure, not success.
    monkeypatch.setattr(ev_mod.settings, "sandbox_runtime", "docker", raising=False)
    sb = _fake_sandbox({"status": "error", "exit_code": 7, "stderr": "boom"})
    engine = ReplayabilityTruthEngine(sandbox_manager=sb)

    out = await engine.execute_replay(_pkg(replay_script=["curl", "http://x"]))

    assert out["verified"] is False
    assert out["provenance"] == "live"
    assert out["exit_code"] == 7


@pytest.mark.asyncio
async def test_sandbox_error_is_unverified_not_success(monkeypatch):
    monkeypatch.setattr(ev_mod.settings, "sandbox_runtime", "docker", raising=False)
    sb = _fake_sandbox({})
    sb.execute_in_sandbox = AsyncMock(side_effect=RuntimeError("daemon down"))
    engine = ReplayabilityTruthEngine(sandbox_manager=sb)

    out = await engine.execute_replay(_pkg(replay_script=["curl", "http://x"]))

    assert out["verified"] is False
    assert out["provenance"] == "unverified"
    sb.destroy_sandbox.assert_awaited_once()  # cleanup still runs on error
