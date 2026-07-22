"""RECONNAISSANCE must dispatch a guest browser XHR-capture (AIOSOP-SPA-XHR-RECON).

The GET link crawler never observes a SPA's client-side XHR/fetch calls, so the
whole API surface of an app like Juice Shop went undiscovered and active
injection had no API targets. Entering RECONNAISSANCE must now also schedule a
guest capture_authenticated_surface task (browser -> HAR -> Endpoint{type:'api'}),
unconditionally — not gated on stored credentials.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import EngagementPhase
from ai_osop.core.models import ScopeDefinition, SessionState
from ai_osop.orchestrator.phase_monitor import PhaseMonitor


def _session() -> SessionState:
    scope = ScopeDefinition(engagement_id="e1", domains=["localhost:3000"])
    return SessionState(session_id="eng-1", scope=scope, phase="reconnaissance")


def _orch() -> MagicMock:
    orch = MagicMock()
    orch.task_scheduler.schedule_task = AsyncMock()
    orch.engagement_manager._domain_to_url = MagicMock(return_value="http://localhost:3000")
    orch.engagement_manager.ensure_authenticated_discovery = AsyncMock()
    return orch


@pytest.mark.asyncio
async def test_recon_dispatches_guest_xhr_capture_alongside_full_recon():
    orch = _orch()
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(_session(), EngagementPhase.RECONNAISSANCE)

    scheduled = [c.args[0] for c in orch.task_scheduler.schedule_task.call_args_list]
    types = [t.type for t in scheduled]
    assert "full_recon" in types  # GET crawler still runs
    assert "capture_authenticated_surface" in types  # + browser XHR discovery
    assert "register" in types  # + registration probe (POST /api/Users discovery)
    assert "authenticate" in types  # + valid-credential login-probe

    xhr = next(t for t in scheduled if t.type == "capture_authenticated_surface")
    assert xhr.payload["user_label"].startswith("guest-")  # per-domain unauth surface
    assert xhr.payload["url"] == "http://localhost:3000"

    reg = next(t for t in scheduled if t.type == "register")
    assert reg.payload["user_label"].startswith("recon-probe-")
    assert reg.payload["register_url"].endswith("/#/register")
    # obviously-synthetic probe credentials, never real (RFC 6761 .test TLD)
    assert reg.payload["credentials"]["email"].endswith("@recon.test")

    probe = next(t for t in scheduled if t.type == "authenticate")
    assert probe.payload["user_label"].startswith("recon-auth-")
    assert probe.payload["login_url"].endswith("/#/login")
    # login reuses the synthetic account the register probe creates, and must
    # wait for registration so the account exists before it fires
    assert probe.payload["credentials"]["email"].endswith("@recon.test")
    assert reg.id in probe.dependencies


@pytest.mark.asyncio
async def test_xhr_capture_skipped_when_url_unresolvable():
    orch = _orch()
    orch.engagement_manager._domain_to_url = MagicMock(return_value="")  # no resolvable URL
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(_session(), EngagementPhase.RECONNAISSANCE)
    types = [c.args[0].type for c in orch.task_scheduler.schedule_task.call_args_list]
    assert "full_recon" in types  # recon still proceeds
    assert "capture_authenticated_surface" not in types  # no capture without a URL
