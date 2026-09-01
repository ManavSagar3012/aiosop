"""FLEET-MODE-001: unit tests for the multi-target intake and aggregation.

Covers the safety invariants and the happy path:
  - happy path: N authorized domains -> N engagements, each confirmed and in
    reconnaissance, per-target scopes isolated (one domain per engagement)
  - authorization_ref is mandatory (fails closed without one)
  - fleet size ceiling: more than MAX_FLEET_TARGETS is refused by the model
  - invalid domains are skipped per-target (never sink the fleet)
  - status aggregation: per-target tasks/findings + totals
"""

from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from ai_osop.api.routers.fleet import (
    FleetIntakeRequest,
    _clean_domain,
    fleet_intake,
    fleet_status,
)
from ai_osop.core.config import EngagementPhase
from ai_osop.core.models import ScopeDefinition, SessionState


def _make_orch():
    orch = MagicMock()
    sessions: Dict[str, SessionState] = {}
    created: List[str] = []

    async def create_engagement(scope, roe, created_by=None):
        sid = f"eng-{datetime.utcnow().strftime('%H%M%S%f')}-{scope.engagement_id}"
        created.append(scope.engagement_id)
        sessions[sid] = SessionState(
            session_id=sid,
            scope=scope,
            roe=roe,
            phase="initialized",
        )
        return sessions[sid]

    async def confirm(sid, operator_id):
        sessions[sid].authorization_confirmed = True
        return sessions[sid]

    async def transition(sid, phase):
        sessions[sid].phase = phase.value
        return sessions[sid]

    orch.create_engagement = create_engagement
    orch.confirm_engagement = confirm
    orch.transition_phase = transition
    orch._sessions = sessions
    orch.state = MagicMock()
    orch.state.get_all_tasks = MagicMock(
        return_value={}  # no tasks in these unit engagements
    )
    orch.graph_memory = MagicMock()
    orch.graph_memory.run_read_query = AsyncMock(return_value=[])
    return orch


def _patch_state(monkeypatch, orch):
    """Swap the fleet module's state binding for one carrying our orchestrator."""
    from ai_osop.api.routers import fleet as fleet_mod

    class _State(dict):
        pass

    fake = _State()
    fake["orchestrator"] = orch
    monkeypatch.setattr(fleet_mod, "state", fake)


OPERATOR = {"sub": "operator-1", "role": "senior_operator"}


async def test_fleet_intake_launches_one_engagement_per_domain(monkeypatch):
    orch = _make_orch()
    _patch_state(monkeypatch, orch)
    req = FleetIntakeRequest(
        targets=["https://alpha.example.com", "beta.example.com"],
        authorization_ref="https://program.example.com/policy operator-1",
    )
    result = await fleet_intake(req, operator=OPERATOR)
    assert result["fleet_id"].startswith("fleet-")
    assert len(result["launched"]) == 2
    assert result["skipped"] == []
    # every engagement confirmed + advanced to reconnaissance
    for t in result["launched"]:
        sess = orch._sessions[t["session_id"]]
        assert sess.authorization_confirmed is True
        assert sess.phase == "reconnaissance"
        # per-target isolation: exactly ONE domain per engagement scope
        assert len(sess.scope.domains) == 1
    domains = sorted(t["domain"] for t in result["launched"])
    assert domains == ["alpha.example.com", "beta.example.com"]
    # the authorization ref flowed onto every engagement card
    for sess in orch._sessions.values():
        assert sess.scope.authorization_ref.startswith("FLEET ")


async def test_fleet_intake_requires_authorization_ref(monkeypatch):
    orch = _make_orch()
    _patch_state(monkeypatch, orch)
    req = FleetIntakeRequest(targets=["x.example.com"], authorization_ref="short")
    with pytest.raises(HTTPException) as ei:
        await fleet_intake(req, operator=OPERATOR)
    assert "authorization_ref" in str(ei.value.detail)


async def test_fleet_size_ceiling_enforced():
    # The pydantic model itself refuses > MAX_FLEET_TARGETS entries.
    with pytest.raises(Exception):
        FleetIntakeRequest(
            targets=[f"t{i}.example.com" for i in range(9)],
            authorization_ref="policy operator-1",
        )


async def test_fleet_intake_skips_invalid_domain_not_fleet(monkeypatch):
    orch = _make_orch()
    _patch_state(monkeypatch, orch)
    req = FleetIntakeRequest(
        targets=["good.example.com", "not a domain", ""],
        authorization_ref="policy operator-1",
    )
    result = await fleet_intake(req, operator=OPERATOR)
    assert len(result["launched"]) == 1
    assert len(result["skipped"]) == 2
    assert result["skipped"][0]["domain"] == "not a domain"


def test_clean_domain_strips_schemes_ports_paths():
    assert _clean_domain("https://x.example.com/path?q=1") == "x.example.com"
    assert _clean_domain("http://Y.example.COM:8443") == "y.example.com"
    with pytest.raises(HTTPException):
        _clean_domain("no-dot-host")
    with pytest.raises(HTTPException):
        _clean_domain("")


async def test_fleet_status_aggregates(monkeypatch):
    orch = _make_orch()
    _patch_state(monkeypatch, orch)
    req = FleetIntakeRequest(
        targets=["a.example.com", "b.example.com"], authorization_ref="policy operator-1"
    )
    await fleet_intake(req, operator=OPERATOR)
    # one target completes; one carries findings via the graph mock
    first_sid = next(iter(orch._sessions))
    orch._sessions[first_sid].phase = "completed"

    async def _query(q, params):
        if params.get("sid") == first_sid:
            return [{"sev": "high"}, {"sev": "high"}, {"sev": "info"}]
        return []

    orch.graph_memory.run_read_query = AsyncMock(side_effect=_query)
    result = await fleet_status(operator=OPERATOR)
    assert result["active_engagements"] == 1
    assert result["totals"]["findings"] == 3
    assert result["totals"]["high"] == 2
    phases = {t["phase"] for t in result["targets"]}
    assert "completed" in phases
    completed_row = next(t for t in result["targets"] if t["phase"] == "completed")
    assert completed_row["report_ready"] is True
