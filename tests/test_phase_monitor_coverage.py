"""Coverage target tests for ai_osop.orchestrator.phase_monitor (PhaseMonitor).

Baseline: 68% coverage, 317 stmts / 103 missed. The uncovered regions are:

* ``_assert_vulnerability_mcp_ready``  (empty registry, missing servers, circuit state)
* ``_auto_advance_phase``              (hyp-gate livelock bound, backoff gate,
                                        transition success/failure bookkeeping)
* ``_on_phase_enter``                  (RECON chain, VULNERABILITY_DISCOVERY fan-out,
                                        EXPLOITATION exploit-gating, REPORTING dispatch)

These tests drive the helper methods directly with a mocked Orchestrator
boundary — the real 5-second background monitor loop is never spawned
(except for two deliberately-tiny single-tick loop tests).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType, EngagementPhase
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.phase_monitor import PhaseMonitor


def _session(
    phase: EngagementPhase,
    engagement_id: str = "eng-cov",
    domains: Optional[List[str]] = None,
) -> SessionState:
    """Build a real SessionState — canonical_engagement_id resolves to scope.engagement_id."""
    scope = ScopeDefinition(
        engagement_id=engagement_id,
        domains=list(domains) if domains is not None else ["example.com"],
    )
    return SessionState(
        session_id=f"sess-{engagement_id}",
        scope=scope,
        phase=phase.value,
    )


def _make_orch(
    *,
    phase_policy: Optional[Dict] = None,
    is_complete: bool = True,
    auto_next: Any = EngagementPhase.VULNERABILITY_DISCOVERY,
    ready: bool = True,
    transition_err: Optional[Exception] = None,
    reasoning_loop: Any = None,
    hypotheses: Optional[List[Dict[str, Any]]] = None,
) -> MagicMock:
    """Mock Orchestrator with the attributes PhaseMonitor actually touches."""
    orch = MagicMock()
    orch.PHASE_POLICY = (
        phase_policy
        if phase_policy is not None
        else {
            EngagementPhase.RECONNAISSANCE: {"auto_next": EngagementPhase.VULNERABILITY_DISCOVERY},
        }
    )
    orch.reasoning_loop = reasoning_loop
    orch.graph_memory = AsyncMock()
    orch.graph_memory.get_hypotheses_by_engagement = AsyncMock(
        return_value=list(hypotheses or [])
    )
    orch.graph_memory.run_read_query = AsyncMock(return_value=[])
    orch._is_phase_complete = AsyncMock(return_value=is_complete)
    orch._resolve_auto_next = AsyncMock(return_value=auto_next)
    orch._auto_transition_ready = MagicMock(return_value=ready)
    orch._auto_transition_failures = {}
    orch._record_auto_transition_failure = MagicMock()
    orch._audit_log = AsyncMock()

    em = MagicMock()
    em._domain_to_url = MagicMock(side_effect=lambda d: f"https://{d}")
    em.transition_phase = AsyncMock(side_effect=transition_err)
    em.ensure_authenticated_discovery = AsyncMock()
    orch.engagement_manager = em

    scheduler = MagicMock()
    scheduler.schedule_task = AsyncMock()
    scheduler._persist_task_dependency = AsyncMock()
    orch.task_scheduler = scheduler

    return orch


def _registry(server_map: Optional[Dict[str, MagicMock]] = None) -> MagicMock:
    """MCP registry mock; ``server_map`` keys become ``_servers``/``get_server`` sources."""
    registry = MagicMock()
    server_map = server_map or {}
    registry._servers = server_map
    registry.get_server = MagicMock(side_effect=lambda sid: server_map.get(sid))
    return registry


def _conn(state: str = "closed", initialized: bool = True) -> MagicMock:
    c = MagicMock()
    c.get_circuit_state = MagicMock(return_value=state)
    c._initialized = initialized
    return c


def _scheduled(orch: MagicMock) -> List[Task]:
    return [c.args[0] for c in orch.task_scheduler.schedule_task.call_args_list]


# ---------------------------------------------------------------------------
# _assert_vulnerability_mcp_ready
# ---------------------------------------------------------------------------


def test_vuln_mcp_fails_closed_on_empty_registry():
    orch = MagicMock()
    orch.mcp_registry = _registry({})
    pm = PhaseMonitor(orch)
    with pytest.raises(WorkflowException, match="no MCP servers"):
        pm._assert_vulnerability_mcp_ready()


def test_vuln_mcp_fails_when_both_critical_scanners_missing():
    orch = MagicMock()
    orch.mcp_registry = _registry({"websocket-mcp": _conn()})
    pm = PhaseMonitor(orch)
    with pytest.raises(WorkflowException, match="critical MCPs are not ready"):
        pm._assert_vulnerability_mcp_ready()


def test_vuln_mcp_fails_when_circuits_open_or_uninitialized():
    # nuclei present but circuit closed WITHOUT init flag; burp circuit open
    orch = MagicMock()
    orch.mcp_registry = _registry(
        {
            "nuclei-mcp": _conn("closed", initialized=False),
            "burp-mcp": _conn("open"),
        }
    )
    pm = PhaseMonitor(orch)
    with pytest.raises(WorkflowException):
        pm._assert_vulnerability_mcp_ready()


def test_vuln_mcp_passes_when_one_critical_scanner_healthy():
    orch = MagicMock()
    orch.mcp_registry = _registry(
        {
            "nuclei-mcp": _conn("closed", initialized=True),
            "burp-mcp": None,
        }
    )
    # server_map value None -> get_server returns None for burp, that's fine
    pm = PhaseMonitor(orch)
    pm._assert_vulnerability_mcp_ready()  # must not raise


# ---------------------------------------------------------------------------
# _auto_advance_phase
# ---------------------------------------------------------------------------


async def test_auto_advance_advances_when_phase_complete():
    orch = _make_orch()
    pm = PhaseMonitor(orch)
    pm._tick = 3
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch.engagement_manager.transition_phase.assert_awaited_once_with(
        "eng-cov", EngagementPhase.VULNERABILITY_DISCOVERY
    )
    orch._record_auto_transition_failure.assert_not_called()


async def test_auto_advance_uses_canonical_engagement_id():
    phase = EngagementPhase.RECONNAISSANCE
    orch = _make_orch(phase_policy={phase: {"auto_next": EngagementPhase.VULNERABILITY_DISCOVERY}})
    pm = PhaseMonitor(orch)
    sess = _session(phase, engagement_id="scope-key")
    await pm._auto_advance_phase(sess)

    orch._is_phase_complete.assert_awaited_once_with("scope-key", phase)
    first_call = orch.engagement_manager.transition_phase.await_args_list[0]
    assert first_call.args[0] == "scope-key"


async def test_auto_advance_skips_phase_without_policy():
    # RECON has no entry in the policy at all — nothing should happen.
    orch = _make_orch(phase_policy={EngagementPhase.EXPLOITATION: {"auto_next": None}})
    pm = PhaseMonitor(orch)
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch._is_phase_complete.assert_not_called()
    orch.engagement_manager.transition_phase.assert_not_called()


async def test_auto_advance_skips_non_auto_phase():
    # auto_next falsy -> manual gate; never auto-advance.
    orch = _make_orch(phase_policy={EngagementPhase.VULNERABILITY_DISCOVERY: {"auto_next": None}})
    pm = PhaseMonitor(orch)
    await pm._auto_advance_phase(_session(EngagementPhase.VULNERABILITY_DISCOVERY))

    orch._is_phase_complete.assert_not_called()
    orch.engagement_manager.transition_phase.assert_not_called()


async def test_auto_advance_blocked_while_phase_incomplete():
    orch = _make_orch(is_complete=False)
    pm = PhaseMonitor(orch)
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch._resolve_auto_next.assert_not_called()
    orch.engagement_manager.transition_phase.assert_not_called()


async def test_auto_advance_returns_when_next_phase_none():
    orch = _make_orch(auto_next=None)
    pm = PhaseMonitor(orch)
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch._auto_transition_ready.assert_not_called()
    orch.engagement_manager.transition_phase.assert_not_called()


async def test_auto_advance_respects_backoff_gate():
    orch = _make_orch(ready=False)
    pm = PhaseMonitor(orch)
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch._auto_transition_ready.assert_called_once()
    orch.engagement_manager.transition_phase.assert_not_called()


async def test_auto_advance_records_exception_and_backoff():
    orch = _make_orch(transition_err=RuntimeError("guard refused hop"))
    pm = PhaseMonitor(orch)
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch._record_auto_transition_failure.assert_called_once()
    args = orch._record_auto_transition_failure.call_args.args
    assert args[0] == "eng-cov"
    assert args[1] == EngagementPhase.RECONNAISSANCE
    assert isinstance(args[3], RuntimeError)


async def test_auto_advance_clears_failure_state_on_success():
    orch = _make_orch()
    pm = PhaseMonitor(orch)
    orch._auto_transition_failures["eng-cov"] = {"phase": "reconnaissance", "count": 3, "next_tick": 1}
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch.engagement_manager.transition_phase.assert_awaited_once()
    assert "eng-cov" not in orch._auto_transition_failures


async def test_hyp_gates_when_open_untested_hypothesis_within_window():
    loop = MagicMock(_tested_hypotheses={"h-done"})
    orch = _make_orch(
        reasoning_loop=loop,
        hypotheses=[
            {"id": "h-open", "status": "open"},
            {"id": "h-done", "status": "open"},
            {"id": "h-conf", "status": "confirmed"},
        ],
    )
    pm = PhaseMonitor(orch)
    pm._tick = 1
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    # Gate key recorded; no advance, completion never evaluated.
    orch._is_phase_complete.assert_not_called()
    orch.engagement_manager.transition_phase.assert_not_called()
    assert pm._hyp_gate_first_tick[("eng-cov", "reconnaissance")] == 1


async def test_hyp_gate_bound_exceeded_advances_anyway():
    loop = MagicMock(_tested_hypotheses=set())
    orch = _make_orch(reasoning_loop=loop, hypotheses=[{"id": "h", "status": "open"}])
    pm = PhaseMonitor(orch)
    pm._hyp_gate_first_tick[("eng-cov", "reconnaissance")] = 1
    pm._tick = 1 + PhaseMonitor.HYP_GATE_MAX_TICKS  # exactly at the bound
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch.engagement_manager.transition_phase.assert_awaited_once()


async def test_hyp_gate_state_reset_when_no_open_hypotheses():
    loop = MagicMock(_tested_hypotheses={"h1"})
    orch = _make_orch(
        reasoning_loop=loop,
        hypotheses=[{"id": "h1", "status": "open"}],  # open but already tested
    )
    pm = PhaseMonitor(orch)
    pm._hyp_gate_first_tick[("eng-cov", "reconnaissance")] = 2
    pm._tick = 3
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch.engagement_manager.transition_phase.assert_awaited_once()
    assert ("eng-cov", "reconnaissance") not in pm._hyp_gate_first_tick


async def test_hyp_gate_graph_failure_still_advances():
    loop = MagicMock(_tested_hypotheses=set())
    orch = _make_orch(reasoning_loop=loop)
    orch.graph_memory.get_hypotheses_by_engagement = AsyncMock(
        side_effect=ConnectionError("neo4j down")
    )
    pm = PhaseMonitor(orch)
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch.engagement_manager.transition_phase.assert_awaited_once()


async def test_hyp_gate_skipped_when_no_reasoning_loop():
    orch = _make_orch(reasoning_loop=None)
    pm = PhaseMonitor(orch)
    await pm._auto_advance_phase(_session(EngagementPhase.RECONNAISSANCE))

    orch.graph_memory.get_hypotheses_by_engagement.assert_not_called()
    orch.engagement_manager.transition_phase.assert_awaited_once()


# ---------------------------------------------------------------------------
# _on_phase_enter — RECONNAISSANCE
# ---------------------------------------------------------------------------


async def test_recon_dispatches_full_chain_per_domain():
    orch = _make_orch()
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.RECONNAISSANCE, domains=["example.com"]),
        EngagementPhase.RECONNAISSANCE,
    )

    tasks = _scheduled(orch)
    assert len(tasks) == 8  # recon, openapi, xhr, reg_a, login_a, reg_b, login_b, harvest

    recon_t = next(t for t in tasks if t.type == "full_recon")
    assert recon_t.agent_type == AgentType.RECON
    assert recon_t.engagement_id == "eng-cov"  # canonical id
    assert recon_t.payload["domain"] == "example.com"
    assert recon_t.priority == 5

    openapi = next(t for t in tasks if t.type == "openapi_ingest")
    assert openapi.payload["url"] == "https://example.com"

    xhr = next(t for t in tasks if t.type == "capture_authenticated_surface")
    assert xhr.agent_type == AgentType.WORKFLOW
    assert xhr.payload["user_label"].startswith("guest-")
    assert xhr.payload["scope_hosts"] == ["example.com"]

    regs = [t for t in tasks if t.type == "register"]
    logins = [t for t in tasks if t.type == "authenticate"]
    assert {t.engagement_id for t in regs + logins} == {"eng-cov"}

    # Every login depends on its identity's registration completing first.
    for login in logins:
        assert len(login.dependencies) == 1
        assert login.dependencies[0] in {r.id for r in regs}

    # harvest runs after the LAST login (identity 'b' per source comment).
    harvest = next(t for t in tasks if t.type == "spa_harvest")
    assert harvest.dependencies == [logins[-1].id]

    # distinct labels per identity
    assert {t.payload["user_label"] for t in tasks if t.type == "register"} == {
        "recon-probe-example-com-a",
        "recon-probe-example-com-b",
    }
    em = orch.engagement_manager
    em.ensure_authenticated_discovery.assert_awaited_once_with(
        "eng-cov", url_hint="https://example.com"
    )


async def test_recon_no_domains_schedules_nothing_but_ensures_discovery():
    orch = _make_orch()
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.RECONNAISSANCE, domains=[]),
        EngagementPhase.RECONNAISSANCE,
    )
    assert _scheduled(orch) == []
    orch.engagement_manager.ensure_authenticated_discovery.assert_awaited_once_with(
        "eng-cov", url_hint=None
    )


async def test_recon_survives_url_derivation_failure():
    orch = _make_orch()
    orch.engagement_manager._domain_to_url = MagicMock(
        side_effect=ValueError("bad domain")
    )
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.RECONNAISSANCE, domains=["bad_domain"]),
        EngagementPhase.RECONNAISSANCE,
    )

    types = [t.type for t in _scheduled(orch)]
    # full_recon + openapi_ingest still scheduled; browser/auth chain skipped
    assert types == ["full_recon", "openapi_ingest"]


# ---------------------------------------------------------------------------
# _on_phase_enter — VULNERABILITY_DISCOVERY
# ---------------------------------------------------------------------------


def _vuln_graph(graph, *, assets=(), endpoints=(), param_records=(), body_records=()):
    """Route graph_memory.run_read_query by its cypher MATCH target."""
    async def _run(query, params=None):
        if "Asset" in query:
            return [{"domain": d} for d in assets]
        if "status_code IS NOT NULL" in query and "CONTAINS" not in query:
            return [
                {
                    "url": u,
                    "method": "GET",
                    "status_code": 200,
                    "technologies": [],
                }
                for u in endpoints
            ]
        if "query_keys" in query:
            return [dict(r) for r in param_records]
        if "has_body" in query:
            return [dict(r) for r in body_records]
        raise AssertionError(f"unexpected query: {query[:80]}")

    graph.run_read_query = AsyncMock(side_effect=_run)


def _vuln_orch(graph_setup=None, registry=None):
    orch = _make_orch()
    _vuln_graph(
        orch.graph_memory,
        **(graph_setup or {}),
    )
    orch.mcp_registry = registry if registry is not None else _registry(
        {"nuclei-mcp": _conn("closed", True)}
    )
    orch.session_store = MagicMock()
    orch.session_store.list_sessions = AsyncMock(return_value=[])
    return orch


async def test_vuln_entry_fails_closed_when_scanners_unavailable():
    orch = _vuln_orch(registry=_registry({}))
    pm = PhaseMonitor(orch)
    with pytest.raises(WorkflowException):
        await pm._on_phase_enter(
            _session(EngagementPhase.VULNERABILITY_DISCOVERY),
            EngagementPhase.VULNERABILITY_DISCOVERY,
        )
    orch.task_scheduler.schedule_task.assert_not_called()


async def test_vuln_falls_back_to_domain_nuclei_scan_without_endpoints():
    orch = _vuln_orch({"assets": ("example.com",)})
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.VULNERABILITY_DISCOVERY),
        EngagementPhase.VULNERABILITY_DISCOVERY,
    )

    tasks = _scheduled(orch)
    burp = next(t for t in tasks if t.type == "burp_scan")
    assert burp.payload["url"] == "https://example.com"
    assert burp.timeout_seconds == 600

    nuclei = [t for t in tasks if t.type == "nuclei_scan"]
    assert len(nuclei) == 1
    assert nuclei[0].payload["targets"] == ["https://example.com"]


async def test_vuln_endpoint_batched_nuclei_scans():
    orch = _vuln_orch({"assets": ("example.com",), "endpoints": ("https://example.com/a",)})
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.VULNERABILITY_DISCOVERY),
        EngagementPhase.VULNERABILITY_DISCOVERY,
    )

    nuclei = [t for t in _scheduled(orch) if t.type == "nuclei_scan"]
    assert len(nuclei) == 1
    assert nuclei[0].payload["targets"] == ["https://example.com/a"]
    assert nuclei[0].payload["severity"] == "critical,high,medium"


async def test_vuln_get_injection_targets_dispatch_sqli_and_xss():
    orch = _vuln_orch(
        {
            "assets": ("example.com",),
            "param_records": (
                {
                    "url": "https://example.com/search?q=ab&id=1",
                    "query_keys": ["q", "id"],
                    "method": "GET",
                    "technologies": [],
                    "has_body": False,
                    "body_keys": [],
                    "content_type": "",
                    "status_code": 200,
                },
            ),
        }
    )
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.VULNERABILITY_DISCOVERY),
        EngagementPhase.VULNERABILITY_DISCOVERY,
    )

    tasks = _scheduled(orch)
    sqli = [t for t in tasks if t.type == "sqli_scan"]
    xss = [t for t in tasks if t.type == "xss_scan"]
    assert len(sqli) == 1 and len(xss) == 1
    assert sqli[0].payload["method"] == "GET"
    assert sqli[0].payload["level"] == 1  # query params -> bounded level
    assert "data" not in sqli[0].payload
    assert sqli[0].timeout_seconds == PhaseMonitor.SQLI_TASK_TIMEOUT_SECONDS
    assert xss[0].timeout_seconds == PhaseMonitor.ACTIVE_SCAN_TIMEOUT_SECONDS

    # No technologies -> CSRF + JWT fallback scanners fire.
    fallback = {t.type for t in tasks if t.type in {"csrf_scan", "jwt_scan"}}
    assert fallback == {"csrf_scan", "jwt_scan"}


async def test_vuln_body_injection_uses_json_body_and_level2():
    orch = _vuln_orch(
        {
            "assets": ("example.com",),
            "param_records": (
                {
                    "url": "https://example.com/api/login",
                    "query_keys": [],
                    "method": "POST",
                    "technologies": ["express"],
                    "has_body": True,
                    "body_keys": ["email", "password"],
                    "content_type": "application/json",
                },
            ),
        }
    )
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.VULNERABILITY_DISCOVERY),
        EngagementPhase.VULNERABILITY_DISCOVERY,
    )

    tasks = _scheduled(orch)
    sqli = next(t for t in tasks if t.type == "sqli_scan")
    assert sqli.payload["level"] == 2  # body targets need deeper sqlmap pass
    assert sqli.payload["method"] == "POST"
    assert sqli.payload["data"] == '{"email":"test","password":"test"}'


async def test_vuln_no_observed_parameters_audits_and_skips_injection():
    orch = _vuln_orch({"assets": ("example.com",)})
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.VULNERABILITY_DISCOVERY),
        EngagementPhase.VULNERABILITY_DISCOVERY,
    )

    types = [t.type for t in _scheduled(orch)]
    assert "sqli_scan" not in types and "xss_scan" not in types

    orch._audit_log.assert_awaited_once()
    event = orch._audit_log.await_args.args[0]
    assert event.event_type == "active_injection_skipped"
    assert event.engagement_id == "eng-cov"


async def test_vuln_mass_assignment_targets_exclude_auth_endpoints():
    orch = _vuln_orch(
        {
            "assets": ("example.com",),
            "body_records": (
                {
                    "url": "https://example.com/api/Users",
                    "method": "POST",
                    "content_type": "application/json",
                    "body_keys": ["email", "role"],
                },
                # auth-ish path -> must be filtered (JS-NEG-004)
                {
                    "url": "https://example.com/rest/user/login",
                    "method": "POST",
                    "content_type": "application/json",
                    "body_keys": ["email", "password"],
                },
            ),
        }
    )
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.VULNERABILITY_DISCOVERY),
        EngagementPhase.VULNERABILITY_DISCOVERY,
    )

    ma = [t for t in _scheduled(orch) if t.type == "mass_assignment_scan"]
    assert len(ma) == 1
    assert ma[0].payload["url"] == "https://example.com/api/Users"
    # privileged field stripped from base_body
    assert ma[0].payload["base_body"] == {"email": "test"}


async def test_vuln_no_massassign_targets_records_nothing():
    orch = _vuln_orch({"assets": ("example.com",)})
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.VULNERABILITY_DISCOVERY),
        EngagementPhase.VULNERABILITY_DISCOVERY,
    )
    assert not [t for t in _scheduled(orch) if t.type == "mass_assignment_scan"]


async def test_vuln_jwt_dispatch_and_authz_fanout():
    session_a = MagicMock(user_label="user-a", bearer_token="tok-a")
    session_b = MagicMock(user_label="user-b", bearer_token="tok-b")

    orch = _vuln_orch({"assets": ("example.com",)})
    orch.session_store.list_sessions = AsyncMock(side_effect=[
        [session_a],          # jwt poll loop: first poll finds a token
        [session_a, session_b],  # authz section: two identities
    ])
    pm = PhaseMonitor(orch)
    await pm._on_phase_enter(
        _session(EngagementPhase.VULNERABILITY_DISCOVERY, domains=["example.com"]),
        EngagementPhase.VULNERABILITY_DISCOVERY,
    )

    tasks = _scheduled(orch)
    jwt_t = next(t for t in tasks if t.type == "jwt_scan")
    assert jwt_t.payload["url"] == "https://example.com/rest/user/whoami"
    assert jwt_t.payload["user_label"] == "user-a"

    surf = next(t for t in tasks if t.type == "capture_authenticated_surface")
    diff = next(t for t in tasks if t.type == "run_diff_auth_analysis")
    assert diff.dependencies == [surf.id]
    assert diff.payload["user_a"] == "user-a"
    assert diff.payload["user_b"] == "user-b"


async def test_vuln_jwt_poll_exhausts_then_skips_jwt_scan():
    orch = _vuln_orch({"assets": ("example.com",)})
    # Never any token-bearing session: poll loops 12 times, then skips jwt.
    no_token = MagicMock(user_label="anon", bearer_token=None)
    orch.session_store.list_sessions = AsyncMock(return_value=[no_token])

    slept = []

    async def fast_sleep(secs):
        slept.append(secs)  # never actually sleeps; yield via returning None

    # Patch the module-level asyncio.sleep reference used inside phase_monitor.
    import ai_osop.orchestrator.phase_monitor as pm_module

    orig = pm_module.asyncio.sleep
    pm_module.asyncio.sleep = fast_sleep
    try:
        await PhaseMonitor(orch)._on_phase_enter(
            _session(EngagementPhase.VULNERABILITY_DISCOVERY),
            EngagementPhase.VULNERABILITY_DISCOVERY,
        )
    finally:
        pm_module.asyncio.sleep = orig

    assert slept.count(5) == 11  # 12 polls, sleep between each pair
    assert not [t for t in _scheduled(orch) if t.type == "jwt_scan"]
    # sessions exist but no tokens: authz still runs with anonymous identity
    # (sessions list non-empty)
    assert any(t.type == "run_diff_auth_analysis" for t in _scheduled(orch))


async def test_vuln_authz_lookup_failure_is_swallowed():
    orch = _vuln_orch({"assets": ("example.com",)})
    orch.session_store.list_sessions = AsyncMock(side_effect=RuntimeError("db gone"))

    import ai_osop.orchestrator.phase_monitor as pm_module
    orig = pm_module.asyncio.sleep
    async def fast_sleep(_):
        return None
    pm_module.asyncio.sleep = fast_sleep
    try:
        await PhaseMonitor(orch)._on_phase_enter(
            _session(EngagementPhase.VULNERABILITY_DISCOVERY),
            EngagementPhase.VULNERABILITY_DISCOVERY,
        )
    finally:
        pm_module.asyncio.sleep = orig

    tasks = _scheduled(orch)
    # the failure branch means no authz tasks
    assert not any(t.type == "run_diff_auth_analysis" for t in tasks)
    assert not any(t.type == "capture_authenticated_surface" for t in tasks)


# ---------------------------------------------------------------------------
# _on_phase_enter — EXPLOITATION
# ---------------------------------------------------------------------------


def _exploit_orch(vuln_rows):
    orch = _make_orch()
    orch.graph_memory.run_read_query = AsyncMock(return_value=vuln_rows)
    orch.graph_memory.get_endpoint_url_for_vulnerability = AsyncMock(
        side_effect=lambda vid: f"https://example.com/ep/{vid}"
    )
    orch.graph_memory.get_node_details = AsyncMock(
        side_effect=lambda vid: {"vuln_type": f"sqli-{vid}"}
    )
    return orch


async def test_exploitation_dispatches_scanner_suite_and_validation_flow():
    vuln_rows = [
        {"vuln_id": "v1", "severity": "high", "confidence": 0.9},
    ]
    orch = _exploit_orch(vuln_rows)
    await PhaseMonitor(orch)._on_phase_enter(
        _session(EngagementPhase.EXPLOITATION), EngagementPhase.EXPLOITATION
    )

    tasks = _scheduled(orch)
    scan_types = [t for t in tasks if t.type.endswith("_scan")]
    assert len(scan_types) == 11  # one per registered scanner type
    assert all(t.payload["url"] == "https://example.com" for t in scan_types)
    assert all(t.timeout_seconds == PhaseMonitor.ACTIVE_SCAN_TIMEOUT_SECONDS for t in scan_types)

    payload_t = next(t for t in tasks if t.type == "generate_payloads")
    assert payload_t.payload["vuln_type"] == "sqli-v1"
    assert payload_t.payload["count"] == 3

    valid_t = next(t for t in tasks if t.type == "exploit_validation")
    assert valid_t.approval_required is True
    assert valid_t.dependencies == [payload_t.id]
    assert valid_t.payload["vulnerability_id"] == "v1"
    assert valid_t.payload["severity"] == "high"

    orch.task_scheduler._persist_task_dependency.assert_awaited_once_with(
        payload_t, valid_t
    )


async def test_exploitation_filters_info_and_low_confidence():
    vuln_rows = [
        {"vuln_id": "v-info", "severity": "info", "confidence": 1.0},
        {"vuln_id": "v-lowconf", "severity": "high", "confidence": 0.1},
        {"vuln_id": "v-unknown", "severity": "unknown", "confidence": 0.9},
        {"vuln_id": None, "severity": "high", "confidence": 1.0},  # no id -> skipped
    ]
    orch = _exploit_orch(vuln_rows)
    await PhaseMonitor(orch)._on_phase_enter(
        _session(EngagementPhase.EXPLOITATION), EngagementPhase.EXPLOITATION
    )

    types = [t.type for t in _scheduled(orch)]
    assert "generate_payloads" not in types
    assert "exploit_validation" not in types


async def test_exploitation_handles_missing_vuln_node_details():
    vuln_rows = [{"vuln_id": "v1", "severity": "medium", "confidence": 0.8}]
    orch = _exploit_orch(vuln_rows)
    orch.graph_memory.get_node_details = AsyncMock(return_value=None)
    await PhaseMonitor(orch)._on_phase_enter(
        _session(EngagementPhase.EXPLOITATION), EngagementPhase.EXPLOITATION
    )
    payload_t = next(t for t in _scheduled(orch) if t.type == "generate_payloads")
    assert payload_t.payload["vuln_type"] == "unknown"


# ---------------------------------------------------------------------------
# _on_phase_enter — REPORTING
# ---------------------------------------------------------------------------


async def test_reporting_schedules_generate_report():
    orch = _make_orch()
    await PhaseMonitor(orch)._on_phase_enter(
        _session(EngagementPhase.REPORTING), EngagementPhase.REPORTING
    )
    tasks = _scheduled(orch)
    assert len(tasks) == 1
    t = tasks[0]
    assert t.type == "generate_report"
    assert t.agent_type == AgentType.REPORTING
    assert t.payload == {"format": "markdown", "detail_level": "high"}
    assert t.engagement_id == "eng-cov"


async def test_unmatched_phase_is_noop():
    orch = _make_orch()
    await PhaseMonitor(orch)._on_phase_enter(
        _session(EngagementPhase.POST_EXPLOITATION), EngagementPhase.POST_EXPLOITATION
    )
    assert _scheduled(orch) == []
    orch.engagement_manager.transition_phase.assert_not_called()


# ---------------------------------------------------------------------------
# _phase_monitor loop (single-tick smoke)
# ---------------------------------------------------------------------------


async def test_phase_monitor_loop_advances_live_session_once():
    orch = _make_orch()
    orch._running = True
    sess = _session(EngagementPhase.RECONNAISSANCE, engagement_id="live-1")
    orch._sessions = {sess.session_id: sess}

    pm = PhaseMonitor(orch)

    real_sleep = asyncio.sleep
    async def short_sleep(_):
        orch._running = False
        await real_sleep(0)

    import ai_osop.orchestrator.phase_monitor as pm_module
    orig = pm_module.asyncio.sleep
    pm_module.asyncio.sleep = short_sleep
    try:
        await pm._phase_monitor()
    finally:
        pm_module.asyncio.sleep = orig

    assert pm._tick == 1
    orch.engagement_manager.transition_phase.assert_awaited_once()


async def test_phase_monitor_skips_terminal_sessions():
    orch = _make_orch()
    orch._running = True
    sess = _session(EngagementPhase.RECONNAISSANCE, engagement_id="done-1")
    sess.phase = "completed"
    orch._sessions = {sess.session_id: sess}

    pm = PhaseMonitor(orch)
    real_sleep = asyncio.sleep
    async def short_sleep(_):
        orch._running = False
        await real_sleep(0)

    import ai_osop.orchestrator.phase_monitor as pm_module
    orig = pm_module.asyncio.sleep
    pm_module.asyncio.sleep = short_sleep
    try:
        await pm._phase_monitor()
    finally:
        pm_module.asyncio.sleep = orig

    orch._is_phase_complete.assert_not_called()
    orch.engagement_manager.transition_phase.assert_not_called()
