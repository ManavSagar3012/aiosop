import uuid
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.attack_chain_agent import AttackChainAgent
from ai_osop.agents.base import AgentContext
from ai_osop.core.goal_planner import GoalAction, GoalPlanner, GoalState
from ai_osop.core.models import AttackPath, Task


def test_simple_2_step_plan():
    """
    Test a simple 2-step planning scenario:
    anonymous -> find vulnerability -> execute code.
    """
    planner = GoalPlanner()
    initial_state = GoalState(properties={"role": "anonymous", "vuln_discovered": []})
    goal_state = GoalState(properties={"vuln_discovered": ["rce"]})

    actions = [
        GoalAction(
            name="vuln_scan_discover_sqli",
            preconditions={"role": "anonymous"},
            effects={"vuln_discovered": "sqli"},
            cost=1.0,
        ),
        GoalAction(
            name="sqli_to_rce",
            preconditions={"vuln_discovered": "sqli"},
            effects={"vuln_discovered": "rce"},
            cost=2.0,
        ),
    ]

    path = planner.plan(initial_state, goal_state, actions)
    assert path is not None
    assert len(path) == 2
    assert path[0].name == "vuln_scan_discover_sqli"
    assert path[1].name == "sqli_to_rce"


def test_complex_privilege_escalation():
    """
    Test a complex privilege escalation chain:
    standard user -> find IDOR -> steal admin token -> vertical PE.
    """
    planner = GoalPlanner()
    initial_state = GoalState(
        properties={
            "role": "standard_user",
            "vuln_discovered": [],
            "credentials": [],
        }
    )
    goal_state = GoalState(properties={"role": "admin"})

    actions = [
        GoalAction(
            name="find_idor",
            preconditions={"role": "standard_user"},
            effects={"vuln_discovered": "idor"},
            cost=1.0,
        ),
        GoalAction(
            name="steal_admin_token",
            preconditions={"vuln_discovered": "idor"},
            effects={"credentials": "admin_token"},
            cost=2.0,
        ),
        GoalAction(
            name="vertical_pe",
            preconditions={"credentials": "admin_token"},
            effects={"role": "admin"},
            cost=1.0,
        ),
    ]

    path = planner.plan(initial_state, goal_state, actions)
    assert path is not None
    assert len(path) == 3
    assert path[0].name == "find_idor"
    assert path[1].name == "steal_admin_token"
    assert path[2].name == "vertical_pe"


def test_cost_based_path_selection():
    """
    Test that the planner chooses a lower cost path over a higher cost path.
    """
    planner = GoalPlanner()
    initial_state = GoalState(properties={"role": "anonymous", "vuln_discovered": []})
    goal_state = GoalState(properties={"role": "admin"})

    # Path A: vuln_scan_sqli -> exploit_sqli_takeover (Total cost = 1.0 + 3.0 = 4.0)
    # Path B: vuln_scan_idor -> exploit_idor_vertical_pe (Total cost = 1.0 + 1.0 = 2.0)
    actions = [
        GoalAction(
            name="vuln_scan_sqli",
            preconditions={"role": "anonymous"},
            effects={"vuln_discovered": "sqli"},
            cost=1.0,
        ),
        GoalAction(
            name="exploit_sqli_takeover",
            preconditions={"vuln_discovered": "sqli"},
            effects={"role": "admin"},
            cost=3.0,
        ),
        GoalAction(
            name="vuln_scan_idor",
            preconditions={"role": "anonymous"},
            effects={"vuln_discovered": "idor"},
            cost=1.0,
        ),
        GoalAction(
            name="exploit_idor_vertical_pe",
            preconditions={"vuln_discovered": "idor"},
            effects={"role": "admin"},
            cost=1.0,
        ),
    ]

    path = planner.plan(initial_state, goal_state, actions)
    assert path is not None
    assert len(path) == 2
    assert path[0].name == "vuln_scan_idor"
    assert path[1].name == "exploit_idor_vertical_pe"

    # Verify direct high cost action vs indirect low cost sequence
    # Direct Path: direct_pe (cost = 10.0)
    # Indirect Path: vuln_scan_idor -> exploit_idor_vertical_pe (cost = 2.0)
    actions.append(
        GoalAction(
            name="direct_pe",
            preconditions={"role": "anonymous"},
            effects={"role": "admin"},
            cost=10.0,
        )
    )
    path_with_direct = planner.plan(initial_state, goal_state, actions)
    assert path_with_direct is not None
    assert len(path_with_direct) == 2
    assert path_with_direct[0].name == "vuln_scan_idor"
    assert path_with_direct[1].name == "exploit_idor_vertical_pe"


def test_unsolvable_plan():
    """
    Verify that planning returns None when no path can be found.
    """
    planner = GoalPlanner()
    initial_state = GoalState(properties={"role": "anonymous", "vuln_discovered": []})
    goal_state = GoalState(properties={"role": "admin"})

    actions = [
        GoalAction(
            name="vuln_scan_sqli",
            preconditions={"role": "anonymous"},
            effects={"vuln_discovered": "sqli"},
            cost=1.0,
        ),
        # No action to escalate from SQLi to admin is provided
    ]

    path = planner.plan(initial_state, goal_state, actions)
    assert path is None


@pytest.mark.asyncio
async def test_attack_chain_agent_discover_paths_integration():
    """
    Mocked AttackChainAgent tests verifying that _discover_paths successfully
    calls the planner and maps steps to AttackPath.
    """
    mock_ctx = MagicMock(spec=AgentContext)
    mock_ctx.agent_id = "test-chain-agent"
    mock_ctx.graph_memory = AsyncMock()
    mock_ctx.session_memory = AsyncMock()
    mock_ctx.current_task = MagicMock(spec=Task)
    mock_ctx.current_task.engagement_id = "test-eng"

    # Mock GraphMemory query responses:
    # 1. active session query: role "standard"
    # 2. active credential query: has_token True (returns a dummy record)
    mock_ctx.graph_memory.run_read_query.side_effect = [
        [],  # Pathfinding query (no dynamic paths found)
        [{"role_name": "standard"}],  # Session query
        [{"cred_type": "api_token"}],  # Credential query
    ]

    # Mock vulnerabilities in graph: returns an existing IDOR vulnerability
    mock_ctx.graph_memory.get_vulnerabilities_by_engagement.return_value = [{"vuln_type": "idor"}]

    agent = AttackChainAgent(mock_ctx)

    payload = {
        "engagement_id": "test-eng",
        "entry_node_id": "node-entry",
        "goal_types": ["admin_access"],
    }

    result = await agent._discover_paths(payload)

    assert result["status"] == "success"
    assert result["paths_discovered"] > 0
    assert len(result["top_paths"]) > 0

    # Verify that the path was stored in discovered_paths
    assert len(agent.discovered_paths) > 0
    path = agent.discovered_paths[0]
    assert isinstance(path, AttackPath)
    assert path.entry_node_id == "node-entry"
    assert path.engagement_id == "test-eng"
    assert "node-admin" in path.node_ids[-1]
    assert len(path.node_ids) == 2
    assert len(path.edge_ids) == 1
    assert path.edge_ids[0] == "LEADS_TO-0"


@pytest.mark.asyncio
async def test_attack_chain_agent_discover_dynamic_paths():
    """Verify that when Neo4j has LEADS_TO paths, they are traversed and returned directly."""
    mock_ctx = MagicMock(spec=AgentContext)
    mock_ctx.agent_id = "test-chain-agent"
    mock_ctx.graph_memory = AsyncMock()
    mock_ctx.session_memory = AsyncMock()
    mock_ctx.current_task = MagicMock(spec=Task)
    mock_ctx.current_task.engagement_id = "test-eng"

    # Mock GraphMemory to return a dynamic path
    mock_ctx.graph_memory.run_read_query.return_value = [
        {
            "node_ids": ["node-start", "node-vuln"],
            "node_types": ["Endpoint", "Vulnerability"],
            "node_labels": ["http://target.test/login", "SQL Injection"],
        }
    ]

    agent = AttackChainAgent(mock_ctx)
    payload = {
        "engagement_id": "test-eng",
        "entry_node_id": "node-start",
        "goal_types": ["rce"],
    }

    result = await agent._discover_paths(payload)

    assert result["status"] == "success"
    assert result["paths_discovered"] == 1
    assert len(result["top_paths"]) == 1
    assert (
        result["top_paths"][0]["description"]
        == "Graph-traversed path: http://target.test/login -> SQL Injection"
    )
