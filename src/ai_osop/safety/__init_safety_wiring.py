"""Safety Module Wiring (T1.1, T1.2, T2.1, T2.2, T3.1, T3.3, T3.4)

This module provides initialization and wiring functions for the new
safety modules. Called from the API lifespan to integrate them into
the existing orchestrator and agent infrastructure.
"""

import logging
from typing import Any

logger = logging.getLogger("ai_osop.safety.wiring")


def wire_tool_call_validator(mcp_registry: Any) -> Any:
    """Initialize and return a ToolCallValidator wired to the MCP registry."""
    from ai_osop.safety.tool_call_validator import ToolCallValidator
    from ai_osop.safety.output_schema import register_known_tools

    validator = ToolCallValidator(mcp_registry=mcp_registry)

    # Register known tools from MCP registry
    if hasattr(mcp_registry, "_servers"):
        for server_id, conn in mcp_registry._servers.items():
            try:
                tools = getattr(conn, "_tools", []) or []
                tool_names = [t.name for t in tools if hasattr(t, "name")]
                if tool_names:
                    register_known_tools(server_id, tool_names)
            except Exception as e:
                logger.debug("tool_registration_skip server=%s error=%s", server_id, e)

    return validator


def wire_stagnation_detector(orchestrator: Any) -> Any:
    """Initialize and attach a StagnationDetector to the orchestrator."""
    from ai_osop.orchestrator.stagnation_detector import StagnationDetector

    detector = StagnationDetector()
    orchestrator._stagnation_detector = detector
    return detector


def wire_effort_tracker(orchestrator: Any) -> Any:
    """Initialize and attach an EffortTracker to the orchestrator."""
    from ai_osop.core.effort_tracker import EffortTracker

    tracker = EffortTracker()
    orchestrator._effort_tracker = tracker
    return tracker


def wire_effectiveness_tracker(orchestrator: Any) -> Any:
    """Initialize and attach an EffectivenessTracker to the orchestrator."""
    from ai_osop.core.effectiveness_tracker import EffectivenessTracker

    tracker = EffectivenessTracker()
    orchestrator._effectiveness_tracker = tracker
    return tracker


def wire_agent_pools(orchestrator: Any) -> Any:
    """Initialize and attach an AgentPoolManager to the orchestrator."""
    from ai_osop.orchestrator.agent_pool import AgentPoolManager

    manager = AgentPoolManager()
    orchestrator._agent_pool_manager = manager
    return manager


def wire_self_test_runner() -> Any:
    """Initialize the SelfTestRunner."""
    from ai_osop.safety.self_test import SelfTestRunner

    return SelfTestRunner()


async def run_startup_self_tests(orchestrator: Any = None) -> dict:
    """Run self-tests at startup and return results."""
    from ai_osop.safety.self_test import SelfTestRunner

    runner = SelfTestRunner(orchestrator=orchestrator)
    suite = await runner.run_all()

    logger.info(
        "self_test_results total=%d passed=%d failed=%d score=%.2f secure=%s",
        suite.total,
        suite.passed,
        suite.failed,
        suite.score,
        suite.is_secure,
    )

    return {
        "total": suite.total,
        "passed": suite.passed,
        "failed": suite.failed,
        "score": suite.score,
        "is_secure": suite.is_secure,
        "results": [
            {
                "test": r.test_name,
                "category": r.category,
                "passed": r.passed,
                "severity": r.severity,
                "description": r.description,
            }
            for r in suite.results
        ],
    }
