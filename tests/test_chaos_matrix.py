"""
Pytest integration for Phase P2 Chaos Matrix & Boundary Containment
"""

import pytest
from scripts.chaos.run_chaos_matrix import (
    test_case_1_redis_disconnect_resilience,
    test_case_2_mcp_disconnect_resilience,
    test_case_3_worker_crash_exploit_quarantine,
    test_case_4_revocation_kill_switch,
    test_case_5_loop_detection,
    test_case_6_budget_caps,
    test_case_7_scope_boundary_containment,
)


@pytest.mark.asyncio
async def test_chaos_case_1_redis():
    assert await test_case_1_redis_disconnect_resilience() is True


@pytest.mark.asyncio
async def test_chaos_case_2_mcp():
    assert await test_case_2_mcp_disconnect_resilience() is True


@pytest.mark.asyncio
async def test_chaos_case_3_quarantine():
    assert await test_case_3_worker_crash_exploit_quarantine() is True


@pytest.mark.asyncio
async def test_chaos_case_4_killswitch():
    assert await test_case_4_revocation_kill_switch() is True


def test_chaos_case_5_loop():
    assert test_case_5_loop_detection() is True


def test_chaos_case_6_budget():
    assert test_case_6_budget_caps() is True


def test_chaos_case_7_scope():
    assert test_case_7_scope_boundary_containment() is True
