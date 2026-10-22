"""Unit tests for safety and environment self_test suite."""

import pytest
from ai_osop.safety.self_test import SafetySelfTest, run_safety_self_test


@pytest.mark.asyncio
async def test_cryptographic_primitives_pass():
    tester = SafetySelfTest()
    res = tester.check_cryptographic_primitives()
    assert res["status"] in ("PASS", "WARN")
    assert "latency_ms" in res


@pytest.mark.asyncio
async def test_scope_enforcement_logic_pass():
    tester = SafetySelfTest()
    res = tester.check_scope_enforcement_logic()
    assert res["status"] == "PASS"
    assert "latency_ms" in res


@pytest.mark.asyncio
async def test_container_runtime_check():
    tester = SafetySelfTest()
    res = tester.check_container_runtime()
    assert res["status"] in ("PASS", "WARN")


@pytest.mark.asyncio
async def test_run_all_diagnostics():
    report = await run_safety_self_test()
    assert report["overall_status"] in ("PASS", "WARN")
    assert "checks" in report
    assert "cryptography" in report["checks"]
    assert "scope_enforcer" in report["checks"]
    assert "container_runtime" in report["checks"]
