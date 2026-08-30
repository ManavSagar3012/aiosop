#!/usr/bin/env python3
"""AIOSOP Golden Path CI Gate (2026-08-30).

Pass/fail gate for the product's core claim: "AIOSOP produces verified,
submission-ready findings from a deliberately-vulnerable target."

Run as: python golden_path_ci_gate.py [--vuln-only]

The gate:
  1. Starts the golden-path vulnerable target
  2. Runs the VulnAnalysisAgent's sqli_http_scan against it
  3. Asserts the finding is validated and has the right shape
  4. Runs the ValidationEngine differential playbook against the target
  5. Asserts the playbook confirms the finding
  6. Stops the target

Exit code 0 = pipeline CAN find real bugs (product claim holds)
Exit code 1 = pipeline CANNOT find real bugs (product claim broken)
"""

import argparse
import json
import os
import subprocess
import sys
import time
import traceback

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Import the target
sys.path.insert(0, os.path.dirname(__file__))
from golden_path_target import run_golden_path_server, PORT

PASS = 0
FAIL = 1


def _log(step: str, msg: str):
    print(f"  [{step}] {msg}")


def _run(step: str, marker: str, func) -> bool:
    """Run a step, print pass/fail, return bool."""
    _log(step, f"starting: {marker}")
    try:
        func()
        print(f"  [PASS] [{step}] {marker}")
        return True
    except Exception as e:
        detail = "".join(traceback.format_exception_only(type(e), e)).strip()
        print(f"  [FAIL] [{step}] {marker}: {detail}")
        return False


def main():
    parser = argparse.ArgumentParser(description="AIOSOP Golden Path CI Gate")
    parser.add_argument(
        "--vuln-only",
        action="store_true",
        help="Only test the target is vulnerable, skip the full pipeline",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("AIOSOP Golden Path CI Gate")
    print("=" * 60)
    print()

    results = []

    # ---- Step 1: Start the target ----
    def _start_target():
        nonlocal server
        nonlocal url
        import requests
        import threading
        from golden_path_target import GoldenPathHandler

        # Find a free port
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 0))
        port = s.getsockname()[1]
        s.close()
        _port = port

        # Bind to the found port
        server = run_golden_path_server(_port)
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()
        time.sleep(0.5)
        url = f"http://localhost:{_port}"
        r = requests.get(f"{url}/health", timeout=5)
        assert r.status_code == 200, f"health check failed: {r.status_code}"

    server = None
    url = None
    results.append(_run("1/5", "start golden-path target", _start_target))
    if not results[-1]:
        return FAIL

    # ---- Step 2: Verify target is exploitable ----
    def _verify_exploitable():
        import requests
        payloads = [
            {"username": "' OR 1=1 --", "password": "x"},
            {"username": "admin' --", "password": "x"},
        ]
        successes = 0
        for p in payloads:
            r = requests.post(f"{url}/login", data=p, timeout=10)
            if "Welcome" in r.text:
                successes += 1
        assert successes >= 2, f"only {successes}/2 payloads succeeded"

    results.append(_run("2/5", "target is exploitable", _verify_exploitable))
    if not results[-1]:
        if server:
            server.shutdown()
        return FAIL

    if args.vuln_only:
        _log("gate", "vuln-only mode: target is exploitable, gate PASSES")
        if server:
            server.shutdown()
        return PASS

    # ---- Step 3: Run the agent's sqli_http_scan ----
    def _run_agent_scan():
        from unittest.mock import AsyncMock, MagicMock
        from ai_osop.agents.base import AgentContext
        from ai_osop.agents.vuln_agent import VulnAnalysisAgent
        from ai_osop.core.config import AgentType
        from ai_osop.core.models import Task

        ctx = AgentContext(
            agent_id="vuln-ci",
            agent_type=AgentType.VULN_ANALYSIS,
            session_id="ci-golden-path",
            session_memory=AsyncMock(),
            graph_memory=AsyncMock(),
            vector_memory=AsyncMock(),
            llm_client=AsyncMock(),
            mcp_registry=MagicMock(),
            rate_limiter=AsyncMock(),
            threat_intel_adapter=None,
            audit_callback=None,
            coordination_bus=None,
        )
        ctx.mcp_registry._servers = {}
        ctx.session_memory.get_session_state = AsyncMock(return_value=None)
        ctx.session_memory.load_session_state = AsyncMock(return_value=None)

        import asyncio
        agent = VulnAnalysisAgent(ctx)
        asyncio.run(agent._setup_resources())

        task = Task(
            type="sqli_http_scan",
            agent_type=AgentType.VULN_ANALYSIS,
            payload={
                "url": f"{url}/login",
                "parameter": "username",
                "control": "__nonexistent_user__",
                "payload": "' OR 1=1 --",
                "success": "Welcome",
                "failure": "Login failed",
                "engagement_id": "ci-golden-path",
            },
            engagement_id="ci-golden-path",
            scope_check=False,
        )

        import asyncio
        result = asyncio.run(agent._execute(task))

        assert result["status"] == "success", f"status: {result.get('status')}"
        assert result["injectable"] is True, "not injectable"
        assert result["findings_count"] == 1, f"count: {result['findings_count']}"
        finding = result["findings"][0]
        assert finding["vuln_type"] == "sqli"
        assert finding.get("validated") is True, "finding not validated"
        assert "login parameter" in finding["title"].lower()
        _log("3/5", f"finding: {finding['title']} [validated={finding.get('validated')}]")

    results.append(_run("3/5", "sqli_http_scan produces validated finding", _run_agent_scan))
    if not results[-1]:
        if server:
            server.shutdown()
        return FAIL

    # ---- Step 4: Run the ValidationEngine differential playbook ----
    def _run_validation():
        from types import SimpleNamespace
        from ai_osop.core import confidence_engine as ce
        from ai_osop.core.validation_engine import (
            PB_SQLI_HTTP_DIFFERENTIAL,
            ValidationEngine,
        )

        import asyncio
        hyp = SimpleNamespace(
            id="hyp-ci-sqli",
            playbook=PB_SQLI_HTTP_DIFFERENTIAL,
            target=f"{url}/login",
            test_plan={
                "url": f"{url}/login",
                "parameter": "username",
                "control_value": "__nonexistent_user__",
                "payload": "' OR 1=1 --",
                "success_marker": "Welcome",
                "failure_marker": "Login failed",
            },
        )
        engine = ValidationEngine(timeout=10.0)
        outcome = asyncio.run(engine.validate(hyp))
        assert outcome.validation_state == ce.VALIDATED, (
            f"got {outcome.validation_state}: {outcome.explanation}"
        )

    results.append(_run("4/5", "ValidationEngine confirms the finding", _run_validation))

    # ---- Step 5: Cleanup ----
    def _cleanup():
        if server:
            server.shutdown()
        _log("5/5", "golden-path target stopped")

    results.append(_run("5/5", "cleanup", _cleanup))

    # ---- Summary ----
    print()
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"{'=' * 60}")
    print(f"  CI Gate: {passed}/{total} steps passed")
    print(f"{'=' * 60}")

    if all(results):
        print()
        print("  [PASS] PRODUCT CLAIM HOLDS: AIOSOP produces a verified finding")
        print("     from a deliberately-vulnerable target.")
        print()
        return PASS
    else:
        print()
        print("  [FAIL] PRODUCT CLAIM BROKEN: Pipeline cannot produce a verified finding.")
        print("     Investigate the failing step above.")
        print()
        return FAIL


if __name__ == "__main__":
    sys.exit(main())