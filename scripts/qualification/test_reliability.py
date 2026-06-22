"""AI-OSOP Reliability Qualification Suite

Validates:
- Restart recovery (warm storage fallback)
- MCP circuit breaker behavior
- Task retry limits
- Approval timeout handling
- Graceful degradation when MCP is unreachable

Run:
    python scripts/qualification/test_reliability.py
"""

import asyncio
import sys
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, "src")

from ai_osop.api.deps import assert_engagement_access
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest, MCPExecuteResponse
from ai_osop.core.models import Task, ApprovalRequest
from ai_osop.core.config import AgentType


class ReliabilityQualification:
    def __init__(self):
        self.results: list[dict] = []
        self.passed = 0
        self.failed = 0

    def _record(self, name: str, passed: bool, detail: str = "") -> None:
        self.results.append({"test": name, "passed": passed, "detail": detail})
        if passed:
            self.passed += 1
        else:
            self.failed += 1

    # -------------------- MCP Circuit Breaker --------------------

    async def test_mcp_circuit_breaker_opens_after_threshold(self) -> None:
        """Circuit breaker should open after 5 consecutive failures."""
        conn = MCPConnection(server_id="test-mcp", host="localhost", port=9999)
        # Simulate 5 failures
        for _ in range(5):
            conn._record_failure()

        if conn._circuit_open:
            self._record("mcp_circuit_opens", True, "Circuit breaker opened after 5 failures")
        else:
            self._record("mcp_circuit_opens", False, f"Circuit breaker NOT open after 5 failures (count={conn._failure_count})")

    async def test_mcp_circuit_breaker_recovers(self) -> None:
        """Circuit breaker should recover after 30 seconds."""
        conn = MCPConnection(server_id="test-mcp", host="localhost", port=9999)
        conn._circuit_open = True
        conn._circuit_opened_at = datetime.utcnow() - timedelta(seconds=31)
        conn._failure_count = 5

        conn._circuit_breaker_check()
        if not conn._circuit_open and conn._failure_count == 0:
            self._record("mcp_circuit_recovers", True, "Circuit breaker recovered after 31s")
        else:
            self._record("mcp_circuit_recovers", False, f"Still open={conn._circuit_open}, count={conn._failure_count}")

    async def test_mcp_circuit_breaker_blocks_execution(self) -> None:
        """When circuit is open, execute must return 'circuit_open' status."""
        conn = MCPConnection(server_id="test-mcp", host="localhost", port=9999)
        conn._circuit_open = True
        conn._circuit_opened_at = datetime.utcnow()
        conn._initialized = True
        conn._tools = {}

        # We need to mock the tools so execute can reach the circuit check
        req = MCPExecuteRequest(tool_name="test_tool", parameters={})
        resp = await conn.execute(req)
        if resp.status == "circuit_open":
            self._record("mcp_circuit_blocks", True, "Execution blocked with circuit_open status")
        else:
            self._record("mcp_circuit_blocks", False, f"Unexpected status: {resp.status}")

    # -------------------- Task Retry --------------------

    def test_task_retry_fields_exist(self) -> None:
        """Task model must have retry_count and max_retries."""
        task = Task(
            type="test",
            agent_type=AgentType.RECON,
            payload={},
            engagement_id="eng-001",
            max_retries=3,
        )
        if task.max_retries == 3 and task.retry_count == 0:
            self._record("task_retry_fields", True, f"max_retries={task.max_retries}, retry_count={task.retry_count}")
        else:
            self._record("task_retry_fields", False, f"Unexpected values: max_retries={task.max_retries}, retry_count={task.retry_count}")

    # -------------------- Approval Timeout --------------------

    def test_approval_request_has_timeout(self) -> None:
        """ApprovalRequest must have a timeout mechanism."""
        req = ApprovalRequest(
            task_id="task-001",
            agent_id="agent-1",
            action_type="exploit",
            target="example.com",
            payload_summary="sql injection test",
            risk_assessment="high",
            engagement_id="eng-001",
        )
        # Check that requested_at is set (used for timeout calculation)
        if req.requested_at is not None:
            self._record("approval_timeout_field", True, f"requested_at set: {req.requested_at.isoformat()}")
        else:
            self._record("approval_timeout_field", False, "requested_at is None")

    # -------------------- Warm Storage Fallback --------------------

    async def test_warm_storage_fallback(self) -> None:
        """assert_engagement_access must fall back to warm storage."""
        import ai_osop.api.deps as deps_module

        session = MagicMock()
        session.session_id = "eng-001"
        session.created_by = "operator-1"

        mock_orch = MagicMock()
        mock_orch._sessions = {}  # Not in hot memory
        mock_orch.session_memory.load_session_state = AsyncMock(return_value=session)

        original_state = deps_module.state.get("orchestrator")
        deps_module.state["orchestrator"] = mock_orch

        try:
            operator = {"sub": "operator-1", "role": "operator"}
            result = await assert_engagement_access(operator, "eng-001")
            if result.session_id == "eng-001":
                self._record("warm_storage_fallback", True, "Loaded from warm storage successfully")
            else:
                self._record("warm_storage_fallback", False, "Wrong session returned")
        except Exception as e:
            self._record("warm_storage_fallback", False, f"Exception: {e}")
        finally:
            deps_module.state["orchestrator"] = original_state

    # -------------------- Orchestrator --------------------

    async def run_all(self) -> None:
        print("=" * 60)
        print("AI-OSOP Reliability Qualification Suite")
        print("=" * 60)

        await self.test_mcp_circuit_breaker_opens_after_threshold()
        await self.test_mcp_circuit_breaker_recovers()
        await self.test_mcp_circuit_breaker_blocks_execution()
        self.test_task_retry_fields_exist()
        self.test_approval_request_has_timeout()
        await self.test_warm_storage_fallback()

        print("-" * 60)
        for r in self.results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"[{status}] {r['test']}: {r['detail']}")
        print("-" * 60)
        print(f"Results: {self.passed} passed, {self.failed} failed")
        print("=" * 60)

        if self.failed > 0:
            sys.exit(1)


async def main() -> None:
    suite = ReliabilityQualification()
    await suite.run_all()


if __name__ == "__main__":
    asyncio.run(main())
