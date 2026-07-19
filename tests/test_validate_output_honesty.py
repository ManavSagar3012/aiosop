"""Unit tests for the central honesty guard in BaseAgent._validate_output.

Phase-1 issue #7: ``_validate_output`` was previously a no-op stub
(``return result``). Every scanner in vuln_agent.py self-guards with an
``execution_verified`` flag, but a future scanner that forgets the flag could
silently report ``status="success"`` with no evidence — and nothing in the
framework would reject it.

These tests pin the new contract: ``status="success"`` requires verifiable
execution evidence (flag, findings with evidence, or a raw tool result).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ai_osop.agents.base import BaseAgent


class _ConcreteAgent(BaseAgent):
    """Minimal concrete subclass so we can instantiate and call
    _validate_output without supplying real agent machinery."""

    @property
    def agent_type(self):
        from ai_osop.core.config import AgentType

        return AgentType.VULN_ANALYSIS

    async def _setup_resources(self):
        pass

    async def _cleanup_resources(self):
        pass

    async def _execute(self, task):
        return {"status": "success"}


def _agent():
    """Build a BaseAgent subclass instance — only _validate_output is called."""
    inst = _ConcreteAgent.__new__(_ConcreteAgent)
    return inst


@pytest.mark.asyncio
async def test_success_with_execution_verified_passes():
    result = {"status": "success", "execution_verified": True, "tool": "burp"}
    out = await _agent()._validate_output(result)
    assert out == result  # unchanged


@pytest.mark.asyncio
async def test_success_with_findings_and_evidence_passes():
    result = {
        "status": "success",
        "findings_count": 1,
        "findings": [{"id": "v1", "evidence": [{"type": "request"}]}],
    }
    out = await _agent()._validate_output(result)
    assert out == result


@pytest.mark.asyncio
async def test_success_with_raw_tool_result_passes():
    result = {
        "status": "success",
        "tool_result": {"scan_id": "abc", "vulns": []},
    }
    out = await _agent()._validate_output(result)
    assert out == result


@pytest.mark.asyncio
async def test_success_with_response_payload_passes():
    result = {"status": "success", "response": {"status_code": 200, "body": "..."}}
    out = await _agent()._validate_output(result)
    assert out == result


@pytest.mark.asyncio
async def test_success_without_any_evidence_is_downgraded_to_error():
    """The headline case: a bare ``{"status": "success", "reasoning": "..."}``
    must NOT pass. This is exactly the failure mode that produced mock
    findings on the parent branch."""
    result = {"status": "success", "reasoning": "looks safe based on LLM analysis"}
    out = await _agent()._validate_output(result)
    assert out["status"] == "error"
    assert "verifiable execution evidence" in out["error"]
    assert out["original_result"] == result


@pytest.mark.asyncio
async def test_success_with_empty_findings_list_is_downgraded():
    """An empty findings list is NOT evidence — the agent ran but found
    nothing, so success requires execution_verified OR a raw result."""
    result = {"status": "success", "findings": [], "findings_count": 0}
    out = await _agent()._validate_output(result)
    assert out["status"] == "error"


@pytest.mark.asyncio
async def test_success_with_findings_but_no_evidence_is_downgraded():
    """Findings without evidence lists are not proof — a scanner that emits
    a finding dict with no ``evidence`` key fails the contract."""
    result = {
        "status": "success",
        "findings": [{"id": "v1"}],  # no evidence key
    }
    out = await _agent()._validate_output(result)
    assert out["status"] == "error"


@pytest.mark.asyncio
async def test_success_with_empty_tool_result_is_downgraded():
    """An empty tool_result is not a real tool run."""
    result = {"status": "success", "tool_result": None}
    out = await _agent()._validate_output(result)
    assert out["status"] == "error"

    result = {"status": "success", "tool_result": ""}
    out = await _agent()._validate_output(result)
    assert out["status"] == "error"

    result = {"status": "success", "tool_result": []}
    out = await _agent()._validate_output(result)
    assert out["status"] == "error"


@pytest.mark.asyncio
async def test_failure_status_passes_through_unchanged():
    """Failure / error results are already honest — do not double-process."""
    result = {"status": "failed", "error": "scanner exception"}
    out = await _agent()._validate_output(result)
    assert out == result


@pytest.mark.asyncio
async def test_non_dict_result_passes_through_unchanged():
    """Defensive: a non-dict result is returned unchanged (some legacy paths)."""
    out = await _agent()._validate_output(None)  # type: ignore[arg-type]
    assert out is None


@pytest.mark.asyncio
async def test_execution_verified_false_does_not_satisfy_contract():
    """``execution_verified: False`` is NOT the same as the flag being absent —
    a scanner that explicitly says 'not verified' must NOT pass even if it
    also carries findings with evidence... unless it carries findings with
    evidence (contract 2). The point of contract (1) is the explicit True."""
    # Explicit False + no other evidence -> downgrade.
    result = {"status": "success", "execution_verified": False}
    out = await _agent()._validate_output(result)
    assert out["status"] == "error"

    # Explicit False BUT findings carry evidence -> contract (2) satisfies.
    result = {
        "status": "success",
        "execution_verified": False,
        "findings": [{"id": "v1", "evidence": [{"type": "request"}]}],
    }
    out = await _agent()._validate_output(result)
    assert out == result
