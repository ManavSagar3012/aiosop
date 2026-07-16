"""Regression tests for scan-result and Nuclei false-positive guards."""

from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.orchestrator.task_scheduler import TaskScheduler


def test_burp_success_requires_execution_evidence():
    task = Task(type="burp_scan", agent_type=AgentType.VULN_ANALYSIS, engagement_id="eng-test")
    result = {"status": "success", "tool": "burp_scanner", "reasoning": "looks safe"}

    assert TaskScheduler._execution_contract_error(task, result) == (
        "burp_scan result did not prove tool execution"
    )


def test_nuclei_status_match_on_nextjs_response_is_downranked_before_persistence():
    agent = object.__new__(VulnAnalysisAgent)
    raw = {
        "template-id": "default-login",
        "matcher-name": "status-200",
        "host": "https://example.test/login",
        "response": '<script src="/_next/static/chunks/main.js"></script>',
        "info": {"name": "Default Login", "severity": "high"},
    }

    vuln = agent._normalize_nuclei_finding(raw)
    agent._apply_spa_status_only_fp_guard(raw, vuln)

    assert vuln.confidence == 0.1
    assert vuln.exploitability == "low"
    assert vuln.evidence[0]["false_positive_signal"]["status_only_match"] is True

    vuln.confidence = 0.95
    vuln.exploitability = "high"
    GraphMemory._apply_nuclei_spa_persistence_guard(vuln)
    assert vuln.confidence == 0.1
    assert vuln.exploitability == "low"
