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


def test_evidence_bearing_scan_requires_evidence():
    """R3 (2026-07-20): per-class scanners (sqli_scan etc.) must prove execution
    via ``execution_verified=True`` OR a finding carrying evidence. A bare
    ``status=success`` with no findings and no flag is rejected so a future
    scanner cannot silently report success."""
    task = Task(type="sqli_scan", agent_type=AgentType.VULN_ANALYSIS, engagement_id="eng-test")

    bare_success = {"status": "success", "reasoning": "looks injectable"}
    assert TaskScheduler._execution_contract_error(task, bare_success) == (
        "sqli_scan result claimed success without execution_verified "
        "and without any finding carrying evidence"
    )

    flagged = {"status": "success", "execution_verified": True}
    assert TaskScheduler._execution_contract_error(task, flagged) is None

    finding_with_evidence = {
        "status": "success",
        "findings": [{"evidence": [{"request": "GET /?q=' OR 1=1--"}]}],
    }
    assert TaskScheduler._execution_contract_error(task, finding_with_evidence) is None

    # Non-scan task types are unaffected by the contract.
    other_task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="eng-test")
    assert TaskScheduler._execution_contract_error(other_task, {"status": "success"}) is None


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
