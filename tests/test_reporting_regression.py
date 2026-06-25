import pytest
from unittest.mock import AsyncMock, MagicMock
from ai_osop.agents.reporting_agent import ReportingAgent
from ai_osop.core.models import Task
from ai_osop.core.config import AgentType
from ai_osop.reporting.exporters import ReportExporter
import json
import os

class MockAgentContext:
    def __init__(self):
        self.agent_id = "reporting-agent-001"
        self.agent_type = AgentType.REPORTING
        self.session_id = "test-session"
        self.status = "idle"
        self.current_task = None
        self.session_memory = AsyncMock()
        self.graph_memory = AsyncMock()
        self.llm_client = AsyncMock()

@pytest.mark.asyncio
async def test_reporting_stats_keys():
    """
    Guards Bug #1: Ensure stats mapping correctly retrieves 'assets' and 'endpoints'
    from get_graph_stats instead of 'total_assets' and 'total_endpoints'.
    """
    ctx = MockAgentContext()
    
    # Mock graph_stats to return the correct database keys
    ctx.graph_memory.get_graph_stats = AsyncMock(return_value={
        "assets": 12,
        "endpoints": 4,
        "total_nodes": 16,
        "vulnerabilities": 0,
        "exploits": 0
    })
    
    # Mock LLM response
    ctx.llm_client.complete = AsyncMock(return_value="Mocked risk narrative.")
    
    # Mock session for Cypher queries (empty findings and graph)
    session_mock = AsyncMock()
    session_mock.run = AsyncMock()
    # Mock result.data() to return empty list
    result_mock = AsyncMock()
    result_mock.data = AsyncMock(return_value=[])
    session_mock.run.return_value = result_mock
    
    ctx.graph_memory._driver.session = MagicMock(return_value=session_mock)
    
    agent = ReportingAgent(ctx)
    await agent.initialize()
    
    task = Task(
        id="task-test-stats",
        type="generate_report",
        agent_type=AgentType.REPORTING,
        engagement_id="eng-test-stats",
        payload={"version": "v1.0-test"}
    )
    ctx.current_task = task
    
    result = await agent._execute(task)
    assert result["status"] == "success"
    
    # Verify report was saved in memory and check its stats
    report_id = "report-eng-test-stats-v1.0-test"
    assert report_id in agent.generated_reports
    
    report_json = agent.generated_reports[report_id]["json"]
    report_data = json.loads(report_json)
    
    assert report_data["stats"]["assets_count"] == 12
    assert report_data["stats"]["endpoints_count"] == 4
    
    # Cleanup files written to disk during test
    reports_dir = os.path.join("reports", "eng-test-stats")
    if os.path.exists(reports_dir):
        for f in os.listdir(reports_dir):
            os.remove(os.path.join(reports_dir, f))
        os.rmdir(reports_dir)

@pytest.mark.asyncio
async def test_reporting_graph_render():
    """
    Guards Bug #2: Ensure the attack graph generator does not raise an AttributeError
    when iterating over results from result.data() (which are plain dicts).
    """
    ctx = MockAgentContext()
    
    ctx.graph_memory.get_graph_stats = AsyncMock(return_value={
        "assets": 2,
        "endpoints": 1,
        "total_nodes": 3
    })
    ctx.llm_client.complete = AsyncMock(return_value="Mocked risk narrative.")
    # Mock session to return real node dictionaries with 'id' and 'labels' keys
    session_mock = AsyncMock()
    session_mock.__aenter__.return_value = session_mock
    # Mock result.data() for findings, nodes, and edges
    findings_result = AsyncMock()
    findings_result.data = AsyncMock(return_value=[])
    
    nodes_result = AsyncMock()
    nodes_result.data = AsyncMock(return_value=[
        {"id": "asset-1", "labels": ["Asset", "Domain"]},
        {"id": "endpoint-1", "labels": ["Endpoint"]}
    ])
    
    edges_result = AsyncMock()
    edges_result.data = AsyncMock(return_value=[
        {"source": "asset-1", "target": "endpoint-1", "type": "HAS_ENDPOINT"}
    ])
    
    # Configure session.run to return the appropriate mock on successive calls
    session_mock.run.side_effect = [findings_result, nodes_result, edges_result]
    
    ctx.graph_memory._driver.session = MagicMock(return_value=session_mock)
    
    agent = ReportingAgent(ctx)
    await agent.initialize()
    
    task = Task(
        id="task-test-graph",
        type="generate_report",
        agent_type=AgentType.REPORTING,
        engagement_id="eng-test-graph",
        payload={"version": "v1.0-test"}
    )
    ctx.current_task = task
    
    # This should execute without throwing AttributeError!
    result = await agent._execute(task)
    assert result["status"] == "success"
    
    report_id = "report-eng-test-graph-v1.0-test"
    report_json = agent.generated_reports[report_id]["json"]
    
    # Check that graph HTML is populated with nodes and edges
    graph_html = agent.generated_reports[report_id]["graph_html"]
    assert "asset-1" in graph_html
    assert "endpoint-1" in graph_html
    assert "HAS_ENDPOINT" in graph_html
    
    # Cleanup files written to disk during test
    reports_dir = os.path.join("reports", "eng-test-graph")
    if os.path.exists(reports_dir):
        for f in os.listdir(reports_dir):
            os.remove(os.path.join(reports_dir, f))
        os.rmdir(reports_dir)


@pytest.mark.asyncio
async def test_finding_certification_engine():
    """
    Guards FindingCertificationEngine and MISSION_QUALITY_CERTIFICATE.md generation.
    """
    from ai_osop.core.findings_quality import FindingCertificationEngine
    from ai_osop.core.models import Vulnerability
    from ai_osop.core.config import Severity, VulnClass
    
    # 1. Test Certify Vulnerability with no evidence
    vuln_low = Vulnerability(
        id="vuln-low-1",
        title="Missing Security Headers",
        description="HSTS/CSP headers are missing.",
        severity=Severity.INFO,
        vuln_type=VulnClass.VULN_SCAN,
        tool_source="nuclei",
        confidence=0.5,
        engagement_id="eng-test-cert"
    )
    cert_low = FindingCertificationEngine.certify_vulnerability(vuln_low, None)
    assert cert_low["evidence_completeness"] == 0.0
    assert cert_low["exploitability_score"] == 0.15
    assert cert_low["business_impact"] == "low"
    assert cert_low["actionable"] is False
    
    # 2. Test Certify Vulnerability with complete evidence (RCE)
    vuln_high = Vulnerability(
        id="vuln-high-1",
        title="Remote Code Execution",
        description="Command injection on target.",
        severity=Severity.CRITICAL,
        vuln_type=VulnClass.RCE,
        tool_source="burp",
        confidence=0.9,
        engagement_id="eng-test-cert"
    )
    evidence = (
        "Request payload: '; id;'\n"
        "Response status: 200 OK\n"
        "Match regex: uid=0(root) gid=0(root) groups=0(root)"
    )
    cert_high = FindingCertificationEngine.certify_vulnerability(vuln_high, evidence)
    assert cert_high["exploitability_score"] == 0.95
    assert cert_high["business_impact"] == "critical"
    assert cert_high["actionable"] is True
    
    # 3. Test generate_mission_certificate with mocked memories
    session_memory_mock = AsyncMock()
    graph_memory_mock = AsyncMock()
    
    graph_memory_mock.get_graph_stats = AsyncMock(return_value={
        "assets": 10,
        "endpoints": 5,
        "total_nodes": 15
    })
    
    session_mock = AsyncMock()
    # Mock result.data() to return our mock RCE vulnerability node
    vuln_result = AsyncMock()
    vuln_result.data = AsyncMock(return_value=[
        {
            "v": {
                "id": "vuln-high-1",
                "title": "Remote Code Execution",
                "severity": "CRITICAL",
                "vuln_type": "rce",
                "evidence": evidence,
                "engagement_id": "eng-test-cert"
            }
        }
    ])
    session_mock.run = AsyncMock(return_value=vuln_result)
    session_mock.__aenter__.return_value = session_mock
    graph_memory_mock._driver.session = MagicMock(return_value=session_mock)
    
    # Run certificate generation
    eid = "eng-test-cert"
    result = await FindingCertificationEngine.generate_mission_certificate(
        eid, session_memory_mock, graph_memory_mock
    )
    
    assert result["verdict"] == "PASS"
    assert result["assets_count"] == 10
    assert result["endpoints_count"] == 5
    assert result["total_findings"] == 1
    assert result["actionable_findings"] == 1
    assert result["avg_evidence_completeness"] == 1.0
    
    # Check that MISSION_QUALITY_CERTIFICATE.md was written to disk
    cert_file_path = os.path.join("reports", eid, "MISSION_QUALITY_CERTIFICATE.md")
    assert os.path.exists(cert_file_path)
    
    with open(cert_file_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "# MISSION QUALITY CERTIFICATE" in content
    assert f"**Engagement ID:** `{eid}`" in content
    assert "**Verdict:** **PASS**" in content
    assert "Remote Code Execution" in content
    assert "10" in content # Assets count
    assert "5" in content # Endpoints count
    
    # Clean up files written to disk
    reports_dir = os.path.join("reports", eid)
    if os.path.exists(reports_dir):
        for f in os.listdir(reports_dir):
            os.remove(os.path.join(reports_dir, f))
        os.rmdir(reports_dir)



@pytest.mark.asyncio
async def test_attack_surface_certifier():
    """
    Guards AttackSurfaceCertifier and ATTACK_SURFACE_CERTIFICATE.md generation.
    """
    from ai_osop.core.findings_quality import AttackSurfaceCertifier
    
    session_memory_mock = AsyncMock()
    graph_memory_mock = AsyncMock()
    
    graph_memory_mock.get_graph_stats = AsyncMock(return_value={
        "assets": 2,
        "endpoints": 1,
        "total_nodes": 3
    })
    
    session_mock = AsyncMock()
    
    # Mock task result (to get raw crawled count)
    task_result = AsyncMock()
    task_result.single = AsyncMock(return_value={"res": '{"endpoints_found": 194}'})
    
    # Mock assets result
    assets_result = AsyncMock()
    assets_result.data = AsyncMock(return_value=[
        {"a": {"type": "subdomain", "value": "api.target.com"}},
        {"a": {"type": "subdomain", "value": "www.target.com"}},
        {"a": {"type": "host", "value": "12.34.56.78"}}
    ])
    
    # Mock endpoints result
    endpoints_result = AsyncMock()
    endpoints_result.data = AsyncMock(return_value=[
        {
            "e": {
                "url": "https://api.target.com/v1/users",
                "path": "/v1/users",
                "query_keys": ["id"],
                "body_schema_keys": []
            }
        }
    ])
    
    # Mock auth endpoints result for Privilege Expansion (PER)
    auth_eps_result = AsyncMock()
    auth_eps_result.data = AsyncMock(return_value=[
        {"auth_required": False, "user_label": "anonymous"},
        {"auth_required": True, "user_label": "admin"}
    ])
    
    session_mock.run.side_effect = [task_result, assets_result, endpoints_result, auth_eps_result]
    session_mock.__aenter__.return_value = session_mock
    graph_memory_mock._driver.session = MagicMock(return_value=session_mock)
    
    # Run certificate generation
    eid = "eng-test-surface"
    result = await AttackSurfaceCertifier.generate_attack_surface_certificate(
        eid, session_memory_mock, graph_memory_mock
    )
    
    assert result["discovery_level"] == "MODERATE"
    assert result["subdomains_count"] == 2
    assert result["hosts_count"] == 1
    assert result["endpoints_count"] == 1
    assert result["api_endpoints_count"] == 1
    assert result["parameter_endpoints_count"] == 1
    assert result["coverage_percent"] == 1.0
    assert result["expansion_ratio"] == "3x"
    assert result["raw_crawled_count"] == 194
    assert result["anonymous_count"] == 1
    assert result["auth_only_count"] == 1
    assert result["admin_only_count"] == 1
    assert result["privilege_expansion_ratio"] == "1.0x"
    
    # Check that ATTACK_SURFACE_EXPANSION_CERTIFICATE.md was written to disk
    cert_file_path = os.path.join("reports", eid, "ATTACK_SURFACE_EXPANSION_CERTIFICATE.md")
    assert os.path.exists(cert_file_path)
    
    with open(cert_file_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "# ATTACK SURFACE EXPANSION CERTIFICATE" in content
    assert "Privilege Expansion (PER)" in content
    assert f"**Engagement ID:** `{eid}`" in content
    assert "api.target.com" in content
    
    # Clean up files written to disk
    reports_dir = os.path.join("reports", eid)
    if os.path.exists(reports_dir):
        for f in os.listdir(reports_dir):
            os.remove(os.path.join(reports_dir, f))
        os.rmdir(reports_dir)

