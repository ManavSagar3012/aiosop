import pytest
from unittest.mock import MagicMock, AsyncMock
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.task_scheduler import TaskScheduler
from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.agents.experimental.graphql_agent import GraphQLAgent
from ai_osop.agents.experimental.js_analyzer_agent import JSAnalyzerAgent
from ai_osop.agents.experimental.mobile_agent import MobileAnalysisAgent

class MockAgentContext:
    def __init__(self, agent_id, agent_type, status="idle"):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.status = status

@pytest.mark.asyncio
async def test_specialized_agents_reject_general_scans():
    """
    Guards Bug #3: Verify that when the primary vuln-agent-001 is busy,
    general scan tasks (nuclei_scan, burp_scan) are NOT routed to
    specialized agents (graphql-agent, js-analyzer, mobile-agent).
    """
    # 1. Create mock agents
    # Primary vuln agent is busy (status = "running")
    vuln_ctx = MockAgentContext("vuln-agent-001", AgentType.VULN_ANALYSIS, "running")
    vuln_agent = VulnAnalysisAgent(vuln_ctx)
    
    # GraphQL agent is idle (status = "idle")
    gql_ctx = MockAgentContext("graphql-agent-001", AgentType.VULN_ANALYSIS, "idle")
    gql_agent = GraphQLAgent(gql_ctx)
    
    # JS Analyzer agent is idle
    js_ctx = MockAgentContext("js-analyzer-agent-001", AgentType.VULN_ANALYSIS, "idle")
    js_agent = JSAnalyzerAgent(js_ctx)
    
    # Mobile agent is idle
    mob_ctx = MockAgentContext("mobile-agent-001", AgentType.VULN_ANALYSIS, "idle")
    mob_agent = MobileAnalysisAgent(mob_ctx)
    
    # 2. Setup mock orchestrator
    mock_orch = MagicMock()
    mock_orch._agents = {
        "vuln-agent-001": vuln_agent,
        "graphql-agent-001": gql_agent,
        "js-analyzer-agent-001": js_agent,
        "mobile-agent-001": mob_agent
    }
    mock_orch._busy_agents = set()
    mock_orch.session_memory.acquire_lock = AsyncMock(return_value=True)
    mock_orch.session_memory.release_lock = AsyncMock(return_value=True)
    
    scheduler = TaskScheduler(mock_orch)
    
    # 3. Attempt to find an agent for a general 'nuclei_scan' task
    agent = await scheduler._find_available_agent(AgentType.VULN_ANALYSIS, "nuclei_scan")
    
    # Assert that no agent was matched (since the primary is busy, and specialized agents reject it)
    assert agent is None
    
    # 4. Attempt to find an agent for a general 'burp_scan' task
    agent_burp = await scheduler._find_available_agent(AgentType.VULN_ANALYSIS, "burp_scan")
    assert agent_burp is None

@pytest.mark.asyncio
async def test_scheduler_routing_correctness():
    """
    Verify that tasks are routed to the correct agent depending on support:
    - nuclei_scan -> goes to VulnAnalysisAgent if idle
    - gql_discover_schema -> goes to GraphQLAgent if idle
    - analyze_js -> goes to JSAnalyzerAgent if idle
    """
    # All agents are idle
    vuln_ctx = MockAgentContext("vuln-agent-001", AgentType.VULN_ANALYSIS, "idle")
    vuln_agent = VulnAnalysisAgent(vuln_ctx)
    
    gql_ctx = MockAgentContext("graphql-agent-001", AgentType.VULN_ANALYSIS, "idle")
    gql_agent = GraphQLAgent(gql_ctx)
    
    js_ctx = MockAgentContext("js-analyzer-agent-001", AgentType.VULN_ANALYSIS, "idle")
    js_agent = JSAnalyzerAgent(js_ctx)
    
    mock_orch = MagicMock()
    mock_orch._agents = {
        "vuln-agent-001": vuln_agent,
        "graphql-agent-001": gql_agent,
        "js-analyzer-agent-001": js_agent
    }
    mock_orch._busy_agents = set()
    mock_orch.session_memory.acquire_lock = AsyncMock(return_value=True)
    mock_orch.session_memory.release_lock = AsyncMock(return_value=True)
    
    scheduler = TaskScheduler(mock_orch)
    
    # nuclei_scan should route to vuln-agent-001 (its supports_task_type falls back to True)
    agent_nuclei = await scheduler._find_available_agent(AgentType.VULN_ANALYSIS, "nuclei_scan")
    assert agent_nuclei is not None
    assert agent_nuclei.ctx.agent_id == "vuln-agent-001"
    
    # Reset busy agents
    mock_orch._busy_agents.clear()
    vuln_ctx.status = "idle"
    gql_ctx.status = "idle"
    js_ctx.status = "idle"
    
    # gql_discover_schema should route to graphql-agent-001 (VulnAnalysisAgent supports it,
    # but we want to verify GraphQLAgent specifically claims it and the scheduler can match it)
    agent_gql = await scheduler._find_available_agent(AgentType.VULN_ANALYSIS, "gql_discover_schema")
    assert agent_gql is not None
    # Depending on registry order, either could match, but graphql-agent-001 MUST support it:
    assert agent_gql.supports_task_type("gql_discover_schema") is True
    
    # Reset busy agents and make vuln-agent busy to force specialized routing
    mock_orch._busy_agents.clear()
    vuln_ctx.status = "running"
    gql_ctx.status = "idle"
    
    # With vuln-agent busy, gql_discover_schema must match graphql-agent-001
    agent_gql_forced = await scheduler._find_available_agent(AgentType.VULN_ANALYSIS, "gql_discover_schema")
    assert agent_gql_forced is not None
    assert agent_gql_forced.ctx.agent_id == "graphql-agent-001"
    
    # With vuln-agent busy, analyze_js must match js-analyzer-agent-001
    agent_js_forced = await scheduler._find_available_agent(AgentType.VULN_ANALYSIS, "analyze_js")
    assert agent_js_forced is not None
    assert agent_js_forced.ctx.agent_id == "js-analyzer-agent-001"
