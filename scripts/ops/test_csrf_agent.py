import asyncio
import sys
from ai_osop.core.models import Task
from ai_osop.agents.csrf_agent import CSRFAgent
from ai_osop.agents.base import AgentContext
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.vector_memory import VectorMemory
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.safety.rate_limiter import RateLimiter
from ai_osop.adapters.threat_intel_mcp import ThreatIntelAdapter
from ai_osop.orchestrator.coordination_bus import AgentCoordinationBus
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.config import settings, AgentType

async def test():
    session_memory = SessionMemory()
    await session_memory.connect()
    graph_memory = GraphMemory()
    await graph_memory.connect()
    vector_memory = VectorMemory(settings.postgres_uri)
    await vector_memory.connect()
    mcp_registry = MCPRegistry()
    llm_client = LiteLLMClient()
    rate_limiter = RateLimiter()
    threat_intel_adapter = ThreatIntelAdapter()
    coordination_bus = AgentCoordinationBus()
    
    ctx = AgentContext(
        agent_id="test-csrf-agent",
        agent_type=AgentType.CSRF_SCANNER,
        session_id="test-session",
        session_memory=session_memory,
        graph_memory=graph_memory,
        vector_memory=vector_memory,
        llm_client=llm_client,
        mcp_registry=mcp_registry,
        rate_limiter=rate_limiter,
        threat_intel_adapter=threat_intel_adapter,
        audit_callback=lambda x: asyncio.create_task(asyncio.sleep(0)),
        coordination_bus=coordination_bus,
    )
    agent = CSRFAgent(ctx)
    await agent.initialize()
    
    task = Task(
        id="test-task",
        type="csrf_scan",
        agent_type="csrf_scanner",
        engagement_id="test-eng",
        payload={"url": "https://ginandjuice.shop/catalog?searchTerm=test", "method": "GET"}
    )
    
    # Execute via execute_task
    res = await agent.execute_task(task)
    print("execute_task result:", res)
    
    await session_memory.close()
    await graph_memory.close()
    await vector_memory.close()
    await mcp_registry.close_all()

if __name__ == "__main__":
    asyncio.run(test())
