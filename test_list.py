import asyncio
import sys
import traceback

async def test():
    print("Starting test...")
    from ai_osop.orchestrator.orchestrator import Orchestrator
    from ai_osop.memory.session_memory import SessionMemory
    from ai_osop.memory.graph_memory import GraphMemory
    from ai_osop.mcp.protocol import MCPRegistry
    from ai_osop.core.llm_client import LiteLLMClient

    print("Connecting SessionMemory...")
    sm = SessionMemory()
    await sm.connect()
    print("Connecting GraphMemory...")
    gm = GraphMemory()
    await gm.connect()
    print("Initializing Orchestrator...")
    mcp = MCPRegistry()
    llm = LiteLLMClient()
    orch = Orchestrator(session_memory=sm, graph_memory=gm, mcp_registry=mcp, llm_client=llm)
    await orch.initialize()
    print("Orchestrator initialized!")
    print("Sessions:", len(orch._sessions))
    for s_id, s in orch._sessions.items():
        print(f"Session {s_id}: {s.model_dump(mode='json')}")

if __name__ == "__main__":
    try:
        asyncio.run(test())
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)
