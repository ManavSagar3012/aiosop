import asyncio
import sys
from ai_osop.memory.session_memory import SessionMemory

async def run():
    mem = SessionMemory()
    await mem.connect()
    
    # Query all active agent heartbeats in Redis
    agents = await mem.get_all_agents()
    print("--- AGENT STATUS IN REDIS ---")
    for agent_id, data in agents.items():
        print(f"Agent ID: {agent_id}")
        print(f"  Data: {data}")
        print("-" * 50)
        
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
