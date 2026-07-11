import asyncio
from ai_osop.memory.session_memory import SessionMemory

async def run():
    mem = SessionMemory()
    await mem.connect()
    for i in range(1, 6):
        agent_id = f"vuln-agent-{i:03d}"
        hb_key = f"agent:heartbeat:{agent_id}"
        hb = await mem.retrieve_hot(hb_key)
        state_key = f"agent:{agent_id}"
        state = await mem.retrieve_hot(state_key)
        
        print(f"Agent: {agent_id}")
        if hb:
            print(f"  Live Heartbeat -> Status: {hb.get('status')} | Current Task: {hb.get('task_id')} | Last Seen: {hb.get('last_seen')}")
        else:
            print("  Live Heartbeat -> None")
        if state:
            print(f"  Stored State -> Status: {state.get('status')} | Shutdown At: {state.get('shutdown_at')}")
        else:
            print("  Stored State -> None")
        print("-" * 50)
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
