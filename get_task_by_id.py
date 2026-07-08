import asyncio
from sqlalchemy import text
from ai_osop.memory.session_memory import SessionMemory

async def main():
    sm = SessionMemory()
    await sm.connect()
    
    async with sm._async_session() as session:
        result = await session.execute(
            text("SELECT id, type, agent_type, status, assigned_agent_id, payload FROM tasks WHERE id = 'task-6f9ee8fb9d3e';")
        )
        row = result.fetchone()
        if row:
            print(f"Task ID: {row[0]}")
            print(f"Type: {row[1]}")
            print(f"Agent Type: {row[2]}")
            print(f"Status: {row[3]}")
            print(f"Agent ID: {row[4]}")
            print(f"Payload: {row[5]}")
        else:
            print("Task not found.")
            
    await sm.close()

if __name__ == "__main__":
    asyncio.run(main())
