import asyncio
from sqlalchemy import text
from ai_osop.memory.session_memory import SessionMemory

async def main():
    sm = SessionMemory()
    await sm.connect()
    
    async with sm._async_session() as session:
        result = await session.execute(
            text("SELECT id, type, agent_type, status FROM tasks ORDER BY created_at DESC LIMIT 10;")
        )
        for row in result.fetchall():
            print(f"Task ID: {row[0]}, Type: {row[1]}, Agent Type in DB: {row[2]}, Status: {row[3]}")
            
    await sm.close()

if __name__ == "__main__":
    asyncio.run(main())
