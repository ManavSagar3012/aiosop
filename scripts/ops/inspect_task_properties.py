import asyncio
from ai_osop.memory.session_memory import SessionMemory
from sqlalchemy import select
from ai_osop.memory.session_memory import TaskORM

async def run():
    mem = SessionMemory()
    await mem.connect()
    async with mem._async_session() as session:
        tids = ["task-e2c1026cad50"]
        for tid in tids:
            res = await session.execute(
                select(TaskORM).where(TaskORM.id == tid)
            )
            task = res.scalar()
            if task:
                print(f"Task: {task.id} | Status: {task.status} | Agent: {task.assigned_agent_id}")
                print(f"  Payload: {task.payload}")
                print(f"  Result: {task.result}")
                print(f"  Deps: {task.dependencies}")
            else:
                print(f"Task {tid} not found.")
    await mem.close()

if __name__ == "__main__":
    asyncio.run(run())
