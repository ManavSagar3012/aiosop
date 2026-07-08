import asyncio
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.core.config import settings

async def main():
    print("Connecting to SessionMemory...")
    sm = SessionMemory()
    await sm.connect()
    
    print("\n--- Engagements ---")
    engagements = await sm.list_engagements()
    if not engagements:
        print("No engagements found in SessionMemory.")
    for eng in engagements:
        print(f"ID: {eng.engagement_id}, Status: {eng.status}, Phase: {eng.phase}")
        
        print(f"  --- Tasks for {eng.engagement_id} ---")
        tasks = await sm.list_tasks(eng.engagement_id)
        if not tasks:
            print("  No tasks found for this engagement.")
        for task in tasks:
            print(f"  Task ID: {task.id}, Type: {task.type}, Status: {task.status}, Agent: {task.assigned_agent_id}")
            if getattr(task, "error", None):
                print(f"    Error: {task.error}")
            if getattr(task, "result", None):
                print(f"    Result: {task.result}")

    print("\n--- Redis Raw Task Queues ---")
    if sm._redis:
        keys = await sm._redis.keys("queue:tasks:*")
        print(f"Queue keys in Redis: {keys}")
        for key in keys:
            length = await sm._redis.zcard(key)
            print(f"  Queue {key}: {length} pending tasks")
            # Print task details
            tasks_data = await sm._redis.zrange(key, 0, -1)
            print(f"  Tasks data: {tasks_data}")

    print("\n--- DLQ (Dead Letter Queue) ---")
    from ai_osop.reliability.dlq import DeadLetterQueue
    dlq = DeadLetterQueue(sm)
    failed_tasks = await dlq.list_failed()
    print(f"Failed tasks in DLQ: {len(failed_tasks)}")
    for ft in failed_tasks:
        print(f"  Task: {ft.task_id}, Reason: {ft.reason}, Failed At: {ft.failed_at}")

    await sm._pg_engine.dispose()
    if sm._redis:
        await sm._redis.close()

if __name__ == "__main__":
    asyncio.run(main())
