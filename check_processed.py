import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from ai_osop.core.config import settings

async def main():
    engine = create_async_engine(settings.postgres_uri)
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT id, entity_id, processed FROM outbox LIMIT 5"))
        for row in result:
            print(f"ID: {row.id}, Entity ID: {row.entity_id}, Processed: {row.processed}")
    await engine.dispose()

asyncio.run(main())
