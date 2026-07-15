import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from ai_osop.core.config import settings

async def main():
    engine = create_async_engine(settings.postgres_uri)
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT * FROM outbox"))
        for row in result:
            print(row)
    await engine.dispose()

asyncio.run(main())
