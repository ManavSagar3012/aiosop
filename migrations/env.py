"""Alembic migration environment.

Async SQLAlchemy support for AI-OSOP.
"""

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import AsyncEngine

from ai_osop.auth.session_store import Base as AuthBase

# Import all models so Alembic can discover them
from ai_osop.memory.session_memory import Base as SessionMemoryBase

# Combine metadata from all bases
target_metadata = SessionMemoryBase.metadata

config = context.config

# CLI migrations must use the same database as API startup. Respect an
# explicitly supplied Config URL (e.g. a disposable qualification database).
configured_uri = os.environ.get("OSOP_POSTGRES_URI")
if (
    configured_uri
    and config.get_main_option("sqlalchemy.url")
    == "postgresql+asyncpg://postgres:postgres@localhost:5432/ai_osop"
):
    config.set_main_option("sqlalchemy.url", configured_uri.replace("%", "%%"))

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode with async engine."""
    connectable = AsyncEngine(
        engine_from_config(
            config.get_section(config.config_ini_section, {}),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
            future=True,
        )
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
elif config.attributes.get("connection") is not None:
    # API startup already owns an asyncpg connection and a PostgreSQL
    # transaction. Reuse its sync facade so stamp+upgrade are atomic and do
    # not create another event loop or independent migration transaction.
    do_run_migrations(config.attributes["connection"])
else:
    asyncio.run(run_migrations_online())
