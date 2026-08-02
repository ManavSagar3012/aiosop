"""Alembic migration environment.

Async SQLAlchemy support for AI-OSOP.
"""

import asyncio
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import AsyncEngine

from alembic import context

# Import all models so Alembic can discover them
from ai_osop.memory.session_memory import Base as SessionMemoryBase
from ai_osop.auth.session_store import Base as AuthBase

# Combine metadata from all bases
target_metadata = SessionMemoryBase.metadata

config = context.config

# AIOSOP-ALEMBIC-URL-001: the ini hardcoded a stale WSL host IP
# (172.27.190.63:5432) that drifts per-boot and does not match where Postgres
# actually listens on dev hosts (127.0.0.1:15432). Prefer the SAME runtime env
# var the application uses so `alembic` always targets the real database; fall
# back to the ini only when it is unset.
import os

_env_db_url = os.environ.get("OSOP_POSTGRES_URI")
if _env_db_url:
    config.set_main_option("sqlalchemy.url", _env_db_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


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
else:
    asyncio.run(run_migrations_online())
