"""Versioned PostgreSQL schema upgrades before serving worker/API traffic.

Legacy deployments created ORM tables without Alembic tracking. We identify
their actual base schema before stamping so partial/unknown databases fail
closed instead of silently accepting a guessed migration baseline.
"""

from pathlib import Path
from typing import Optional

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine

# Register supervision ORM tables in the SessionMemory Base before create_all.
from ai_osop.memory import supervision_store as _supervision_models  # noqa: F401
from ai_osop.memory import terminal_lifecycle as _terminal_models  # noqa: F401
from ai_osop.memory import model_usage as _model_usage_models  # noqa: F401


# Only stamp an unversioned legacy schema when the columns expected by the
# historical baseline are actually present. Table-name checks alone are not
# sufficient: stamping a truncated table would skip its missing migrations.
_LEGACY_BASE_COLUMNS = {
    "tasks": {
        "id", "type", "priority", "agent_type", "payload", "dependencies",
        "max_retries", "timeout_seconds", "scope_check", "approval_required",
        "status", "result", "retry_count", "created_at", "started_at",
        "completed_at", "engagement_id", "assigned_agent_id",
    },
    "session_states": {
        "session_id", "scope", "roe", "phase", "agents", "checkpoint_id",
        "audit_log_position", "created_at", "updated_at",
    },
    "approval_requests": {
        "id", "task_id", "agent_id", "action_type", "target", "payload_summary",
        "risk_assessment", "evidence", "status", "operator_id",
        "operator_notes", "requested_at", "responded_at", "engagement_id",
    },
    "audit_logs": {
        "event_id", "timestamp", "event_type", "severity", "actor_type",
        "actor_id", "action", "result", "context", "integrity_hash",
        "engagement_id",
    },
    "user_sessions": {
        "pk", "engagement_id", "user_label", "cookies", "bearer_token",
        "local_storage", "session_storage", "csrf_token", "extra_headers",
        "user_agent", "captured_at", "expires_at", "metadata_blob",
    },
}


async def _legacy_revision(engine: AsyncEngine) -> Optional[str]:
    """Return baseline revision for a verified unversioned legacy installation."""
    async with engine.connect() as connection:
        def inspect_schema(sync_connection):
            inspector = inspect(sync_connection)
            if inspector.has_table("alembic_version"):
                return None
            required = set(_LEGACY_BASE_COLUMNS)
            found = set(inspector.get_table_names())
            if not (found & required):
                return None
            if not required <= found:
                raise RuntimeError("Partial legacy database: manual schema reconciliation required")
            session_columns = set()
            for table, expected_columns in _LEGACY_BASE_COLUMNS.items():
                actual_columns = {
                    column["name"] for column in inspector.get_columns(table)
                }
                missing = expected_columns - actual_columns
                if missing:
                    raise RuntimeError(
                        f"Legacy table {table} missing required baseline columns: "
                        + ", ".join(sorted(missing))
                    )
                if table == "session_states":
                    session_columns = actual_columns
            return "0002" if "created_by" in session_columns else "0001"

        return await connection.run_sync(inspect_schema)


def _upgrade_migrations(
    sync_connection, db_uri: str, legacy_revision: Optional[str]
) -> None:
    """Run Alembic commands against one existing PG DDL transaction."""
    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parents[3]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    # ConfigParser percent interpolation requires literal escaping.
    config.set_main_option("sqlalchemy.url", db_uri.replace("%", "%%"))
    config.attributes["connection"] = sync_connection
    if legacy_revision:
        command.stamp(config, legacy_revision)
    command.upgrade(config, "head")


async def ensure_schema(engine: AsyncEngine, db_uri: str) -> None:
    """Upgrade known schemas and refuse startup when migration tooling fails."""
    # All API replicas use the same session-scoped advisory lock so the Alembic
    # version row cannot be stamped/upgraded concurrently at startup.
    async with engine.connect() as lock_connection:
        await lock_connection.execute(text("SELECT pg_advisory_lock(805060110003)"))
        try:
            legacy_revision = await _legacy_revision(engine)
            # PostgreSQL supports transactional DDL. A failed migration now
            # rolls back both Alembic's legacy version stamp and schema DDL.
            async with engine.begin() as migration_connection:
                await migration_connection.run_sync(
                    _upgrade_migrations, db_uri, legacy_revision
                )
        finally:
            await lock_connection.execute(text("SELECT pg_advisory_unlock(805060110003)"))
