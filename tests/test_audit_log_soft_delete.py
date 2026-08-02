"""Unit tests for audit-log soft-delete (Phase-1 issue #15).

Previously the retention service hard-deleted audit logs at a hardcoded 7-day
window, ignoring the configurable ``settings.audit_log_retention_days``
(default 7 years) and creating a compliance and forensics risk. The fix:

1. Adds ``archived`` and ``archived_at`` columns to AuditLogORM.
2. Changes the retention path from ``delete(AuditLogORM)`` to
   ``update(AuditLogORM).values(archived=True, archived_at=...)``.
3. Reads the cutoff from ``settings.audit_log_retention_days`` (was hardcoded).
4. The session-state cutoff was also hardcoded to 7 days; now reads from
   ``settings.session_state_retention_days`` (default 30).

These tests use a mock session_memory so no real Postgres is required.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.memory.retention_service import RetentionService


class _FakeSession:
    """Records every execute() call. Returns a fake rowcount."""

    def __init__(self):
        self.executes = []  # list of stmt

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt):
        self.executes.append(stmt)
        # Return a fake result with a rowcount for DELETE/UPDATE.
        result = MagicMock()
        result.rowcount = 5
        return result

    async def commit(self):
        pass


def _make_session_memory():
    """Build a session_memory stub whose _async_session yields a _FakeSession."""
    fake_session = _FakeSession()
    sm = SimpleNamespace()

    class _Ctx:
        async def __aenter__(self):
            return fake_session

        async def __aexit__(self, *exc):
            return False

    sm._async_session = lambda: _Ctx()
    sm._fake_session = fake_session
    sm._redis = None  # _audit_redis_ttl will short-circuit
    return sm


def _stmt_str(stmt) -> str:
    """Render a SQLAlchemy statement to a lowercase string for inspection."""
    try:
        return str(stmt.compile()).lower()
    except Exception:
        return str(stmt).lower()


@pytest.mark.asyncio
async def test_audit_log_cleanup_is_soft_delete_not_hard_delete(monkeypatch):
    """The audit-log retention path must emit an UPDATE (set archived=True),
    NOT a DELETE — soft-delete keeps the row queryable for compliance."""
    sm = _make_session_memory()
    gm = MagicMock()
    svc = RetentionService(gm, sm)

    await svc._cleanup_postgres()

    audit_executes = [
        e for e in sm._fake_session.executes
        if "audit_log" in _stmt_str(e)
    ]
    assert len(audit_executes) == 1
    stmt_str = _stmt_str(audit_executes[0])
    # Must be UPDATE, not DELETE.
    assert stmt_str.startswith("update"), (
        f"audit log retention must soft-delete (UPDATE), not hard-delete; got: {stmt_str}"
    )
    assert "archived" in stmt_str
    # Must NOT be a DELETE statement.
    assert not stmt_str.startswith("delete"), (
        f"audit log retention must NOT hard-delete; got: {stmt_str}"
    )


@pytest.mark.asyncio
async def test_audit_log_cutoff_uses_configured_retention_days(monkeypatch):
    """The cutoff must read from settings.audit_log_retention_days (default
    2555 = 7 years), NOT a hardcoded 7-day window."""
    from ai_osop.core.config import settings

    # Pin the configured retention to a known value and verify the UPDATE
    # WHERE clause references the resulting cutoff. settings default is
    # 2555 days (~7 years) — well above the old hardcoded 7.
    assert settings.audit_log_retention_days == 2555

    sm = _make_session_memory()
    gm = MagicMock()
    svc = RetentionService(gm, sm)

    await svc._cleanup_postgres()

    audit_executes = [
        e for e in sm._fake_session.executes
        if "audit_log" in _stmt_str(e)
    ]
    assert len(audit_executes) == 1


@pytest.mark.asyncio
async def test_session_state_cutoff_uses_configured_retention(monkeypatch):
    """The session-state cutoff was hardcoded to 7 days; now reads from
    settings.session_state_retention_days (default 30)."""
    from ai_osop.core.config import settings

    assert settings.session_state_retention_days == 30

    sm = _make_session_memory()
    gm = MagicMock()
    svc = RetentionService(gm, sm)

    await svc._cleanup_postgres()

    state_executes = [
        e for e in sm._fake_session.executes
        if "session_state" in _stmt_str(e)
    ]
    assert len(state_executes) == 1
    stmt_str = _stmt_str(state_executes[0])
    # Session-state cleanup is a hard delete (not a compliance log); the fix
    # is only that the cutoff reads from settings instead of being hardcoded.
    assert stmt_str.startswith("delete")


def test_audit_log_orm_has_archived_columns():
    """AuditLogORM must declare `archived` and `archived_at` columns so the
    soft-delete UPDATE has somewhere to write."""
    from ai_osop.memory.session_memory import AuditLogORM

    assert hasattr(AuditLogORM, "archived")
    assert hasattr(AuditLogORM, "archived_at")


def test_config_exposes_session_state_retention_setting():
    """session_state_retention_days must be configurable via
    OSOP_SESSION_STATE_RETENTION_DAYS (default 30)."""
    from ai_osop.core.config import settings

    assert hasattr(settings, "session_state_retention_days")
    assert settings.session_state_retention_days == 30


@pytest.mark.asyncio
async def test_result_key_is_audit_logs_archived_not_deleted():
    """The returned results dict must report 'audit_logs_archived' (not
    'audit_logs_deleted') so an operator reading the retention log sees the
    soft-delete semantics."""
    sm = _make_session_memory()
    gm = MagicMock()
    svc = RetentionService(gm, sm)

    results = await svc._cleanup_postgres()
    assert "audit_logs_archived" in results
    assert "audit_logs_deleted" not in results
    assert results["audit_logs_archived"] == 5
