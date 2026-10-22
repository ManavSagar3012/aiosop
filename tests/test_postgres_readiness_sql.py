"""Tests verifying PostgreSQL readiness probe and SQLAlchemy 2.x execution (F-03 remediation)."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock
from sqlalchemy import text
from sqlalchemy.sql.elements import TextClause
from sqlalchemy.exc import ObjectNotExecutableError

from ai_osop.api.deps import state
from ai_osop.api.health import _check_postgres


class TestPostgresReadinessSQL:
    async def test_check_postgres_uses_sqlalchemy_text_clause(self) -> None:
        """_check_postgres must pass a TextClause (via text('SELECT 1')) to conn.execute."""
        mock_orch = MagicMock()
        mock_orch.session_memory = MagicMock()
        
        executed_stmts = []
        mock_conn = AsyncMock()

        async def fake_execute(stmt):
            executed_stmts.append(stmt)
            # In SQLAlchemy 2.x, executing a raw string raises ObjectNotExecutableError:
            if isinstance(stmt, str):
                raise ObjectNotExecutableError(stmt)
            return MagicMock(scalar_one=lambda: 1)

        mock_conn.execute = AsyncMock(side_effect=fake_execute)

        mock_engine = MagicMock()
        mock_engine.connect.return_value.__aenter__.return_value = mock_conn
        mock_orch.session_memory._pg_engine = mock_engine

        state["orchestrator"] = mock_orch

        result = await _check_postgres()
        assert result["status"] == "healthy"
        assert len(executed_stmts) == 1
        stmt = executed_stmts[0]
        # Assert stmt is a SQLAlchemy TextClause, not a raw str
        assert isinstance(stmt, TextClause), f"Expected TextClause, got {type(stmt)}"
        assert str(stmt.text).strip().upper() == "SELECT 1"

    async def test_sqlalchemy_2_rejects_raw_string_simulation(self) -> None:
        """Simulate passing a raw string without text() to ensure probe would fail if un-wrapped."""
        mock_orch = MagicMock()
        mock_orch.session_memory = MagicMock()

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(
            side_effect=ObjectNotExecutableError("Not an executable object: 'SELECT 1'")
        )

        mock_engine = MagicMock()
        mock_engine.connect.return_value.__aenter__.return_value = mock_conn
        mock_orch.session_memory._pg_engine = mock_engine

        state["orchestrator"] = mock_orch

        result = await _check_postgres()
        assert result["status"] == "unhealthy"
        assert result["error"] == "postgres connectivity unavailable"
