"""The PostgreSQL readiness probe must use executable SQLAlchemy 2.x SQL."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.sql.elements import TextClause

from ai_osop.api.deps import state
from ai_osop.api.health import _check_postgres


@pytest.mark.asyncio
async def test_postgres_probe_executes_sqlalchemy_text_clause() -> None:
    conn = AsyncMock()
    engine = MagicMock()
    engine.connect.return_value.__aenter__ = AsyncMock(return_value=conn)
    engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
    previous = state.get("orchestrator")
    state["orchestrator"] = SimpleNamespace(
        session_memory=SimpleNamespace(_pg_engine=engine)
    )
    try:
        result = await _check_postgres()
    finally:
        state["orchestrator"] = previous
    assert result["status"] == "healthy"
    statement = conn.execute.await_args.args[0]
    assert isinstance(statement, TextClause)
    assert str(statement) == "SELECT 1"
