"""ReceiptStore tests. DB-backed tests skip when Postgres is unavailable;
pure-function tests (signing) always run."""
import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
async def sa_engine():
    """Real SQLAlchemy AsyncEngine from SessionMemory (mirrors session_memory.py:321)."""
    from ai_osop.memory.session_memory import SessionMemory

    sm = SessionMemory()
    try:
        await sm.connect()
    except Exception as e:
        pytest.skip(f"Postgres not available: {e}")
    yield sm._pg_engine
    await sm.close()


async def test_ensure_schema_creates_table(sa_engine):
    from sqlalchemy import text

    from ai_osop.evidence.migrations import ensure_schema

    await ensure_schema(sa_engine)
    async with sa_engine.connect() as conn:
        row = await conn.execute(text("SELECT to_regclass('public.exploit_receipts')"))
        assert row.scalar_one() == "exploit_receipts"
