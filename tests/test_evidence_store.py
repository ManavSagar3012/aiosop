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


def test_signature_is_deterministic_and_key_dependent():
    from ai_osop.evidence.store import _sign_receipt_fields

    canonical = {"receipt_id": "rcpt-1", "engagement_id": "eng-1", "vuln_id": "v1"}
    sig1 = _sign_receipt_fields(b"key-a", "prev-x", canonical)
    sig2 = _sign_receipt_fields(b"key-a", "prev-x", canonical)
    sig3 = _sign_receipt_fields(b"key-b", "prev-x", canonical)
    sig4 = _sign_receipt_fields(b"key-a", "prev-y", canonical)
    assert sig1 == sig2
    assert sig1 != sig3 and sig1 != sig4
