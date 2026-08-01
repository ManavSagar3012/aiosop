"""SQLAlchemy Core table for exploit receipts (mirrors session_memory metadata style)."""

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, Index, Integer,
                        MetaData, String, Table)

metadata = MetaData()

exploit_receipts = Table(
    "exploit_receipts",
    metadata,
    Column("receipt_id", String, primary_key=True),
    Column("engagement_id", String, nullable=False),
    Column("vuln_id", String, nullable=False),
    Column("approval_id", String, nullable=False),
    Column("hop_idx", Integer, nullable=True),
    Column("chain_id", String, nullable=True),
    Column("verdict", String, nullable=False),
    Column("confidence", Float, nullable=False),
    Column("confirmation_note", String, nullable=False, server_default=""),
    Column("oracle_signals", JSON, nullable=False),
    Column("artifacts", JSON, nullable=False),
    Column("request_summary", JSON, nullable=False),
    Column("response_summary", JSON, nullable=False),
    Column("scope_hash", String, nullable=False, server_default=""),
    Column("prev_receipt_hash", String, nullable=False, server_default=""),
    Column("integrity_sig", String, nullable=False, server_default=""),
    Column("simulated", Boolean, nullable=False, server_default="false"),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Index("idx_exploit_receipts_eng", "engagement_id"),
    Index("idx_exploit_receipts_vuln", "vuln_id"),
)


async def ensure_schema(sa_engine) -> None:
    async with sa_engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
