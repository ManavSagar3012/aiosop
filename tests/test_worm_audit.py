"""WORM audit log: append-only hash-chained event records."""

from datetime import datetime

import pytest

from ai_osop.core.worm_audit import GENESIS_HASH, WormAuditLog


class _FakeMemory:
    """In-memory approximation of the SessionMemory Postgres surface."""

    def __init__(self):
        self.rows = []

    async def run_write(self, query, *params):
        if "INSERT" in query:
            self.rows.append(
                {
                    "id": params[0],
                    "tenant_id": params[1],
                    "prev_hash": params[2],
                    "entry_hash": params[3],
                    "payload": params[4],
                    "created_at": params[5],
                }
            )

    async def run_read(self, query, *params):
        if "entry_hash FROM" in query and "LIMIT 1" in query:
            tenant = params[0]
            rows = [r for r in self.rows if r["tenant_id"] == tenant]
            if not rows:
                return []
            return [{"entry_hash": rows[-1]["entry_hash"]}]
        if "ORDER BY" in query:
            if params:
                return [r for r in self.rows if r["tenant_id"] == params[0]]
            return list(self.rows)
        return []


@pytest.mark.asyncio
async def test_append_chains_and_verifies():
    wal = WormAuditLog(_FakeMemory())
    a1 = await wal.append({"actor": "sys", "action": "task_created", "task_id": "t-1"})
    a2 = await wal.append({"actor": "sys", "action": "task_completed", "task_id": "t-1"})
    assert a1.prev_hash == GENESIS_HASH
    assert a2.prev_hash == a1.entry_hash
    assert await wal.verify_chain() is True


@pytest.mark.asyncio
async def test_tamper_detected():
    wal = WormAuditLog(_FakeMemory())
    await wal.append({"actor": "eve", "action": "modified"})
    await wal.append({"actor": "eve", "action": "covered_up"})
    wal._mem.rows[1]["prev_hash"] = "tampered"
    assert await wal.verify_chain() is False


@pytest.mark.asyncio
async def test_schema_created_on_init():
    wal = WormAuditLog(_FakeMemory())
    await wal.initialize()
    assert await wal.verify_chain() is True
