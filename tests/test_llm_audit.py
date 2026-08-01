"""LLM-call audit ledger: hashed prompt/response persisted to WORM audit log."""

import pytest

from ai_osop.core.llm_audit import make_llm_audit_callback
from ai_osop.core.worm_audit import WormAuditLog


class _FakeMemory:
    def __init__(self):
        self.rows = []

    async def run_write(self, query, *params):
        if "INSERT" in query:
            self.rows.append({"payload": params[4]})

    async def run_read(self, query, *params):
        return []


@pytest.mark.asyncio
async def test_llm_call_writes_audit_entry_with_hashes():
    mem = _FakeMemory()
    wal = WormAuditLog(mem)
    cb = make_llm_audit_callback(wal)

    await cb(
        model="gpt-4o",
        messages=[{"role": "user", "content": "hello"}],
        response_text="world",
        usage={"total_tokens": 42},
        tenant_id="org-blue",
    )

    assert len(mem.rows) == 1
    import json as _json

    payload = _json.loads(mem.rows[0]["payload"])
    assert payload["event"] == "llm_call"
    assert payload["model"] == "gpt-4o"
    assert payload["total_tokens"] == 42
    assert payload["prompt_hash"] != payload["response_hash"]
    # Hashes, not content:
    assert "hello" not in str(payload)
    assert "world" not in str(payload)
    assert len(payload["prompt_hash"]) == 64


@pytest.mark.asyncio
async def test_audit_failure_is_silent():
    class _Boom:
        async def append(self, payload, tenant_id):
            raise RuntimeError("nope")

    cb = make_llm_audit_callback(_Boom())
    # Should not raise
    await cb(model="x", messages=[], response_text="ok", usage=None, tenant_id="default")
