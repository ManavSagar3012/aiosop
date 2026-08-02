"""Tests for Sprint 1.2 — Primitive Ledger model + persistence layer."""

import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.models import AttackChain, ChainStatus, PrimitiveLedger, PrimitiveType
from ai_osop.memory.primitive_ledger import PrimitiveLedgerStore

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _prim(**kw) -> PrimitiveLedger:
    defaults = dict(
        primitive_type=PrimitiveType.NUCLEI_SIGNAL,
        engagement_id="eng-test",
        source="nuclei",
        dedup_key="sha256-test-key",
        target="http://example.com/vuln",
        raw={"template_id": "cve-2024-xxxx"},
        confidence=0.75,
        severity_hint="high",
    )
    defaults.update(kw)
    return PrimitiveLedger(**defaults)


def _fake_driver(single_record=None):
    """Build a minimal AsyncDriver double."""
    session_ctx = MagicMock()
    # run() → result → single()
    result_mock = AsyncMock()
    result_mock.single = AsyncMock(
        return_value=single_record
        or {"node_id": "prim-abc123", "created_at": datetime.utcnow().isoformat()}
    )

    async def _aiter_result(self):
        for row in []:
            yield row

    result_mock.__aiter__ = _aiter_result
    session_ctx.__aenter__ = AsyncMock(return_value=session_ctx)
    session_ctx.__aexit__ = AsyncMock(return_value=None)
    session_ctx.run = AsyncMock(return_value=result_mock)

    driver = MagicMock()
    driver.session = MagicMock(return_value=session_ctx)
    return driver, session_ctx


# --------------------------------------------------------------------------
# Model tests
# --------------------------------------------------------------------------


class TestPrimitiveLedgerModel:
    def test_default_id_prefix(self):
        p = _prim()
        assert p.id.startswith("prim-")

    def test_primitive_type_enum(self):
        for pt in PrimitiveType:
            p = _prim(primitive_type=pt)
            assert p.primitive_type == pt

    def test_dedup_key_required(self):
        p = _prim(dedup_key="stable-fingerprint")
        assert p.dedup_key == "stable-fingerprint"

    def test_confidence_bounds(self):
        p_low = _prim(confidence=0.0)
        p_high = _prim(confidence=1.0)
        assert p_low.confidence == 0.0
        assert p_high.confidence == 1.0

    def test_not_promoted_by_default(self):
        p = _prim()
        assert p.promoted_to_finding is False
        assert p.finding_id is None


class TestAttackChainModel:
    def test_chain_id_prefix(self):
        c = AttackChain(
            engagement_id="eng-test",
            primitive_ids=["prim-1", "prim-2"],
            title="Test chain",
            status=ChainStatus.BUILDING,
        )
        assert c.id.startswith("chain-")

    def test_chain_default_status(self):
        c = AttackChain(engagement_id="eng-test")
        assert c.status == ChainStatus.BUILDING

    def test_chain_poc_script_default_empty(self):
        c = AttackChain(engagement_id="eng-test")
        assert c.poc_script == []


# --------------------------------------------------------------------------
# Store tests (all Neo4j calls mocked)
# --------------------------------------------------------------------------


class TestPrimitiveLedgerStore:
    @pytest.mark.asyncio
    async def test_upsert_primitive_calls_merge(self):
        driver, session = _fake_driver()
        store = PrimitiveLedgerStore(driver=driver)
        prim = _prim()
        node_id = await store.upsert_primitive(prim)
        assert node_id == "prim-abc123"
        session.run.assert_awaited()

    @pytest.mark.asyncio
    async def test_upsert_primitive_serialises_raw_as_json(self):
        driver, session = _fake_driver()
        store = PrimitiveLedgerStore(driver=driver)
        prim = _prim(raw={"key": "value", "nested": [1, 2, 3]})
        await store.upsert_primitive(prim)
        # Verify the raw argument passed to run was JSON-encoded
        call_args = session.run.call_args
        params = call_args[0][1]  # positional second arg is the param dict
        assert json.loads(params["raw"]) == {"key": "value", "nested": [1, 2, 3]}

    @pytest.mark.asyncio
    async def test_promote_to_finding(self):
        driver, session = _fake_driver()
        store = PrimitiveLedgerStore(driver=driver)
        # promote_to_finding doesn't use single() — just runs a SET
        session.run = AsyncMock(return_value=MagicMock())
        await store.promote_to_finding("prim-xyz", "vuln-abc")
        session.run.assert_awaited()

    @pytest.mark.asyncio
    async def test_setup_schema_ignores_already_exists(self):
        """DDL errors for 'already exists' must be swallowed."""
        from neo4j.exceptions import ClientError

        driver = MagicMock()
        session_ctx = MagicMock()
        session_ctx.__aenter__ = AsyncMock(return_value=session_ctx)
        session_ctx.__aexit__ = AsyncMock(return_value=None)
        # Simulate "already exists" error
        err = Exception("already exists for this label combination")
        session_ctx.run = AsyncMock(side_effect=err)
        driver.session = MagicMock(return_value=session_ctx)
        store = PrimitiveLedgerStore(driver=driver)
        # Should NOT raise
        await store.setup_schema()

    @pytest.mark.asyncio
    async def test_upsert_chain(self):
        driver, session = _fake_driver()
        store = PrimitiveLedgerStore(driver=driver)
        chain = AttackChain(
            engagement_id="eng-test",
            primitive_ids=["prim-1", "prim-2"],
            title="Test chain",
        )
        chain_id = await store.upsert_chain(chain)
        assert chain_id == chain.id
        # run was called for chain MERGE + link for each primitive
        assert session.run.call_count >= 1
