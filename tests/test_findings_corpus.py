"""Withdrawal-rule tests for external corpus ingestion (Task 7)."""

import pytest

from ai_osop.core.findings_corpus import FindingCorpusService


@pytest.mark.asyncio
async def test_ingest_refuses_withdrawn_entries():
    svc = FindingCorpusService(graph_memory=None, session_memory=None)
    entry = {"id": "syn-1", "withdrawn": True, "vuln_class": "idor"}
    with pytest.raises(ValueError, match="withdrawn"):
        await svc.ingest_external([entry])


@pytest.mark.asyncio
async def test_ingest_accepts_clean_entries():
    svc = FindingCorpusService(graph_memory=None, session_memory=None)
    entries = [
        {"id": "syn-1", "withdrawn": False, "vuln_class": "idor"},
        {"id": "syn-2", "vuln_class": "xss_reflected"},
    ]
    assert await svc.ingest_external(entries) == 2
