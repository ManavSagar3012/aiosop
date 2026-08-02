"""Task 14: ReceiptStore construction gated by evidence_receipts_enabled flag."""

from __future__ import annotations


async def test_receipt_store_none_when_flag_off():
    from ai_osop.api.main import _build_receipt_store_if_enabled
    from ai_osop.core.config import settings

    settings.evidence_receipts_enabled = False
    try:
        assert _build_receipt_store_if_enabled(sa_engine=None, integrity=None) is None
    finally:
        settings.evidence_receipts_enabled = False
