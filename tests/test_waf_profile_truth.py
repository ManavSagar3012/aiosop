"""WAF readback must not report a fabricated observation."""

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.api.routers import intelligence


@pytest.mark.asyncio
async def test_waf_profiles_report_unavailable_after_engagement_access(monkeypatch):
    access = AsyncMock()
    monkeypatch.setattr(intelligence, "assert_engagement_access", access)

    with pytest.raises(HTTPException) as failure:
        await intelligence.get_waf_profiles("eng-local-lab", {"sub": "operator-local"})

    access.assert_awaited_once()
    assert failure.value.status_code == 503
    assert failure.value.detail == "WAF telemetry unavailable"
