"""Verify state-changing requests retain structured audit with stdlib logging.

The ASGI fixture has no app startup or real database/target access.
"""

from __future__ import annotations

import logging

import httpx
import pytest
from fastapi import FastAPI, Request

from ai_osop.api.main import AuditLogMiddleware


@pytest.mark.asyncio
async def test_post_succeeds_and_audit_fields_are_structured(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = FastAPI()
    app.add_middleware(AuditLogMiddleware)

    @app.post("/audit-fixture")
    async def accepted(request: Request) -> dict[str, bool]:
        request.scope["operator"] = {"sub": "operator-fixture"}
        request.state.request_id = "correlation-fixture"
        return {"accepted": True}

    with caplog.at_level(logging.INFO, logger="ai_osop.api"):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://unit.test"
        ) as client:
            response = await client.post("/audit-fixture", json={"request": "inert"})

    assert response.status_code == 200
    assert response.json() == {"accepted": True}
    records = [record for record in caplog.records if record.getMessage() == "api_audit"]
    assert len(records) == 1
    record = records[0]
    assert record.method == "POST"
    assert record.path == "/audit-fixture"
    assert record.operator_id == "operator-fixture"
    assert record.status_code == 200
    assert record.request_id == "correlation-fixture"
