"""Correlation cleanup must never replace the true downstream exception.

Inert FastAPI ASGI fixtures exercise production middleware without application
startup, databases, scanners, targets or provider credentials.
"""

import httpx
import pytest
from fastapi import FastAPI

from ai_osop.api.middleware import CorrelationIdMiddleware


@pytest.mark.asyncio
async def test_downstream_exception_is_not_masked_by_request_id_finalizer() -> None:
    app = FastAPI()
    app.add_middleware(CorrelationIdMiddleware)

    @app.get("/fixture/fails")
    async def failing() -> dict[str, bool]:
        raise RuntimeError("original-controlled-fixture-failure")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
        base_url="http://unit.test",
    ) as client:
        with pytest.raises(RuntimeError, match="original-controlled-fixture-failure"):
            await client.get("/fixture/fails", headers={"X-Request-ID": "req-inert"})


@pytest.mark.asyncio
async def test_successful_middleware_preserves_response_and_request_id() -> None:
    app = FastAPI()
    app.add_middleware(CorrelationIdMiddleware)

    @app.get("/fixture/succeeds")
    async def successful() -> dict[str, bool]:
        return {"accepted": True}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://unit.test"
    ) as client:
        response = await client.get("/fixture/succeeds", headers={"X-Request-ID": "req-safe"})
    assert response.status_code == 200
    assert response.json() == {"accepted": True}
    assert response.headers["X-Request-ID"] == "req-safe"
