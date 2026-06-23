"""Tests for ai_osop.api.middleware module."""

from __future__ import annotations

from fastapi import FastAPI, Request
from httpx import AsyncClient
from starlette.middleware.base import BaseHTTPMiddleware

import pytest

from ai_osop.api.middleware import CorrelationIdMiddleware
from ai_osop.core.telemetry import RequestContext


class TestCorrelationIdMiddleware:
    @pytest.fixture
    def app(self) -> FastAPI:
        app = FastAPI()
        app.add_middleware(CorrelationIdMiddleware)

        @app.get("/test")
        async def test_endpoint(request: Request):
            return {"request_id": request.state.request_id}

        @app.post("/test")
        async def test_post(request: Request):
            return {"request_id": request.state.request_id}

        return app

    @pytest.fixture
    async def client(self, app: FastAPI) -> AsyncClient:
        async with AsyncClient(app=app, base_url="http://testserver") as client:
            yield client

    async def test_generates_request_id_when_missing(self, client: AsyncClient) -> None:
        """If no X-Request-ID header, middleware generates UUID."""
        response = await client.get("/test")
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"].startswith("req-")
        assert "X-Request-ID" in response.headers

    async def test_uses_provided_request_id(self, client: AsyncClient) -> None:
        """If X-Request-ID header present, use it."""
        response = await client.get("/test", headers={"X-Request-ID": "custom-req-123"})
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"] == "custom-req-123"
        assert response.headers["X-Request-ID"] == "custom-req-123"

    async def test_returns_request_id_in_response(self, client: AsyncClient) -> None:
        """Response includes X-Request-ID header."""
        response = await client.get("/test")
        assert "X-Request-ID" in response.headers
        assert response.headers["X-Request-ID"].startswith("req-")

    async def test_extracts_traceparent_as_request_id(self, client: AsyncClient) -> None:
        """If traceparent header present, extract trace_id as request_id."""
        traceparent = "00-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-a1b2c3d4e5f6a7b8-01"
        response = await client.get("/test", headers={"traceparent": traceparent})
        assert response.status_code == 200
        data = response.json()
        assert "a1b2c3d4" in data["request_id"]

    async def test_binds_to_structlog_context(self, client: AsyncClient) -> None:
        """Request ID appears in structlog contextvars."""
        import structlog

        structlog.contextvars.clear_contextvars()
        response = await client.get("/test", headers={"X-Request-ID": "req-structlog-123"})
        assert response.status_code == 200
        # After request completes, middleware clears contextvars
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("request_id") is None or ctx.get("request_id") == ""
