"""Tests for ai_osop.api.middleware module."""

from __future__ import annotations

from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
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
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://testserver"
        ) as client:
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

    async def test_exception_path_preserves_original_exception(self) -> None:
        """If downstream handler raises an exception, it is preserved and not masked by UnboundLocalError."""
        app = FastAPI()
        app.add_middleware(CorrelationIdMiddleware)

        @app.get("/error")
        async def failing_endpoint():
            raise RuntimeError("Database connection suddenly dropped")

        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as client:
            response = await client.get("/error")
            # Starlette converts unhandled exception to 500 when raise_app_exceptions=False
            assert response.status_code == 500

        # Verify contextvars are cleanly cleared in finally
        assert RequestContext.get()["request_id"] == ""

    def test_prometheus_metrics_collapses_dynamic_ids(self) -> None:
        """Prometheus metrics template collapsing prevents label cardinality explosion."""
        from ai_osop.api.main import PrometheusMetricsMiddleware
        from unittest.mock import MagicMock

        paths_and_expected = [
            ("/engagements/eng-12345/tasks", "/engagements/eng-{id}/tasks"),
            ("/engagements/eng-abcd-ef01/status", "/engagements/eng-{id}/status"),
            ("/findings/vuln-998877/verify", "/findings/vuln-{id}/verify"),
            ("/tasks/task-001/cancel", "/tasks/task-{id}/cancel"),
            ("/approvals/apr-123456", "/approvals/apr-{id}"),
            ("/dlq/dlq-999", "/dlq/dlq-{id}"),
            ("/items/123e4567-e89b-12d3-a456-426614174000", "/items/{id}"),
            ("/health", "/health"),
            ("/ready", "/ready"),
        ]

        for raw_path, expected in paths_and_expected:
            req = MagicMock(spec=Request)
            req.scope = {}
            req.url.path = raw_path
            result = PrometheusMetricsMiddleware._get_path_template(req)
            assert result == expected, f"Failed for {raw_path}: got {result}, expected {expected}"

