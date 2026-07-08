"""FastAPI middleware for AI-OSOP observability.

Middleware stack (applied in order, bottom = closest to request):
  CorrelationIdMiddleware  → injects X-Request-ID, binds RequestContext
  PrometheusMetricsMiddleware → counts/durations/errors
  AuditLogMiddleware       → audit log for state-changing requests
  SecurityHeadersMiddleware → security headers
"""

from __future__ import annotations

import time
import uuid
from typing import Optional

import structlog
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from ai_osop.core.telemetry import (
    RequestContext,
    extract_trace_id_from_traceparent,
    generate_request_id,
)
from ai_osop.core.tracing import trace_span

logger = structlog.get_logger("ai_osop.api.middleware")


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Inject correlation ID into every request, bind to contextvars, and return in response.

    Order of precedence for request ID:
      1. X-Request-ID header (if provided by client)
      2. traceparent header trace_id (if client sends W3C trace context)
      3. Generated UUID4 (new request)

    The request ID is:
      - Bound to RequestContext contextvars (async-safe)
      - Bound to structlog contextvars (auto-injected into all logs)
      - Returned in the X-Request-ID response header
      - Added to every OTel span as attribute ai_osop.request_id
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        # 1. Extract or generate request ID
        request_id = self._extract_request_id(request)
        request.state.request_id = request_id

        # 2. Extract user identity from auth if available
        user_id: Optional[str] = None
        try:
            operator = request.scope.get("operator", {})
            if isinstance(operator, dict):
                user_id = operator.get("sub")
        except Exception as e:
            logger.warning("broad_exception_caught", error=str(e))
            pass

        # 3. Bind to contextvars and structlog
        RequestContext.bind(request_id=request_id, user_id=user_id or "anonymous")
        RequestContext.sync_from_otel()

        # 4. Create OTel span for the API request (if OTel enabled)
        span_name = f"api.{request.method.lower()}.{request.url.path}"
        try:
            with trace_span(
                span_name,
                attributes={
                    "ai_osop.request_id": request_id,
                    "http.method": request.method,
                    "http.target": request.url.path,
                    "http.scheme": request.url.scheme,
                    "http.host": request.url.hostname or "",
                },
            ):
                # 5. Process request
                response = await call_next(request)

                # 6. Attach request ID to response
                response.headers["X-Request-ID"] = request_id

            return response
        finally:
            # 7. Cleanup contextvars for this request
            RequestContext.clear()

    @staticmethod
    def _extract_request_id(request: Request) -> str:
        """Extract request ID from headers or generate a new one."""
        # Priority 1: explicit X-Request-ID header
        header_id = request.headers.get("X-Request-ID")
        if header_id:
            return header_id

        # Priority 2: traceparent header trace_id
        traceparent = request.headers.get("traceparent")
        trace_id = extract_trace_id_from_traceparent(traceparent)
        if trace_id:
            return f"req-{trace_id[:16]}"

        # Priority 3: generate new UUID
        return generate_request_id()
