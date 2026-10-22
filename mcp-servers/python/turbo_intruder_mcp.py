"""Turbo Intruder MCP: deny synthetic race success without real target proof.

The previous implementation invented HTTP status codes, response bodies and
race outcomes based solely on a requested concurrency number. No source-side
signed Task authority, synchronized network runner or target verification is
currently implemented. Fail closed even for direct HTTP clients.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="Turbo Intruder MCP Server")

_SERVER = "turbo-intruder-mcp"
_ERROR = "server_unavailable"
_TOOLS: list[dict[str, Any]] = [
    {
        "name": "execute_single_packet_attack",
        "description": (
            "UNAVAILABLE: signed Task-bound target admission, safe synchronized "
            "request dispatch, and independent result verification do not exist."
        ),
        "parameters": [
            {
                "name": "target_url",
                "type": "string",
                "description": "Explicitly approved HTTPS lab target",
                "required": True,
            },
            {
                "name": "method",
                "type": "string",
                "description": "Explicitly approved HTTP method",
                "required": True,
            },
            {
                "name": "headers",
                "type": "object",
                "description": "Only explicitly reviewed request headers",
                "required": False,
            },
            {
                "name": "body",
                "type": "string",
                "description": "Only explicitly reviewed request body",
                "required": False,
            },
            {
                "name": "concurrent_requests",
                "type": "integer",
                "description": "Approved bounded concurrent request count",
                "required": True,
            },
        ],
        "returns": {"type": "object", "description": "No results while unavailable"},
        "side_effect_class": "INVASIVE_EXPLOIT",
        "requires_approval": True,
        "scope_check": True,
        "timeout_seconds": 10,
        "required_permissions": ["signed_race_test_target_scope"],
    }
]


def _headers() -> dict[str, str]:
    return {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        headers=_headers(),
        content={
            "server_id": _SERVER,
            "status": "unavailable",
            "execution_enabled": False,
            "source_side_signed_authorization_verified": False,
        },
    )


@app.post("/mcp/initialize")
async def mcp_initialize() -> JSONResponse:
    return JSONResponse(
        status_code=200,
        headers=_headers(),
        content={
            "server_id": _SERVER,
            "version": "1.1.0",
            "capabilities": ["execution_unavailable"],
            "status": "unavailable",
            "tools": _TOOLS,
            "execution_enabled": False,
            "source_side_signed_authorization_verified": False,
        },
    )


@app.post("/mcp/execute")
async def mcp_execute() -> JSONResponse:
    # No fake body, status code, winning race or target-response attribution.
    # Neither JSON parameters nor user bearer assertions are authority.
    return JSONResponse(
        status_code=503,
        headers=_headers(),
        content={"status": "error", "error": _ERROR, "execution_enabled": False},
    )


if __name__ == "__main__":
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8098)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
