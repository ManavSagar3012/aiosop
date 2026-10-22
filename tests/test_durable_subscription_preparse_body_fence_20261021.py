"""Actual FastAPI route-class rejects malicious bytes before Pydantic parsing.

No application lifespan/database, provider, consequential tool or signer is used.
"""

import httpx
import pytest
from fastapi import APIRouter, FastAPI
from pydantic import BaseModel

from ai_osop.api.routers.durable_supervision_subscriptions import (
    _BoundedSubscriptionRoute,
    router as durable_router,
)


class _Payload(BaseModel):
    value: str


@pytest.fixture
def application():
    app = FastAPI()
    route = APIRouter(route_class=_BoundedSubscriptionRoute)
    seen = []

    @route.post("/fixture")
    async def receive(body: _Payload):
        seen.append(body.value)
        return {"value": body.value}

    app.include_router(route)
    return app, seen


@pytest.mark.asyncio
async def test_route_streams_exact_small_payload_into_normal_pydantic(application):
    app, seen = application
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://unit.test"
    ) as client:
        response = await client.post("/fixture", json={"value": "unchanged"})
    assert response.status_code == 200
    assert response.json() == {"value": "unchanged"}
    assert seen == ["unchanged"]


@pytest.mark.asyncio
async def test_oversized_body_rejected_before_pydantic_accepts_it(application):
    app, seen = application
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://unit.test"
    ) as client:
        oversized = b'{"value":"' + b"x" * 100000 + b'"}'
        response = await client.post(
            "/fixture", content=oversized, headers={"content-type": "application/json"}
        )
    assert response.status_code == 413
    assert seen == []


@pytest.mark.asyncio
async def test_chunked_oversize_without_content_length_fails_before_schema(application):
    app, seen = application

    async def chunks():
        yield b'{"value":"' + b"x" * 2000
        yield b"x" * 2000
        yield b"x" * 2000 + b'"}'

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://unit.test"
    ) as client:
        response = await client.post(
            "/fixture", content=chunks(), headers={"content-type": "application/json"}
        )
    assert response.status_code == 413
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw,expected",
    [
        (b'{"value":"safe","value":"override"}', 422),
        (b'{"value":NaN}', 422),
        (b'{"value":Infinity}', 422),
        (b'{"value":1e309}', 422),
        (b'{"value":"ok"}', 200),
    ],
)
async def test_original_json_ambiguity_fenced_before_schema(application, raw, expected):
    app, seen = application
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://unit.test"
    ) as client:
        response = await client.post(
            "/fixture", content=raw, headers={"content-type": "application/json"}
        )
    assert response.status_code == expected
    assert seen == (["ok"] if expected == 200 else [])


def test_six_actual_mounted_mutating_subscription_routes_use_preparse_fence():
    routes = [
        route for route in durable_router.routes if "POST" in getattr(route, "methods", set())
    ]
    assert len(routes) == 6
    assert all(type(route) is _BoundedSubscriptionRoute for route in routes)
