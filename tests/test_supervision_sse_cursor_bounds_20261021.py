"""Source-scoped SSE replay cursor safety on the live router boundary."""

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ai_osop.api.deps import verify_token
from ai_osop.api.routers import supervision


@pytest.mark.parametrize(
    "header",
    [
        "9" * 5000,
        "9223372036854775808",
        "-1",
        "+1",
        "1\n2",
        " 1",
        "１",
        "1e4",
    ],
)
def test_invalid_last_event_id_denied_before_conversion(header):
    with pytest.raises(HTTPException) as denied:
        supervision._sse_resume_cursor(0, header)
    assert denied.value.status_code == 422


def test_bigint_limit_and_query_precedence():
    assert supervision._sse_resume_cursor(0, "9223372036854775807") == 9223372036854775807
    assert supervision._sse_resume_cursor(7, "9" * 5000) == 7
    assert supervision._sse_resume_cursor(0, None) == 0
    for value in (-1, True, 9223372036854775808):
        with pytest.raises(HTTPException) as denied:
            supervision._sse_resume_cursor(value, None)
        assert denied.value.status_code == 422


@pytest.mark.asyncio
async def test_actual_stream_handler_rejects_oversized_resume_before_db_poll(monkeypatch):
    auth = AsyncMock()
    monkeypatch.setattr(supervision, "_stream_revalidate", auth)

    class Request:
        headers = {"last-event-id": "8" * 5000}

        async def is_disconnected(self):
            return True

    with pytest.raises(HTTPException) as denied:
        await supervision.stream_events(
            "eng-owned", Request(), 0, None, {"sub": "owned", "role": "operator"}
        )
    assert denied.value.status_code == 422
    auth.assert_awaited_once()


@pytest.mark.parametrize("endpoint", ["events", "events/stream"])
def test_http_query_cursor_above_postgres_bigint_rejected(endpoint):
    app = FastAPI()
    app.include_router(supervision.router)
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "authorized-test-operator",
        "role": "operator",
    }
    response = TestClient(app).get(
        "/supervision/engagements/eng-test/" + endpoint + "?after_sequence=9223372036854775808"
    )
    assert response.status_code == 422
