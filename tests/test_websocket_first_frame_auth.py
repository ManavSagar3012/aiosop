"""WebSocket auth and owner fencing, with no real databases or live targets."""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from starlette.websockets import WebSocketDisconnect

from ai_osop.api.deps import state
from ai_osop.api.main import app
from ai_osop.core.config import settings
from ai_osop.core.models import ScopeDefinition, SessionState


@pytest.fixture
def ws_environment(monkeypatch):
    monkeypatch.setattr(settings, "jwt_secret", "websocket-qualification-jwt-secret")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "cors_allowed_origins", ["http://localhost:5173"])
    session = SessionState(
        session_id="eng-ws-test",
        created_by="alice",
        phase="reconnaissance",
        scope=ScopeDefinition(engagement_id="eng-ws-test", domains=["owned.example"]),
        roe={},
    )
    memory = SimpleNamespace(
        load_session_state=AsyncMock(return_value=session),
        assert_signed_authorization=AsyncMock(return_value={"status": "active"}),
    )
    orch = SimpleNamespace(
        session_memory=memory,
        _sessions={"eng-ws-test": session},
        halt_engagement=AsyncMock(),
    )
    monkeypatch.setitem(state, "orchestrator", orch)

    def token(sub="alice", role="operator"):
        return jwt.encode(
            {
                "sub": sub,
                "role": role,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            },
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )

    return SimpleNamespace(
        client=TestClient(app, base_url="http://127.0.0.1"),
        session=session,
        orch=orch,
        memory=memory,
        token=token,
        url="wss://127.0.0.1/ws/engagements/eng-ws-test",
        headers={"origin": "http://localhost:5173"},
    )


def _ready(ws, token):
    ws.send_json({"type": "auth", "token": token})
    assert ws.receive_json() == {
        "type": "auth_ready", "session_id": "eng-ws-test",
    }


def _closed(ws, expected=1008):
    with pytest.raises(WebSocketDisconnect) as exc:
        ws.receive_json()
    assert exc.value.code == expected


def test_first_frame_ready_ack_only_after_authenticated_durable_owner(ws_environment):
    h = ws_environment
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        _ready(ws, h.token())
        h.memory.load_session_state.assert_awaited()
        ws.send_json({"action": "status"})
        result = ws.receive_json()
        assert result == {
            "type": "status", "session_id": "eng-ws-test",
            "phase": "reconnaissance",
        }
        ws.send_json({"action": "ping"})
        assert ws.receive_json() == {"type": "pong"}
        h.memory.assert_signed_authorization.assert_not_awaited()
        assert h.memory.load_session_state.await_count == 3


def test_idle_websocket_observes_durable_account_disable_without_client_messages(
    ws_environment, monkeypatch,
):
    """An idle authenticated channel cannot stay authorized indefinitely."""
    from ai_osop.api import deps
    from ai_osop.api import main as api_main
    from ai_osop.memory.operator_revocation import OperatorRevoked

    class DurableStatus:
        disabled = False
        reads = 0

        async def assert_active(self, token, principal):
            self.reads += 1
            if self.disabled:
                raise OperatorRevoked("disabled")

    status = DurableStatus()
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    monkeypatch.setattr(deps, "_operator_revocation_ledger", lambda: status)
    monkeypatch.setattr(api_main, "_WS_AUTH_RECHECK_SECONDS", 0.025)
    h = ws_environment
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        _ready(ws, h.token())
        status.disabled = True
        _closed(ws)
    assert status.reads >= 2
    h.orch.halt_engagement.assert_not_awaited()


@pytest.mark.parametrize("frame", [
    {"action": "status"},
    {"action": "halt"},
    {"type": "auth"},
    {"type": "auth", "token": "fake", "action": "status"},
    {"type": "not_auth", "token": "fake"},
    [1, 2, 3],
])
def test_no_action_or_event_before_valid_auth(ws_environment, frame):
    h = ws_environment
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        ws.send_json(frame)
        _closed(ws)
        h.orch.halt_engagement.assert_not_awaited()


def test_query_credentials_rejected_even_with_valid_first_frame(ws_environment):
    h = ws_environment
    with pytest.raises(WebSocketDisconnect) as exc:
        with h.client.websocket_connect(
            h.url + "?token=" + h.token(), headers=h.headers,
        ):
            pass
    assert exc.value.code == 1008
    h.memory.load_session_state.assert_not_awaited()


def test_rejects_cross_origin(ws_environment):
    h = ws_environment
    with pytest.raises(WebSocketDisconnect) as exc:
        with h.client.websocket_connect(
            h.url, headers={"origin": "https://hostile.example"},
        ):
            pass
    assert exc.value.code == 1008
    h.memory.load_session_state.assert_not_awaited()


@pytest.mark.parametrize("sub,role", [
    ("mallory", "operator"), ("alice", "viewer"),
])
def test_role_and_tenant_guards(ws_environment, sub, role):
    h = ws_environment
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        ws.send_json({"type": "auth", "token": h.token(sub, role)})
        _closed(ws)
    h.orch.halt_engagement.assert_not_awaited()


def test_cached_owner_cannot_override_durable_owner(ws_environment):
    h = ws_environment
    h.memory.load_session_state.return_value = h.session.model_copy(
        update={"created_by": "bob"}
    )
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        ws.send_json({"type": "auth", "token": h.token()})
        _closed(ws)


def test_owner_revocation_midstream_stops_further_reads_and_commands(ws_environment):
    h = ws_environment
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        _ready(ws, h.token())
        h.memory.load_session_state.return_value = h.session.model_copy(
            update={"created_by": "bob"}
        )
        ws.send_json({"action": "status"})
        _closed(ws)
    h.orch.halt_engagement.assert_not_awaited()


def test_revoked_signed_roe_allows_owner_status_but_never_halt(ws_environment):
    h = ws_environment
    h.memory.assert_signed_authorization.side_effect = RuntimeError("leaked-db-password")
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        _ready(ws, h.token(role="senior_operator"))
        ws.send_json({"action": "status"})
        assert ws.receive_json()["type"] == "status"
        ws.send_json({"action": "halt", "reason": "Operator halt"})
        _closed(ws)
    h.orch.halt_engagement.assert_not_awaited()
    h.memory.assert_signed_authorization.assert_awaited_once_with("eng-ws-test")


def test_halt_needs_senior_role_and_current_signed_policy(ws_environment):
    h = ws_environment
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        _ready(ws, h.token())
        ws.send_json({"action": "halt"})
        _closed(ws)
    h.orch.halt_engagement.assert_not_awaited()

    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        _ready(ws, h.token(role="senior_operator"))
        ws.send_json({"action": "halt", "reason": "Urgent stop"})
        assert ws.receive_json() == {
            "type": "halt_requested",
            "session_id": "eng-ws-test",
            "remote_stop_confirmed": False,
        }
    h.orch.halt_engagement.assert_awaited_once_with("eng-ws-test", "Urgent stop")


@pytest.mark.parametrize("payload,code", [
    ('{"type":"auth",', 1008),
    ('not-json', 1008),
    (json.dumps({"type": "auth", "token": "a" * 9000}), 1009),
])
def test_malformed_oversized_first_frame_closes_safely(ws_environment, payload, code):
    h = ws_environment
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        ws.send_text(payload)
        _closed(ws, code)


def test_oversized_post_auth_command_fails_before_processing(ws_environment):
    h = ws_environment
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        _ready(ws, h.token(role="senior_operator"))
        ws.send_text(json.dumps({"action": "halt", "reason": "A" * 9000}))
        _closed(ws, 1009)
    h.orch.halt_engagement.assert_not_awaited()


def test_durable_state_failure_does_not_echo_secret(ws_environment):
    h = ws_environment
    h.memory.load_session_state.side_effect = RuntimeError("PASSWORD_SENSITIVE_DETAIL")
    with h.client.websocket_connect(h.url, headers=h.headers) as ws:
        ws.send_json({"type": "auth", "token": h.token()})
        _closed(ws)
    h.orch.halt_engagement.assert_not_awaited()


@pytest.mark.asyncio
async def test_unverified_first_frame_times_out_in_five_seconds(ws_environment):
    from ai_osop.api.main import websocket_engagement
    from starlette.datastructures import URL

    async def never_send():
        await asyncio.Event().wait()

    fake = SimpleNamespace(
        url=URL("wss://127.0.0.1/ws/engagements/eng-ws-test"),
        headers={"origin": "http://localhost:5173"},
        query_params={},
        accept=AsyncMock(),
        receive=AsyncMock(side_effect=never_send),
        close=AsyncMock(),
    )
    start = time.monotonic()
    await websocket_engagement(fake, "eng-ws-test")
    elapsed = time.monotonic() - start
    assert 4.8 <= elapsed < 6.5
    fake.accept.assert_awaited_once()
    fake.close.assert_awaited_once_with(code=1008)
    ws_environment.memory.load_session_state.assert_not_awaited()
