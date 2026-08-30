"""Unit tests for core.session_manager using mocked httpx responses."""

import httpx
import pytest

from ai_osop.core.session_manager import AuthenticatedSession, AuthenticationFailed, SessionManager

FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def mock_client_transport(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    """Force every httpx.AsyncClient created during a test onto a MockTransport."""
    transport = httpx.MockTransport(handler)
    original_init = httpx.AsyncClient.__init__

    def patched(client_self, *args, **kwargs):
        kwargs["transport"] = transport
        original_init(client_self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched)


def login_success_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        headers=[
            ("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly"),
            ("Set-Cookie", "csrftoken=xyz789; Path=/"),
        ],
        json={"access_token": FAKE_JWT, "token_type": "bearer", "role": "admin"},
    )


async def test_successful_login_extracts_cookies_tokens_and_role(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return login_success_handler(request)

    mock_client_transport(monkeypatch, handler)
    manager = SessionManager("https://target.example")

    session = await manager.login("admin", "secret123")

    assert session.username == "admin"
    assert session.cookies == {"sessionid": "abc123", "csrftoken": "xyz789"}
    assert session.tokens == {"access_token": FAKE_JWT}
    assert session.role == "admin"
    assert session.is_valid()
    assert len(calls) == 1


async def test_failed_login_raises_and_does_not_retry(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(401, json={"detail": "invalid credentials"})

    mock_client_transport(monkeypatch, handler)
    manager = SessionManager("https://target.example")

    with pytest.raises(AuthenticationFailed):
        await manager.login("admin", "wrong-password")
    assert len(calls) == 1


async def test_create_session_pair_returns_two_distinct_sessions(monkeypatch):
    def handler(request):
        user = "alice" if b"alice" in request.content else "bob"
        return httpx.Response(200, headers=[("Set-Cookie", f"sid={user}-cookie; Path=/")], json={})

    mock_client_transport(monkeypatch, handler)
    manager = SessionManager("https://target.example")

    session_a, session_b = await manager.create_session_pair(("alice", "pw-a"), ("bob", "pw-b"))

    assert session_a.username == "alice"
    assert session_b.username == "bob"
    assert session_a.session_id != session_b.session_id
    assert session_a.cookies != session_b.cookies


async def test_refresh_session_reauthenticates_with_stored_credentials(monkeypatch):
    mock_client_transport(monkeypatch, login_success_handler)
    manager = SessionManager("https://target.example")
    session = await manager.login("admin", "secret123")

    refreshed = await manager.refresh_session(session)

    assert refreshed.username == "admin"
    assert refreshed.session_id != session.session_id
    assert refreshed.role == "admin"
    assert refreshed.is_valid()


async def test_persistent_network_failure_gives_up_after_three_attempts(monkeypatch):
    attempts = []

    def handler(request):
        attempts.append(request)
        raise httpx.ConnectError("target down", request=request)

    mock_client_transport(monkeypatch, handler)
    manager = SessionManager("https://target.example")

    with pytest.raises(AuthenticationFailed):
        await manager.login("admin", "secret123")
    assert len(attempts) == 3


def test_get_auth_headers_merges_cookie_and_bearer():
    session = AuthenticatedSession(
        username="user1",
        role="editor",
        headers={"X-Custom": "probe"},
        cookies={"sid": "1"},
        tokens={"access_token": FAKE_JWT},
    )

    headers = SessionManager.get_auth_headers(session)

    assert headers["Cookie"] == "sid=1"
    assert headers["Authorization"] == f"Bearer {FAKE_JWT}"
    assert headers["X-Custom"] == "probe"
