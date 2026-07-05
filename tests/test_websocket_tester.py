"""Offline proofs for WebSocketTester.

Every test injects a fake connector so no live server is needed. The fake models
the three server behaviours the oracles key on: Origin enforcement, cookie-scoped
authed data, and handshake acceptance/rejection.
"""
from __future__ import annotations

import asyncio

import pytest

from ai_osop.core.websocket_tester import WebSocketTester, WSFinding


AUTH_DATA = '{"user":"victim@corp.test","balance":9001,"secret":"SENTINEL-PRIVATE"}'
PUBLIC_DATA = '{"motd":"welcome, please log in"}'
AUTH_MARKER = "SENTINEL-PRIVATE"


class FakeConn:
    """A minimal WSConnection: hands back one preloaded frame."""

    def __init__(self, frame: str):
        self._frame = frame
        self.sent: list[str] = []
        self.closed = False

    async def send(self, message: str) -> None:
        self.sent.append(message)

    async def recv(self) -> str:
        return self._frame

    async def close(self) -> None:
        self.closed = True


def make_connector(
    *,
    enforce_origin: bool,
    trusted_origins=("https://app.test",),
    authed_frame: str = AUTH_DATA,
    public_frame: str = PUBLIC_DATA,
    reject_all: bool = False,
):
    """Build a fake connector modelling one server policy.

    - reject_all: refuses every handshake (e.g. auth-required socket).
    - enforce_origin: refuses handshakes whose Origin is not trusted.
    - with cookies -> returns authed_frame; without cookies -> public_frame.
    """

    async def connector(uri, *, origin, cookies, timeout):
        if reject_all:
            raise ConnectionRefusedError("handshake rejected")
        if enforce_origin and origin not in trusted_origins:
            raise ConnectionRefusedError(f"origin {origin} not allowed")
        frame = authed_frame if cookies else public_frame
        return FakeConn(frame)

    return connector


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---- (a) origin NOT enforced + authed data => confirmed ---------------------
def test_cswsh_confirmed_when_origin_not_enforced():
    tester = WebSocketTester(
        "wss://app.test/ws",
        origin="https://app.test",
        cookies="session=victim-abc",
        auth_markers=[AUTH_MARKER],
        connector=make_connector(enforce_origin=False),
    )
    finding = _run(tester.test_cswsh())
    assert isinstance(finding, WSFinding)
    assert finding.confirmed is True
    assert finding.evidence["handshake_completed"] is True
    assert finding.evidence["returned_auth_data"] is True
    # control proved the data was cookie-scoped, not public
    assert finding.evidence["anon_control_returned_auth_data"] is False


# ---- (b1) origin enforced / handshake rejected => not confirmed (no FP) ------
def test_cswsh_not_confirmed_when_origin_enforced():
    tester = WebSocketTester(
        "wss://app.test/ws",
        origin="https://app.test",
        cookies="session=victim-abc",
        auth_markers=[AUTH_MARKER],
        connector=make_connector(enforce_origin=True),
    )
    finding = _run(tester.test_cswsh())
    assert finding.confirmed is False
    assert finding.evidence["handshake_completed"] is False


# ---- (b2) origin not enforced but data is public => not confirmed (no FP) ----
def test_cswsh_not_confirmed_when_data_is_public():
    # Server returns the authed frame regardless of cookies -> data is public,
    # so the anon control also sees the marker -> not a hijack.
    tester = WebSocketTester(
        "wss://app.test/ws",
        origin="https://app.test",
        cookies="session=victim-abc",
        auth_markers=[AUTH_MARKER],
        connector=make_connector(
            enforce_origin=False, public_frame=AUTH_DATA  # public == authed frame
        ),
    )
    finding = _run(tester.test_cswsh())
    assert finding.confirmed is False
    assert finding.evidence["anon_control_returned_auth_data"] is True


# ---- (c) timeout never raises ------------------------------------------------
def test_timeout_degrades_without_raising():
    async def hanging_connector(uri, *, origin, cookies, timeout):
        await asyncio.sleep(60)  # would hang forever without the tester's bound
        raise AssertionError("should never be reached")

    tester = WebSocketTester(
        "wss://app.test/ws",
        origin="https://app.test",
        cookies="session=victim-abc",
        auth_markers=[AUTH_MARKER],
        connector=hanging_connector,
        connect_timeout=0.05,
        recv_timeout=0.05,
    )
    finding = _run(tester.test_cswsh())  # must return, not raise
    assert finding.confirmed is False
    assert finding.evidence["handshake_completed"] is False


def test_recv_timeout_after_handshake_does_not_raise():
    class HangingRecvConn(FakeConn):
        async def recv(self) -> str:
            await asyncio.sleep(60)
            return ""

    async def connector(uri, *, origin, cookies, timeout):
        return HangingRecvConn(AUTH_DATA)

    tester = WebSocketTester(
        "wss://app.test/ws",
        origin="https://app.test",
        cookies="session=victim-abc",
        auth_markers=[AUTH_MARKER],
        connector=connector,
        recv_timeout=0.05,
    )
    finding = _run(tester.test_cswsh())
    # handshake completed but no data frame -> not confirmed, no raise
    assert finding.confirmed is False
    assert finding.evidence["handshake_completed"] is True
    assert finding.evidence["returned_auth_data"] is False


# ---- missing_auth oracle -----------------------------------------------------
def test_missing_auth_confirmed_when_privileged_action_succeeds():
    async def connector(uri, *, origin, cookies, timeout):
        return FakeConn('{"result":"ok","admin_action":"DELETED_ALL"}')

    tester = WebSocketTester(
        "wss://app.test/ws",
        origin="https://app.test",
        privileged_message='{"op":"admin.delete_all"}',
        privileged_success_markers=["DELETED_ALL"],
        connector=connector,
    )
    finding = _run(tester.test_missing_auth())
    assert finding.confirmed is True
    assert finding.evidence["privileged_action_succeeded"] is True


def test_missing_auth_not_confirmed_when_rejected():
    tester = WebSocketTester(
        "wss://app.test/ws",
        origin="https://app.test",
        privileged_message='{"op":"admin.delete_all"}',
        privileged_success_markers=["DELETED_ALL"],
        connector=make_connector(enforce_origin=False, reject_all=True),
    )
    finding = _run(tester.test_missing_auth())
    assert finding.confirmed is False


# ---- unencrypted_transport oracle -------------------------------------------
def test_unencrypted_transport_confirmed_for_ws_on_https_origin():
    async def connector(uri, *, origin, cookies, timeout):
        return FakeConn(PUBLIC_DATA)

    tester = WebSocketTester(
        "ws://app.test/ws",
        origin="https://app.test",
        connector=connector,
    )
    finding = _run(tester.test_unencrypted_transport())
    assert finding.confirmed is True
    assert finding.evidence["ws_scheme"] == "ws"


def test_unencrypted_transport_not_confirmed_for_wss():
    tester = WebSocketTester(
        "wss://app.test/ws",
        origin="https://app.test",
        connector=make_connector(enforce_origin=False),
    )
    finding = _run(tester.test_unencrypted_transport())
    assert finding.confirmed is False


def test_unencrypted_transport_not_confirmed_when_ws_dead():
    tester = WebSocketTester(
        "ws://app.test/ws",
        origin="https://app.test",
        connector=make_connector(enforce_origin=False, reject_all=True),
    )
    finding = _run(tester.test_unencrypted_transport())
    assert finding.confirmed is False


# ---- run() aggregates only confirmed ----------------------------------------
def test_run_returns_only_confirmed():
    tester = WebSocketTester(
        "ws://app.test/ws",
        origin="https://app.test",
        cookies="session=victim-abc",
        auth_markers=[AUTH_MARKER],
        connector=make_connector(enforce_origin=False),
    )
    findings = _run(tester.run())
    techs = {f.technique for f in findings}
    # cswsh (origin not enforced) + unencrypted (ws on https) both confirm
    assert "cswsh" in techs
    assert "unencrypted_transport" in techs
    assert all(f.confirmed for f in findings)
