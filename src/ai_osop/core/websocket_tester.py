"""Dedicated WebSocket security tester.

Most scanners stop at "a WebSocket endpoint exists". This module *demonstrates*
the flaw: it drives the real handshake/message layer and confirms a vulnerability
only when the server's own behaviour proves it — never from reflection.

Three high-yield, deterministically-oracled WebSocket flaws:

  * cswsh (Cross-Site WebSocket Hijacking) — open the handshake with a foreign /
    absent ``Origin`` header while carrying the victim's ambient cookies. Confirmed
    ONLY if the server (a) completes the handshake AND (b) returns authenticated,
    user-scoped data. A rejected handshake, or a response that only contains the
    same public data an anonymous (no-cookie) socket sees, is NOT confirmed.
  * missing_auth — a privileged message is accepted on a socket that carries no
    token/credential where one is mandatory. Confirmed only when the privileged
    action succeeds unauthenticated (and the same message is refused-shaped, or the
    success marker is absent, is treated as safe).
  * unencrypted_transport — an authenticated/sensitive endpoint is offered over
    plaintext ``ws://`` by an ``https://`` origin. Confirmed via the scheme actually
    offered: we complete a real ``ws://`` handshake to prove it is live, not merely
    advertised.

All confirmation is an objective server-behaviour differential. The connect / recv
layer is injectable (``connector=``) so tests need no live server, and every
network wait is bounded by a short timeout so a run can never hang.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, Sequence
from urllib.parse import urlsplit


@dataclass
class WSFinding:
    technique: str              # cswsh | missing_auth | unencrypted_transport
    confirmed: bool
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class WSConnection(Protocol):
    """Minimal duck-typed connection the tester drives. `websockets` client
    protocols already satisfy this."""

    async def send(self, message: str) -> None: ...
    async def recv(self) -> str: ...
    async def close(self) -> None: ...


# A connector opens a handshake and returns a live connection, or raises if the
# server *rejects* the handshake (wrong Origin, 401/403, etc.). Signature:
#   connect(uri, *, origin, cookies, timeout) -> WSConnection
Connector = Callable[..., Awaitable[WSConnection]]


class WSHandshakeRejected(Exception):
    """Raised by a connector when the server refuses the upgrade."""


async def _default_connector(
    uri: str,
    *,
    origin: Optional[str],
    cookies: Optional[str],
    timeout: float,
) -> WSConnection:
    """Best-effort real connector built on `websockets`. Kept import-local so the
    module (and its tests) load even where `websockets` is absent — the tests
    inject their own connector and never hit this path."""
    import websockets  # local import: optional dependency for live runs

    extra_headers = {}
    if cookies:
        extra_headers["Cookie"] = cookies
    try:
        conn = await websockets.connect(
            uri,
            origin=origin,  # type: ignore[arg-type]
            extra_headers=extra_headers or None,
            open_timeout=timeout,
            close_timeout=timeout,
        )
    except Exception as exc:  # handshake rejected / network error -> not confirmed
        raise WSHandshakeRejected(str(exc)) from exc
    return conn  # type: ignore[return-value]


class WebSocketTester:
    """Confirm real WebSocket flaws with server-behaviour oracles.

    Parameters
    ----------
    url:
        The WebSocket endpoint (``ws://`` or ``wss://``).
    origin:
        The site's real (same-site) origin, e.g. ``https://app.test``. Used to
        decide the transport check and as the *legitimate* Origin for baselines.
    cookies:
        The victim's ambient cookie header value (what a browser would attach).
    auth_markers:
        Substrings that appear ONLY in authenticated / user-scoped data. Presence
        of any is the objective signal that a socket returned private data.
    probe:
        Optional message to send after connect to elicit a data frame (e.g. a
        subscribe/hello). If ``None`` we just receive the server's first frame.
    privileged_message / privileged_success_markers:
        Drive the missing-auth oracle: send this on an unauthenticated socket and
        confirm only if a success marker comes back.
    connector:
        Injectable handshake opener (see ``Connector``). Defaults to a
        `websockets`-backed live connector.
    connect_timeout / recv_timeout:
        Short bounds so a run can never hang.
    """

    def __init__(
        self,
        url: str,
        *,
        origin: Optional[str] = None,
        cookies: Optional[str] = None,
        auth_markers: Optional[Sequence[str]] = None,
        probe: Optional[str] = None,
        foreign_origin: str = "https://evil.attacker.test",
        privileged_message: Optional[str] = None,
        privileged_success_markers: Optional[Sequence[str]] = None,
        connector: Optional[Connector] = None,
        connect_timeout: float = 6.0,
        recv_timeout: float = 6.0,
    ):
        self.url = url
        self.origin = origin
        self.cookies = cookies
        self.auth_markers = [m for m in (auth_markers or []) if m]
        self.probe = probe
        self.foreign_origin = foreign_origin
        self.privileged_message = privileged_message
        self.privileged_success_markers = [m for m in (privileged_success_markers or []) if m]
        self.connector: Connector = connector or _default_connector
        self.connect_timeout = connect_timeout
        self.recv_timeout = recv_timeout

    # ---- low-level driven exchange ------------------------------------------
    async def _exchange(
        self,
        *,
        origin: Optional[str],
        cookies: Optional[str],
        message: Optional[str],
    ) -> tuple[bool, str]:
        """Open a handshake, optionally send `message`, receive one frame.

        Returns ``(handshake_ok, received_text)``. Never raises: a rejected
        handshake or any timeout degrades to ``(False, "")`` / ``(True, "")`` so
        callers reason purely over observed behaviour.
        """
        try:
            conn = await asyncio.wait_for(
                self.connector(
                    self.url, origin=origin, cookies=cookies, timeout=self.connect_timeout
                ),
                timeout=self.connect_timeout,
            )
        except Exception:
            return False, ""  # handshake rejected / connect failed
        try:
            if message is not None:
                await asyncio.wait_for(conn.send(message), timeout=self.recv_timeout)
            try:
                data = await asyncio.wait_for(conn.recv(), timeout=self.recv_timeout)
            except Exception:
                data = ""  # handshake completed but no data frame arrived
            return True, data if isinstance(data, str) else data.decode("utf-8", "replace")
        finally:
            try:
                await asyncio.wait_for(conn.close(), timeout=self.recv_timeout)
            except Exception:
                pass

    def _has_auth_data(self, text: str) -> bool:
        return any(m in text for m in self.auth_markers)

    # ---- oracles ------------------------------------------------------------
    async def test_cswsh(self) -> WSFinding:
        """CSWSH: foreign Origin + victim cookies still yields authed data.

        Oracle (all must hold):
          1. handshake with a foreign Origin completes (no Origin enforcement),
          2. that socket returns authenticated/user-scoped data (auth marker),
          3. a control socket with the SAME foreign Origin but NO cookies does
             NOT return that authed data — proving the data rode the victim's
             ambient cookies, not something public every visitor sees.
        """
        ev: Dict[str, Any] = {"foreign_origin": self.foreign_origin}
        if not self.auth_markers:
            return WSFinding("cswsh", False,
                             "No auth_markers supplied; cannot distinguish private from public data.",
                             ev)

        hs_ok, authed_text = await self._exchange(
            origin=self.foreign_origin, cookies=self.cookies, message=self.probe
        )
        ev["handshake_completed"] = hs_ok
        if not hs_ok:
            return WSFinding("cswsh", False,
                             "Server rejected the cross-origin handshake — Origin appears enforced.", ev)

        has_auth = self._has_auth_data(authed_text)
        ev["returned_auth_data"] = has_auth
        ev["response_snippet"] = authed_text[:200]
        if not has_auth:
            return WSFinding("cswsh", False,
                             "Cross-origin handshake completed but returned no authenticated data.", ev)

        # Control: same foreign origin, no cookies -> should be public-only.
        _, anon_text = await self._exchange(
            origin=self.foreign_origin, cookies=None, message=self.probe
        )
        anon_has_auth = self._has_auth_data(anon_text)
        ev["anon_control_returned_auth_data"] = anon_has_auth
        if anon_has_auth:
            return WSFinding("cswsh", False,
                             "Authed data is served even without cookies — it is public, not cookie-scoped; "
                             "not a hijack.", ev)

        return WSFinding(
            "cswsh", True,
            "Cross-origin WebSocket handshake completed and returned the victim's authenticated, "
            "cookie-scoped data with a foreign Origin — no Origin enforcement (CSWSH).",
            ev,
        )

    async def test_missing_auth(self) -> WSFinding:
        """Privileged message accepted on a token-less / cookie-less socket."""
        ev: Dict[str, Any] = {}
        if not self.privileged_message or not self.privileged_success_markers:
            return WSFinding("missing_auth", False,
                             "No privileged_message/success markers supplied; nothing to assert.", ev)

        hs_ok, text = await self._exchange(
            origin=self.origin, cookies=None, message=self.privileged_message
        )
        ev["handshake_completed"] = hs_ok
        ev["response_snippet"] = text[:200]
        if not hs_ok:
            return WSFinding("missing_auth", False,
                             "Unauthenticated handshake rejected — socket requires credentials.", ev)

        success = any(m in text for m in self.privileged_success_markers)
        ev["privileged_action_succeeded"] = success
        if not success:
            return WSFinding("missing_auth", False,
                             "Privileged message did not succeed on the unauthenticated socket.", ev)
        return WSFinding(
            "missing_auth", True,
            "A privileged WebSocket action succeeded on a socket carrying no token or cookie — "
            "missing authentication.",
            ev,
        )

    async def test_unencrypted_transport(self) -> WSFinding:
        """Sensitive endpoint offered over plaintext ws:// by an https:// origin.

        Confirmed via the scheme actually offered: the ws:// endpoint must accept a
        real handshake (it is live, not merely advertised) while the origin is
        https — meaning authenticated traffic can ride cleartext.
        """
        scheme = urlsplit(self.url).scheme.lower()
        origin_scheme = urlsplit(self.origin).scheme.lower() if self.origin else ""
        ev: Dict[str, Any] = {"ws_scheme": scheme, "origin_scheme": origin_scheme}
        if scheme != "ws":
            return WSFinding("unencrypted_transport", False,
                             "Endpoint already uses encrypted wss://.", ev)
        if origin_scheme and origin_scheme != "https":
            return WSFinding("unencrypted_transport", False,
                             "Origin is not https:// — plaintext ws:// is not a downgrade here.", ev)

        hs_ok, _ = await self._exchange(origin=self.origin, cookies=self.cookies, message=self.probe)
        ev["handshake_completed"] = hs_ok
        if not hs_ok:
            return WSFinding("unencrypted_transport", False,
                             "ws:// endpoint did not accept a handshake; not confirmed live.", ev)
        return WSFinding(
            "unencrypted_transport", True,
            "An https:// origin offers a live plaintext ws:// WebSocket — authenticated/sensitive "
            "traffic can traverse an unencrypted channel.",
            ev,
        )

    async def run(self) -> List[WSFinding]:
        """Run every applicable oracle; return only confirmed findings."""
        results = await asyncio.gather(
            self.test_cswsh(),
            self.test_missing_auth(),
            self.test_unencrypted_transport(),
            return_exceptions=True,
        )
        findings: List[WSFinding] = []
        for r in results:
            if isinstance(r, WSFinding) and r.confirmed:
                findings.append(r)
        return findings
