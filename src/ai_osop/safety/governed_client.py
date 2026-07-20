"""Governed HTTP egress — one chokepoint for scope + rate + research-header + audit.

WHY THIS EXISTS (M1 in docs/BUG_BOUNTY_READINESS_GAPS.md)
    The scan oracles and agents build ~42 independent ``httpx.AsyncClient(...)``
    instances and fire raw requests. Nothing re-checks scope per request, nothing
    rate-limits the individual probe, and the mandatory ``X-HackerOne-Research``
    header is injected nowhere. On a real bug-bounty program those are three
    disqualifying gaps (out-of-scope traffic, automated-attack/DoS rate, missing
    identity header).

    Rather than patch 42 call sites, this is the single seam they migrate to. It
    returns a NORMAL ``httpx.AsyncClient`` — a drop-in for every ``httpx.AsyncClient(...)``
    site — whose async request event-hook enforces, on EVERY request regardless of
    verb or wrapper:

      1. SCOPE   — out-of-scope host raises OutOfScopeError before the request goes out.
      2. RATE    — per-request throttle via the shared RateLimiter (not just per-task).
      3. HEADER  — injects the program's research-identity header.
      4. AUDIT   — structured log of every egress (host, method, allowed).

    Because it hooks httpx itself, it governs the request whether the caller uses
    ``.get``/``.post``/``.request`` directly or the client is wrapped by something
    else — there is no verb it can slip past.

USAGE
    from ai_osop.safety.governed_client import governed_client
    from ai_osop.safety.scope import ScopeEnforcer

    async with governed_client(
        scope=ScopeEnforcer(engagement.scope),
        rate_limiter=orchestrator.rate_limiter,
        research_header=("X-HackerOne-Research", "my-h1-username"),
        verify=False, follow_redirects=True, timeout=15,
    ) as client:
        await client.get("https://in-scope.example.com/?q=1")   # allowed, throttled, tagged
        await client.get("https://evil.example.net/")           # raises OutOfScopeError

    Every arg except the httpx passthrough is optional: omit ``scope`` to skip the
    scope gate, omit ``rate_limiter`` to skip throttling, omit ``research_header``
    to inject nothing. With all three omitted this is exactly ``httpx.AsyncClient``,
    so migrating a call site is never a behavior regression — governance is added
    only where the caller supplies the corresponding guard.
"""
from __future__ import annotations

import logging
from typing import Any, Optional, Tuple

import httpx

from ai_osop.core.exceptions import OutOfScopeError

logger = logging.getLogger(__name__)


def research_header_from_settings() -> Optional[Tuple[str, str]]:
    """Build the (name, value) research header from config, or None if unset.

    Kept here so every adopter derives the header the same way instead of reading
    the two settings by hand. Returns None when the name is blank (feature off).
    """
    from ai_osop.core.config import settings

    name = (getattr(settings, "research_header_name", "") or "").strip()
    value = (getattr(settings, "research_header_value", "") or "").strip()
    if not name:
        return None
    return (name, value)


def governed_client(
    *,
    scope: Optional[Any] = None,
    rate_limiter: Optional[Any] = None,
    research_header: Optional[Tuple[str, str]] = None,
    tool: str = "scan",
    **httpx_kwargs: Any,
) -> httpx.AsyncClient:
    """Return an ``httpx.AsyncClient`` that enforces scope + rate + header + audit.

    - ``scope``:          a ScopeEnforcer (anything with ``host_in_scope(host)->bool``).
                          Out-of-scope host raises OutOfScopeError before egress.
    - ``rate_limiter``:   anything with ``async acquire(target=, tool=)``. Called
                          once per request (per-request throttle, not per-task).
    - ``research_header`` (name, value) injected on every request.
    - ``tool``:           label passed to the rate limiter for per-tool buckets.
    - ``**httpx_kwargs``: passed straight to httpx.AsyncClient (verify, timeout, ...).

    Any existing ``event_hooks={"request": [...]}`` the caller passes is preserved;
    the governance hook is appended so caller hooks still run.
    """

    async def _govern_request(request: httpx.Request) -> None:
        host = request.url.host

        # 1. Scope — fail closed. An out-of-scope host never leaves the process.
        if scope is not None and host and not scope.host_in_scope(host):
            logger.warning(
                "governed_egress_blocked host=%s method=%s reason=out_of_scope",
                host, request.method,
            )
            raise OutOfScopeError(
                f"governed_client blocked out-of-scope host: {host!r} "
                f"({request.method} {request.url})"
            )

        # 2. Rate limit — per request, using the shared limiter's per-target bucket.
        if rate_limiter is not None:
            await rate_limiter.acquire(target=host, tool=tool)

        # 3. Research-identity header — required by some programs on prod traffic.
        if research_header is not None:
            name, value = research_header
            if name:
                request.headers[name] = value

        # 4. Audit — one structured line per allowed egress.
        logger.debug(
            "governed_egress_allow host=%s method=%s scoped=%s throttled=%s tagged=%s",
            host, request.method, scope is not None,
            rate_limiter is not None, research_header is not None,
        )

    hooks = dict(httpx_kwargs.pop("event_hooks", {}) or {})
    request_hooks = list(hooks.get("request", []))
    request_hooks.append(_govern_request)
    hooks["request"] = request_hooks

    return httpx.AsyncClient(event_hooks=hooks, **httpx_kwargs)


if __name__ == "__main__":
    # Runnable self-check: proves scope-block, header-injection, and rate-limit are
    # all applied by the hook, offline (MockTransport — no real network).
    import asyncio

    class _Scope:
        def __init__(self, allowed):
            self._allowed = set(allowed)

        def host_in_scope(self, host):
            return host in self._allowed

    class _Limiter:
        def __init__(self):
            self.calls = []

        async def acquire(self, target=None, tool=None):
            self.calls.append((target, tool))

    async def _main() -> None:
        seen_headers = {}

        def _handler(request: httpx.Request) -> httpx.Response:
            seen_headers.update(dict(request.headers))
            return httpx.Response(200, text="ok")

        limiter = _Limiter()
        client = governed_client(
            scope=_Scope(["in.example.com"]),
            rate_limiter=limiter,
            research_header=("X-HackerOne-Research", "tester"),
            transport=httpx.MockTransport(_handler),
        )
        async with client:
            # allowed host: header injected + limiter consulted
            r = await client.get("https://in.example.com/?q=1")
            assert r.status_code == 200
            assert seen_headers.get("x-hackerone-research") == "tester", seen_headers
            assert limiter.calls == [("in.example.com", "scan")], limiter.calls

            # out-of-scope host: blocked before egress
            blocked = False
            try:
                await client.get("https://evil.example.net/")
            except OutOfScopeError:
                blocked = True
            assert blocked, "out-of-scope request was NOT blocked"
            # limiter not consulted for the blocked request
            assert limiter.calls == [("in.example.com", "scan")], limiter.calls

        print("governed_client self-check passed")

    asyncio.run(_main())
