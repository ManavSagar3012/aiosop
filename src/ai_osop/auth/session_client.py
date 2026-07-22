"""
SessionClient — auth-aware httpx.AsyncClient wrapper.

Every agent calls this instead of constructing an httpx.AsyncClient directly.
Responsibilities:
    1. Inject cookies from the bound UserSession.
    2. Inject Authorization: Bearer <token> if bearer_token is set.
    3. Inject CSRF token header(s) when csrf_token is present.
    4. Inject User-Agent + extra_headers.
    5. Capture Set-Cookie from responses so the SessionStore can persist
       the rotated cookies on context exit.

Usage (from agents):
    async with store.as_user(engagement_id, "user_a") as client:
        r = await client.get("https://api.target.com/me")
        r.raise_for_status()
        ...

Or standalone (if you already loaded a UserSession):
    client = SessionClient(session=sess)
    try:
        r = await client.get("...")
    finally:
        await client.aclose()

CSRF injection:
    If the captured session has a csrf_token, it's injected into
    `X-CSRF-Token`, `X-CSRFToken`, `X-XSRF-TOKEN` and `csrf-token` headers
    on unsafe methods (POST/PUT/PATCH/DELETE). Sites that use a different
    header name can override via session.extra_headers.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Dict, Optional

import httpx

if TYPE_CHECKING:
    from ai_osop.auth.session_store import SessionStore, UserSession


logger = logging.getLogger(__name__)


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_HEADER_NAMES = ("X-CSRF-Token", "X-CSRFToken", "X-XSRF-TOKEN", "csrf-token")

# Max auth-refresh retries before giving up on a 401 response.
_MAX_TOKEN_REFRESH_RETRIES = 2

# Type alias: async callback that receives the current UserSession (as dict) and
# returns updated credentials: {"bearer_token": str, "cookies": list}.
# Implementations typically call the IdP's refresh endpoint using the session's
# refresh_token, then return the new access token + any rotated cookies.
TokenRefreshCallback = Callable[[Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]


class SessionClient:
    """Auth-aware httpx wrapper.

    The session is held by reference — when this client receives Set-Cookie
    headers it mutates session.cookies in place and flips cookies_dirty=True
    so SessionStore.as_user can persist them on context exit.

    Token refresh:
        If a ``token_refresh_callback`` is provided, a 401/403 response triggers
        an async call to refresh the bearer_token and retry the request once.
        This keeps long-running scans alive when the original token expires.
        The callback receives the current session dict and returns updated
        credentials {"bearer_token": "...", "cookies": [...]}.
    """

    def __init__(
        self,
        *,
        session: "UserSession",
        base_url: str = "",
        store: Optional["SessionStore"] = None,
        timeout: float = 30.0,
        verify: bool = True,
        follow_redirects: bool = True,
        token_refresh_callback: "Optional[TokenRefreshCallback]" = None,
        governance_hook: Optional[Callable[..., Any]] = None,
    ):
        self.session = session
        self.store = store
        self.cookies_dirty = False
        self.token_refresh_callback = token_refresh_callback
        self._refresh_retries: Dict[str, int] = {}  # url -> retry count

        # Build httpx cookie jar from the session's cookies list
        cookies = httpx.Cookies()
        for c in session.cookies:
            try:
                cookies.set(
                    name=c["name"],
                    value=c["value"],
                    domain=c.get("domain") or "",
                    path=c.get("path") or "/",
                )
            except (KeyError, TypeError) as e:
                logger.debug("session.cookie_skip err=%s cookie=%r", e, c)

        headers: Dict[str, str] = {}
        if session.user_agent:
            headers["User-Agent"] = session.user_agent
        if session.bearer_token:
            headers["Authorization"] = f"Bearer {session.bearer_token}"
        # CSRF baseline (will be re-applied per unsafe call too — see _request)
        if session.csrf_token:
            for h in CSRF_HEADER_NAMES:
                headers[h] = session.csrf_token
        # Operator-supplied freeform headers win last
        headers.update(session.extra_headers or {})

        # M1 governed egress: when a governance hook is supplied, attach it to the
        # internal client so every authenticated probe is scope-checked, rate-
        # limited, and research-tagged — same guarantees as the unauthenticated
        # governed client, applied to the authed session path.
        client_kwargs: Dict[str, Any] = dict(
            base_url=base_url,
            cookies=cookies,
            headers=headers,
            timeout=timeout,
            verify=verify,
            follow_redirects=follow_redirects,
        )
        if governance_hook is not None:
            from ai_osop.safety.governed_client import attach_governance

            client_kwargs = attach_governance(client_kwargs, governance_hook)
        self._client = httpx.AsyncClient(**client_kwargs)

    # -- lifecycle -------------------------------------------------------------

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "SessionClient":
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type],
        exc: Optional[BaseException],
        tb: Optional[Any],
    ) -> None:
        await self.aclose()

    # -- public verb methods ---------------------------------------------------

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request(method.upper(), url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("OPTIONS", url, **kwargs)

    # -- internals -------------------------------------------------------------

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if method in UNSAFE_METHODS and self.session.csrf_token:
            extra = kwargs.pop("headers", None) or {}
            for h in CSRF_HEADER_NAMES:
                extra.setdefault(h, self.session.csrf_token)
            kwargs["headers"] = extra

        response = await self._client.request(method, url, **kwargs)
        self._absorb_set_cookies(response)

        # Token refresh on 401/403: if a callback is configured and we haven't
        # exhausted retries for this URL, attempt to refresh the credential and
        # replay the request once. This keeps long-running authenticated scans
        # alive when the original token expires mid-scan.
        if response.status_code in (401, 403) and self.token_refresh_callback is not None:
            retries = self._refresh_retries.get(url, 0)
            if retries < _MAX_TOKEN_REFRESH_RETRIES:
                self._refresh_retries[url] = retries + 1
                logger.info(
                    "session_token_refresh_attempt url=%s status=%s attempt=%d",
                    url,
                    response.status_code,
                    retries + 1,
                )
                try:
                    updated = await self.token_refresh_callback(self.session.to_dict())
                    if updated and isinstance(updated, dict):
                        self._apply_refreshed_credentials(updated)
                        # Strip any stale auth headers from kwargs so the
                        # refreshed client-level credential is used on retry
                        # rather than being overridden by the stale token.
                        # Strip stale auth headers from kwargs in place so the
                        # refreshed client-level credential is used on retry.
                        _stale_headers = kwargs.get("headers")
                        if _stale_headers is not None:
                            kwargs["headers"] = _without_auth_headers(_stale_headers)
                        response = await self._client.request(method, url, **kwargs)
                        self._absorb_set_cookies(response)
                        logger.info(
                            "session_token_refresh_success url=%s new_status=%d",
                            url,
                            response.status_code,
                        )
                except Exception as e:
                    logger.warning(
                        "session_token_refresh_failed url=%s error=%s",
                        url,
                        e,
                    )

        return response

    def _apply_refreshed_credentials(self, updated: Dict[str, Any]) -> None:
        """Apply refreshed credentials to the in-memory session and httpx client.

        Called after a successful token refresh callback. Mutates the session
        and rebuilds the httpx client's auth headers so subsequent requests
        carry the fresh credential.
        """
        bearer = updated.get("bearer_token")
        new_cookies = updated.get("cookies")

        if bearer:
            self.session.bearer_token = bearer
            self.cookies_dirty = True

        if new_cookies:
            self.session.cookies = list(new_cookies)
            self.cookies_dirty = True

        # Rebuild the httpx client's default headers so the fresh credential
        # is used on subsequent requests.  Clear and update in place rather
        # than reassigning — httpx.AsyncClient.headers may be read-only on
        # some versions.
        headers: Dict[str, str] = {}
        if self.session.user_agent:
            headers["User-Agent"] = self.session.user_agent
        if self.session.bearer_token:
            headers["Authorization"] = f"Bearer {self.session.bearer_token}"
        if self.session.csrf_token:
            for h in CSRF_HEADER_NAMES:
                headers[h] = self.session.csrf_token
        headers.update(self.session.extra_headers or {})
        self._client.headers.clear()
        self._client.headers.update(headers)

        # Rebuild cookies from the updated list
        new_jar = httpx.Cookies()
        for c in self.session.cookies:
            try:
                new_jar.set(
                    name=c["name"],
                    value=c["value"],
                    domain=c.get("domain") or "",
                    path=c.get("path") or "/",
                )
            except (KeyError, TypeError) as e:
                logger.debug("session.cookie_rebuild_skip err=%s cookie=%r", e, c)
        self._client.cookies = new_jar

    def _absorb_set_cookies(self, response: httpx.Response) -> None:
        """Mirror any Set-Cookie back into the UserSession's cookie list."""
        # httpx's response.cookies is a Cookies jar; we walk the raw headers
        # because we need domain/path/expires that the jar normalizes away.
        for header_value in response.headers.get_list("set-cookie"):
            parsed = _parse_set_cookie(header_value, default_domain=response.url.host)
            if parsed is None:
                continue
            self._upsert_cookie(parsed)

    def _upsert_cookie(self, new_cookie: Dict[str, Any]) -> None:
        """Insert or replace a cookie in session.cookies (by name+domain+path)."""
        existing = self.session.cookies
        match_key = (new_cookie["name"], new_cookie.get("domain", ""), new_cookie.get("path", "/"))
        for i, c in enumerate(existing):
            if (
                c.get("name") == match_key[0]
                and (c.get("domain") or "") == match_key[1]
                and (c.get("path") or "/") == match_key[2]
            ):
                existing[i] = new_cookie
                self.cookies_dirty = True
                return
        existing.append(new_cookie)
        self.cookies_dirty = True


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _without_auth_headers(headers: Any) -> Dict[str, Any]:
    """Return a copy of *headers* with ``Authorization`` (and similar)
    entries removed so a retry request uses the fresh client-level
    credential instead of the stale per-request override."""
    if not headers:
        return {}
    _AUTH_KEYS = {"authorization", "x-api-key", "api-key"}
    return {k: v for k, v in dict(headers).items() if k.lower() not in _AUTH_KEYS}


# ─────────────────────────────────────────────────────────────────────────────
#  Set-Cookie parser (minimal, RFC 6265-ish; enough for credential rotation)
# ─────────────────────────────────────────────────────────────────────────────


def _parse_set_cookie(header_value: str, *, default_domain: str = "") -> Optional[Dict[str, Any]]:
    """Parse a single Set-Cookie header into our cookie dict shape.

    Returns None if the header is malformed.
    """
    if not header_value:
        return None
    parts = [p.strip() for p in header_value.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    cookie: Dict[str, Any] = {
        "name": name.strip(),
        "value": value.strip(),
        "domain": default_domain,
        "path": "/",
    }
    for attr in parts[1:]:
        if "=" in attr:
            k, _, v = attr.partition("=")
            k = k.strip().lower()
            v = v.strip()
            if k == "domain":
                cookie["domain"] = v.lstrip(".")
            elif k == "path":
                cookie["path"] = v or "/"
            elif k == "expires":
                # leave to caller — Playwright wants epoch float; we keep
                # the header form so save_session can re-parse if needed.
                cookie["expires_raw"] = v
            elif k == "max-age":
                try:
                    cookie["max_age"] = int(v)
                except ValueError:
                    pass
            elif k == "samesite":
                cookie["sameSite"] = v.capitalize()
        else:
            flag = attr.strip().lower()
            if flag == "secure":
                cookie["secure"] = True
            elif flag == "httponly":
                cookie["httpOnly"] = True
    return cookie
