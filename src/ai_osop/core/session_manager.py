"""HTTP authentication session lifecycle for multi-session authorization testing."""

import logging
import re
import uuid
from typing import Any, Dict, Optional, Tuple

import httpx

from ai_osop.core.exceptions import OSOException

logger = logging.getLogger(__name__)

MAX_LOGIN_ATTEMPTS = 3
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}(\.[A-Za-z0-9_.+-]*)?$")
LoginArtifacts = Tuple[Dict[str, str], Dict[str, str], str]


class AuthenticationFailed(OSOException):
    """Login was rejected, unreachable, or yielded no usable credentials."""


class AuthenticatedSession:
    """One identity's authenticated state against the target application."""

    def __init__(
        self,
        username: str,
        role: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        tokens: Optional[Dict[str, str]] = None,
    ) -> None:
        self.session_id = f"sess-{uuid.uuid4().hex[:12]}"
        self.username = username
        self.role = role
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.tokens = tokens or {}

    def is_valid(self) -> bool:
        return bool(self.cookies) or bool(self.tokens)


class SessionManager:
    """Performs logins and manages authenticated sessions for a single target."""

    def __init__(self, target_base_url: str) -> None:
        self.target_base_url = target_base_url.rstrip("/")
        self._credentials: Dict[str, Tuple[str, str]] = {}

    async def login(
        self,
        username: str,
        password: str,
        login_path: str = "/login",
        form_fields: Optional[Dict[str, str]] = None,
    ) -> AuthenticatedSession:
        url = f"{self.target_base_url}/{login_path.lstrip('/')}"
        payload = {"username": username, "password": password, **(form_fields or {})}

        response = await self._post_with_retry(url, payload)
        if response.status_code >= 400:
            raise AuthenticationFailed(
                "login rejected by target",
                details={"url": url, "status": response.status_code, "username": username},
            )

        cookies, tokens, role = self._parse_response(response)
        if not cookies and not tokens:
            raise AuthenticationFailed(
                "login accepted but no credentials returned",
                details={"url": url, "status": response.status_code, "username": username},
            )

        session = AuthenticatedSession(username=username, role=role, cookies=cookies, tokens=tokens)
        self._credentials[session.session_id] = (username, password)
        return session

    async def create_session_pair(
        self, creds_a: Tuple[str, str], creds_b: Tuple[str, str]
    ) -> Tuple[AuthenticatedSession, AuthenticatedSession]:
        session_a = await self.login(*creds_a)
        session_b = await self.login(*creds_b)
        return session_a, session_b

    async def refresh_session(self, session: AuthenticatedSession) -> AuthenticatedSession:
        stored = self._credentials.get(session.session_id)
        if stored is None:
            raise AuthenticationFailed(
                "no stored credentials for session refresh",
                details={"session_id": session.session_id},
            )
        refreshed = await self.login(stored[0], stored[1])
        refreshed.role = session.role if session.role != "unknown" else refreshed.role
        return refreshed

    @staticmethod
    def get_auth_headers(session: AuthenticatedSession) -> Dict[str, str]:
        headers = dict(session.headers)
        if session.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        bearer = next(iter(session.tokens.values()), None)
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        return headers

    async def _post_with_retry(self, url: str, payload: Dict[str, Any]) -> httpx.Response:
        last_error: Optional[Exception] = None
        for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
            try:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                    return await client.post(url, data=payload)
            except httpx.HTTPError as exc:
                last_error = exc
                logger.warning(
                    "login attempt %d/%d to %s failed (%s)",
                    attempt,
                    MAX_LOGIN_ATTEMPTS,
                    url,
                    type(exc).__name__,
                )
        raise AuthenticationFailed(
            "target unreachable after maximum retries",
            details={"url": url, "attempts": MAX_LOGIN_ATTEMPTS},
        ) from last_error

    def _parse_response(self, response: httpx.Response) -> LoginArtifacts:
        cookies: Dict[str, str] = {}
        for raw in response.headers.get_list("set-cookie"):
            pair = raw.split(";", 1)[0]
            if "=" in pair:
                name, _, value = pair.partition("=")
                cookies[name.strip()] = value.strip()

        tokens: Dict[str, str] = {}
        role = "unknown"
        try:
            body = response.json()
            if not isinstance(body, dict):
                body = {}
        except ValueError:
            body = {}
        for key, value in body.items():
            if isinstance(value, str) and JWT_PATTERN.fullmatch(value):
                tokens[key] = value
            elif key.lower() == "role" and isinstance(value, (str, int)):
                role = str(value)
        return cookies, tokens, role
