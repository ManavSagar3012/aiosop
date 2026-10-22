"""Signed browser identity reads cannot resurrect Redis session credentials."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.workflow_agent import PlaywrightAgent
from ai_osop.auth.session_store import SessionStore, UserSession
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.authenticated_resource_paths import ResourcePathDenied

ENGAGEMENT = "eng-browser-signed-auth"
USER = "trusted-user"


def imported(*, engagement_id=ENGAGEMENT, cookies=True, expired=False, bearer=False):
    return UserSession(
        engagement_id=engagement_id,
        user_label=USER,
        cookies=[{"name": "sid", "value": "test-only", "domain": "example.test"}] if cookies else [],
        bearer_token="test-only-bearer" if bearer else "",
        expires_at=datetime.now(timezone.utc) + (
            timedelta(minutes=-1) if expired else timedelta(minutes=60)
        ),
    )


def agent_context(*, signed=True, kind="capture_authenticated_surface"):
    task = Task(
        id="task-signed-browser-auth",
        engagement_id=ENGAGEMENT,
        agent_type=AgentType.WORKFLOW,
        type=kind,
        status="running",
        payload={
            "url": "https://example.test/",
            "user_label": USER,
            "_authorization_version": 1,
            "name": "Auto Authenticated Journey",
        } if signed else {"url": "https://example.test/", "user_label": USER},
    )
    session = imported()
    auth_read = AsyncMock(return_value=session)
    cache_read = AsyncMock(side_effect=AssertionError("Must not read Redis for signed auth"))
    agent = PlaywrightAgent.__new__(PlaywrightAgent)
    agent.ctx = SimpleNamespace(session_id=ENGAGEMENT, current_task=task)
    agent.session_store = SimpleNamespace(
        get_session_authoritative=auth_read,
        get_session_or_none=cache_read,
    )
    return agent, auth_read, cache_read


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["map_workflow", "capture_authenticated_surface"])
async def test_signed_auth_navigation_reads_only_postgres_and_never_cache(kind):
    agent, authoritative, cached = agent_context(kind=kind)
    state = await PlaywrightAgent._load_storage_state(agent, USER)
    assert state["cookies"][0]["name"] == "sid"
    authoritative.assert_awaited_once_with(ENGAGEMENT, USER)
    cached.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("problem", [
    "revoked_pg_session", "expired_session", "foreign_tenant",
    "bearer_only", "db_outage", "revoked_user_label",
])
async def test_signed_browser_identity_missing_or_stale_fails_closed(problem):
    agent, authoritative, cached = agent_context()
    if problem == "revoked_pg_session":
        authoritative.return_value = None
    elif problem == "expired_session":
        authoritative.return_value = imported(expired=True)
    elif problem == "foreign_tenant":
        authoritative.return_value = imported(engagement_id="eng-foreign")
    elif problem == "bearer_only":
        authoritative.return_value = imported(cookies=False, bearer=True)
    elif problem == "db_outage":
        authoritative.side_effect = OSError("secret=do-not-echo")
    elif problem == "revoked_user_label":
        authoritative.return_value = UserSession(
            engagement_id=ENGAGEMENT, user_label="other-user", cookies=[{"name": "sid"}]
        )
    with pytest.raises(ResourcePathDenied, match="Signed authenticated browser session unavailable") as exc:
        await PlaywrightAgent._load_storage_state(agent, USER)
    assert "do-not-echo" not in str(exc.value)
    cached.assert_not_awaited()


@pytest.mark.asyncio
async def test_manual_unauthed_navigation_retains_legacy_behavior_without_leaking_errors():
    agent, authoritative, cached = agent_context(signed=False, kind="navigate")
    cached.side_effect = OSError("secret=manual-import")
    assert await PlaywrightAgent._load_storage_state(agent, USER) is None
    authoritative.assert_not_awaited()


class FakePGSession:
    def __init__(self, result):
        self.result = result
        self.queries = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def execute(self, _statement):
        self.queries += 1
        return SimpleNamespace(scalar_one_or_none=lambda: self.result)


@pytest.mark.asyncio
async def test_authoritative_session_method_never_uses_redis_and_checks_pg_identity():
    user = imported()
    pg = FakePGSession(user)
    store = SessionStore.__new__(SessionStore)
    store.sm = SimpleNamespace(_async_session=lambda: pg)
    store._encryption = None
    store._orm_to_dto = lambda row, _key: row
    store._cache_get = AsyncMock(side_effect=AssertionError("Redis is not authority"))
    assert await SessionStore.get_session_authoritative(store, ENGAGEMENT, USER) is user
    assert pg.queries == 1
    store._cache_get.assert_not_awaited()

    pg.result = imported(expired=True)
    with pytest.raises(RuntimeError, match="unavailable or expired"):
        await SessionStore.get_session_authoritative(store, ENGAGEMENT, USER)
    pg.result = imported(engagement_id="eng-foreign")
    with pytest.raises(RuntimeError, match="unavailable or expired"):
        await SessionStore.get_session_authoritative(store, ENGAGEMENT, USER)
    pg.result = None
    assert await SessionStore.get_session_authoritative(store, ENGAGEMENT, USER) is None


@pytest.mark.asyncio
async def test_authoritative_session_bad_identity_never_hits_sql():
    pg = FakePGSession(imported())
    store = SessionStore.__new__(SessionStore)
    store.sm = SimpleNamespace(_async_session=lambda: pg)
    with pytest.raises(ValueError, match="identity"):
        await SessionStore.get_session_authoritative(store, ENGAGEMENT, "../../wrong")
    assert pg.queries == 0
