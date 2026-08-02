import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.agents.recon_agent import ReconAgent
from ai_osop.auth.session_store import UserSession
from ai_osop.core.config import AgentType
from ai_osop.core.models import Endpoint, Task


class MockReconContext:
    def __init__(self, session_memory, graph_memory, task):
        self.agent_id = "recon-agent-001"
        self.agent_type = AgentType.RECON
        self.session_id = "test-session"
        self.session_memory = session_memory
        self.graph_memory = graph_memory
        self.current_task = task
        self.llm_client = AsyncMock()


@pytest.mark.asyncio
async def test_swarm_identity_crawling():
    """
    Verify the crawler performs identity-aware crawling across multiple sessions.
    """
    sm = AsyncMock()
    gm = AsyncMock()

    # Mock SessionStore.list_sessions() with disjoint tokens to prevent substring matches
    sessions = [
        UserSession(engagement_id="eng-1", user_label="user_a", bearer_token="token-user-a"),
        UserSession(engagement_id="eng-1", user_label="admin", bearer_token="token-admin"),
    ]
    with MagicMock() as mock_store:
        mock_store.list_sessions = AsyncMock(return_value=sessions)

        # Setup Task
        task = Task(
            id="t1",
            type="full_recon",
            agent_type=AgentType.RECON,
            engagement_id="eng-1",
            payload={"domain": "target.com"},
        )
        ctx = MockReconContext(sm, gm, task)
        ctx.mcp_registry = AsyncMock()
        agent = ReconAgent(ctx)
        await agent.initialize()

        active_headers = {}

        def get_mock_response(url, **kwargs):
            # Inspect the headers of the active ClientSession
            auth = active_headers.get("Authorization", "")

            resp = AsyncMock()
            resp.status = 200
            resp.headers = {"Content-Type": "text/html"}

            # Check the token to simulate different pages visible to different roles
            if "token-user-a" in auth:
                resp.url = "https://target.com/user_a_only"
                resp.text = AsyncMock(
                    return_value="<html><body><a href='/user_a_dashboard'>link</a></body></html>"
                )
            elif "token-admin" in auth:
                resp.url = "https://target.com/admin_only"
                resp.text = AsyncMock(
                    return_value="<html><body><a href='/admin_dashboard'>link</a></body></html>"
                )
            else:
                resp.url = "https://target.com/anonymous_only"
                resp.text = AsyncMock(
                    return_value="<html><body><a href='/public_dashboard'>link</a></body></html>"
                )

            resp.__aenter__.return_value = resp
            resp.__aexit__ = AsyncMock()
            return resp

        # Use MagicMock so calling get() returns the context manager directly without returning a coroutine
        mock_session = MagicMock()
        mock_session.get = MagicMock(side_effect=get_mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock()

        def mock_client_session_constructor(headers=None, **kwargs):
            nonlocal active_headers
            active_headers = headers or {}
            return mock_session

        with patch("aiohttp.ClientSession", side_effect=mock_client_session_constructor):
            # Run the REAL _active_crawl_target method
            discovered = await agent._active_crawl_target("target.com", session_store=mock_store)

        print("\nDISCOVERED ENDPOINTS IN TEST:")
        for e in discovered:
            print(f"  URL: {e.url}, User Label: {e.user_label}")

        # Verify we crawled for each identity
        assert len(discovered) > 0
        assert any(e.user_label == "anonymous" for e in discovered)
        assert any(e.user_label == "user_a" for e in discovered)
        assert any(e.user_label == "admin" for e in discovered)

        # Verify identity loading
        mock_store.list_sessions.assert_called_once_with("eng-1")
