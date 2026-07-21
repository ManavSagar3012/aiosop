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

        # BLK-3 (2026-07-21): the recon crawler now issues requests through the
        # governed httpx client (get_governed_client), not aiohttp. Serve the
        # identity-specific pages via an httpx MockTransport that keys off the
        # per-identity Authorization header the crawler sets (recon_agent.py:900
        # passes headers=headers into get_governed_client, so the header rides on
        # every request and the transport handler can read it).
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("Authorization", "")
            if "token-user-a" in auth:
                body = "<html><body><a href='/user_a_dashboard'>link</a></body></html>"
            elif "token-admin" in auth:
                body = "<html><body><a href='/admin_dashboard'>link</a></body></html>"
            else:
                body = "<html><body><a href='/public_dashboard'>link</a></body></html>"
            return httpx.Response(200, text=body, headers={"Content-Type": "text/html"})

        def fake_governed_client(tool="scan", **httpx_kwargs):
            # Mirror get_governed_client's contract: return a real httpx.AsyncClient
            # carrying the caller's identity headers, but backed by MockTransport
            # so no real network egress happens.
            httpx_kwargs.pop("verify", None)
            httpx_kwargs.pop("follow_redirects", None)
            httpx_kwargs.pop("timeout", None)
            return httpx.AsyncClient(transport=httpx.MockTransport(handler), **httpx_kwargs)

        agent.get_governed_client = fake_governed_client  # type: ignore[assignment]

        # Run the REAL _active_crawl_target method through the governed (mocked) client.
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
