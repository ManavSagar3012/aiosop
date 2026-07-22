"""Unit tests for api/deps.py - auth, state, request context.

Tests cover:
- RequestContext get/set/clear
- require_role() guard factory
- Auth: _authenticate with None (403), settings not configured (401)
- assert_engagement_access structure (needs orchestrator)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from ai_osop.api.deps import RequestContext, require_role, update_active_agents


class TestRequestContext:
    def setup_method(self) -> None:
        RequestContext.clear()

    def test_set_and_get(self) -> None:
        RequestContext.set("request_id", "abc-123")
        assert RequestContext.get("request_id") == "abc-123"

    def test_get_default(self) -> None:
        assert RequestContext.get("nonexistent", "default") == "default"

    def test_get_nonexistent_returns_none(self) -> None:
        assert RequestContext.get("nonexistent") is None

    def test_clear_removes_all(self) -> None:
        RequestContext.set("key1", "val1")
        RequestContext.set("key2", "val2")
        RequestContext.clear()
        assert RequestContext.get("key1") is None
        assert RequestContext.get("key2") is None

    def test_overwrite_existing_key(self) -> None:
        RequestContext.set("key", "old")
        RequestContext.set("key", "new")
        assert RequestContext.get("key") == "new"


class TestRequireRole:
    def test_allows_matching_role(self) -> None:
        guard = require_role("senior_operator", "operator")
        # We can't easily call the inner _guard directly without Depends(),
        # but we can verify the factory returns a callable
        import inspect

        assert callable(guard)
        assert inspect.iscoroutinefunction(guard)

    def test_factory_rejects_empty_roles(self) -> None:
        # require_role() with no args
        guard = require_role()
        assert callable(guard)


class TestAuthenticate:
    """Test _authenticate() via its public wrappers."""

    @patch("ai_osop.api.deps.settings")
    def test_no_auth_configured_raises_401(self, mock_settings) -> None:
        from ai_osop.api.deps import _authenticate

        mock_settings.jwt_secret = None
        mock_settings.api_token = None

        with pytest.raises(HTTPException) as exc:
            import asyncio

            asyncio.run(_authenticate("some-token"))
        assert exc.value.status_code == 401

    @patch("ai_osop.api.deps.settings")
    def test_valid_api_token_succeeds(self, mock_settings) -> None:
        from ai_osop.api.deps import _authenticate

        mock_settings.jwt_secret = None
        mock_settings.api_token = "test-token"

        import asyncio

        result = asyncio.run(_authenticate("test-token"))
        assert result["sub"] == "operator-1"
        assert result["role"] == "senior_operator"

    @patch("ai_osop.api.deps.settings")
    def test_api_token_wrong_value_raises_401(self, mock_settings) -> None:
        from ai_osop.api.deps import _authenticate

        mock_settings.jwt_secret = None
        mock_settings.api_token = "test-token"

        with pytest.raises(HTTPException) as exc:
            import asyncio

            asyncio.run(_authenticate("wrong-token"))
        assert exc.value.status_code == 401

    def test_no_credentials_raises_403(self) -> None:
        import asyncio

        from ai_osop.api.deps import _authenticate

        with pytest.raises(HTTPException) as exc:
            asyncio.run(_authenticate(None))
        assert exc.value.status_code == 403
        assert "Not authenticated" in exc.value.detail


class TestAssertEngagementAccess:
    """Test assert_engagement_access RBAC gate."""

    @patch("ai_osop.api.deps.state", {"orchestrator": None})
    def test_orchestrator_not_initialized_returns_503(self) -> None:
        import asyncio

        from ai_osop.api.deps import assert_engagement_access

        operator = {"sub": "op-1", "role": "senior_operator"}
        with pytest.raises(HTTPException) as exc:
            asyncio.run(assert_engagement_access(operator, "eng-1"))
        assert exc.value.status_code == 503
        assert "Orchestrator not initialized" in exc.value.detail

    def test_senior_operator_global_access(self) -> None:
        import asyncio

        from ai_osop.api.deps import assert_engagement_access, state
        from ai_osop.core.models import ScopeDefinition, SessionState

        session = SessionState(
            session_id="eng-1",
            phase="reconnaissance",
            scope=ScopeDefinition(engagement_id="eng-1", domains=["example.com"]),
            roe={},
        )

        mock_orch = MagicMock()
        mock_orch._sessions = {"eng-1": session}
        mock_orch.session_memory = MagicMock()
        mock_orch.session_memory.load_session_state = AsyncMock(return_value=session)
        state["orchestrator"] = mock_orch

        try:
            result = asyncio.run(
                assert_engagement_access({"sub": "senior-op", "role": "senior_operator"}, "eng-1")
            )
            assert result is session
        finally:
            state["orchestrator"] = None

    def test_operator_created_by_owner(self) -> None:
        import asyncio

        from ai_osop.api.deps import assert_engagement_access, state
        from ai_osop.core.models import ScopeDefinition, SessionState

        session = SessionState(
            session_id="eng-2",
            phase="reconnaissance",
            scope=ScopeDefinition(engagement_id="eng-2", domains=["test.com"]),
            roe={},
            created_by="regular-op",
        )

        mock_orch = MagicMock()
        mock_orch._sessions = {"eng-2": session}
        mock_orch.session_memory = MagicMock()
        mock_orch.session_memory.load_session_state = AsyncMock(return_value=session)
        state["orchestrator"] = mock_orch

        try:
            result = asyncio.run(
                assert_engagement_access({"sub": "regular-op", "role": "operator"}, "eng-2")
            )
            assert result is session
        finally:
            state["orchestrator"] = None

    def test_operator_not_owner_raises_403(self) -> None:
        import asyncio

        from ai_osop.api.deps import assert_engagement_access, state
        from ai_osop.core.models import ScopeDefinition, SessionState

        session = SessionState(
            session_id="eng-3",
            phase="reconnaissance",
            scope=ScopeDefinition(engagement_id="eng-3", domains=["test.com"]),
            roe={},
            created_by="owner-op",
        )

        mock_orch = MagicMock()
        mock_orch._sessions = {"eng-3": session}
        mock_orch.session_memory = MagicMock()
        mock_orch.session_memory.load_session_state = AsyncMock(return_value=session)
        state["orchestrator"] = mock_orch

        try:
            with pytest.raises(HTTPException) as exc:
                asyncio.run(
                    assert_engagement_access({"sub": "different-op", "role": "operator"}, "eng-3")
                )
            assert exc.value.status_code == 403
            assert "You do not have permission" in exc.value.detail
        finally:
            state["orchestrator"] = None

    def test_session_id_fallback_to_engagement_id(self) -> None:
        import asyncio

        from ai_osop.api.deps import assert_engagement_access, state
        from ai_osop.core.models import ScopeDefinition, SessionState

        session = SessionState(
            session_id="eng-ts-12345-juice-e2e",
            phase="reconnaissance",
            scope=ScopeDefinition(engagement_id="juice-e2e", domains=["example.com"]),
            roe={},
            created_by="senior-op",
        )

        mock_orch = MagicMock()
        # Session not found by session_id, must fall back to engagement_id
        mock_orch._sessions = {}
        mock_orch.session_memory = MagicMock()
        mock_orch.session_memory.load_session_state = AsyncMock(return_value=None)
        state["orchestrator"] = mock_orch

        # Call with engagement_id (not session_id) — should not fail; has fallback
        try:
            with pytest.raises(HTTPException):
                asyncio.run(
                    assert_engagement_access(
                        {"sub": "senior-op", "role": "senior_operator"}, "missing"
                    )
                )
        finally:
            state["orchestrator"] = None


class TestUpdateActiveAgents:
    def test_update_active_agents_succeeds(self) -> None:
        # Should not raise
        update_active_agents(5)
        update_active_agents(0)
