"""Tests for startup retry and Redis reconnection."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.memory.session_memory import SessionMemory


class TestStartupRetry:
    async def test_connect_with_retry_succeeds_first_try(self):
        """connect_with_retry should succeed on first attempt."""
        connector = AsyncMock()
        from ai_osop.api.main import connect_with_retry

        result = await connect_with_retry(connector, "test-service", max_retries=3)
        assert result is True
        connector.assert_awaited_once()

    async def test_connect_with_retry_succeeds_after_failures(self):
        """connect_with_retry should retry and eventually succeed."""
        connector = AsyncMock(side_effect=[Exception("fail1"), Exception("fail2"), None])
        from ai_osop.api.main import connect_with_retry

        result = await connect_with_retry(connector, "test-service", max_retries=3, base_delay=0.1)
        assert result is True
        assert connector.await_count == 3

    async def test_connect_with_retry_exhausts_all_attempts(self):
        """connect_with_retry should return False after exhausting retries."""
        connector = AsyncMock(side_effect=Exception("always fails"))
        from ai_osop.api.main import connect_with_retry

        result = await connect_with_retry(connector, "test-service", max_retries=3, base_delay=0.1)
        assert result is False
        assert connector.await_count == 4


class TestRedisReconnection:
    @pytest.fixture
    def session_memory(self):
        sm = SessionMemory()
        sm._redis = MagicMock()
        return sm

    async def test_ensure_redis_returns_healthy_connection(self, session_memory):
        """_ensure_redis should return existing connection if healthy."""
        session_memory._redis.ping = AsyncMock()
        result = await session_memory._ensure_redis()
        assert result is session_memory._redis
        session_memory._redis.ping.assert_awaited_once()

    async def test_ensure_redis_reconnects_on_failure(self, session_memory):
        """_ensure_redis should reconnect when ping fails."""
        session_memory._redis.ping = AsyncMock(side_effect=Exception("Connection refused"))
        with patch("redis.asyncio.from_url") as mock_from_url:
            new_redis = MagicMock()
            mock_from_url.return_value = new_redis
            result = await session_memory._ensure_redis()
            assert result is new_redis
            mock_from_url.assert_called_once()

    async def test_ensure_redis_creates_new_connection_when_none(self, session_memory):
        """_ensure_redis should create connection when _redis is None."""
        session_memory._redis = None
        with patch("redis.asyncio.from_url") as mock_from_url:
            new_redis = MagicMock()
            mock_from_url.return_value = new_redis
            result = await session_memory._ensure_redis()
            assert result is new_redis
            mock_from_url.assert_called_once()
