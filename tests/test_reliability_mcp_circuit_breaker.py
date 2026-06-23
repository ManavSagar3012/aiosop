"""Tests for MCP circuit breaker v2 (half-open state)."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest


class TestMCPCircuitBreakerV2:
    @pytest.fixture
    def mcp_conn(self):
        return MCPConnection(
            server_id="test-mcp",
            host="localhost",
            port=8080,
            auth_token=None,
        )

    def test_initial_state_is_closed(self, mcp_conn):
        assert mcp_conn.get_circuit_state() == "closed"
        assert not mcp_conn._circuit_open
        assert not mcp_conn._half_open

    def test_failure_threshold_opens_circuit(self, mcp_conn):
        threshold = mcp_conn.CIRCUIT_THRESHOLD
        for _ in range(threshold):
            mcp_conn._record_failure()
        assert mcp_conn.get_circuit_state() == "open"
        assert mcp_conn._circuit_open

    def test_success_resets_failure_count(self, mcp_conn):
        mcp_conn._record_failure()
        mcp_conn._record_failure()
        assert mcp_conn._failure_count == 2
        mcp_conn._record_success()
        assert mcp_conn._failure_count == 0

    def test_circuit_opens_after_threshold(self, mcp_conn):
        for _ in range(mcp_conn.CIRCUIT_THRESHOLD):
            mcp_conn._record_failure()
        assert mcp_conn.get_circuit_state() == "open"
        assert mcp_conn._circuit_opened_at is not None

    def test_half_open_after_recovery_timeout(self, mcp_conn):
        # Force circuit open
        for _ in range(mcp_conn.CIRCUIT_THRESHOLD):
            mcp_conn._record_failure()
        assert mcp_conn.get_circuit_state() == "open"

        # Backdate the opened_at to simulate recovery timeout elapsed
        mcp_conn._circuit_opened_at = datetime.utcnow() - timedelta(
            seconds=mcp_conn.CIRCUIT_RECOVERY_SECONDS + 1
        )
        mcp_conn._circuit_breaker_check()
        assert mcp_conn.get_circuit_state() == "half_open"

    def test_half_open_success_closes_circuit(self, mcp_conn):
        # Set half-open state
        mcp_conn._circuit_open = False
        mcp_conn._half_open = True
        mcp_conn._consecutive_successes = 0

        # Record enough successes to close
        for _ in range(mcp_conn.CIRCUIT_HALF_OPEN_SUCCESS_REQUIRED):
            mcp_conn._record_success()
        assert mcp_conn.get_circuit_state() == "closed"
        assert mcp_conn._failure_count == 0

    def test_half_open_failure_reopens_circuit(self, mcp_conn):
        # Set half-open state
        mcp_conn._circuit_open = False
        mcp_conn._half_open = True
        mcp_conn._consecutive_successes = 1

        mcp_conn._record_failure()
        assert mcp_conn.get_circuit_state() == "open"
        assert mcp_conn._consecutive_successes == 0

    def test_recovery_attempts_incremented(self, mcp_conn):
        # Force circuit open and backdate
        for _ in range(mcp_conn.CIRCUIT_THRESHOLD):
            mcp_conn._record_failure()
        mcp_conn._circuit_opened_at = datetime.utcnow() - timedelta(
            seconds=mcp_conn.CIRCUIT_RECOVERY_SECONDS + 1
        )
        mcp_conn._circuit_breaker_check()
        assert mcp_conn._recovery_attempts == 1

    def test_last_success_at_updated(self, mcp_conn):
        before = datetime.utcnow()
        mcp_conn._record_success()
        assert mcp_conn._last_success_at is not None
        assert mcp_conn._last_success_at >= before

    def test_last_failure_at_updated(self, mcp_conn):
        before = datetime.utcnow()
        mcp_conn._record_failure()
        assert mcp_conn._last_failure_at is not None
        assert mcp_conn._last_failure_at >= before

    @patch("ai_osop.core.observability.record_circuit_breaker_state")
    def test_metrics_emitted_on_state_change(self, mock_record, mcp_conn):
        # Force circuit open
        for _ in range(mcp_conn.CIRCUIT_THRESHOLD):
            mcp_conn._record_failure()
        assert mock_record.called
        mock_record.assert_called_with(mcp_conn.server_id, is_open=True)

    @patch("ai_osop.core.observability.record_circuit_breaker_state")
    def test_metrics_emitted_on_close(self, mock_record, mcp_conn):
        # Force circuit open
        for _ in range(mcp_conn.CIRCUIT_THRESHOLD):
            mcp_conn._record_failure()
        mock_record.reset_mock()

        # Backdate and go half-open, then succeed to close
        mcp_conn._circuit_opened_at = datetime.utcnow() - timedelta(
            seconds=mcp_conn.CIRCUIT_RECOVERY_SECONDS + 1
        )
        mcp_conn._circuit_breaker_check()
        assert mcp_conn._half_open

        for _ in range(mcp_conn.CIRCUIT_HALF_OPEN_SUCCESS_REQUIRED):
            mcp_conn._record_success()
        assert mcp_conn.get_circuit_state() == "closed"
        assert mock_record.called
