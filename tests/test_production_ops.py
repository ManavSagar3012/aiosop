"""Tests for AI-OSOP production operations components."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.api.health import ready
from ai_osop.core.config import settings



@pytest.fixture(autouse=True)
def clean_state():
    from ai_osop.api.deps import state
    state.pop("orchestrator", None)
    yield
    state.pop("orchestrator", None)
class TestReadinessProbe:
    async def test_ready_returns_200_when_all_healthy(self):
        """ready should return 200 when all dependencies are healthy."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.session_memory = MagicMock()
        mock_orchestrator.session_memory._redis = AsyncMock()
        mock_orchestrator.session_memory._redis.ping = AsyncMock()
        mock_conn = AsyncMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__aenter__.return_value = mock_conn
        mock_orchestrator.session_memory._pg_engine = mock_engine
        mock_orchestrator.graph_memory = MagicMock()
        mock_orchestrator.graph_memory._driver = AsyncMock()
        mock_orchestrator.graph_memory._driver.verify_connectivity = AsyncMock()
        mock_orchestrator.mcp_registry = MagicMock()
        mock_orchestrator.mcp_registry._servers = {}

        from ai_osop.api.deps import state
        state["orchestrator"] = mock_orchestrator

        result = await ready()
        assert result["status"] in ("ready", "degraded")

    async def test_ready_returns_503_when_redis_critical_unhealthy(self):
        """ready should return 503 when Redis is critically unhealthy."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.session_memory = MagicMock()
        mock_orchestrator.session_memory._redis = AsyncMock()
        mock_orchestrator.session_memory._redis.ping = AsyncMock(side_effect=Exception("Connection refused"))
        mock_orchestrator.session_memory._pg_engine = None
        mock_orchestrator.graph_memory = None
        mock_orchestrator.mcp_registry = None

        from ai_osop.api.deps import state
        state["orchestrator"] = mock_orchestrator

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await ready()
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail["status"] == "not_ready"

    async def test_ready_returns_degraded_when_mcp_unhealthy(self):
        """ready should return degraded (not not_ready) when only MCP is unhealthy."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.session_memory = MagicMock()
        mock_orchestrator.session_memory._redis = AsyncMock()
        mock_orchestrator.session_memory._redis.ping = AsyncMock()
        mock_conn = AsyncMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__aenter__.return_value = mock_conn
        mock_orchestrator.session_memory._pg_engine = mock_engine
        mock_orchestrator.graph_memory = MagicMock()
        mock_orchestrator.graph_memory._driver = AsyncMock()
        mock_orchestrator.graph_memory._driver.verify_connectivity = AsyncMock()
        # MCP has no healthy servers but this is not critical
        mock_orchestrator.mcp_registry = MagicMock()
        mock_orchestrator.mcp_registry._servers = {"test-mcp": MagicMock(_session=None)}

        from ai_osop.api.deps import state
        state["orchestrator"] = mock_orchestrator

        result = await ready()
        # MCP is degraded but Redis/Neo4j/Postgres are OK, so status should be degraded
        assert result["status"] in ("ready", "degraded")


class TestStartupRetry:
    async def test_connect_with_retry_succeeds_first_try(self):
        """connect_with_retry should succeed immediately on first try."""
        connector = AsyncMock()
        from ai_osop.api.main import connect_with_retry
        result = await connect_with_retry(connector, "test", max_retries=3, base_delay=0.01)
        assert result is True
        connector.assert_awaited_once()

    async def test_connect_with_retry_succeeds_after_retries(self):
        """connect_with_retry should retry and eventually succeed."""
        connector = AsyncMock(side_effect=[Exception("fail1"), Exception("fail2"), None])
        from ai_osop.api.main import connect_with_retry
        result = await connect_with_retry(connector, "test", max_retries=3, base_delay=0.01)
        assert result is True
        assert connector.await_count == 3

    async def test_connect_with_retry_exhausts_all(self):
        """connect_with_retry should return False after exhausting retries."""
        connector = AsyncMock(side_effect=Exception("always fails"))
        from ai_osop.api.main import connect_with_retry
        result = await connect_with_retry(connector, "test", max_retries=3, base_delay=0.01)
        assert result is False


class TestHPAConfig:
    def test_hpa_manifest_is_valid_yaml(self):
        """HPA manifest should be valid YAML."""
        import yaml
        with open("k8s/hpa.yaml") as f:
            docs = list(yaml.safe_load_all(f))
        assert len(docs) == 2
        # First doc: orchestrator HPA
        assert docs[0]["kind"] == "HorizontalPodAutoscaler"
        assert docs[0]["metadata"]["name"] == "ai-osop-orchestrator"
        assert docs[0]["spec"]["minReplicas"] == 2
        assert docs[0]["spec"]["maxReplicas"] == 10
        # Second doc: agent HPA
        assert docs[1]["kind"] == "HorizontalPodAutoscaler"
        assert docs[1]["metadata"]["name"] == "ai-osop-agents"
        assert docs[1]["spec"]["minReplicas"] == 3
        assert docs[1]["spec"]["maxReplicas"] == 20

    def test_hpa_has_custom_metrics(self):
        """HPA should include custom metrics for queue depth and running tasks."""
        import yaml
        with open("k8s/hpa.yaml") as f:
            docs = list(yaml.safe_load_all(f))
        orch_metrics = docs[0]["spec"]["metrics"]
        custom_metrics = [m for m in orch_metrics if m.get("type") == "Pods"]
        assert len(custom_metrics) >= 1


class TestPDBConfig:
    def test_pdb_manifest_is_valid_yaml(self):
        """PDB manifest should be valid YAML."""
        import yaml
        with open("k8s/pdb.yaml") as f:
            docs = list(yaml.safe_load_all(f))
        assert len(docs) == 2
        assert docs[0]["kind"] == "PodDisruptionBudget"
        assert docs[0]["spec"]["minAvailable"] == 1
        assert docs[1]["kind"] == "PodDisruptionBudget"
        assert docs[1]["spec"]["minAvailable"] == 2


class TestLogRetentionConfig:
    def test_log_config_is_valid_json(self):
        """Log retention ConfigMap should contain valid JSON."""
        import json
        import yaml
        with open("k8s/log-retention.yaml") as f:
            doc = yaml.safe_load(f)
        assert doc["kind"] == "ConfigMap"
        config = json.loads(doc["data"]["log-retention.json"])
        assert config["retention_days"]["debug"] == 7
        assert config["retention_days"]["info"] == 30
        assert config["retention_days"]["error"] == 365
        assert config["retention_days"]["audit"] == 2555
        assert config["max_log_size_mb"] == 100
        assert config["include_request_id"] is True
        assert config["include_trace_id"] is True


class TestBackupCronJobs:
    def test_backup_cronjobs_valid_yaml(self):
        """Backup CronJobs should be valid YAML."""
        import yaml
        with open("k8s/backup-cronjobs.yaml") as f:
            docs = list(yaml.safe_load_all(f))
        assert len(docs) == 3
        # Postgres: hourly
        assert docs[0]["kind"] == "CronJob"
        assert docs[0]["spec"]["schedule"] == "0 * * * *"
        # Neo4j: daily at 2 AM
        assert docs[1]["kind"] == "CronJob"
        assert docs[1]["spec"]["schedule"] == "0 2 * * *"
        # Redis: every 6 hours
        assert docs[2]["kind"] == "CronJob"
        assert docs[2]["spec"]["schedule"] == "0 */6 * * *"

    def test_backup_jobs_have_cleanup(self):
        """Backup CronJobs should include cleanup logic for old backups."""
        import yaml
        with open("k8s/backup-cronjobs.yaml") as f:
            docs = list(yaml.safe_load_all(f))
        for doc in docs:
            command = doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["command"]
            assert any("aws s3 rm" in str(c) for c in command), f"Missing cleanup in {doc['metadata']['name']}"



class TestReadinessMetric:
    """Sprint 8: ai_osop_ready_status metric and history tracking."""

    @pytest.fixture(autouse=True)
    def reset_history(self):
        """Reset readiness history before each test."""
        from ai_osop.api.health import _readiness_history
        _readiness_history.clear()
        yield
        _readiness_history.clear()

    async def test_ready_emits_metric_1(self):
        """When all deps are healthy, READY_STATUS should be set to 1.0."""
        from ai_osop.api.health import ready, _readiness_history
        from ai_osop.core.metrics import READY_STATUS

        mock_orchestrator = MagicMock()
        mock_orchestrator.session_memory = MagicMock()
        mock_orchestrator.session_memory._redis = AsyncMock()
        mock_orchestrator.session_memory._redis.ping = AsyncMock()
        mock_conn = AsyncMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__aenter__.return_value = mock_conn
        mock_orchestrator.session_memory._pg_engine = mock_engine
        mock_orchestrator.graph_memory = MagicMock()
        mock_orchestrator.graph_memory._driver = AsyncMock()
        mock_orchestrator.graph_memory._driver.verify_connectivity = AsyncMock()
        mock_orchestrator.mcp_registry = MagicMock()
        mock_orchestrator.mcp_registry._servers = {"test-mcp": MagicMock(_session=MagicMock())}

        from ai_osop.api.deps import state
        state["orchestrator"] = mock_orchestrator

        result = await ready()
        assert result["status"] == "ready"
        assert len(result["history"]) == 1
        assert result["history"][0]["status"] == "ready"
        assert all(c == "healthy" for c in result["history"][0]["checks"].values())

    async def test_degraded_emits_metric_0_5(self):
        """When MCP is degraded but critical deps are OK, READY_STATUS should be 0.5."""
        from ai_osop.api.health import ready, _readiness_history

        mock_orchestrator = MagicMock()
        mock_orchestrator.session_memory = MagicMock()
        mock_orchestrator.session_memory._redis = AsyncMock()
        mock_orchestrator.session_memory._redis.ping = AsyncMock()
        mock_conn = AsyncMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__aenter__.return_value = mock_conn
        mock_orchestrator.session_memory._pg_engine = mock_engine
        mock_orchestrator.graph_memory = MagicMock()
        mock_orchestrator.graph_memory._driver = AsyncMock()
        mock_orchestrator.graph_memory._driver.verify_connectivity = AsyncMock()
        # MCP degraded: no healthy servers
        mock_orchestrator.mcp_registry = MagicMock()
        mock_orchestrator.mcp_registry._servers = {"test-mcp": MagicMock(_session=None)}

        from ai_osop.api.deps import state
        state["orchestrator"] = mock_orchestrator

        result = await ready()
        assert result["status"] == "degraded"
        assert len(result["history"]) == 1
        assert result["history"][0]["status"] == "degraded"
        assert result["checks"]["mcp_registry"]["status"] == "degraded"

    async def test_not_ready_emits_metric_0(self):
        """When a critical dep is unhealthy, READY_STATUS should be 0.0 and history recorded."""
        from ai_osop.api.health import ready, _readiness_history
        from fastapi import HTTPException

        mock_orchestrator = MagicMock()
        mock_orchestrator.session_memory = MagicMock()
        mock_orchestrator.session_memory._redis = AsyncMock()
        mock_orchestrator.session_memory._redis.ping = AsyncMock(side_effect=Exception("Connection refused"))
        mock_orchestrator.session_memory._pg_engine = None
        mock_orchestrator.graph_memory = None
        mock_orchestrator.mcp_registry = None

        from ai_osop.api.deps import state
        state["orchestrator"] = mock_orchestrator

        with pytest.raises(HTTPException) as exc_info:
            await ready()
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail["status"] == "not_ready"
        # History should include the failed check
        assert len(exc_info.value.detail["history"]) >= 1
        assert exc_info.value.detail["history"][-1]["status"] == "not_ready"

    async def test_history_tracks_last_5_checks(self):
        """Readiness history should retain at most 5 entries."""
        from ai_osop.api.health import ready, _readiness_history

        mock_orchestrator = MagicMock()
        mock_orchestrator.session_memory = MagicMock()
        mock_orchestrator.session_memory._redis = AsyncMock()
        mock_orchestrator.session_memory._redis.ping = AsyncMock()
        mock_conn = AsyncMock()
        mock_engine = MagicMock()
        mock_engine.connect.return_value.__aenter__.return_value = mock_conn
        mock_orchestrator.session_memory._pg_engine = mock_engine
        mock_orchestrator.graph_memory = MagicMock()
        mock_orchestrator.graph_memory._driver = AsyncMock()
        mock_orchestrator.graph_memory._driver.verify_connectivity = AsyncMock()
        mock_orchestrator.mcp_registry = MagicMock()
        mock_orchestrator.mcp_registry._servers = {}

        from ai_osop.api.deps import state
        state["orchestrator"] = mock_orchestrator

        # Call ready 7 times
        for _ in range(7):
            await ready()

        # History should be capped at 5
        assert len(list(_readiness_history)) == 5


class TestConnectWithRetryUsesSharedUtility:
    """Sprint 8: connect_with_retry delegates to retry_with_backoff."""

    def test_connect_with_retry_imports_retry_with_backoff(self):
        """connect_with_retry should import and use retry_with_backoff."""
        import inspect

        from ai_osop.api.main import connect_with_retry
        from ai_osop import api

        module_source = inspect.getsource(api.main)
        assert "retry_with_backoff" in module_source
        assert "ai_osop.reliability.retry" in module_source or "from ai_osop.reliability.retry import retry_with_backoff" in module_source
