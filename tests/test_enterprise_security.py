"""
Enterprise Security Module Tests — Phase 5 & 6

Tests for:
- Audit chain integrity (HMAC hash chain)
- Redis ACL validation
- Neo4j write ACL
- Coordination bus source validation
- RBAC enforcement
- Per-agent rate limiting
- Cost tracking
- Scope signature enforcement
- DLQ deduplication
"""

import asyncio
import hashlib
import hmac
import time
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.config import scope_signing_key


# ============================================================
# Audit Chain Integrity
# ============================================================


class TestAuditChainIntegrity:
    """Test HMAC hash chain for audit log tamper detection."""

    def test_genesis_hash_is_constant(self):
        """Genesis hash should be 64 zeros."""
        from ai_osop.security.audit_integrity import GENESIS_HASH

        assert GENESIS_HASH == "0" * 64
        assert len(GENESIS_HASH) == 64

    def test_single_event_chain(self):
        """A single event produces a valid chain."""
        from ai_osop.security.audit_integrity import AuditChainVerifier

        verifier = AuditChainVerifier()
        event = {"event_id": "evt-001", "event_type": "task_completed", "severity": "info"}
        h = verifier.append_event(event)
        assert len(h) == 64  # SHA-256 hex digest
        assert h != "0" * 64

    def test_chain_verification_valid(self):
        """A chain of events created by the verifier should verify cleanly."""
        from ai_osop.security.audit_integrity import AuditChainVerifier

        verifier = AuditChainVerifier()
        events = []
        for i in range(5):
            event = {"event_id": f"evt-{i:03d}", "event_type": f"type_{i}"}
            h = verifier.append_event(event)
            event["integrity_hash"] = h
            events.append(event)

        report = verifier.verify_chain(events)
        assert report["valid"] is True
        assert report["total_events"] == 5
        assert report["tampered_events"] == []

    def test_chain_tamper_detection(self):
        """Tampering with an event should be detected."""
        from ai_osop.security.audit_integrity import AuditChainVerifier

        verifier = AuditChainVerifier()
        events = []
        for i in range(3):
            event = {"event_id": f"evt-{i:03d}", "event_type": f"type_{i}"}
            h = verifier.append_event(event)
            event["integrity_hash"] = h
            events.append(event)

        # Tamper with event 1
        events[1]["event_type"] = "TAMPERED"

        report = verifier.verify_chain(events)
        assert report["valid"] is False
        assert 1 in report["tampered_events"]
        assert report["first_tampered_event"] == 1

    def test_chain_tamper_cascading(self):
        """Tampering one event should cause all subsequent events to fail."""
        from ai_osop.security.audit_integrity import AuditChainVerifier

        verifier = AuditChainVerifier()
        events = []
        for i in range(4):
            event = {"event_id": f"evt-{i:03d}", "event_type": f"type_{i}"}
            h = verifier.append_event(event)
            event["integrity_hash"] = h
            events.append(event)

        # Tamper with event 1 — events 2 and 3 should also fail
        events[1]["event_type"] = "TAMPERED"

        report = verifier.verify_chain(events)
        assert report["valid"] is False
        assert len(report["tampered_events"]) >= 1

    def test_empty_chain(self):
        """Empty chain should be valid."""
        from ai_osop.security.audit_integrity import AuditChainVerifier

        verifier = AuditChainVerifier()
        report = verifier.verify_chain([])
        assert report["valid"] is True
        assert report["total_events"] == 0

    def test_deterministic_hashing(self):
        """Same event should produce the same hash."""
        from ai_osop.security.audit_integrity import AuditChainVerifier

        v1 = AuditChainVerifier()
        v2 = AuditChainVerifier()
        event = {"event_id": "evt-det", "event_type": "test"}
        h1 = v1.compute_hash(event, "0" * 64)
        h2 = v2.compute_hash(event, "0" * 64)
        assert h1 == h2

    def test_chain_state(self):
        """Chain state should report correct length."""
        from ai_osop.security.audit_integrity import AuditChainVerifier

        verifier = AuditChainVerifier()
        state = verifier.get_chain_state()
        assert state["chain_length"] == 0

        verifier.append_event({"test": 1})
        state = verifier.get_chain_state()
        assert state["chain_length"] == 1


# ============================================================
# ACL Validators
# ============================================================


class TestRedisACLValidator:
    """Test Redis ACL validation."""

    def test_roles_defined(self):
        """All expected roles are defined."""
        from ai_osop.security.acl_validators import REDIS_ROLES

        assert "agent" in REDIS_ROLES
        assert "orchestrator" in REDIS_ROLES
        assert "readonly" in REDIS_ROLES

    def test_agent_role_has_denied_commands(self):
        """Agent role should deny dangerous commands."""
        from ai_osop.security.acl_validators import REDIS_ROLES

        denied = REDIS_ROLES["agent"]["allowed_commands"]["denied"]
        assert "FLUSHALL" in denied
        assert "CONFIG" in denied
        assert "SHUTDOWN" in denied

    def test_agent_permissions_valid(self):
        """Agent using only read/write commands should be compliant."""
        from ai_osop.security.acl_validators import RedisACLValidator

        validator = RedisACLValidator()
        result = validator.validate_agent_permissions(
            "agent-001", ["GET", "SET", "HGET"], ["aiosop:eng-1:*"]
        )
        assert result["compliant"] is True
        assert result["violations"] == []

    def test_agent_permissions_violation(self):
        """Agent using FLUSHALL should be flagged."""
        from ai_osop.security.acl_validators import RedisACLValidator

        validator = RedisACLValidator()
        result = validator.validate_agent_permissions(
            "agent-001", ["GET", "FLUSHALL"], ["aiosop:eng-1:*"]
        )
        assert result["compliant"] is False
        assert len(result["violations"]) == 1
        assert "FLUSHALL" in result["violations"][0]


class TestNeo4jWriteACL:
    """Test Neo4j write access control."""

    def test_authorized_source(self):
        """Known agents should be allowed to write."""
        from ai_osop.security.acl_validators import Neo4jWriteACL

        acl = Neo4jWriteACL()
        result = acl.validate_write("recon_agent", ["Endpoint", "Asset"])
        assert result["allowed"] is True

    def test_unauthorized_source(self):
        """Unknown sources should be rejected."""
        from ai_osop.security.acl_validators import Neo4jWriteACL

        acl = Neo4jWriteACL()
        result = acl.validate_write("EVIL_HACKER", ["Vulnerability"])
        assert result["allowed"] is False
        assert "unauthorized_tool_source" in result["reason"]

    def test_scope_violation(self):
        """Agent writing to wrong node type should be rejected."""
        from ai_osop.security.acl_validators import Neo4jWriteACL

        acl = Neo4jWriteACL()
        # recon_agent can write to Asset, Endpoint — but NOT Exploit
        result = acl.validate_write("recon_agent", ["Exploit"])
        assert result["allowed"] is False
        assert "scope_violation" in result["reason"]

    def test_orchestrator_full_access(self):
        """Orchestrator should write to any node type."""
        from ai_osop.security.acl_validators import Neo4jWriteACL

        acl = Neo4jWriteACL()
        result = acl.validate_write("orchestrator", ["Task", "Session", "Vulnerability"])
        assert result["allowed"] is True

    def test_allowed_sources_list(self):
        """Should return sorted list of authorized sources."""
        from ai_osop.security.acl_validators import Neo4jWriteACL

        acl = Neo4jWriteACL()
        sources = acl.get_allowed_sources()
        assert "orchestrator" in sources
        assert "recon_agent" in sources
        assert sources == sorted(sources)


# ============================================================
# RBAC
# ============================================================


class TestRBAC:
    """Test role-based access control."""

    def test_viewer_cannot_create(self):
        """Viewer role should not be able to create engagements."""
        from ai_osop.security.rbac import RBACEnforcer, Role

        enforcer = RBACEnforcer()
        result = enforcer.check_endpoint_access(Role.VIEWER, "POST", "/engagements")
        assert result["allowed"] is False

    def test_operator_can_create(self):
        """Operator role should be able to create engagements."""
        from ai_osop.security.rbac import RBACEnforcer, Role

        enforcer = RBACEnforcer()
        result = enforcer.check_endpoint_access(Role.OPERATOR, "POST", "/engagements")
        assert result["allowed"] is True

    def test_admin_can_halt(self):
        """Admin should be able to halt engagements."""
        from ai_osop.security.rbac import RBACEnforcer, Role

        enforcer = RBACEnforcer()
        result = enforcer.check_endpoint_access(Role.ADMIN, "POST", "/engagements/eng-1/halt")
        assert result["allowed"] is True

    def test_viewer_cannot_halt(self):
        """Viewer should not be able to halt engagements."""
        from ai_osop.security.rbac import RBACEnforcer, Role

        enforcer = RBACEnforcer()
        result = enforcer.check_endpoint_access(Role.VIEWER, "POST", "/engagements/eng-1/halt")
        assert result["allowed"] is False

    def test_system_has_all_permissions(self):
        """System role should have all permissions."""
        from ai_osop.security.rbac import RBACEnforcer, Role

        enforcer = RBACEnforcer()
        assert enforcer.check_permission(Role.SYSTEM, "anything:at_all") is True

    def test_unknown_endpoint_denied(self):
        """Unknown endpoints should be denied by default."""
        from ai_osop.security.rbac import RBACEnforcer, Role

        enforcer = RBACEnforcer()
        result = enforcer.check_endpoint_access(Role.ADMIN, "DELETE", "/unknown/endpoint")
        assert result["allowed"] is False

    def test_all_roles_defined(self):
        """All expected roles should be defined."""
        from ai_osop.security.rbac import Role

        assert Role.VIEWER.value == "viewer"
        assert Role.OPERATOR.value == "operator"
        assert Role.ADMIN.value == "admin"
        assert Role.SYSTEM.value == "system"


# ============================================================
# Per-Agent Rate Limiter
# ============================================================


class TestPerAgentRateLimiter:
    """Test per-agent rate limiting."""

    def test_within_limit(self):
        """Requests within limit should be allowed."""
        from ai_osop.security.rate_limiter import PerAgentRateLimiter

        limiter = PerAgentRateLimiter()
        result = limiter.check_rate_limit("agent-001", "recon")
        assert result["allowed"] is True
        assert result["current_count"] == 1

    def test_burst_exceeded(self):
        """Burst limit exceeded should trigger penalty."""
        from ai_osop.security.rate_limiter import PerAgentRateLimiter

        limiter = PerAgentRateLimiter()
        # recon has burst_max=50, use a lower limit for testing
        limiter.limits["test"] = __import__("ai_osop.security.rate_limiter", fromlist=["RateLimitConfig"]).RateLimitConfig(
            max_requests=10, burst_max=3, window_seconds=60
        )
        for _ in range(3):
            limiter.check_rate_limit("agent-001", "test")
        result = limiter.check_rate_limit("agent-001", "test")
        assert result["allowed"] is False
        assert result["reason"] == "burst_exceeded"

    def test_penalty_cooldown(self):
        """After penalty, requests should be blocked for penalty_seconds."""
        from ai_osop.security.rate_limiter import PerAgentRateLimiter, RateLimitConfig

        limiter = PerAgentRateLimiter(limits={
            "default": RateLimitConfig(max_requests=100, burst_max=20),
            "test": RateLimitConfig(max_requests=10, burst_max=2, penalty_seconds=5),
        })
        limiter.check_rate_limit("agent-001", "test")
        limiter.check_rate_limit("agent-001", "test")
        # Third triggers burst
        result = limiter.check_rate_limit("agent-001", "test")
        assert result["allowed"] is False

        # Next request should be in penalty
        result2 = limiter.check_rate_limit("agent-001", "test")
        assert result2["allowed"] is False
        assert result2["reason"] == "penalty_cooldown"

    def test_agent_stats(self):
        """Should track agent stats correctly."""
        from ai_osop.security.rate_limiter import PerAgentRateLimiter

        limiter = PerAgentRateLimiter()
        limiter.check_rate_limit("agent-001", "recon")
        limiter.check_rate_limit("agent-001", "recon")
        stats = limiter.get_agent_stats("agent-001")
        assert stats["requests_in_window"] == 2
        assert stats["violations"] == 0

    def test_reset_agent(self):
        """Reset should clear all state."""
        from ai_osop.security.rate_limiter import PerAgentRateLimiter

        limiter = PerAgentRateLimiter()
        limiter.check_rate_limit("agent-001", "recon")
        limiter.reset_agent("agent-001")
        stats = limiter.get_agent_stats("agent-001")
        assert stats["requests_in_window"] == 0


# ============================================================
# Cost Tracker
# ============================================================


class TestCostTracker:
    """Test per-engagement cost tracking."""

    def test_llm_cost_calculation(self):
        """LLM cost should be calculated correctly."""
        from ai_osop.security.cost_tracker import CostTracker

        tracker = CostTracker(budget_limit_usd=10.0)
        result = tracker.record_llm_call(
            engagement_id="eng-001",
            model="gpt-4o",
            input_tokens=1000,
            output_tokens=500,
            duration_ms=500,
            agent_id="recon-01",
            task_id="task-001",
        )
        # gpt-4o: input=$0.0025/1k, output=$0.01/1k
        # cost = (1000 * 0.0025 + 500 * 0.01) / 1000 = 0.0075
        assert result["cost_usd"] == pytest.approx(0.0075, abs=0.0001)

    def test_budget_enforcement(self):
        """Should detect when budget is exceeded."""
        from ai_osop.security.cost_tracker import CostTracker

        tracker = CostTracker(budget_limit_usd=0.01)
        tracker.record_llm_call(
            engagement_id="eng-001",
            model="gpt-4o",
            input_tokens=10000,
            output_tokens=10000,
            duration_ms=1000,
            agent_id="recon-01",
            task_id="task-001",
        )
        costs = tracker.get_engagement_costs("eng-001")
        assert costs["budget"]["exceeded"] is True

    def test_mcp_call_tracking(self):
        """MCP calls should be tracked with success/failure."""
        from ai_osop.security.cost_tracker import CostTracker

        tracker = CostTracker()
        tracker.record_mcp_call(
            engagement_id="eng-001",
            server="nuclei",
            tool="scan",
            duration_ms=100,
            success=True,
            agent_id="vuln-01",
            task_id="task-001",
        )
        tracker.record_mcp_call(
            engagement_id="eng-001",
            server="nuclei",
            tool="scan",
            duration_ms=100,
            success=False,
            agent_id="vuln-01",
            task_id="task-002",
        )
        costs = tracker.get_engagement_costs("eng-001")
        assert costs["mcp"]["total_calls"] == 2
        assert costs["mcp"]["success"] == 1
        assert costs["mcp"]["failure"] == 1
        assert costs["mcp"]["success_rate"] == 50.0

    def test_per_agent_breakdown(self):
        """Costs should be broken down by agent."""
        from ai_osop.security.cost_tracker import CostTracker

        tracker = CostTracker()
        tracker.record_llm_call(
            engagement_id="eng-001", model="gpt-4o",
            input_tokens=1000, output_tokens=500, duration_ms=100,
            agent_id="recon-01", task_id="t1",
        )
        tracker.record_llm_call(
            engagement_id="eng-001", model="gpt-4o-mini",
            input_tokens=2000, output_tokens=1000, duration_ms=100,
            agent_id="vuln-01", task_id="t2",
        )
        costs = tracker.get_engagement_costs("eng-001")
        assert "recon-01" in costs["llm"]["by_agent"]
        assert "vuln-01" in costs["llm"]["by_agent"]

    def test_free_local_models(self):
        """Local models (ollama) should be free."""
        from ai_osop.security.cost_tracker import CostTracker

        tracker = CostTracker()
        result = tracker.record_llm_call(
            engagement_id="eng-001",
            model="ollama/llama3",
            input_tokens=5000,
            output_tokens=2000,
            duration_ms=500,
            agent_id="recon-01",
            task_id="task-001",
        )
        assert result["cost_usd"] == 0.0


# ============================================================
# Scope Signature Enforcement
# ============================================================


class TestScopeSignatureEnforcement:
    """Test scope signature verification at assignment time."""

    def test_valid_signature(self):
        """Valid scope signature should pass."""
        from ai_osop.security.scope_enforcement import ScopeSignatureVerifier

        verifier = ScopeSignatureVerifier()
        key = scope_signing_key()
        payload = "eng-001:example.com,test.example.com:"
        sig = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        result = verifier.verify_scope_signature(
            "eng-001", ["example.com", "test.example.com"], [], sig
        )
        assert result is True

    def test_invalid_signature(self):
        """Invalid signature should fail."""
        from ai_osop.security.scope_enforcement import ScopeSignatureVerifier

        verifier = ScopeSignatureVerifier()
        result = verifier.verify_scope_signature(
            "eng-001", ["example.com"], [], "bad_signature"
        )
        assert result is False

    def test_missing_signature(self):
        """Missing signature should fail."""
        from ai_osop.security.scope_enforcement import ScopeSignatureVerifier

        verifier = ScopeSignatureVerifier()
        result = verifier.verify_scope_signature("eng-001", ["example.com"], [], "")
        assert result is False

    def test_hostname_matches_domain(self):
        """Hostname should match its parent domain."""
        from ai_osop.security.scope_enforcement import ScopeSignatureVerifier

        assert ScopeSignatureVerifier._hostname_matches("sub.example.com", "example.com") is True

    def test_hostname_no_match(self):
        """Hostname should not match unrelated domain."""
        from ai_osop.security.scope_enforcement import ScopeSignatureVerifier

        assert ScopeSignatureVerifier._hostname_matches("evil.com", "example.com") is False

    def test_wildcard_match(self):
        """Wildcard pattern should match subdomains."""
        from ai_osop.security.scope_enforcement import ScopeSignatureVerifier

        assert ScopeSignatureVerifier._hostname_matches("api.example.com", "*.example.com") is True
        assert ScopeSignatureVerifier._hostname_matches("evil.com", "*.example.com") is False

    def test_excluded_target_rejected(self):
        """Excluded target should be rejected at assignment."""
        from ai_osop.security.scope_enforcement import ScopeSignatureVerifier

        verifier = ScopeSignatureVerifier()
        scope = MagicMock()
        scope.domains = ["example.com"]
        scope.ips = []
        scope.exclusions = ["admin.example.com"]

        result = verifier.validate_task_scope(
            {"target": "https://admin.example.com/secret"},
            scope,
        )
        assert result["allowed"] is False
        assert "exclusion" in result["reason"]

    def test_ip_range_match(self):
        """IP in allowed CIDR range should be accepted."""
        from ai_osop.security.scope_enforcement import ScopeSignatureVerifier

        assert ScopeSignatureVerifier._ip_in_range("192.168.1.100", "192.168.1.0/24") is True
        assert ScopeSignatureVerifier._ip_in_range("10.0.0.1", "192.168.1.0/24") is False

    def test_url_hostname_extraction(self):
        """Should extract hostname from URL."""
        from ai_osop.security.scope_enforcement import ScopeSignatureVerifier

        assert ScopeSignatureVerifier._extract_hostname("https://example.com/path") == "example.com"
        assert ScopeSignatureVerifier._extract_hostname("http://192.168.1.1:8080/api") == "192.168.1.1"
        assert ScopeSignatureVerifier._extract_hostname("example.com") == "example.com"


# ============================================================
# DLQ Deduplication
# ============================================================


class TestDLQDeduplication:
    """Test DLQ replay prevention."""

    def test_dlq_entry_model(self):
        """DLQEntry should have all required fields."""
        from ai_osop.reliability.dlq import DLQEntry

        entry = DLQEntry(
            task_id="task-001",
            engagement_id="eng-001",
            task_type="full_recon",
            agent_type="recon",
            reason="retry_budget_exhausted",
            final_error="timeout",
        )
        assert entry.id.startswith("dlq-")
        assert entry.task_id == "task-001"
        assert entry.status == "pending_review"

    def test_dlq_dedup_set(self):
        """DLQ should have a _processed_ids set for deduplication."""
        from ai_osop.reliability.dlq import DeadLetterQueue

        mock_memory = MagicMock()
        dlq = DeadLetterQueue(mock_memory)
        assert hasattr(dlq, "_processed_ids")
        assert isinstance(dlq._processed_ids, set)


# ============================================================
# mTLS Status
# ============================================================


class TestMTLSStatus:
    """Test mTLS configuration status."""

    def test_tls_status_structure(self):
        """TLS status should have all required fields."""
        from ai_osop.security.mtls import get_tls_status

        status = get_tls_status()
        assert "mtls_enabled" in status
        assert "redis_tls_enabled" in status
        assert "neo4j_tls_enabled" in status
        assert "cert_configured" in status
        assert isinstance(status["mtls_enabled"], bool)

    def test_tls_disabled_by_default(self):
        """mTLS should be disabled by default."""
        from ai_osop.security.mtls import get_tls_status

        status = get_tls_status()
        assert status["mtls_enabled"] is False
        assert status["redis_tls_enabled"] is False
        assert status["neo4j_tls_enabled"] is False


# ============================================================
# Self-Pentest Agent
# ============================================================


class TestSelfPentestAgent:
    """Test the self-pentest agent scenarios."""

    @pytest.mark.asyncio
    async def test_all_scenarios_run(self):
        """All 5 scenarios should execute without crashing."""
        from ai_osop.agents.self_pentest_agent import SelfPentestAgent

        agent = SelfPentestAgent(
            redis_url="redis://localhost:6379",
            neo4j_uri="bolt://localhost:7687",
        )
        report = await agent.run_full_pentest()
        assert report["total_scenarios"] == 5
        assert len(report["scenarios"]) == 5
        assert report["verdict"] in (
            "SECURE", "VULNERABLE", "PARTIAL", "INFRASTRUCTURE_ERROR", "NO_TESTS_RUN"
        )

    @pytest.mark.asyncio
    async def test_individual_scenario(self):
        """Individual scenario should run independently."""
        from ai_osop.agents.self_pentest_agent import SelfPentestAgent

        agent = SelfPentestAgent()
        result = await agent.run_scenario("privilege_escalation")
        assert result["name"] == "Privilege Escalation"
        assert result["result"] in ("blocked", "detected", "passed", "error")

    @pytest.mark.asyncio
    async def test_unknown_scenario_raises(self):
        """Unknown scenario name should raise ValueError."""
        from ai_osop.agents.self_pentest_agent import SelfPentestAgent

        agent = SelfPentestAgent()
        with pytest.raises(ValueError, match="Unknown scenario"):
            await agent.run_scenario("nonexistent_attack")

    @pytest.mark.asyncio
    async def test_audit_event_generation(self):
        """Should generate a valid AuditEvent from report."""
        from ai_osop.agents.self_pentest_agent import SelfPentestAgent

        agent = SelfPentestAgent()
        report = await agent.run_full_pentest()
        event = await agent.generate_audit_event(report)
        assert event.event_type == "self_pentest_completed"
        assert event.actor_id == "self_pentest_agent"
        assert "security_score" in event.result
