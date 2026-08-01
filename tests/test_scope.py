import ipaddress
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.exceptions import OutOfScopeError, SandboxException, ScopeValidationError
from ai_osop.core.models import AuditEvent, ScopeDefinition
from ai_osop.safety.scope import ApprovalGate, AuditIntegrity, SandboxManager, ScopeEnforcer


@pytest.fixture
def dummy_scope():
    return ScopeDefinition(
        engagement_id="test-eng",
        domains=["example.com", "test.org"],
        ips=["192.168.1.0/24"],
        exclusions=["admin.example.com", "192.168.1.100"],
        approval_required_for=["rce", "sqli"],
    )


def test_scope_enforcer_valid_targets(dummy_scope):
    enforcer = ScopeEnforcer(dummy_scope)

    # Valid domains
    assert enforcer.validate_target("example.com") is True
    assert enforcer.validate_target("sub.example.com") is True
    assert enforcer.validate_target("test.org") is True

    # Valid IPs
    assert enforcer.validate_target("192.168.1.50") is True

    # Valid URLs
    assert enforcer.validate_target("https://example.com/path") is True
    assert enforcer.validate_target("http://192.168.1.50:8080/") is True


def test_scope_enforcer_accepts_host_bits_cidr():
    """A CIDR with host bits set ('10.0.0.5/24') must not crash the constructor.
    A raised constructor makes callers fall back to _scope_manager=None, i.e.
    'no scope == allow everything' (fail-OPEN scope bypass). strict=False
    normalizes it to 10.0.0.0/24. (AIOSOP-SCOPE-STRICT regression)
    """
    enforcer = ScopeEnforcer(ScopeDefinition(engagement_id="e", domains=[], ips=["10.0.0.5/24"]))
    assert enforcer.host_in_scope("10.0.0.42") is True
    assert enforcer.validate_target("10.0.0.42") is True
    with pytest.raises(OutOfScopeError):
        enforcer.validate_target("10.0.1.1")


def test_scope_enforcer_skips_invalid_ip_without_failing_open():
    """A single malformed IP entry must not nuke the whole enforcer (which would
    make callers fail OPEN). The bad entry is skipped; valid ranges still work
    and everything else stays out of scope (fail CLOSED)."""
    enforcer = ScopeEnforcer(
        ScopeDefinition(engagement_id="e", domains=[], ips=["not-an-ip", "192.168.5.0/24"])
    )
    assert enforcer.host_in_scope("192.168.5.10") is True
    assert enforcer.host_in_scope("8.8.8.8") is False


def test_scope_enforcer_normalizes_port_in_domain():
    """A scope domain with a port ('localhost:3000') must match the URL host
    ('localhost', port-stripped by urlparse) — else every in-scope browser
    navigation is rejected. (AIOSOP-SCOPE-PORT regression: the autonomous login
    probe failed with 'Domain localhost not in scope. Allowed: localhost:3000').
    """
    enforcer = ScopeEnforcer(ScopeDefinition(engagement_id="e", domains=["localhost:3000"], ips=[]))
    assert enforcer.validate_target("http://localhost:3000/#/login") is True
    assert enforcer.validate_target("http://localhost:3000/rest/user/login") is True
    assert enforcer.validate_target("localhost") is True
    assert enforcer.validate_target("localhost:3000") is True
    assert enforcer.host_in_scope("localhost") is True
    # scope-widening guard: a different host is still rejected
    with pytest.raises(OutOfScopeError):
        enforcer.validate_target("http://evil.com/")
    assert enforcer.host_in_scope("evil.com") is False


def test_scope_enforcer_excludes_cidr_carveout():
    """An IP/CIDR exclusion carved out of an in-scope range must fail CLOSED.
    Exclusions were string-only, so an excluded sub-range ('192.168.1.0/28'
    inside in-scope '192.168.1.0/24') matched nothing and its hosts stayed IN
    scope — a fail-OPEN hole. (AIOSOP-SCOPE-EXCLUDE)"""
    enforcer = ScopeEnforcer(
        ScopeDefinition(
            engagement_id="e",
            domains=[],
            ips=["192.168.1.0/24"],
            exclusions=["192.168.1.0/28"],
        )
    )
    # In-scope range still resolves outside the carve-out.
    assert enforcer.host_in_scope("192.168.1.50") is True
    assert enforcer.validate_target("192.168.1.50") is True
    # Hosts inside the excluded /28 (.0-.15) are out of scope via BOTH APIs.
    assert enforcer.host_in_scope("192.168.1.5") is False
    with pytest.raises(OutOfScopeError):
        enforcer.validate_target("192.168.1.5")
    with pytest.raises(OutOfScopeError):
        enforcer.validate_target("http://192.168.1.5:8080/admin")


def test_scope_enforcer_excludes_ipv6_carveout():
    """IPv6 carve-outs must fail CLOSED too. The naive port-strip regex mangled
    bare IPv6 literals ('2001:db8::1' -> '2001:db8:'), so every IPv6 exclusion
    silently matched nothing. (AIOSOP-SCOPE-EXCLUDE ipv6)"""
    enforcer = ScopeEnforcer(
        ScopeDefinition(
            engagement_id="e",
            domains=[],
            ips=["2001:db8::/32"],
            exclusions=["2001:db8:0:1::/64"],
        )
    )
    # In-scope IPv6 outside the carve-out still resolves.
    assert enforcer.host_in_scope("2001:db8::5") is True
    # Inside the excluded /64 -> out of scope via both APIs.
    assert enforcer.host_in_scope("2001:db8:0:1::5") is False
    with pytest.raises(OutOfScopeError):
        enforcer.validate_target("2001:db8:0:1::5")


def test_scope_enforcer_invalid_targets(dummy_scope):
    enforcer = ScopeEnforcer(dummy_scope)

    # Excluded targets
    with pytest.raises(OutOfScopeError):
        enforcer.validate_target("admin.example.com")

    with pytest.raises(OutOfScopeError):
        enforcer.validate_target("192.168.1.100")

    # Out of scope domain
    with pytest.raises(OutOfScopeError):
        enforcer.validate_target("evil.com")

    # Out of scope IP
    with pytest.raises(OutOfScopeError):
        enforcer.validate_target("10.0.0.1")

    # Invalid input
    with pytest.raises(ScopeValidationError):
        enforcer.validate_target(None)
    with pytest.raises(ScopeValidationError):
        enforcer.validate_target("http://")


def test_scope_enforcer_time_window():
    now = datetime.utcnow()
    scope = ScopeDefinition(
        engagement_id="test-eng",
        domains=["example.com"],
        testing_window_start=now - timedelta(hours=1),
        testing_window_end=now + timedelta(hours=1),
    )
    enforcer = ScopeEnforcer(scope)
    assert enforcer.validate_time_window() is True

    past_scope = ScopeDefinition(
        engagement_id="test-eng",
        domains=["example.com"],
        testing_window_end=now - timedelta(hours=1),
    )
    with pytest.raises(OutOfScopeError):
        ScopeEnforcer(past_scope).validate_time_window()

    future_scope = ScopeDefinition(
        engagement_id="test-eng",
        domains=["example.com"],
        testing_window_start=now + timedelta(hours=1),
    )
    with pytest.raises(OutOfScopeError):
        ScopeEnforcer(future_scope).validate_time_window()


def test_scope_get_network_policy(dummy_scope):
    enforcer = ScopeEnforcer(dummy_scope)
    policy = enforcer.get_network_policy()
    assert "example.com" in policy["egress"]["allowed_domains"]
    assert "192.168.1.0/24" in policy["egress"]["allowed_ips"]
    assert policy["ingress"]["allowed"] is False


@pytest.mark.asyncio
async def test_approval_gate(dummy_scope):
    mock_memory = AsyncMock()
    gate = ApprovalGate(mock_memory)

    assert await gate.requires_approval("rce", dummy_scope) is True
    assert await gate.requires_approval("sqli", dummy_scope) is True
    assert await gate.requires_approval("xss", dummy_scope) is False
    assert await gate.requires_approval("lateral_movement", dummy_scope) is True

    req = await gate.create_request("t1", "a1", "rce", "tgt", "payload", [], "eng1")
    assert req.action_type == "rce"
    assert "CRITICAL" in req.risk_assessment
    mock_memory.store_hot.assert_called_once()


@pytest.mark.asyncio
@patch("docker.from_env")
async def test_sandbox_manager(mock_docker_from_env):
    mock_client = MagicMock()
    mock_docker_from_env.return_value = mock_client

    mock_container = MagicMock()
    mock_container.id = "c123"
    mock_client.containers.run.return_value = mock_container
    mock_client.containers.get.return_value = mock_container

    manager = SandboxManager()

    # Test Create
    sandbox = await manager.create_sandbox("sb1", {"egress": {}})
    assert sandbox["id"] == "sb1"
    assert sandbox["container_id"] == "c123"
    assert "sb1" in manager._active_sandboxes
    mock_client.containers.run.assert_called_once()

    # Test Execute
    mock_result = MagicMock()
    mock_result.exit_code = 0
    mock_result.output = [b"success", b""]
    mock_container.exec_run.return_value = mock_result

    res = await manager.execute_in_sandbox("sb1", ["ls"])
    assert res["status"] == "success"
    assert res["stdout"] == "success"

    # Test Execute not found
    with pytest.raises(SandboxException):
        await manager.execute_in_sandbox("invalid", ["ls"])

    # Test Destroy
    await manager.destroy_sandbox("sb1")
    assert "sb1" not in manager._active_sandboxes
    mock_container.stop.assert_called_once()
    mock_container.remove.assert_called_once()


def test_audit_integrity():
    key = b"supersecretkey"
    audit = AuditIntegrity(key)

    event1 = AuditEvent(
        event_id="e1",
        timestamp=datetime.utcnow(),
        actor_id="a1",
        actor_type="agent",
        event_type="test",
        severity="info",
        action={},
        result={},
        context={},
        engagement_id="eng1",
    )
    hash1 = audit.sign_event(event1)
    event1.integrity_hash = hash1

    event2 = AuditEvent(
        event_id="e2",
        timestamp=datetime.utcnow(),
        actor_id="a1",
        actor_type="agent",
        event_type="test",
        severity="info",
        action={},
        result={},
        context={},
        engagement_id="eng1",
    )
    hash2 = audit.sign_event(event2)
    event2.integrity_hash = hash2

    assert audit.verify_chain([event1, event2]) is True

    # Tamper
    event2.event_type = "tampered"
    assert audit.verify_chain([event1, event2]) is False
