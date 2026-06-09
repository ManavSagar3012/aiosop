import pytest

from ai_osop.safety.ebpf_filter import NetworkIsolationPolicy, SandboxNetworkPolicyBuilder


def test_network_policy_builder_allows_only_configured_egress() -> None:
    policy = NetworkIsolationPolicy(allowed_cidrs=("203.0.113.0/24",), allowed_ports=(443,))
    builder = SandboxNetworkPolicyBuilder(policy)

    manifest = builder.build_network_policy()

    assert manifest["kind"] == "NetworkPolicy"
    assert manifest["spec"]["policyTypes"] == ["Egress"]
    assert manifest["spec"]["egress"][0]["to"][0]["ipBlock"]["cidr"] == "203.0.113.0/24"
    assert manifest["spec"]["egress"][0]["ports"] == [{"protocol": "TCP", "port": 443}]


def test_tetragon_policy_kills_raw_socket_creation() -> None:
    policy = NetworkIsolationPolicy()
    builder = SandboxNetworkPolicyBuilder(policy)

    manifest = builder.build_tetragon_policy()

    assert manifest["kind"] == "TracingPolicyNamespaced"
    raw_socket_selector = manifest["spec"]["kprobes"][0]["selectors"][0]
    assert raw_socket_selector["matchActions"] == [{"action": "Sigkill"}]


def test_network_policy_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError):
        NetworkIsolationPolicy(allowed_cidrs=("not-a-cidr",))

    with pytest.raises(ValueError):
        NetworkIsolationPolicy(allowed_ports=(70000,))
