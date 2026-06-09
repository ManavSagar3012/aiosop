"""Sandbox network isolation policy generation.

The runtime enforcement path is Kubernetes NetworkPolicy for L3/L4 egress plus
Cilium Tetragon for syscall-level observability and process termination on
dangerous socket behavior.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


@dataclass(frozen=True)
class NetworkIsolationPolicy:
    """Inputs used to render sandbox network enforcement manifests."""

    name: str = "ai-osop-sandbox-network-guard"
    namespace: str = "ai-osop"
    pod_selector: Dict[str, str] = field(
        default_factory=lambda: {"app": "ai-osop", "component": "sandbox"}
    )
    allowed_cidrs: Sequence[str] = field(default_factory=tuple)
    allowed_ports: Sequence[int] = field(default_factory=lambda: (53, 80, 443))
    allow_dns: bool = True

    def __post_init__(self) -> None:
        _validate_dns_name(self.name, "name")
        _validate_dns_name(self.namespace, "namespace")
        for key, value in self.pod_selector.items():
            _validate_dns_name(key, "pod selector key")
            _validate_dns_name(value, "pod selector value")
        for cidr in self.allowed_cidrs:
            ipaddress.ip_network(cidr, strict=False)
        for port in self.allowed_ports:
            if port < 1 or port > 65535:
                raise ValueError(f"invalid port: {port}")


class SandboxNetworkPolicyBuilder:
    """Render NetworkPolicy and Tetragon manifests for sandbox egress control."""

    def __init__(self, policy: NetworkIsolationPolicy):
        self.policy = policy

    def build_network_policy(self) -> Dict[str, Any]:
        """Build a Kubernetes NetworkPolicy that defaults sandbox egress to deny."""
        egress_rules: List[Dict[str, Any]] = []

        if self.policy.allowed_cidrs:
            egress_rules.append(
                {
                    "to": [{"ipBlock": {"cidr": cidr}} for cidr in self.policy.allowed_cidrs],
                    "ports": [
                        {"protocol": "TCP", "port": port}
                        for port in sorted(set(self.policy.allowed_ports))
                    ],
                }
            )

        if self.policy.allow_dns:
            egress_rules.append(
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                            }
                        }
                    ],
                    "ports": [
                        {"protocol": "UDP", "port": 53},
                        {"protocol": "TCP", "port": 53},
                    ],
                }
            )

        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": self.policy.name, "namespace": self.policy.namespace},
            "spec": {
                "podSelector": {"matchLabels": dict(self.policy.pod_selector)},
                "policyTypes": ["Egress"],
                "egress": egress_rules,
            },
        }

    def build_tetragon_policy(self) -> Dict[str, Any]:
        """Build a Tetragon policy for high-risk socket syscalls in sandbox pods."""
        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicyNamespaced",
            "metadata": {
                "name": f"{self.policy.name}-syscalls",
                "namespace": self.policy.namespace,
            },
            "spec": {
                "podSelector": {"matchLabels": dict(self.policy.pod_selector)},
                "kprobes": [
                    {
                        "call": "security_socket_create",
                        "syscall": False,
                        "args": [
                            {"index": 0, "type": "int", "label": "family"},
                            {"index": 1, "type": "int", "label": "type"},
                            {"index": 2, "type": "int", "label": "protocol"},
                        ],
                        "selectors": [
                            {
                                "matchArgs": [{"index": 1, "operator": "Equal", "values": ["3"]}],
                                "matchActions": [{"action": "Sigkill"}],
                            }
                        ],
                    },
                    {
                        "call": "security_socket_connect",
                        "syscall": False,
                        "args": [
                            {"index": 0, "type": "sock", "label": "socket"},
                            {"index": 1, "type": "sockaddr", "label": "destination"},
                        ],
                        "selectors": [{"matchActions": [{"action": "Post"}]}],
                    },
                ],
            },
        }

    def build_manifest_bundle(self) -> List[Dict[str, Any]]:
        """Return all manifests needed for sandbox network enforcement."""
        return [self.build_network_policy(), self.build_tetragon_policy()]

    def render_manifest_json(self) -> str:
        """Render manifests as JSON documents for deterministic tests and tooling."""
        return "\n---\n".join(
            json.dumps(manifest, indent=2, sort_keys=True)
            for manifest in self.build_manifest_bundle()
        )


def _validate_dns_name(value: str, field_name: str) -> None:
    if not value or len(value) > 63 or not _DNS_LABEL.match(value):
        raise ValueError(f"invalid Kubernetes DNS label for {field_name}: {value!r}")
