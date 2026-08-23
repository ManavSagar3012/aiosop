"""
Safety & Security Architecture
Scope enforcement, sandbox management, approval gates, and audit integrity.
"""

import hashlib
import hmac
import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import structlog

from ai_osop.core.config import settings
from ai_osop.core.exceptions import (
    ApprovalDeniedError,
    OutOfScopeError,
    SandboxException,
    ScopeValidationError,
)
from ai_osop.core.models import ApprovalRequest, AuditEvent, ScopeDefinition

logger = structlog.get_logger()


class ScopeEnforcer:
    """
    Defense-in-depth scope enforcement.

    Layers:
    1. Application-level validation (this class)
    2. Network-level filtering (eBPF/iptables)
    3. DNS resolution validation
    """

    def __init__(self, scope: ScopeDefinition):
        self.scope = scope
        self._allowed_domains: Set[str] = set(d.lower() for d in scope.domains)
        self._allowed_ips: List[ipaddress.ip_network] = [
            ipaddress.ip_network(ip) for ip in scope.ips
        ]
        self._blocked_targets: Set[str] = set(e.lower() for e in scope.exclusions)
        self._testing_window = (scope.testing_window_start, scope.testing_window_end)

    def validate_target(self, target: str) -> bool:
        """
        Validate target is within scope.

        Raises:
            OutOfScopeError: If target is explicitly out of scope
            ScopeValidationError: If target format is invalid
        """
        if not target or not isinstance(target, str):
            raise ScopeValidationError("Invalid target format")

        target = target.lower().strip()

        # Check exclusions first
        if target in self._blocked_targets:
            raise OutOfScopeError(f"Target {target} is explicitly excluded from scope")

        # Check exclusions first — exact match OR suffix match (e.g. *.evil.com blocks
        # sub.evil.com but not notevil.com). Never use plain substring.
        for exclusion in self._blocked_targets:
            if target == exclusion or target.endswith(f".{exclusion}"):
                raise OutOfScopeError(f"Target {target} matches excluded pattern: {exclusion}")

        # URL validation
        if target.startswith(("http://", "https://")):
            return self._validate_url(target)

        # Domain validation
        if self._is_domain(target):
            return self._validate_domain(target)

        # IP validation
        try:
            ip = ipaddress.ip_address(target)
            return self._validate_ip(ip)
        except ValueError:
            pass

        raise ScopeValidationError(f"Cannot determine target type for: {target}")

    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain/hostname.

        Accepts dotted FQDNs (example.com) *and* single-label hosts such as
        "localhost" or internal service names. Bare IPv4/IPv6 literals are NOT
        domains — the IP-validation path handles those. Previously single-label
        hosts fell through to a ScopeValidationError even when explicitly in
        scope, which broke localhost/internal-hostname engagements.
        """
        if not target:
            return False
        try:
            ipaddress.ip_address(target)
            return False  # bare IP literal -> handled by _validate_ip
        except ValueError:
            pass
        return not target.replace(".", "").replace(":", "").isdigit()

    def _validate_domain(self, domain: str) -> bool:
        """Validate domain against scope."""
        for allowed in self._allowed_domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True

        raise OutOfScopeError(f"Domain {domain} not in scope. Allowed: {self._allowed_domains}")

    def _validate_ip(self, ip: ipaddress.ip_address) -> bool:
        """Validate IP against scope."""
        for network in self._allowed_ips:
            if ip in network:
                return True

        raise OutOfScopeError(f"IP {ip} not in scope. Allowed networks: {self._allowed_ips}")

    def _validate_url(self, url: str) -> bool:
        """Extract host from URL and validate."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            raise ScopeValidationError(f"Cannot extract host from URL: {url}")

        return self.validate_target(host)

    def validate_time_window(self) -> bool:
        """Check if current time is within testing window."""
        now = datetime.utcnow()
        start, end = self._testing_window

        if start and now < start:
            raise OutOfScopeError(f"Testing window has not started. Starts at: {start}")

        if end and now > end:
            raise OutOfScopeError(f"Testing window has ended. Ended at: {end}")

        return True

    def get_network_policy(self) -> Dict[str, Any]:
        """Generate network policy for sandbox configuration."""
        return {
            "egress": {
                "allowed_domains": list(self._allowed_domains),
                "allowed_ips": [str(net) for net in self._allowed_ips],
                "blocked_targets": list(self._blocked_targets),
            },
            "ingress": {"allowed": False},  # No inbound connections
        }


class ApprovalGate:
    """
    Human-in-the-loop approval management.

    Manages:
    - Approval request lifecycle
    - Risk assessment assembly
    - Operator notification routing
    - Timeout handling
    """

    HIGH_IMPACT_ACTIONS = [
        "rce",
        "sqli",
        "lateral_movement",
        "data_exfiltration",
        "privilege_escalation",
        "persistence",
        "backdoor",
    ]

    def __init__(self, session_memory: Any):
        self.session_memory = session_memory

    async def requires_approval(self, action_type: str, scope: ScopeDefinition) -> bool:
        """Determine if action requires operator approval."""
        # Check ROE
        if action_type in scope.approval_required_for:
            return True

        # Check high-impact actions
        if any(impact in action_type.lower() for impact in self.HIGH_IMPACT_ACTIONS):
            return True

        return False

    async def create_request(
        self,
        task_id: str,
        agent_id: str,
        action_type: str,
        target: str,
        payload_summary: str,
        evidence: List[Dict[str, Any]],
        engagement_id: str,
    ) -> ApprovalRequest:
        """Create approval request with risk assessment."""
        # Assemble risk assessment
        risk_assessment = await self._assess_risk(action_type, target, payload_summary, evidence)

        request = ApprovalRequest(
            task_id=task_id,
            agent_id=agent_id,
            action_type=action_type,
            target=target,
            payload_summary=payload_summary,
            risk_assessment=risk_assessment,
            evidence=evidence,
            engagement_id=engagement_id,
        )

        # Store in hot memory
        await self.session_memory.store_hot(
            f"approval:{request.id}",
            request.model_dump(),
            ttl=settings.approval_timeout_seconds + 300,
        )

        return request

    async def _assess_risk(
        self, action_type: str, target: str, payload_summary: str, evidence: List[Dict[str, Any]]
    ) -> str:
        """Generate risk assessment narrative."""
        risk_level = "medium"

        if any(impact in action_type.lower() for impact in ["rce", "sqli"]):
            risk_level = "critical"
        elif "privilege" in action_type.lower():
            risk_level = "high"
        elif "lateral" in action_type.lower():
            risk_level = "high"

        assessment = f"""
        Risk Level: {risk_level.upper()}
        Action: {action_type}
        Target: {target}

        Potential Impact:
        - This action may modify data or system state on the target
        - Successful exploitation could lead to unauthorized access
        - Evidence suggests vulnerability is confirmed with high confidence

        Mitigation:
        - Execution is sandboxed and scope-restricted
        - All actions are logged with cryptographic integrity
        - Execution can be halted at any time

        Recommendation: {'PROCEED WITH CAUTION' if risk_level in ['critical', 'high'] else 'PROCEED'}
        """

        return assessment.strip()


class SandboxManager:
    """
    Container-based execution sandbox.

    Features:
    - Docker/containerd runtime
    - Network namespace isolation
    - CPU/memory limits
    - Read-only root filesystem
    - Seccomp profiles
    """

    def __init__(self):
        self._active_sandboxes: Dict[str, Dict[str, Any]] = {}

    async def create_sandbox(
        self,
        sandbox_id: str,
        network_policy: Dict[str, Any],
        resources: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Create isolated execution environment with Docker network + iptables."""
        import docker

        client = docker.from_env()

        # Build sandbox configuration
        resource_limits = resources or {
            "cpu": settings.sandbox_cpu_limit,
            "memory": settings.sandbox_memory_limit,
        }

        # Create custom bridge network first (so container can attach at creation)
        network_name = f"ai-osop-sandbox-{sandbox_id}"
        subnet_octet = abs(hash(sandbox_id)) % 254 + 1
        subnet = f"172.30.{subnet_octet}.0/24"
        try:
            network = client.networks.create(
                network_name,
                driver="bridge",
                internal=False,
                ipam=docker.types.IPAMConfig(
                    pool_configs=[
                        docker.types.IPAMPool(
                            subnet=subnet,
                            gateway=f"172.30.{subnet_octet}.1",
                        )
                    ]
                ),
                options={
                    "com.docker.network.bridge.name": f"br-{sandbox_id[:12]}",
                },
            )
        except Exception as e:
            raise SandboxException(f"Failed to create sandbox network: {e}")

        # Create container attached to the custom network
        try:
            container = client.containers.run(
                "ai-osop/sandbox:latest",
                detach=True,
                network=network_name,
                cpu_period=100000,
                cpu_quota=int(float(resource_limits["cpu"]) * 100000),
                mem_limit=resource_limits["memory"],
                read_only=True,
                security_opt=["no-new-privileges:true", "seccomp:restricted.json"],
                cap_drop=["ALL"],
                cap_add=["NET_BIND_SERVICE"],
                labels={
                    "ai-osop.sandbox.id": sandbox_id,
                    "ai-osop.sandbox.created": datetime.utcnow().isoformat(),
                },
            )
        except Exception as e:
            try:
                network.remove()
            except Exception as e:
                logger.warning("broad_exception_caught", error=str(e))
                pass
            raise SandboxException(f"Failed to create sandbox container: {e}")

        sandbox = {
            "id": sandbox_id,
            "container_id": container.id,
            "network_name": network_name,
            "network_id": network.id,
            "network_policy": network_policy,
            "resources": resource_limits,
            "created_at": datetime.utcnow(),
            "status": "ready",
        }

        self._active_sandboxes[sandbox_id] = sandbox

        # Setup network filtering if policy allows
        if network_policy.get("egress"):
            try:
                await self._setup_network(container, network_policy["egress"])
            except Exception as e:
                # Cleanup on network setup failure
                try:
                    del self._active_sandboxes[sandbox_id]
                except Exception as e:
                    logger.warning("broad_exception_caught", error=str(e))
                    pass
                try:
                    container.stop(timeout=5)
                    container.remove(force=True)
                except Exception as e:
                    logger.warning("broad_exception_caught", error=str(e))
                    pass
                try:
                    network.remove()
                except Exception as e:
                    logger.warning("broad_exception_caught", error=str(e))
                    pass
                raise SandboxException(f"Failed to setup sandbox network filtering: {e}")

        return sandbox

    async def _setup_network(self, container: Any, egress_policy: Dict[str, Any]) -> None:
        """Setup restricted network access using Docker bridge + iptables.

        Phase A implementation:
        1. Inspect container's network to get bridge interface
        2. Apply iptables rules via a custom chain for easy cleanup:
           - ACCEPT established/related connections
           - ACCEPT DNS (UDP/TCP 53)
           - ACCEPT loopback
           - ACCEPT explicitly allowed IPs/domains
           - DROP everything else
        """
        import socket
        import subprocess

        sandbox_id = container.labels.get("ai-osop.sandbox.id", container.short_id)

        # Get network info from container
        container.reload()
        network_settings = container.attrs.get("NetworkSettings", {})
        networks = network_settings.get("Networks", {})

        # Find the sandbox network
        sandbox_network = None
        for net_name, net_info in networks.items():
            if net_name.startswith("ai-osop-sandbox-"):
                sandbox_network = net_info
                break

        if not sandbox_network:
            raise SandboxException(f"Sandbox network not found for container {container.id}")

        # Get bridge interface name from network ID
        network_id = sandbox_network.get("NetworkID", "")
        bridge_name = f"br-{sandbox_id[:12]}"

        # 1. Resolve allowed domains to IPs
        allowed_ips: set = set()
        for ip_str in egress_policy.get("allowed_ips", []):
            try:
                allowed_ips.add(ipaddress.ip_network(ip_str, strict=False))
            except ValueError:
                pass

        for domain in egress_policy.get("allowed_domains", []):
            try:
                addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
                for _, _, _, _, sockaddr in addr_info:
                    ip = ipaddress.ip_address(sockaddr[0])
                    allowed_ips.add(ipaddress.ip_network(f"{ip}/32"))
            except (socket.gaierror, ValueError):
                pass

        # 2. Build iptables rules using a custom chain for easy cleanup
        chain_name = f"AIOSOP-{sandbox_id[:12]}"
        iptables_cmds = []

        # Create custom chain
        iptables_cmds.append(["iptables", "-N", chain_name])

        # Jump from FORWARD to custom chain (insert at top)
        iptables_cmds.append(
            ["iptables", "-I", "FORWARD", "1", "-i", bridge_name, "-j", chain_name]
        )

        # Allow established/related
        iptables_cmds.append(
            [
                "iptables",
                "-A",
                chain_name,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )

        # Allow DNS (UDP 53, TCP 53)
        iptables_cmds.append(
            ["iptables", "-A", chain_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT"]
        )
        iptables_cmds.append(
            ["iptables", "-A", chain_name, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"]
        )

        # Allow loopback (for containers on same network talking to each other)
        iptables_cmds.append(["iptables", "-A", chain_name, "-d", "127.0.0.1/8", "-j", "ACCEPT"])

        # Allow explicitly permitted IPs
        for ip_net in allowed_ips:
            iptables_cmds.append(["iptables", "-A", chain_name, "-d", str(ip_net), "-j", "ACCEPT"])

        # Drop everything else
        iptables_cmds.append(["iptables", "-A", chain_name, "-j", "DROP"])

        # Apply rules
        for cmd in iptables_cmds:
            result = subprocess.run(cmd, check=False, capture_output=True)
            if result.returncode != 0:
                logger.warning("iptables_rule_failed", cmd=cmd, stderr=result.stderr.decode()[:200])

        # 3. Store network info for cleanup
        self._active_sandboxes[sandbox_id]["network"] = {
            "bridge": bridge_name,
            "chain": chain_name,
        }

    async def execute_in_sandbox(
        self, sandbox_id: str, command: List[str], timeout: int = 300
    ) -> Dict[str, Any]:
        """Execute command in sandbox with monitoring."""
        sandbox = self._active_sandboxes.get(sandbox_id)
        if not sandbox:
            raise SandboxException(f"Sandbox {sandbox_id} not found")

        import docker

        client = docker.from_env()
        container = client.containers.get(sandbox["container_id"])

        start_time = datetime.utcnow()

        try:
            result = container.exec_run(command, demux=True, timeout=timeout)

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            return {
                "status": "success" if result.exit_code == 0 else "error",
                "exit_code": result.exit_code,
                "stdout": result.output[0].decode() if result.output[0] else "",
                "stderr": result.output[1].decode() if result.output[1] else "",
                "execution_time": execution_time,
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "execution_time": (datetime.utcnow() - start_time).total_seconds(),
            }

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """Destroy sandbox and clean up network + iptables resources."""
        sandbox = self._active_sandboxes.pop(sandbox_id, None)
        if not sandbox:
            return

        import subprocess

        import docker

        client = docker.from_env()

        # 1. Remove iptables rules first (while container still exists)
        net_info = sandbox.get("network", {})
        chain_name = net_info.get("chain")
        bridge_name = net_info.get("bridge")

        if chain_name and bridge_name:
            # Remove jump rule from FORWARD chain
            subprocess.run(
                ["iptables", "-D", "FORWARD", "-i", bridge_name, "-j", chain_name],
                check=False,
                capture_output=True,
            )
            # Flush and delete custom chain
            subprocess.run(
                ["iptables", "-F", chain_name],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                ["iptables", "-X", chain_name],
                check=False,
                capture_output=True,
            )

        # 2. Remove container
        try:
            container = client.containers.get(sandbox["container_id"])
            container.stop(timeout=10)
            container.remove(force=True)
        except Exception as e:
            logger.warning("broad_exception_caught", error=str(e))
            pass

        # 3. Remove Docker network
        network_id = sandbox.get("network_id")
        if network_id:
            try:
                network = client.networks.get(network_id)
                network.remove()
            except Exception as e:
                logger.warning("broad_exception_caught", error=str(e))
                pass


class AuditIntegrity:
    """
    Cryptographic audit log integrity.

    Features:
    - SHA-256 hashing per entry
    - Chain hashing (previous entry hash included)
    - HMAC signing with HSM-backed key
    - Tamper detection
    """

    def __init__(self, signing_key: bytes, old_keys: Optional[List[bytes]] = None):
        self.signing_key = signing_key
        self.old_keys = old_keys or []
        self._last_hash: Optional[str] = None

    def sign_event(self, event: AuditEvent) -> str:
        """Generate integrity hash for audit event."""
        # Build canonical representation
        data = f"{event.event_id}:{event.timestamp.isoformat()}:{event.actor_id}:{event.event_type}"

        # Include chain hash if available
        if self._last_hash:
            data = f"{self._last_hash}:{data}"

        # Generate HMAC
        signature = hmac.new(self.signing_key, data.encode(), hashlib.sha256).hexdigest()

        self._last_hash = signature
        return signature

    def verify_chain(self, events: List[AuditEvent]) -> bool:
        """Verify integrity of event chain."""
        last_hash = None

        for event in events:
            expected_data = f"{event.event_id}:{event.timestamp.isoformat()}:{event.actor_id}:{event.event_type}"
            if last_hash:
                expected_data = f"{last_hash}:{expected_data}"

            keys_to_try = [self.signing_key] + self.old_keys
            match_found = False
            for key in keys_to_try:
                expected_hash = hmac.new(key, expected_data.encode(), hashlib.sha256).hexdigest()
                if expected_hash == event.integrity_hash:
                    match_found = True
                    break

            if not match_found:
                return False

            last_hash = event.integrity_hash

        return True
