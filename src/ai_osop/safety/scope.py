"""
Safety & Security Architecture
Scope enforcement, sandbox management, approval gates, and audit integrity.
"""

import hashlib
import hmac
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from ai_osop.core.config import settings
from ai_osop.core.exceptions import (
    ApprovalDeniedError,
    OutOfScopeError,
    SandboxException,
    ScopeValidationError,
)
from ai_osop.core.models import ApprovalRequest, AuditEvent, ScopeDefinition
import structlog

logger = structlog.get_logger()


def action_requires_approval(action_type: str, scope: ScopeDefinition) -> bool:
    """Central ROE and consequential-action approval policy (pure and testable)."""
    action = str(action_type).strip().lower()
    configured = {entry.strip().lower() for entry in scope.approval_required_for}
    high_impact = {
        "rce",
        "sqli",
        "lateral_movement",
        "data_exfiltration",
        "privilege_escalation",
        "persistence",
        "backdoor",
        "exploit",
        "post_exploit",
        "credential_access",
        "modify_target",
    }
    return action in configured or any(marker in action for marker in high_impact)


def validate_payload_targets(
    enforcer: "ScopeEnforcer",
    payload: Dict[str, Any],
    *,
    require_target: bool = False,
) -> bool:
    """Validate *every* declared destination, never just a preferred alias.

    Reject malformed destination values and lists; a scoped URL must not mask
    another out-of-scope URL in the same task payload.
    """
    seen = 0
    for key in ("target", "url", "target_url", "domain", "host", "hostname", "ip"):
        if key not in payload:
            continue
        value = payload[key]
        if not isinstance(value, str) or not value.strip():
            raise ScopeValidationError(f"Invalid {key} target")
        enforcer.validate_target(value)
        seen += 1
    if "targets" in payload:
        targets = payload["targets"]
        if not isinstance(targets, list) or len(targets) > 50:
            raise ScopeValidationError("Invalid targets list")
        for target in targets:
            if not isinstance(target, str) or not target.strip():
                raise ScopeValidationError("Invalid targets item")
            enforcer.validate_target(target)
            seen += 1
    if require_target and seen == 0:
        raise ScopeValidationError("Task requires an explicitly scoped target")
    return True


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

        # Check if any exclusion is a substring
        for exclusion in self._blocked_targets:
            if exclusion in target:
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
        """Check if target is a domain name."""
        return "." in target and not target.replace(".", "").isdigit()

    def _validate_domain(self, domain: str) -> bool:
        """Validate domain against scope."""
        for allowed in self._allowed_domains:
            if domain == allowed or domain.endswith(f".{allowed}"):
                return True

        raise OutOfScopeError(f"Domain {domain} not in scope. Allowed: {self._allowed_domains}")

    CLOUD_METADATA_NETWORKS = [
        ipaddress.ip_network("169.254.169.254/32"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]
    RFC1918_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

    def _validate_ip(self, ip: ipaddress.ip_address) -> bool:
        """Validate IP against scope with defense-in-depth metadata and RFC1918 blocking."""
        # 1. Cloud metadata IP is strictly forbidden under all circumstances
        for meta_net in self.CLOUD_METADATA_NETWORKS:
            if ip in meta_net:
                raise OutOfScopeError(
                    f"Cloud metadata IP {ip} is strictly forbidden by safety policy"
                )

        # 2. Check if explicitly in allowed IPs
        for network in self._allowed_ips:
            if ip in network:
                return True

        # 3. Check if private RFC1918 is requested without explicit permission
        for priv_net in self.RFC1918_NETWORKS:
            if ip in priv_net:
                raise OutOfScopeError(
                    f"Private RFC1918 IP {ip} blocked (not explicitly listed in scope)"
                )

        raise OutOfScopeError(f"IP {ip} not in scope. Allowed networks: {self._allowed_ips}")

    def resolve_and_validate_hostname(self, hostname: str) -> str:
        """Resolve hostname and validate both domain and resolved IP to defeat DNS rebinding."""
        import socket

        self.validate_target(hostname)
        try:
            resolved_ip_str = socket.gethostbyname(hostname)
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
            self._validate_ip(resolved_ip)
            return resolved_ip_str
        except (socket.gaierror, socket.herror):
            return ""

    def _validate_url(self, url: str) -> bool:
        """Extract host from URL and validate."""
        from urllib.parse import urlparse

        # Reject shell command injection characters and dangerous path traversal
        dangerous_chars = {";", "|", "&", "$", "`", "\n", "\r", "\0"}
        if any(c in url for c in dangerous_chars):
            raise ScopeValidationError(
                f"Command injection characters detected in target URL: {url}"
            )
        if "/../" in url or url.endswith("/..") or "\\..\\" in url:
            raise ScopeValidationError(f"Path traversal detected in target URL: {url}")

        parsed = urlparse(url)
        host = parsed.hostname

        if not host:
            raise ScopeValidationError(f"Cannot extract host from URL: {url}")

        return self.validate_target(host)

    def validate_time_window(self) -> bool:
        """Check if current time is within testing window."""
        now = datetime.utcnow()
        start, end = self._testing_window
        # The API and PostgreSQL can supply offset-aware timestamps whereas
        # legacy engagement records use naive UTC. Compare both as UTC.
        if start is not None and start.tzinfo is not None:
            start = start.astimezone(timezone.utc).replace(tzinfo=None)
        if end is not None and end.tzinfo is not None:
            end = end.astimezone(timezone.utc).replace(tzinfo=None)

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
        return action_requires_approval(action_type, scope)

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
        - Vulnerability and target effects remain unverified until independently corroborated

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

    @staticmethod
    def _command_sha256(command: List[str]) -> str:
        """Exact, bounded argv digest; never rely on a model-supplied approval flag."""
        import json

        if (
            not isinstance(command, list)
            or not 1 <= len(command) <= 32
            or any(
                type(arg) is not str or not arg or len(arg) > 4096 or "\x00" in arg
                for arg in command
            )
        ):
            raise SandboxException("Invalid bounded sandbox command")
        encoded = json.dumps(command, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > 16384:
            raise SandboxException("Sandbox command exceeds approved bounds")
        return hashlib.sha256(b"AI-OSOP-APPROVED-SANDBOX-ARGV-V1\x00" + encoded).hexdigest()

    async def create_sandbox(
        self,
        sandbox_id: str,
        network_policy: Dict[str, Any],
        resources: Optional[Dict[str, str]] = None,
        *,
        signed_resource: Any = None,
        resource_reader: Any = None,
    ) -> Dict[str, Any]:
        """Launch worker only after its network firewall is ready.

        Never attach a live worker to an outward-routed bridge before
        enforcement. Previous post-start iptables failures were logged and
        ignored, leaving an unrestricted egress window.
        """
        import docker
        import math
        import re

        if (
            not isinstance(sandbox_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}", sandbox_id) is None
        ):
            raise SandboxException("Invalid sandbox identifier")
        if sandbox_id in self._active_sandboxes:
            raise SandboxException("Sandbox identifier already active")
        if (signed_resource is None) != (resource_reader is None):
            raise SandboxException("Signed resource and verifier must be supplied together")
        if signed_resource is not None:
            from ai_osop.memory.flow_resource_materialization import (
                SignedFlowTaskResources,
                TaskResourceBinding,
            )
            from ai_osop.memory.authoritative_task_resources import (
                PostgresApprovedTaskResourceVerifier,
            )

            if (
                type(signed_resource) is not TaskResourceBinding
                or type(resource_reader) is not SignedFlowTaskResources
                or type(resource_reader.verify_approved_task)
                is not PostgresApprovedTaskResourceVerifier
            ):
                raise SandboxException("Unverified sandbox resource admission")
            try:
                await resource_reader.read(signed_resource)
            except Exception as exc:
                raise SandboxException("Signed sandbox resource source unavailable") from exc
        if settings.sandbox_runtime != "docker" or settings.sandbox_network_mode != "isolated":
            raise SandboxException("Only isolated Docker worker mode is supported")
        if not isinstance(network_policy, dict) or set(network_policy) - {"egress", "ingress"}:
            raise SandboxException("Invalid sandbox network policy")
        ingress, egress = network_policy.get("ingress", {}), network_policy.get("egress", {})
        if (
            not isinstance(ingress, dict)
            or ingress.get("allowed") is True
            or not isinstance(egress, dict)
        ):
            raise SandboxException("Worker ingress must remain disabled")
        resource_limits = (
            resources
            if resources is not None
            else {
                "cpu": settings.sandbox_cpu_limit,
                "memory": settings.sandbox_memory_limit,
            }
        )
        if not isinstance(resource_limits, dict) or set(resource_limits) != {"cpu", "memory"}:
            raise SandboxException("Worker resource limits must only contain cpu and memory")
        try:
            cpu = float(resource_limits["cpu"])
        except (ValueError, TypeError, OverflowError) as exc:
            raise SandboxException("Invalid worker CPU limit") from exc
        if not math.isfinite(cpu) or not 0.1 <= cpu <= 8:
            raise SandboxException("Worker CPU limit outside safe bounds")
        memory = resource_limits["memory"]
        if (
            not isinstance(memory, str)
            or re.fullmatch(r"[1-9][0-9]{0,5}[mMgG](?:[iI])?", memory) is None
        ):
            raise SandboxException("Invalid worker memory limit")
        memory_size = int(memory[:-2] if memory[-2:].lower() in {"mi", "gi"} else memory[:-1])
        memory_unit = memory[-2:] if memory[-2:].lower() in {"mi", "gi"} else memory[-1:]
        memory_bytes = memory_size * 1024 ** (3 if memory_unit.lower().startswith("g") else 2)
        if not 64 * 1024**2 <= memory_bytes <= 8 * 1024**3:
            raise SandboxException("Worker memory limit outside safe bounds")
        # Missing or explicitly empty targets get a Docker-internal network.
        # Named/IP destinations require successful enforcement *before* start.
        allow_external = bool(
            egress.get("allowed_ips")
            or egress.get("allowed_cidrs")
            or egress.get("allowed_domains")
        )
        # Reject a malformed or unbounded scope BEFORE even asking the Docker
        # daemon to create a bridge. _setup_network repeats the check against
        # resolved destinations just before installing the firewall.
        import re as _re

        for key, maximum in (("allowed_ips", 32), ("allowed_cidrs", 32), ("allowed_domains", 16)):
            entries = egress.get(key, [])
            if not isinstance(entries, list) or len(entries) > maximum:
                raise SandboxException("Invalid sandbox egress scope")
            for entry in entries:
                if not isinstance(entry, str):
                    raise SandboxException("Invalid sandbox egress destination")
                if key == "allowed_domains":
                    if _re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", entry) is None:
                        raise SandboxException("Invalid sandbox egress domain")
                else:
                    try:
                        address = ipaddress.ip_network(entry, strict=False)
                    except ValueError as exc:
                        raise SandboxException("Invalid sandbox egress CIDR") from exc
                    if address.version != 4 or address.prefixlen == 0:
                        raise SandboxException("Unbounded or non-IPv4 sandbox egress")
        if allow_external:
            # Host iptables only protects the worker when the daemon's bridge
            # is on this SAME host. Remote TCP/SSH daemons must never be
            # treated as protected by unrelated local iptables rules.
            import os

            daemon = os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock")
            if not daemon.startswith("unix:///"):
                raise SandboxException(
                    "Scoped egress requires a local Docker daemon and host firewall"
                )
        client = docker.from_env()

        # Create custom bridge network first (so container can attach at creation)
        network_name = f"ai-osop-sandbox-{sandbox_id}"
        subnet_octet = abs(hash(sandbox_id)) % 254 + 1
        subnet = f"172.30.{subnet_octet}.0/24"
        bridge_name = "br-" + hashlib.sha256(sandbox_id.encode()).hexdigest()[:12]
        chain_name = "AIOSOP-" + hashlib.sha256(sandbox_id.encode()).hexdigest()[:12]
        try:
            network = client.networks.create(
                network_name,
                driver="bridge",
                internal=not allow_external,
                attachable=False,
                enable_ipv6=False,
                ipam=docker.types.IPAMConfig(
                    pool_configs=[
                        docker.types.IPAMPool(
                            subnet=subnet,
                            gateway=f"172.30.{subnet_octet}.1",
                        )
                    ]
                ),
                options={
                    "com.docker.network.bridge.name": bridge_name,
                },
            )
        except Exception as e:
            raise SandboxException(f"Failed to create sandbox network: {e}")

        # Install the allowlist before connecting any running process to an
        # outward-routed bridge. A failed host firewall aborts container start.
        network_info = None
        if allow_external:
            try:
                network_info = await self._setup_network(
                    sandbox_id, bridge_name, chain_name, egress
                )
            except Exception as exc:
                try:
                    network.remove()
                except Exception:
                    pass
                raise SandboxException("Worker egress policy could not be installed") from exc

        # Create container attached to the already restricted network
        try:
            container = client.containers.run(
                "ai-osop/sandbox:latest",
                detach=True,
                network=network_name,
                cpu_period=100000,
                cpu_quota=int(float(resource_limits["cpu"]) * 100000),
                # The configured default '4Gi' is NOT accepted by docker-py
                # 7.1 parse_bytes. Pass bounded integer byte values instead.
                mem_limit=memory_bytes,
                memswap_limit=memory_bytes,
                read_only=True,
                # Docker built-in default seccomp; no relative unresolved
                # restricted.json profile or seccomp=unconfined escape.
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
                cap_add=[],
                privileged=False,
                user="65534:65534",
                pid_mode="private",
                ipc_mode="private",
                pids_limit=128,
                init=True,
                publish_all_ports=False,
                volumes={},
                mounts=[],
                devices=[],
                device_requests=[],
                tmpfs={
                    "/tmp": "rw,noexec,nosuid,nodev,size=64m",
                    # Root-only delivery staging. A fixed daemon-side writer
                    # makes the directory 0555 and file 0444 *before* the
                    # unprivileged worker may consume original signed bytes.
                    "/run/ai-osop/resources": "rw,noexec,nosuid,nodev,size=8m,mode=0700",
                },
                labels={
                    "ai-osop.sandbox.id": sandbox_id,
                    "ai-osop.sandbox.created": datetime.utcnow().isoformat(),
                },
            )
        except Exception as e:
            if network_info:
                self._remove_network_rules(network_info)
            try:
                network.remove()
            except Exception:
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
            "network_egress": "scoped" if allow_external else "disabled",
            "host_mounts": False,
            "docker_socket_inside": False,
        }
        if network_info:
            sandbox["network"] = network_info

        self._active_sandboxes[sandbox_id] = sandbox

        if signed_resource is not None:
            try:
                await self.provision_approved_flow_resource(
                    sandbox_id,
                    signed_resource,
                    resource_reader,
                )
            except Exception as exc:
                await self.destroy_sandbox(sandbox_id)
                raise SandboxException("Signed resource materialization failed") from exc

        return sandbox

    async def provision_approved_flow_resource(
        self,
        sandbox_id: str,
        binding: Any,
        reader: Any,
    ) -> Dict[str, Any]:
        """Deliver an approved, inert original Flow artifact to Docker tmpfs.

        A typed signed Task reader, not a model/tool payload, supplies bytes.
        No untrusted archive extraction, host path, bind mount or agent prompt.
        This does not independently authorize arbitrary container commands.
        """
        from ai_osop.memory.flow_resource_materialization import (
            SignedFlowTaskResources,
            TaskResourceBinding,
        )
        from ai_osop.memory.authoritative_task_resources import (
            PostgresApprovedTaskResourceVerifier,
        )
        from ai_osop.memory.flow_artifacts import safe_filename

        sandbox = self._active_sandboxes.get(sandbox_id)
        if (
            not isinstance(sandbox, dict)
            or sandbox.get("status") != "ready"
            or sandbox.get("signed_resource") is not None
            or type(binding) is not TaskResourceBinding
            or type(reader) is not SignedFlowTaskResources
            or type(reader.verify_approved_task) is not PostgresApprovedTaskResourceVerifier
        ):
            raise SandboxException("Active unprovisioned sandbox and signed Task required")
        try:
            metadata, original = await reader.read(binding)
            name = metadata["name"]
            if (
                safe_filename(name) != name
                or metadata.get("classification") != "untrusted_original_flow_artifact"
                or metadata.get("approved_for_agent_instructions") is not False
                or not isinstance(original, bytes)
                or not 0 < len(original) <= 2 * 1024 * 1024
            ):
                raise ValueError("Resource admission mismatch")
            import docker
            import asyncio
            import time

            client = docker.from_env()
            container = client.containers.get(sandbox["container_id"])
            # Docker's PUT /archive is incompatible with a read-only rootfs,
            # even when the destination is writable tmpfs. A disposable root
            # exec with a FIXED program reads the bounded resource over the
            # Docker Engine exec stdin socket: no bytes in argv, logs, image,
            # bind mounts, host paths or network. uid 65534 runs unprivileged
            # and cannot rewrite the root-owned immutable tmpfs after handoff.
            # The root writer is a trusted server-only provisioner, not a
            # remotely callable sandbox execute or general shell interface.
            writer = (
                "import os,sys,hashlib\n"
                "root='/run/ai-osop/resources'\n"
                "name,size,digest=sys.argv[1:]\n"
                "data=sys.stdin.buffer.read(int(size))\n"
                "assert len(data)==int(size) and hashlib.sha256(data).hexdigest()==digest\n"
                "path=root+'/'+name\n"
                "fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)\n"
                "try:\n"
                " view=memoryview(data)\n"
                " while view:\n"
                "  n=os.write(fd,view)\n"
                "  assert n>0\n"
                "  view=view[n:]\n"
                " os.fchmod(fd,0o444)\n"
                "finally: os.close(fd)\n"
                "os.chmod(root,0o555)\n"
            )
            exec_id = client.api.exec_create(
                sandbox["container_id"],
                ["python3", "-c", writer, name, str(len(original)), metadata["sha256"]],
                stdin=True,
                tty=False,
                user="0:0",
                privileged=False,
                stdout=False,
                stderr=False,
            )["Id"]
            stream_socket = client.api.exec_start(exec_id, socket=True, tty=False)
            try:
                stream_socket.sendall(original)
                deadline = time.monotonic() + 10.0
                while True:
                    observed = client.api.exec_inspect(exec_id)
                    # Docker can initially expose Running=False/ExitCode=0
                    # before the exec process starts. Its actual Docker API
                    # omits FinishedAt, so require a positive assigned Pid
                    # and a known exit code as well as Running=False.
                    is_finished = (
                        type(observed.get("Pid")) is int
                        and observed["Pid"] > 0
                        and type(observed.get("ExitCode")) is int
                    )
                    if observed.get("Running") is False and is_finished:
                        if observed.get("ExitCode") != 0:
                            raise ValueError("Signed resource transfer command failed")
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Signed resource transfer not acknowledged")
                    await asyncio.sleep(0.05)
            finally:
                stream_socket.close()

            # Docker GET /archive also returns 404 for a real tmpfs file when
            # the container rootfs is read-only (even though `cat` succeeds).
            # Read-back through a fixed *unprivileged* inspector instead;
            # return only digest/length/mode, never raw sensitive file bytes.
            inspector = (
                "import os,sys,hashlib,stat\n"
                "root='/run/ai-osop/resources'\n"
                "name=sys.argv[1]\n"
                "d=os.lstat(root); f=os.lstat(root+'/'+name)\n"
                "assert stat.S_ISDIR(d.st_mode) and d.st_uid==0 and d.st_gid==0\n"
                "assert stat.S_IMODE(d.st_mode)==0o555\n"
                "assert stat.S_ISREG(f.st_mode) and f.st_uid==0 and f.st_gid==0 and f.st_nlink==1\n"
                "assert stat.S_IMODE(f.st_mode)==0o444 and f.st_size<=2097152\n"
                "sha=hashlib.sha256(); total=0\n"
                "with open(root+'/'+name,'rb') as inp:\n"
                " while True:\n"
                "  chunk=inp.read(65536)\n"
                "  if not chunk: break\n"
                "  total+=len(chunk)\n"
                "  assert total<=2097152\n"
                "  sha.update(chunk)\n"
                "print(sha.hexdigest()+':'+str(total),flush=True)\n"
            )
            observed_file = container.exec_run(
                ["python3", "-c", inspector, name],
                user="65534:65534",
                privileged=False,
                demux=True,
                stdin=False,
                tty=False,
            )
            observed_output = observed_file.output
            if (
                observed_file.exit_code != 0
                or not isinstance(observed_output, tuple)
                or len(observed_output) != 2
                or type(observed_output[0]) is not bytes
                or observed_output[1] not in (None, b"")
                or not hmac.compare_digest(
                    observed_output[0].strip(),
                    (metadata["sha256"] + ":" + str(len(original))).encode("ascii"),
                )
            ):
                raise ValueError("Sandbox unprivileged resource digest/readback changed")
            # Reverify CURRENT signed Task/approval/ROE after Docker I/O to
            # catch revocation that occurred while transferring the bytes.
            fresh_meta, fresh_bytes = await reader.read(binding)
            if fresh_meta != metadata or not hmac.compare_digest(fresh_bytes, original):
                raise ValueError("Signed resource changed during delivery")
            sandbox["signed_resource"] = (binding, reader, metadata["sha256"])
            return {
                "status": "materialized_untrusted_read_only",
                "task_id": binding.task_id,
                "artifact_id": binding.artifact_id,
                "sha256": metadata["sha256"],
                "approved_for_agent_instructions": False,
            }
        except Exception as exc:
            # Never retain a live sandbox with a partially provisioned file.
            await self.destroy_sandbox(sandbox_id)
            raise SandboxException("Signed sandbox materialization unavailable") from exc

    async def _setup_network(
        self,
        sandbox_id: str,
        bridge_name: str,
        chain_name: str,
        egress_policy: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Install a deny-by-default Docker egress policy *before* worker start.

        The DOCKER-USER hook precedes Docker's permissive forwarding rules.
        The INPUT hook denies traffic from this bridge to local host services,
        including a host daemon's TCP Docker API. No worker process can run
        while this temporary host policy is being constructed.
        """
        import re
        import socket
        import subprocess

        if not re.fullmatch(r"br-[0-9a-f]{12}", bridge_name) or not re.fullmatch(
            r"AIOSOP-[0-9a-f]{12}", chain_name
        ):
            raise SandboxException("Invalid sandbox firewall identity")
        allowed: set = set()
        ips = egress_policy.get("allowed_ips", [])
        cidrs = egress_policy.get("allowed_cidrs", [])
        domains = egress_policy.get("allowed_domains", [])
        if (
            not isinstance(ips, list)
            or len(ips) > 32
            or not isinstance(cidrs, list)
            or len(cidrs) > 32
            or not isinstance(domains, list)
            or len(domains) > 16
        ):
            raise SandboxException("Egress scope is not bounded")
        try:
            for raw in ips + cidrs:
                if not isinstance(raw, str):
                    raise ValueError("Invalid IP/CIDR")
                net = ipaddress.ip_network(raw, strict=False)
                if net.version != 4 or net.prefixlen == 0:
                    raise ValueError("Unbounded/non-IPv4 egress")
                allowed.add(str(net))
            for domain in domains:
                if not isinstance(domain, str) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", domain
                ):
                    raise ValueError("Invalid egress domain")
                addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
                if not addresses:
                    raise ValueError("Unresolved egress domain")
                for record in addresses:
                    allowed.add(str(ipaddress.ip_network(record[4][0] + "/32")))
        except (ValueError, socket.gaierror, IndexError, TypeError) as exc:
            raise SandboxException("Unable to verify scoped egress addresses") from exc
        if not allowed:
            raise SandboxException("No verified egress destination to allow")

        info = {
            "bridge": bridge_name,
            "chain": chain_name,
            "chain_created": False,
            "forward_hook": False,
            "input_hook": False,
        }
        # Install complete private chain with terminal DROP before attaching it
        # to Docker's forwarding hook. Only our named chain/rules are touched.
        commands = [
            ["iptables", "-N", chain_name],
            *[["iptables", "-A", chain_name, "-d", ip, "-j", "ACCEPT"] for ip in sorted(allowed)],
            ["iptables", "-A", chain_name, "-j", "DROP"],
            ["iptables", "-I", "DOCKER-USER", "1", "-i", bridge_name, "-j", chain_name],
            ["iptables", "-I", "INPUT", "1", "-i", bridge_name, "-j", "DROP"],
        ]
        try:
            for index, cmd in enumerate(commands):
                result = subprocess.run(cmd, check=False, capture_output=True)
                if type(result.returncode) is not int or result.returncode != 0:
                    raise SandboxException("Sandbox firewall rule could not be installed")
                if index == 0:
                    info["chain_created"] = True
                elif index == len(commands) - 2:
                    info["forward_hook"] = True
                elif index == len(commands) - 1:
                    info["input_hook"] = True
        except Exception as exc:
            if info["chain_created"]:
                self._remove_network_rules(info)
            raise SandboxException("Sandbox firewall is not enforcing scope") from exc
        return info

    @staticmethod
    def _remove_network_rules(info: Dict[str, Any]) -> None:
        """Best-effort cleanup of ONLY this worker's exact hook/chain rules."""
        import re
        import subprocess

        bridge, chain = info.get("bridge"), info.get("chain")
        if (
            not isinstance(bridge, str)
            or not re.fullmatch(r"br-[0-9a-f]{12}", bridge)
            or not isinstance(chain, str)
            or not re.fullmatch(r"AIOSOP-[0-9a-f]{12}", chain)
        ):
            return
        commands = []
        if info.get("forward_hook") is True:
            commands.append(["iptables", "-D", "DOCKER-USER", "-i", bridge, "-j", chain])
        if info.get("input_hook") is True:
            commands.append(["iptables", "-D", "INPUT", "-i", bridge, "-j", "DROP"])
        if info.get("chain_created") is True:
            commands.extend((["iptables", "-F", chain], ["iptables", "-X", chain]))
        for cmd in commands:
            try:
                subprocess.run(cmd, check=False, capture_output=True)
            except (OSError, ValueError):
                pass

    async def execute_in_sandbox(
        self, sandbox_id: str, command: List[str], timeout: int = 300
    ) -> Dict[str, Any]:
        """Execute command in sandbox with monitoring."""
        if type(timeout) is not int or not 1 <= timeout <= 300:
            raise SandboxException("Bounded sandbox timeout required")
        # Validate even legacy manual commands before looking up Docker. The
        # signed-resource branch additionally binds this exact digest to the
        # durable human-approved Task; validation alone grants no authority.
        self._command_sha256(command)
        sandbox = self._active_sandboxes.get(sandbox_id)
        if not sandbox:
            raise SandboxException(f"Sandbox {sandbox_id} not found")

        mounted = sandbox.get("signed_resource")
        if mounted is not None:
            try:
                binding, reader, digest = mounted
                fresh_meta, _ = await reader.read(binding)
                if not hmac.compare_digest(fresh_meta["sha256"], digest):
                    raise ValueError("Signed resource read fence changed")
                current = await reader.verify_approved_task(binding)
                approved_argv = current.get("approved_command_sha256")
                if not isinstance(approved_argv, str) or not hmac.compare_digest(
                    approved_argv, self._command_sha256(command)
                ):
                    raise ValueError("Sandbox command differs from signed human-reviewed Task")
            except Exception as exc:
                # Stop the container before allowing expired/revoked resources
                # to be consumed; if stop fails its firewall remains intact.
                await self.destroy_sandbox(sandbox_id)
                raise SandboxException("Signed resource task authority revoked") from exc

        import docker

        client = docker.from_env()
        container = client.containers.get(sandbox["container_id"])

        start_time = datetime.utcnow()

        try:
            # docker-py exec_run does NOT accept a `timeout` keyword. A
            # watchdog applies the deadline to the real Docker SDK call.
            import asyncio

            result = await asyncio.wait_for(
                asyncio.to_thread(container.exec_run, command, demux=True),
                timeout=timeout,
            )

            if mounted is not None:
                # The Task, human approval, signed ROE or lease can be
                # revoked while the Docker exec is in flight. A successful
                # exit code proves neither continuing authorization nor a
                # permissible effect. Recheck after the remote acknowledgement
                # and quarantine on any changed/missing provenance; never
                # expose command output or retry an ambiguous remote effect.
                try:
                    current_meta, _ = await reader.read(binding)
                    current_admission = await reader.verify_approved_task(binding)
                    if not hmac.compare_digest(
                        current_meta["sha256"], digest
                    ) or not hmac.compare_digest(
                        current_admission["approved_command_sha256"],
                        self._command_sha256(command),
                    ):
                        raise ValueError("Signed resource or command approval rotated")
                except Exception:
                    await self.destroy_sandbox(sandbox_id)
                    return {
                        "status": "UNKNOWN",
                        "error": "sandbox_authority_changed_during_remote_execution",
                        "execution_time": (datetime.utcnow() - start_time).total_seconds(),
                    }

            execution_time = (datetime.utcnow() - start_time).total_seconds()

            return {
                "status": "success" if result.exit_code == 0 else "error",
                "exit_code": result.exit_code,
                "stdout": result.output[0].decode() if result.output[0] else "",
                "stderr": result.output[1].decode() if result.output[1] else "",
                "execution_time": execution_time,
            }

        except asyncio.CancelledError:
            # Cancellation is not a durable acknowledgement. In Python it is
            # a BaseException, so the ordinary failure handler cannot fence a
            # remote command that might still be running after local cancel.
            await self.destroy_sandbox(sandbox_id)
            raise
        except asyncio.TimeoutError:
            # The worker may have performed an external effect before the
            # local deadline; stop before allowing ANY new command and do
            # not report this as an ordinary retryable failure or success.
            await self.destroy_sandbox(sandbox_id)
            return {
                "status": "UNKNOWN",
                "error": "sandbox_timeout_remote_effect_unknown",
                "execution_time": (datetime.utcnow() - start_time).total_seconds(),
            }
        except Exception:
            # Transport failures can happen AFTER the remote process started.
            # Retaining a runnable container would permit a second command
            # while the first action is UNKNOWN. As in the timeout branch,
            # quarantine the sandbox before returning an inconclusive result.
            # destroy_sandbox deliberately retains firewall/state on failed
            # removal and raises rather than asserting remote termination.
            await self.destroy_sandbox(sandbox_id)
            return {
                "status": "UNKNOWN",
                "error": "sandbox_execution_outcome_unknown",
                "execution_time": (datetime.utcnow() - start_time).total_seconds(),
            }

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """Stop/remove the worker BEFORE lifting its host firewall restriction."""
        sandbox = self._active_sandboxes.get(sandbox_id)
        if not sandbox:
            return

        import docker

        client = docker.from_env()
        # A failed stop/removal MUST NOT make the still-running worker reachable
        # by deleting its egress firewall. Leave state for a safe retry.
        try:
            container = client.containers.get(sandbox["container_id"])
            container.stop(timeout=10)
            container.remove(force=True)
        except docker.errors.NotFound:
            pass
        except Exception as exc:
            raise SandboxException("Sandbox still present; firewall retained") from exc

        self._active_sandboxes.pop(sandbox_id, None)
        # Only after the container is gone may its exact rules be removed.
        if sandbox.get("network"):
            self._remove_network_rules(sandbox["network"])

        # Finally release only this sandbox's named network.
        network_id = sandbox.get("network_id")
        if network_id:
            try:
                network = client.networks.get(network_id)
                network.remove()
            except Exception:
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
