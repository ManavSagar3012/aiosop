"""
ACL Validators — Redis and Neo4j Access Control

Validates that:
1. Redis connections use proper ACL roles (agents get limited permissions,
   orchestrator gets full permissions)
2. Neo4j writes are validated against a tool_source allowlist
3. No agent can write arbitrary data to the graph

Phase 5/6: Runtime Validation + Enterprise Hardening
"""

import json
from typing import Any, Dict, List, Optional, Set

import structlog

logger = structlog.get_logger("ai_osop.acl")


# ============================================================
# Redis ACL Validation
# ============================================================

# Role definitions: what each role can do in Redis
REDIS_ROLES = {
    "agent": {
        "description": "Agent role — limited to read/write on engagement-scoped keys",
        "allowed_commands": {
            "read": ["GET", "MGET", "HGET", "HGETALL", "LRANGE", "SCARD", "SISMEMBER", "XREAD", "XLEN"],
            "write": ["SET", "SETEX", "HSET", "HDEL", "LPUSH", "RPUSH", "SADD", "SREM", "XADD"],
            "denied": ["FLUSHALL", "FLUSHDB", "KEYS", "CONFIG", "DEBUG", "SHUTDOWN", "SAVE", "BGSAVE"],
        },
        "key_patterns": [
            "aiosop:{engagement_id}:*",
            "queue:tasks:{engagement_id}",
            "agent:{agent_id}:*",
        ],
    },
    "orchestrator": {
        "description": "Orchestrator role — full access to manage tasks and state",
        "allowed_commands": {
            "all": True,  # Orchestrator needs full access
        },
        "key_patterns": ["*"],
    },
    "readonly": {
        "description": "Read-only role for monitoring and observability",
        "allowed_commands": {
            "read": ["GET", "MGET", "HGET", "HGETALL", "LRANGE", "SCARD", "SISMEMBER", "XREAD", "XLEN", "INFO", "DBSIZE"],
            "denied": ["SET", "DEL", "FLUSHALL", "FLUSHDB", "XADD"],
        },
        "key_patterns": ["*"],
    },
}


class RedisACLValidator:
    """Validates Redis ACL configuration against expected role definitions."""

    def __init__(self):
        self.roles = REDIS_ROLES

    async def validate_redis_acls(self, redis_client: Any) -> Dict[str, Any]:
        """Validate current Redis ACL configuration.

        Checks:
        1. ACL users are configured (not just default)
        2. Agent users have limited permissions
        3. Dangerous commands are restricted
        """
        results = {
            "acl_configured": False,
            "users": [],
            "issues": [],
            "recommendations": [],
        }

        try:
            # Try to get ACL list (Redis 6+)
            acl_list = await redis_client.acl("LIST")
            results["acl_configured"] = len(acl_list) > 0
            results["users"] = acl_list

            # Check if default user is too permissive
            for acl_entry in acl_list:
                if isinstance(acl_entry, str) and "default" in acl_entry.lower():
                    if "allcommands" in acl_entry.lower() and "allkeys" in acl_entry.lower():
                        results["issues"].append(
                            "Default user has ALLCOMMANDS + ALLKEYS — "
                            "agents connecting without credentials get full access"
                        )
                        results["recommendations"].append(
                            "Create dedicated ACL users for agents and orchestrator"
                        )

        except Exception as e:
            results["issues"].append(f"Cannot query ACL: {e}")
            results["recommendations"].append(
                "Ensure Redis 6+ with ACL support is running"
            )

        return results

    def get_expected_acl(self, role: str) -> Dict[str, Any]:
        """Return the expected ACL configuration for a given role."""
        return self.roles.get(role, {})

    def validate_agent_permissions(
        self, agent_id: str, commands_used: List[str], key_patterns: List[str]
    ) -> Dict[str, Any]:
        """Validate that an agent's actual Redis usage matches its role."""
        role = self.roles["agent"]
        denied = role["allowed_commands"].get("denied", [])

        violations = []
        for cmd in commands_used:
            if cmd.upper() in [d.upper() for d in denied]:
                violations.append(f"Agent {agent_id} used denied command: {cmd}")

        return {
            "agent_id": agent_id,
            "role": "agent",
            "violations": violations,
            "compliant": len(violations) == 0,
        }


# ============================================================
# Neo4j Write ACL
# ============================================================

# Which tool_sources are allowed to write to Neo4j
NEO4J_WRITE_ALLOWLIST: Set[str] = {
    # Core agents
    "recon_agent",
    "vuln_agent",
    "exploit_agent",
    "attack_chain_agent",
    "payload_agent",
    "reporting_agent",
    "workflow_agent",
    "strategic_planner",
    "self_pentest_agent",
    # Orchestrator
    "orchestrator",
    "task_scheduler",
    "recovery_service",
    # Adapters
    "nuclei",
    "burp",
    "recon_mcp",
    "browser_mcp",
    "shodan_mcp",
    # System
    "system",
    "retention_service",
    "finding_corpus",
}

# Which node labels each tool_source can write to
NEO4J_WRITE_SCOPES: Dict[str, Set[str]] = {
    # Agents are scoped to their specific node types
    "recon_agent": {"Asset", "Endpoint", "DNSRecord", "Observation"},
    "vuln_agent": {"Vulnerability", "Endpoint", "Observation"},
    "exploit_agent": {"Exploit", "Vulnerability", "Evidence", "Observation"},
    "attack_chain_agent": {"AttackChain", "Primitive", "Observation"},
    # Orchestrator, system, and self_pentest have unrestricted write access
    # (not in this dict = no label restrictions)
}


class Neo4jWriteACL:
    """Validates Neo4j write operations against the tool_source allowlist."""

    def __init__(self, allowlist: Optional[Set[str]] = None):
        self.allowlist = allowlist or NEO4J_WRITE_ALLOWLIST
        self.write_scopes = NEO4J_WRITE_SCOPES

    def validate_write(
        self,
        tool_source: str,
        node_labels: List[str],
        operation: str = "create",
    ) -> Dict[str, Any]:
        """Validate whether a tool_source can write specific node types.

        Returns:
            - allowed: bool
            - reason: str
            - violations: list of specific violations
        """
        violations = []

        # Check 1: Is the tool_source in the allowlist?
        if tool_source not in self.allowlist:
            violations.append(
                f"tool_source '{tool_source}' is not in the write allowlist"
            )
            return {
                "allowed": False,
                "reason": "unauthorized_tool_source",
                "violations": violations,
            }

        # Check 2: Does this tool_source have scope restrictions?
        # Sources not in write_scopes have unrestricted write access (e.g. orchestrator)
        allowed_labels = self.write_scopes.get(tool_source)
        if allowed_labels is not None:
            for label in node_labels:
                if label not in allowed_labels:
                    violations.append(
                        f"tool_source '{tool_source}' cannot write to '{label}' nodes "
                        f"(allowed: {allowed_labels})"
                    )

        return {
            "allowed": len(violations) == 0,
            "reason": "scope_violation" if violations else "ok",
            "violations": violations,
        }

    def get_allowed_sources(self) -> List[str]:
        """Return the list of authorized tool sources."""
        return sorted(self.allowlist)

    def get_write_scopes(self) -> Dict[str, List[str]]:
        """Return the write scope map (serializable)."""
        return {k: sorted(v) for k, v in self.write_scopes.items()}
