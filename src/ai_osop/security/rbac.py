"""
Role-Based Access Control (RBAC) for AI-OSOP API

Enforces role-based permissions on API endpoints. Every request must
carry a valid JWT or API token with an associated role. Roles define
what operations are permitted.

Phase 6: Enterprise Hardening
"""

from enum import Enum
from typing import Any, Callable, Dict, Optional, Set

import structlog

logger = structlog.get_logger("ai_osop.rbac")


class Role(str, Enum):
    """Platform roles with ascending privilege levels."""

    VIEWER = "viewer"  # Read-only access to engagement data
    OPERATOR = "operator"  # Can create engagements, schedule tasks
    ADMIN = "admin"  # Full platform management
    SYSTEM = "system"  # Internal system operations (agents, orchestrator)


# Permission definitions: role → set of allowed operations
ROLE_PERMISSIONS: Dict[Role, Set[str]] = {
    Role.VIEWER: {
        "engagement:read",
        "task:read",
        "finding:read",
        "report:read",
        "audit:read",
    },
    Role.OPERATOR: {
        # Includes all viewer permissions
        "engagement:read",
        "engagement:create",
        "engagement:update",
        "task:read",
        "task:create",
        "task:cancel",
        "finding:read",
        "finding:create",
        "report:read",
        "report:create",
        "approval:read",
        "approval:resolve",
        "audit:read",
        "session:import",
    },
    Role.ADMIN: {
        # Includes all operator permissions
        "engagement:read",
        "engagement:create",
        "engagement:update",
        "engagement:delete",
        "engagement:halt",
        "task:read",
        "task:create",
        "task:cancel",
        "task:delete",
        "finding:read",
        "finding:create",
        "finding:delete",
        "report:read",
        "report:create",
        "report:delete",
        "approval:read",
        "approval:resolve",
        "audit:read",
        "audit:delete",
        "session:import",
        "session:delete",
        "agent:read",
        "agent:register",
        "agent:deregister",
        "config:read",
        "config:update",
        "pentest:run",
    },
    Role.SYSTEM: {
        # Full access — used by internal components
        "*",
    },
}

# Endpoint → required permission mapping
ENDPOINT_PERMISSIONS: Dict[str, str] = {
    "GET /engagements": "engagement:read",
    "POST /engagements": "engagement:create",
    "PUT /engagements/{id}": "engagement:update",
    "DELETE /engagements/{id}": "engagement:delete",
    "POST /engagements/{id}/halt": "engagement:halt",
    "GET /tasks": "task:read",
    "POST /tasks": "task:create",
    "POST /tasks/{id}/cancel": "task:cancel",
    "GET /findings": "finding:read",
    "POST /findings": "finding:create",
    "GET /reports": "report:read",
    "POST /reports": "report:create",
    "GET /approvals": "approval:read",
    "POST /approvals/{id}/resolve": "approval:resolve",
    "GET /audit": "audit:read",
    "GET /agents": "agent:read",
    "POST /agents": "agent:register",
    "POST /pentest/run": "pentest:run",
    "GET /config": "config:read",
    "PUT /config": "config:update",
}


class RBACEnforcer:
    """Enforces role-based access control on API requests."""

    def __init__(self):
        self.role_permissions = ROLE_PERMISSIONS
        self.endpoint_permissions = ENDPOINT_PERMISSIONS

    def check_permission(self, role: Role, permission: str) -> bool:
        """Check if a role has a specific permission."""
        if role == Role.SYSTEM:
            return True  # System has all permissions

        role_perms = self.role_permissions.get(role, set())
        return permission in role_perms

    def check_endpoint_access(self, role: Role, method: str, path: str) -> Dict[str, Any]:
        """Check if a role can access a specific endpoint.

        Returns:
            - allowed: bool
            - permission_required: str
            - reason: str
        """
        # Normalize path — strip query params and trailing slashes
        normalized_path = path.split("?")[0].rstrip("/")

        # Try exact match first, then pattern match
        endpoint_key = f"{method.upper()} {normalized_path}"
        permission = self.endpoint_permissions.get(endpoint_key)

        if permission is None:
            # Try pattern matching for parameterized paths
            for pattern, perm in self.endpoint_permissions.items():
                pattern_method, pattern_path = pattern.split(" ", 1)
                if pattern_method != method.upper():
                    continue
                # Simple pattern match: /engagements/{id} matches /engagements/abc-123
                pattern_parts = pattern_path.split("/")
                path_parts = normalized_path.split("/")
                if len(pattern_parts) != len(path_parts):
                    continue
                match = True
                for pp, rp in zip(pattern_parts, path_parts):
                    if pp.startswith("{") and pp.endswith("}"):
                        continue  # Parameter — matches anything
                    if pp != rp:
                        match = False
                        break
                if match:
                    permission = perm
                    break

        if permission is None:
            # Unknown endpoint — deny by default
            return {
                "allowed": False,
                "permission_required": "unknown",
                "reason": f"No permission mapping for {method} {normalized_path}",
            }

        allowed = self.check_permission(role, permission)
        return {
            "allowed": allowed,
            "permission_required": permission,
            "reason": (
                f"Role '{role.value}' {'has' if allowed else 'lacks'} "
                f"permission '{permission}'"
            ),
        }

    def get_role_permissions(self, role: Role) -> Dict[str, Any]:
        """Return all permissions for a role (for observability)."""
        perms = self.role_permissions.get(role, set())
        return {
            "role": role.value,
            "permissions": sorted(perms),
            "permission_count": len(perms),
        }

    def get_all_roles(self) -> Dict[str, Any]:
        """Return all roles and their permissions (for admin dashboard)."""
        return {
            role.value: self.get_role_permissions(role)
            for role in Role
        }
