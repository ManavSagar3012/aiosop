"""Bounded 11-service MCP operator visibility; never a target-effect certificate.

This fixed, non-sensitive roster comes from AGENTS.md. Process registration is
only local telemetry and cannot establish an authorized operation, receipt,
remote provider availability, authenticated target effect, or release.
"""

from __future__ import annotations

from typing import Any


_FLEET = (
    ("burp-mcp", "optional"),
    ("recon-mcp", "optional"),
    ("payload-mcp", "optional"),
    ("nuclei-mcp", "critical"),
    ("shodan-mcp", "optional"),
    ("threat-intel-mcp", "optional"),
    ("security-bridge", "optional"),
    ("browser-mcp", "critical"),
    ("source-map-mcp", "critical"),
    ("cloud-mcp", "critical"),
    ("turbo-intruder-mcp", "critical"),
)


def mcp_fleet_process_visibility(process_health: dict[str, Any]) -> dict[str, Any]:
    """Project the validated process-health roster, without expanding trust.

    No discovery call, endpoint probing or credentials are involved. The API
    caller must have already authenticated the senior operator and validated
    every returned process counter through the existing /mcp/health boundary.
    """
    if (
        type(process_health) is not dict
        or set(process_health) != {"servers", "catalog_scope"}
        or process_health["catalog_scope"] != "process_health_only_unverified"
        or type(process_health["servers"]) is not list
        or len(process_health["servers"]) > 32
    ):
        raise ValueError("Validated MCP health required")
    observed: dict[str, dict[str, Any]] = {}
    for item in process_health["servers"]:
        if (
            type(item) is not dict
            or set(item)
            != {
                "server_id",
                "circuit_state",
                "failure_count",
                "success_count",
                "recovery_attempts",
                "consecutive_successes",
                "initialized",
                "runtime_health_verified",
            }
            or type(item["server_id"]) is not str
            or item["server_id"] in observed
            or type(item["initialized"]) is not bool
            or item["runtime_health_verified"] is not False
        ):
            raise ValueError("Invalid bounded registry telemetry")
        observed[item["server_id"]] = item

    services: list[dict[str, Any]] = []
    for server_id, importance in _FLEET:
        exact_process = observed.get(server_id)
        services.append(
            {
                "server_id": server_id,
                "importance": importance,
                "process_registered": exact_process is not None,
                "process_initialized": (
                    exact_process["initialized"] if exact_process is not None else None
                ),
                "process_circuit": (
                    exact_process["circuit_state"] if exact_process is not None else None
                ),
                # There is deliberately no conclusion based on a process counter.
                "runtime_health_verified": False,
                "current_authorized_operation_verified": False,
                "independent_target_effect_verified": False,
                "production_certified": False,
                "qualification": "process_registration_only" if exact_process else "not_verified",
            }
        )
    return {
        "catalog_scope": "configured_fleet_process_visibility_only",
        "services": services,
        "configured_count": len(_FLEET),
        # Not measured in this operator-wide process view. Do not infer a
        # fleet-wide count of target effects from an empty process ledger.
        "independently_verified_operations": None,
        "production_certified": False,
        "release_decision": "NOT PRODUCTION CERTIFIED / NOT READY",
    }
