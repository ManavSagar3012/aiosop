"""Explicitly opted-in, loopback-only eleven-MCP inert transport diagnostic.

This is NOT a scanner, a source-side authority issuer, a signed Task, a native
grant, an end-to-end qualification, or target-owner effect proof. No service is
contacted without an explicit ``--allow NAME=127.0.0.1:PORT`` argument.

Uses the real MCPRegistry connection/initialize/execute pipeline. The ONLY
possible execution is an exactly named, empty-parameter, declared READ_ONLY,
approval-free ``list_tools`` discovery. Untrusted provider testimony is
collapsed to enums and never reported as independently verified execution.

Usage (from repo root, with project venv):
    python scripts/qualification/mcp_eleven_inert_diagnostic_20261021.py \
        --allow recon-mcp=127.0.0.1:8082 \
        --allow payload-mcp=127.0.0.1:8083

Every service without --allow remains ``not_allowed``. Neither environment
bearers nor an .env file nor any passed native approval/grant is loaded.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

# A standalone repo-local diagnostic; never import the API main module (which
# may trigger application state or dependency initialization).
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from ai_osop.core.telemetry import RequestContext  # noqa: E402
from ai_osop.mcp.protocol import (  # noqa: E402
    MCPInitializeResponse,
    MCPRegistry,
    MCPToolDefinition,
    SideEffectClass,
)


SERVICE_IDS = (
    "burp-mcp",
    "recon-mcp",
    "payload-mcp",
    "nuclei-mcp",
    "shodan-mcp",
    "browser-mcp",
    "security-bridge",
    "threat-intel-mcp",
    "source-map-mcp",
    "cloud-mcp",
    "turbo-intruder-mcp",
)
_PORT = re.compile(r"(?:[1-9][0-9]{0,4})\Z")
_FORBIDDEN_PORTS = frozenset({5432, 5433, 6379, 6380, 7687, 7474, 8200, 5173})
_TIMEOUT = 6.0
_TOOL = "list_tools"
_INERT_OUTCOMES = frozenset({"success", "denied", "error", "unknown", "timeout"})


class UnsafeEndpoint(ValueError):
    """Refuse all locations except explicitly approved numeric loopback."""


def parse_allow(values: Sequence[str]) -> dict[str, int]:
    """All input validated BEFORE registry construction or network I/O."""
    if isinstance(values, (str, bytes)) or len(values) > len(SERVICE_IDS):
        raise UnsafeEndpoint("Invalid eleven-service diagnostic allowlist")
    allowed: dict[str, int] = {}
    occupied: set[int] = set()
    for value in values:
        if type(value) is not str or len(value) > 100 or "=" not in value:
            raise UnsafeEndpoint("Invalid explicit endpoint")
        name, endpoint = value.split("=", 1)
        if (
            name not in SERVICE_IDS
            or name in allowed
            or not endpoint.startswith("127.0.0.1:")
            or endpoint.count(":") != 1
        ):
            raise UnsafeEndpoint("Only one numeric loopback endpoint per service is allowed")
        port_text = endpoint[len("127.0.0.1:") :]
        if _PORT.fullmatch(port_text) is None:
            raise UnsafeEndpoint("Invalid numeric loopback port")
        port = int(port_text)
        if not 1 <= port <= 65535 or port in _FORBIDDEN_PORTS or port in occupied:
            raise UnsafeEndpoint("Non-MCP, duplicated or out-of-range port denied")
        occupied.add(port)
        allowed[name] = port
    return allowed


def _empty_result(name: str) -> dict[str, Any]:
    return {
        "server_id": name,
        "registered": False,
        "initialized": False,
        "inert_outcome": "not_checked",
        "state": "not_allowed",
        "target_effect_verified": False,
        "production_certified": False,
    }


def _inert_declaration(tools: Any) -> bool:
    """Never trust a name or a defaulted READ_ONLY model by itself."""
    if (
        not isinstance(tools, dict)
        or len(tools) > 128
        or _TOOL not in tools
        or type(tools[_TOOL]) is not MCPToolDefinition
    ):
        return False
    definition = tools[_TOOL]
    return (
        definition.name == _TOOL
        and definition.side_effect_class is SideEffectClass.READ_ONLY
        and definition.requires_approval is False
        and definition.scope_check is True
        and definition.required_permissions == []
        and definition.parameters == []
        and type(definition.timeout_seconds) is int
        and 1 <= definition.timeout_seconds <= 6
    )


async def diagnose(
    allow: Mapping[str, int], *, registry: Optional[MCPRegistry] = None
) -> list[dict[str, Any]]:
    """Connect to exactly the authorized ports, one bounded pass, NO retry.

    A supplied registry exists only for isolated in-process tests. The CLI
    always constructs a fresh local MCPRegistry and closes all connections.
    """
    # Revalidate all caller input, including programmatic/mutable mappings.
    if not isinstance(allow, Mapping):
        raise UnsafeEndpoint("Explicit loopback endpoints required")
    canonical = parse_allow(
        [
            f"{name}=127.0.0.1:{port}"
            for name, port in allow.items()
            if type(name) is str and type(port) is int
        ]
    )
    if len(canonical) != len(allow):
        raise UnsafeEndpoint("Malformed loopback endpoint mapping")
    fleet = registry if registry is not None else MCPRegistry()
    results = []
    try:
        for name in SERVICE_IDS:
            row = _empty_result(name)
            results.append(row)
            port = canonical.get(name)
            if port is None:
                continue
            row["state"] = "unknown"
            try:
                connection = await asyncio.wait_for(
                    fleet.register_server(name, "127.0.0.1", port, None),
                    timeout=_TIMEOUT,
                )
                if (
                    getattr(connection, "server_id", None) != name
                    or getattr(connection, "host", None) != "127.0.0.1"
                    or getattr(connection, "port", None) != port
                ):
                    continue
                row["registered"] = True
                response = await asyncio.wait_for(
                    fleet.initialize_server(
                        name, scope={}, credentials={}, session_id="api-bootstrap"
                    ),
                    timeout=_TIMEOUT,
                )
                if (
                    not isinstance(response, MCPInitializeResponse)
                    or response.server_id != name
                    or response.status != "ready"
                    or not response.tools
                    or len(response.tools) != len({t.name for t in response.tools})
                    or connection._initialized is not True
                    or connection._session is None
                ):
                    continue
                row["initialized"] = True
                row["state"] = "initialized_only"
                if not _inert_declaration(connection._tools):
                    row["inert_outcome"] = "not_declared"
                    continue
                # Not a native 0027 grant, scanner activation, or Task approval:
                # bootstrap authorization is only for exact inert discovery.
                # Each request ID is random, never reused, and never retried.
                request_id = "req-" + uuid.uuid4().hex
                RequestContext.bind(engagement_id="api-bootstrap", task_id="task-inert-diagnostic")
                try:
                    result = await asyncio.wait_for(
                        fleet.execute_tool(name, _TOOL, {}, request_id=request_id),
                        timeout=_TIMEOUT,
                    )
                finally:
                    RequestContext.clear()
                if result.request_id != request_id:
                    row["inert_outcome"] = "unknown"
                elif result.status == "success":
                    row["inert_outcome"] = "provider_reported_success_unverified"
                elif result.status in {"scope_denied", "approval_required", "roe_denied"}:
                    row["inert_outcome"] = "denied"
                elif result.status in _INERT_OUTCOMES:
                    row["inert_outcome"] = "unknown" if result.status != "denied" else "denied"
                else:
                    # Includes duplicate_request, expired, conflicting receipt,
                    # stale Action, fake provider approval, ambiguous lost ACK.
                    row["inert_outcome"] = "unknown"
            except Exception:
                # Provider strings, bearer material, database URLs and raw
                # exceptions are NEVER printed or copied into this report.
                if row["inert_outcome"] == "not_checked":
                    row["inert_outcome"] = "unknown"
            # Never retry on timeout, lost ACK, 503, or duplicate_request.
        return results
    finally:
        try:
            await asyncio.wait_for(fleet.close_all(), timeout=_TIMEOUT)
        except Exception:
            pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only, non-certifying diagnostics for eleven local MCP transports"
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="ID=127.0.0.1:PORT",
        help="Explicitly permit only this exact local MCP service, never implicit defaults",
    )
    args = parser.parse_args(argv)
    try:
        allow = parse_allow(args.allow)
    except UnsafeEndpoint:
        parser.error("Invalid diagnostic allowlist; only explicit unique 127.0.0.1 MCP ports")
    rows = asyncio.run(diagnose(allow))
    for row in rows:
        print(json.dumps(row, separators=(",", ":"), sort_keys=True, allow_nan=False))
    return 0 if all(row["state"] == "not_allowed" or row["initialized"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
