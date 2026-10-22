"""Read-only MCP fleet probe; never dispatch an arbitrary advertised tool.

Initialization and an HTTP response are transport evidence, not proof that a
scanner ran or that a finding was verified against an authorized target.
"""

import argparse
import asyncio
import json
from typing import Any, Dict, List, Optional

import httpx

MCP_SERVERS = {
    "burp-mcp": 8081,
    "recon-mcp": 8082,
    "payload-mcp": 8083,
    "nuclei-mcp": 8084,
    "shodan-mcp": 8085,
    "threat-intel-mcp": 8086,
    "security-bridge": 8087,
    "browser-mcp": 8091,
    "source-map-mcp": 8096,
    "cloud-mcp": 8097,
    "turbo-intruder-mcp": 8098,
}

CRITICAL = frozenset(
    {"browser-mcp", "source-map-mcp", "cloud-mcp", "turbo-intruder-mcp", "nuclei-mcp"}
)
_INITIALIZE = {"scope": {}, "auth_credentials": {}, "session_id": "mcp-fleet-probe", "metadata": {}}


async def _probe(
    client: httpx.AsyncClient, name: str, port: int, public_intel_smoke: bool
) -> Dict[str, Any]:
    base = f"http://127.0.0.1:{port}"
    record: Dict[str, Any] = {
        "server_id": name,
        "critical": name in CRITICAL,
        "transport": "unreachable",
        "initialization": "not_attempted",
        "execution": "not_attempted",
        "tool_count": 0,
        "end_to_end_verified": False,
    }
    try:
        health = await client.get(f"{base}/health")
        record["transport"] = "reachable"
        health_data = health.json()
        if not isinstance(health_data, dict):
            record["initialization"] = "invalid_health"
            return record
        record["health"] = str(health_data.get("status", "unknown"))[:40]
        if health.status_code != 200 or health_data.get("status") != "ready":
            record["initialization"] = "unavailable"
            return record

        initialized = await client.post(f"{base}/mcp/initialize", json=_INITIALIZE)
        if initialized.status_code != 200:
            record["initialization"] = "unavailable"
            return record
        declaration = initialized.json()
        if (
            not isinstance(declaration, dict)
            or declaration.get("status") != "ready"
            or declaration.get("server_id") != name
        ):
            record["initialization"] = "unavailable"
            return record
        tools = declaration.get("tools")
        if not isinstance(tools, list) or any(not isinstance(tool, dict) for tool in tools):
            record["initialization"] = "invalid_catalog"
            return record
        record["initialization"] = "ready"
        record["tool_count"] = len(tools)

        # Only a fixed public-data lookup is safe to run without an engagement.
        if name == "threat-intel-mcp" and public_intel_smoke:
            if "cve_lookup" not in {tool.get("name") for tool in tools}:
                record["execution"] = "tool_absent"
                return record
            response = await client.post(
                f"{base}/mcp/execute",
                json={
                    "tool_name": "cve_lookup",
                    "parameters": {"cve_id": "CVE-2021-44228"},
                    "request_id": "req-public-intel-probe",
                },
            )
            result = response.json()
            if (
                response.status_code == 200
                and isinstance(result, dict)
                and result.get("status") == "success"
                and isinstance(result.get("result"), dict)
                and result["result"].get("id") == "CVE-2021-44228"
                and result["result"].get("source") == "NVD_PUBLIC_UNVERIFIED"
                and result["result"].get("target_effect_verified") is False
            ):
                record["execution"] = "public_lookup_verified"
            else:
                record["execution"] = "public_lookup_failed"
        return record
    except (httpx.HTTPError, ValueError, TypeError):
        if record["initialization"] == "ready":
            record["execution"] = "probe_error"
        elif record["transport"] == "reachable":
            record["initialization"] = "probe_error"
        return record


async def validate_mcps(
    *, public_intel_smoke: bool = False, client: Optional[httpx.AsyncClient] = None
) -> List[Dict[str, Any]]:
    """Return bounded observations; no generic scanner execution is attempted."""
    if client is not None:
        return await asyncio.gather(
            *(_probe(client, name, port, public_intel_smoke) for name, port in MCP_SERVERS.items())
        )
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(12.0, connect=2.0), trust_env=False, follow_redirects=False
    ) as owned_client:
        return await validate_mcps(public_intel_smoke=public_intel_smoke, client=owned_client)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-intel-smoke", action="store_true")
    parser.add_argument("--require-critical", action="store_true")
    args = parser.parse_args()
    records = asyncio.run(validate_mcps(public_intel_smoke=args.public_intel_smoke))
    print(json.dumps({"servers": records}, indent=2))
    if args.public_intel_smoke and not any(
        record["server_id"] == "threat-intel-mcp"
        and record["execution"] == "public_lookup_verified"
        for record in records
    ):
        return 1
    if args.require_critical and any(
        record["critical"] and not record["end_to_end_verified"] for record in records
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
