"""Bounded live local observations; no engagement authority or findings invented."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any, Dict

import httpx

ROOT = Path(__file__).resolve().parents[2]


async def main() -> None:
    report: Dict[str, Any] = {"engagement_end_to_end_verified": False}
    async with httpx.AsyncClient(timeout=80, trust_env=False) as client:
        for name, url in {
            "api_health": "http://127.0.0.1:8200/health",
            "api_ready": "http://127.0.0.1:8200/ready",
            "ui": "http://127.0.0.1:5173/",
            "lab": "http://127.0.0.1:8080/api/v1/health",
            "unauthenticated_engagement_access": "http://127.0.0.1:8200/engagements",
        }.items():
            try:
                response = await client.get(url)
                entry: Dict[str, Any] = {"http_status": response.status_code}
                if name in {"api_health", "api_ready", "lab"}:
                    entry["body"] = response.json()
                report[name] = entry
            except (httpx.HTTPError, ValueError):
                report[name] = {"status": "unavailable"}
        token = (ROOT / ".runtime/local-stack/cloud-bearer").read_text(encoding="ascii")
        response = await client.post(
            "http://127.0.0.1:8097/mcp/execute",
            headers={"Authorization": "Bearer " + token},
            json={
                "tool_name": "scan_local_iac",
                "parameters": {},
                "request_id": "req-live-" + uuid.uuid4().hex,
            },
        )
        body = response.json()
        result = body.get("result", {})
        report["cloud_direct_source_scan"] = {
            "http_status": response.status_code,
            "status": body.get("status"),
            "findings_count": result.get("findings_count"),
            "input_manifest_sha256": result.get("input_manifest_sha256"),
            "source": result.get("source"),
            "live_cloud_account_verified": result.get("live_cloud_account_verified", False),
            "engagement_dispatch_verified": False,
        }
    output = ROOT / ".runtime/local-stack/verification.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
