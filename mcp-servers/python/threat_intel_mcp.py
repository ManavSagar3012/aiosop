"""Bounded public CVE lookup via fixed, non-paid NVD/ExploitDB endpoints.

Alternative native Python implementation of threat-intel-mcp. This does not
validate an exploit, supply private target intelligence, or invoke paid APIs.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import re
import uuid
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(title="Threat Intel MCP Server")

_CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}\Z")
_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
_MAX_JSON = 512 * 1024
_MAX_KEV = 16 * 1024 * 1024
_MAX_CSV = 8 * 1024 * 1024


class ThreatIntelUnavailable(RuntimeError):
    """Remote public data missing, invalid or unverified; no upstream text leaks."""


class MCPInitializeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Dict[str, Any] = Field(default_factory=dict)
    auth_credentials: Dict[str, Any] = Field(default_factory=dict)
    session_id: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MCPExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(min_length=1, max_length=64)
    parameters: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = Field(default=None, max_length=128)
    timeout_override: Optional[int] = Field(default=None, ge=1, le=30)


class ThreatIntelManager:
    """Strictly fixed public URLs; no caller-supplied destination, proxy, or redirect."""

    def __init__(self) -> None:
        self.nvd_lock = asyncio.Semaphore(1)

    async def _fetch(self, url: str, *, cve_id: Optional[str] = None) -> bytes:
        if url not in {_NVD, _CISA_KEV, _EXPLOITDB_CSV}:
            raise ThreatIntelUnavailable()
        limit = _MAX_JSON if url == _NVD else _MAX_KEV if url == _CISA_KEV else _MAX_CSV
        try:
            async with httpx.AsyncClient(
                verify=True,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(8.0, connect=3.0),
            ) as client:
                async with client.stream(
                    "GET",
                    url,
                    params={"cveId": cve_id} if url == _NVD else None,
                    follow_redirects=False,
                ) as response:
                    if response.status_code != 200:
                        raise ThreatIntelUnavailable()
                    announced = response.headers.get("content-length", "")
                    if announced and (not announced.isdecimal() or int(announced) > limit):
                        raise ThreatIntelUnavailable()
                    chunks = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(chunks) + len(chunk) > limit:
                            raise ThreatIntelUnavailable()
                        chunks.extend(chunk)
                    return bytes(chunks)
        except (httpx.HTTPError, UnicodeError, ValueError) as exc:
            raise ThreatIntelUnavailable() from exc

    @staticmethod
    def _validated_cve(raw: Any) -> str:
        if type(raw) is not str or _CVE_PATTERN.fullmatch(raw.upper()) is None:
            raise ThreatIntelUnavailable()
        return raw.upper()

    async def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        cve = self._validated_cve(cve_id)
        async with self.nvd_lock:
            try:
                parsed = json.loads(await self._fetch(_NVD, cve_id=cve))
                if not isinstance(parsed, dict):
                    raise ThreatIntelUnavailable()
                vulnerabilities = parsed.get("vulnerabilities")
                if not isinstance(vulnerabilities, list) or not 1 <= len(vulnerabilities) <= 20:
                    raise ThreatIntelUnavailable()
                record = vulnerabilities[0]
                if not isinstance(record, dict):
                    raise ThreatIntelUnavailable()
                entry = record.get("cve")
                if not isinstance(entry, dict) or entry.get("id") != cve:
                    raise ThreatIntelUnavailable()
                descriptions = entry.get("descriptions", [])
                if not isinstance(descriptions, list) or len(descriptions) > 16:
                    raise ThreatIntelUnavailable()
                selected = next(
                    (
                        item.get("value", "")
                        for item in descriptions
                        if isinstance(item, dict) and item.get("lang") == "en"
                    ),
                    "",
                )
                if not isinstance(selected, str):
                    raise ThreatIntelUnavailable()
                return {
                    "id": cve,
                    "description": selected[:600],
                    "cvss": self._extract_cvss(entry.get("metrics", {})),
                    "source": "NVD_PUBLIC_UNVERIFIED",
                    "target_effect_verified": False,
                }
            except (ValueError, TypeError, KeyError, IndexError) as exc:
                raise ThreatIntelUnavailable() from exc

    @staticmethod
    def _extract_cvss(metrics: Any) -> float:
        if not isinstance(metrics, dict):
            return 0.0
        for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            candidates = metrics.get(version, [])
            if isinstance(candidates, list) and candidates and isinstance(candidates[0], dict):
                candidate = candidates[0].get("cvssData", {})
                score = candidate.get("baseScore") if isinstance(candidate, dict) else None
                if type(score) in (int, float) and 0 <= score <= 10:
                    return float(score)
        return 0.0

    async def search_exploitdb(self, cve_id: str) -> Dict[str, Any]:
        cve = self._validated_cve(cve_id)
        try:
            csv_body = await self._fetch(_EXPLOITDB_CSV)
            decoded = csv_body.decode("utf-8-sig")
            findings = []
            for index, row in enumerate(csv.DictReader(io.StringIO(decoded))):
                if index > 100000:
                    raise ThreatIntelUnavailable()
                if not isinstance(row, dict):
                    raise ThreatIntelUnavailable()
                text = " ".join(str(value or "")[:300] for value in row.values()).upper()
                if cve not in text:
                    continue
                identity = row.get("id")
                if not isinstance(identity, str) or not identity.isdecimal() or len(identity) > 12:
                    continue
                title = row.get("description", "")
                findings.append(
                    {
                        "id": identity,
                        "title": title[:160] if isinstance(title, str) else "",
                        "url": f"https://www.exploit-db.com/exploits/{identity}",
                    }
                )
                if len(findings) >= 20:
                    break
            return {
                "exploits": findings,
                "source": "EXPLOITDB_PUBLIC_UNVERIFIED",
                "target_effect_verified": False,
            }
        except (UnicodeError, csv.Error, ValueError, TypeError) as exc:
            raise ThreatIntelUnavailable() from exc

    async def check_cisa_kev(self, cve_id: str) -> Dict[str, Any]:
        """Check a validated public KEV catalog without asserting target exposure."""
        cve = self._validated_cve(cve_id)
        try:
            document = json.loads(await self._fetch(_CISA_KEV))
            entries = document.get("vulnerabilities") if isinstance(document, dict) else None
            if not isinstance(entries, list) or len(entries) > 100000:
                raise ThreatIntelUnavailable()
            found = False
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ThreatIntelUnavailable()
                entry_id = entry.get("cveID")
                if (
                    not isinstance(entry_id, str)
                    or _CVE_PATTERN.fullmatch(entry_id.upper()) is None
                ):
                    raise ThreatIntelUnavailable()
                found = found or entry_id.upper() == cve
            return {
                "cve_id": cve,
                "in_kev": found,
                "source": "CISA_KEV_PUBLIC_UNVERIFIED",
                "target_effect_verified": False,
            }
        except (ValueError, TypeError) as exc:
            raise ThreatIntelUnavailable() from exc


manager = ThreatIntelManager()


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ready", "server": "threat-intel-mcp"}


@app.post("/mcp/initialize")
async def mcp_initialize(req: MCPInitializeRequest) -> Dict[str, Any]:
    return {
        "server_id": "threat-intel-mcp",
        "version": "1.1.0",
        "capabilities": ["public_cve_enrichment_unverified"],
        "status": "ready",
        "tools": [
            {
                "name": "cve_lookup",
                "description": "Read bounded public NVD CVE metadata; not target-effect verification.",
                "parameters": [
                    {
                        "name": "cve_id",
                        "type": "string",
                        "description": "CVE-YYYY-identifier (bounded)",
                        "required": True,
                    }
                ],
                "returns": {"type": "object", "description": "Public unverified CVE metadata"},
                "side_effect_class": "READ_ONLY",
                "requires_approval": False,
                "scope_check": True,
                "timeout_seconds": 10,
            },
            {
                "name": "search_exploits",
                "description": "Search bounded public ExploitDB index, without executing a PoC.",
                "parameters": [
                    {
                        "name": "cve_id",
                        "type": "string",
                        "description": "CVE-YYYY-identifier (bounded)",
                        "required": True,
                    }
                ],
                "returns": {
                    "type": "object",
                    "description": "Public unverified ExploitDB references",
                },
                "side_effect_class": "READ_ONLY",
                "requires_approval": False,
                "scope_check": True,
                "timeout_seconds": 10,
            },
            {
                "name": "kev_check",
                "description": "Check the public CISA KEV catalog; not target exposure verification.",
                "parameters": [
                    {
                        "name": "cve_id",
                        "type": "string",
                        "description": "CVE-YYYY-identifier (bounded)",
                        "required": True,
                    }
                ],
                "returns": {"type": "object", "description": "Public KEV membership"},
                "side_effect_class": "READ_ONLY",
                "requires_approval": False,
                "scope_check": True,
                "timeout_seconds": 10,
            },
        ],
    }


@app.post("/mcp/execute")
async def mcp_execute(req: MCPExecuteRequest) -> Dict[str, Any]:
    request_id = (
        req.request_id
        if req.request_id and re.fullmatch(r"req-[A-Za-z0-9_-]{1,120}", req.request_id)
        else f"req-{uuid.uuid4().hex}"
    )
    if req.tool_name not in {"cve_lookup", "search_exploits", "kev_check"}:
        return {"request_id": request_id, "status": "error", "error": "unsupported_tool"}
    if not isinstance(req.parameters, dict) or set(req.parameters) != {"cve_id"}:
        return {"request_id": request_id, "status": "error", "error": "invalid_cve"}
    try:
        cve = manager._validated_cve(req.parameters["cve_id"])
        operation = {
            "cve_lookup": manager.get_cve_details,
            "search_exploits": manager.search_exploitdb,
            "kev_check": manager.check_cisa_kev,
        }[req.tool_name]
        result = await asyncio.wait_for(operation(cve), timeout=10)
        if not isinstance(result, dict) or "error" in result:
            raise ThreatIntelUnavailable()
    except (ThreatIntelUnavailable, asyncio.TimeoutError, OSError):
        return {"request_id": request_id, "status": "error", "error": "public_intel_unavailable"}
    return {"request_id": request_id, "status": "success", "result": result}


if __name__ == "__main__":
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8086)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port)
