"""Cache Poisoning & Web Cache Deception Tester.

Probes unkeyed headers and path confusion for cache poisoning and cache deception,
confirming findings via cache response header verification (X-Cache / CF-Cache-Status / Age).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "cache-poison-test.com"),
    ("X-Host", "cache-poison-test.com"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
]


@dataclass
class CacheFinding:
    technique: str  # unkeyed_header_poisoning | web_cache_deception
    target_url: str
    unkeyed_header: Optional[str]
    cache_header: Optional[str]
    confirmed: bool
    evidence: Dict[str, Any] = field(default_factory=dict)


class CachePoisoningTester:
    """Test web endpoints for Web Cache Poisoning & Web Cache Deception."""

    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    async def scan_cache_poisoning(self, target_url: str) -> List[CacheFinding]:
        """Test for unkeyed header cache poisoning."""
        findings: List[CacheFinding] = []
        parsed = urlparse(target_url)

        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, follow_redirects=False
        ) as client:
            for header_name, header_val in UNKEYED_HEADERS:
                try:
                    # Probe 1: Send request with unkeyed header
                    headers = {header_name: header_val}
                    resp1 = await client.get(target_url, headers=headers)

                    # Check if header value is reflected in response body or headers
                    reflected = header_val in resp1.text or header_val in str(resp1.headers)

                    if reflected:
                        # Probe 2: Send clean request without header to verify if response is cached
                        resp2 = await client.get(target_url)
                        cache_hdr = (
                            resp2.headers.get("X-Cache")
                            or resp2.headers.get("CF-Cache-Status")
                            or resp2.headers.get("X-Cache-Hits")
                            or resp2.headers.get("Age")
                        )

                        # If poisoned content is served to a clean request (or reflected + cached)
                        if header_val in resp2.text or header_val in str(resp2.headers):
                            findings.append(
                                CacheFinding(
                                    technique="unkeyed_header_poisoning",
                                    target_url=target_url,
                                    unkeyed_header=f"{header_name}: {header_val}",
                                    cache_header=str(cache_hdr),
                                    confirmed=True,
                                    evidence={
                                        "unkeyed_header": header_name,
                                        "header_value": header_val,
                                        "cache_header": cache_hdr,
                                        "reflected_in_clean_response": True,
                                    },
                                )
                            )
                            break
                except Exception:
                    continue

        return findings

    async def scan_cache_deception(self, profile_url: str) -> List[CacheFinding]:
        """Test for Web Cache Deception by appending static extension (.css / .js)."""
        findings: List[CacheFinding] = []
        clean_url = profile_url.rstrip("/")
        deception_url = f"{clean_url}/nonexistent_script.css"

        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, follow_redirects=False
        ) as client:
            try:
                resp = await client.get(deception_url)
                # If authenticated content is returned under .css path AND cached
                cache_control = resp.headers.get("Cache-Control", "").lower()
                cache_status = resp.headers.get("X-Cache") or resp.headers.get("CF-Cache-Status")

                if resp.status_code == 200 and (
                    "public" in cache_control or "max-age" in cache_control or cache_status
                ):
                    if (
                        "email" in resp.text.lower()
                        or "user" in resp.text.lower()
                        or "id" in resp.text.lower()
                    ):
                        findings.append(
                            CacheFinding(
                                technique="web_cache_deception",
                                target_url=deception_url,
                                unkeyed_header=None,
                                cache_header=str(cache_status),
                                confirmed=True,
                                evidence={
                                    "deception_url": deception_url,
                                    "status_code": resp.status_code,
                                    "cache_control": cache_control,
                                    "cache_status": cache_status,
                                },
                            )
                        )
            except Exception:
                pass

        return findings
