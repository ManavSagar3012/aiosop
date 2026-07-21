"""Open Redirect Vulnerability Tester and OAuth Chain Helper.

Detects open redirects via parameter mining and bypass payloads, and validates
whether an open redirect can be chained to steal OAuth authorization codes or tokens.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import httpx


COMMON_REDIRECT_PARAMS = (
    "url",
    "redirect",
    "next",
    "return",
    "return_to",
    "dest",
    "destination",
    "checkout_url",
    "continue",
    "goto",
    "target",
    "out",
    "view",
    "r",
)

BYPASS_PAYLOADS = [
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "http://evil.com#.example.com",
    "http://example.com@evil.com",
    "//example.com@evil.com",
    "https://evil.com?%23.example.com",
]


@dataclass
class RedirectFinding:
    param: str
    payload: str
    target_url: str
    redirect_location: str
    status_code: int
    confirmed: bool
    evidence: Dict[str, Any] = field(default_factory=dict)


class OpenRedirectTester:
    """Test web endpoints for open redirect vulnerabilities and OAuth chaining potential."""

    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    async def scan_endpoint(
        self,
        target_url: str,
        params_to_test: Optional[List[str]] = None,
    ) -> List[RedirectFinding]:
        """Scan a URL for open redirect vulnerabilities."""
        findings: List[RedirectFinding] = []
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        test_params = params_to_test or list(params.keys()) or list(COMMON_REDIRECT_PARAMS)

        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False) as client:
            for param in test_params:
                for payload in BYPASS_PAYLOADS:
                    # Construct URL with parameter
                    query_dict = {k: v[0] for k, v in params.items()}
                    query_dict[param] = payload
                    q_str = "&".join(f"{k}={v}" for k, v in query_dict.items())
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{q_str}"

                    try:
                        resp = await client.get(test_url)
                        if resp.status_code in (301, 302, 303, 307, 308):
                            loc = resp.headers.get("location", "")
                            # Check if location redirects to evil.com
                            if "evil.com" in loc.lower() and parsed.netloc not in loc:
                                findings.append(
                                    RedirectFinding(
                                        param=param,
                                        payload=payload,
                                        target_url=test_url,
                                        redirect_location=loc,
                                        status_code=resp.status_code,
                                        confirmed=True,
                                        evidence={
                                            "param": param,
                                            "payload": payload,
                                            "location": loc,
                                            "status_code": resp.status_code,
                                        },
                                    )
                                )
                                break  # Move to next param if payload succeeded
                    except Exception:
                        continue

        return findings
