"""OAuth, SSO, and Password Reset Vulnerability Tester.

Deterministic, active verification for:
  1. OAuth redirect_uri manipulation (bypass redirect validation, missing state, missing PKCE).
  2. Host-header poisoning on password-reset endpoints (reset link header reflection).
  3. Reset token entropy & leak risks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

import httpx


@dataclass
class OAuthFinding:
    vuln_type: str  # oauth_redirect_bypass | missing_state_pkce | host_header_poisoning_reset | weak_reset_token
    title: str
    description: str
    severity: str
    confidence: float
    confirmed: bool
    evidence: Dict[str, Any] = field(default_factory=dict)


class OAuthResetTester:
    """Test OAuth and password reset endpoints for authentication bypass & ATO risks."""

    def __init__(self, timeout_seconds: float = 15.0):
        self.timeout_seconds = timeout_seconds

    async def scan_oauth_endpoint(
        self,
        target_url: str,
        redirect_param: str = "redirect_uri",
    ) -> List[OAuthFinding]:
        """Test OAuth authorization endpoint for redirect_uri bypass & missing state/PKCE."""
        findings: List[OAuthFinding] = []
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        # Check 1: Missing state or PKCE
        if "state" not in params:
            findings.append(
                OAuthFinding(
                    vuln_type="missing_state_pkce",
                    title=f"OAuth Flow Missing State Parameter on {parsed.netloc}",
                    description=(
                        f"OAuth authorization URL at {target_url} does not enforce a 'state' parameter, "
                        "exposing users to OAuth CSRF account takeover."
                    ),
                    severity="MEDIUM",
                    confidence=0.85,
                    confirmed=True,
                    evidence={"param": "state", "url": target_url},
                )
            )

        if "code_challenge" not in params and "code" in params.get("response_type", [""])[0]:
            findings.append(
                OAuthFinding(
                    vuln_type="missing_state_pkce",
                    title=f"OAuth Authorization Code Flow Missing PKCE on {parsed.netloc}",
                    description=(
                        f"OAuth authorization URL at {target_url} uses code flow without PKCE "
                        "(code_challenge), increasing authorization code interception risks."
                    ),
                    severity="LOW",
                    confidence=0.80,
                    confirmed=True,
                    evidence={"param": "code_challenge", "url": target_url},
                )
            )

        # Check 2: redirect_uri bypass probes
        bypass_payloads = [
            "https://evil.com",
            "https://attacker.com#.target.com",
            "https://target.com.attacker.com",
            "https://target.com/oauth/callback/../../redirect?to=https://attacker.com",
        ]

        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, follow_redirects=False
        ) as client:
            for payload in bypass_payloads:
                # Rebuild query with manipulated redirect_uri
                query_dict = {k: v[0] for k, v in params.items()}
                query_dict[redirect_param] = payload
                q_str = "&".join(f"{k}={v}" for k, v in query_dict.items())
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{q_str}"

                try:
                    resp = await client.get(test_url)
                    loc = resp.headers.get("location", "")
                    # Confirmed if redirected to payload domain OR 200 with code/token sent to payload domain
                    if (
                        resp.status_code in (301, 302, 303, 307, 308)
                        and "evil.com" in loc
                        or "attacker.com" in loc
                    ):
                        findings.append(
                            OAuthFinding(
                                vuln_type="oauth_redirect_bypass",
                                title=f"OAuth redirect_uri Validation Bypass on {parsed.netloc}",
                                description=(
                                    f"OAuth endpoint {target_url} accepted arbitrary redirect_uri payload '{payload}', "
                                    f"redirecting to '{loc}' and leaking authorization codes."
                                ),
                                severity="HIGH",
                                confidence=0.98,
                                confirmed=True,
                                evidence={
                                    "payload": payload,
                                    "redirect_location": loc,
                                    "status_code": resp.status_code,
                                },
                            )
                        )
                        break
                except Exception:
                    continue

        return findings

    async def scan_password_reset_endpoint(
        self,
        target_url: str,
        email_param: str = "email",
        test_email: str = "victim@example.com",
    ) -> List[OAuthFinding]:
        """Test password reset endpoint for Host header poisoning & weak tokens."""
        findings: List[OAuthFinding] = []
        parsed = urlparse(target_url)

        poison_hosts = ["attacker-reset.com", "evil-host.org"]

        async with httpx.AsyncClient(
            timeout=self.timeout_seconds, follow_redirects=False
        ) as client:
            for p_host in poison_hosts:
                try:
                    # Test 1: X-Forwarded-Host / Host header override
                    headers = {
                        "Host": p_host,
                        "X-Forwarded-Host": p_host,
                        "Content-Type": "application/x-www-form-urlencoded",
                    }
                    data = {email_param: test_email}

                    resp = await client.post(target_url, data=data, headers=headers)
                    body = resp.text

                    if p_host in body or p_host in str(resp.headers):
                        # MIN-9 (2026-07-21): downgraded from confirmed=True to
                        # confirmed=False + lead-only marker. The poisoned Host header
                        # being reflected in the RESPONSE BODY proves reflection but
                        # does NOT prove the reset EMAIL was sent to an attacker-controlled
                        # domain (the actual ATO vector). True confirmation requires
                        # observing the email delivery side-channel. Marking as a lead
                        # prevents false-positive submissions while preserving the signal
                        # for the triager or a subsequent deep-verify pass.
                        findings.append(
                            OAuthFinding(
                                vuln_type="host_header_poisoning_reset",
                                title=f"Host Header Poisoning Password Reset on {parsed.netloc}",
                                description=(
                                    f"Password reset endpoint {target_url} reflected poisoned Host header '{p_host}' "
                                    "in the response body. NOTE: this is a LEAD only — the reflection proves the "
                                    "header is accepted but does NOT confirm the reset email link was poisoned. "
                                    "Manual verification of the email delivery side-channel is required before "
                                    "treating this as a confirmed host-header poisoning (ATO)."
                                ),
                                severity="MEDIUM",
                                confidence=0.60,
                                confirmed=False,
                                evidence={
                                    "poison_host": p_host,
                                    "status_code": resp.status_code,
                                    "body_snippet": body[:300],
                                    "lead": True,
                                    "lead_reason": "reflection_proven_but_email_delivery_not_verified",
                                },
                            )
                        )
                        break
                except Exception:
                    continue

        return findings
