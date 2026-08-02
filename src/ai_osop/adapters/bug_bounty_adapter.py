"""
Bug Bounty Platform Adapter
Interfaces with external bug bounty platforms (HackerOne, Bugcrowd)
to sync mission outcomes, triage status, and payouts.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from ai_osop.core.config import settings
from ai_osop.core.models import OutcomeRecord, OutcomeStatus

logger = logging.getLogger(__name__)


class BugBountyAdapter:
    """
    Adapter for syncing data with bug bounty platforms.
    Currently implements HackerOne live sync.
    """

    def __init__(self):
        self.h1_api_identifier = getattr(settings, "h1_api_identifier", None)
        self.h1_api_key = getattr(settings, "h1_api_key", None)
        self.bc_api_key = getattr(settings, "bc_api_key", None)
        self.h1_base_url = "https://api.hackerone.com/v1"
        # Simulation mode is driven by the OSOP_BUG_BOUNTY_SIMULATION setting.
        # Secure default: True — simulation ON, so the adapter never performs a
        # live network submission unless explicitly opted out. This protects
        # against accidental submission of AI-generated reports to a live
        # program. Read at construction so callers/tests opt in via settings.
        self.simulation_mode = bool(getattr(settings, "bug_bounty_simulation", True))

    def _get_h1_auth(self) -> Optional[httpx.BasicAuth]:
        if self.h1_api_identifier and self.h1_api_key:
            return httpx.BasicAuth(self.h1_api_identifier, self.h1_api_key)
        return None

    def _simulated_outcomes(self, engagement_id: str) -> List[OutcomeRecord]:
        """Deterministic synthetic outcomes used when simulation_mode is on."""
        return [
            OutcomeRecord(
                finding_id=f"sim-{engagement_id}-1",
                finding_type="idor",
                status=OutcomeStatus.TRIAGED,
                severity="high",
                cost_total=0.0,
                time_to_finding_seconds=0,
                agent_id_responsible="external-sync-sim",
                program_name="Simulated Program",
                external_report_id="H1-SIM-0001",
                program_payout=750.0,
                is_accepted=True,
                engagement_id=engagement_id,
            ),
            OutcomeRecord(
                finding_id=f"sim-{engagement_id}-2",
                finding_type="xss",
                status=OutcomeStatus.PAID,
                severity="medium",
                cost_total=0.0,
                time_to_finding_seconds=0,
                agent_id_responsible="external-sync-sim",
                program_name="Simulated Program",
                external_report_id="H1-SIM-0002",
                program_payout=300.0,
                is_accepted=True,
                engagement_id=engagement_id,
            ),
        ]

    def _parse_finding_type_from_h1_report(self, report: Dict[str, Any]) -> str:
        """Parse finding type from HackerOne report structure (weakness fields or title/content)."""
        weakness_data = report.get("relationships", {}).get("weakness", {}).get("data", {})
        if weakness_data:
            weakness_attrs = weakness_data.get("attributes", {})
            weakness_name = (weakness_attrs.get("name") or weakness_data.get("name") or "").lower()
            cwe = (weakness_attrs.get("cwe") or weakness_data.get("cwe") or "").upper()

            if cwe:
                if "CWE-79" in cwe:
                    return "xss"
                if "CWE-89" in cwe:
                    return "sqli"
                if "CWE-918" in cwe:
                    return "ssrf"
                if "CWE-639" in cwe or "CWE-285" in cwe or "CWE-22" in cwe:
                    return "idor"
                if "CWE-352" in cwe:
                    return "csrf"
                if "CWE-94" in cwe or "CWE-78" in cwe:
                    return "rce"
                if "CWE-601" in cwe:
                    return "open_redirect"

            if weakness_name:
                if "xss" in weakness_name or "cross-site scripting" in weakness_name:
                    return "xss"
                if "sql" in weakness_name or "sqli" in weakness_name:
                    return "sqli"
                if "ssrf" in weakness_name or "server-side request" in weakness_name:
                    return "ssrf"
                if (
                    "idor" in weakness_name
                    or "bola" in weakness_name
                    or "access control" in weakness_name
                ):
                    return "idor"
                if "csrf" in weakness_name or "request forgery" in weakness_name:
                    return "csrf"
                if (
                    "remote code" in weakness_name
                    or "rce" in weakness_name
                    or "command execution" in weakness_name
                ):
                    return "rce"
                if "redirect" in weakness_name:
                    return "open_redirect"
                if "graphql" in weakness_name:
                    return "graphql"

        attrs = report.get("attributes", {})
        title = attrs.get("title", "").lower()
        vuln_info = attrs.get("vulnerability_information", "").lower()
        combined = f"{title} {vuln_info}"

        if (
            "xss" in combined
            or "cross-site scripting" in combined
            or "cross site scripting" in combined
        ):
            return "xss"
        if (
            "idor" in combined
            or "bola" in combined
            or "bfla" in combined
            or "broken access" in combined
            or "insecure direct object" in combined
        ):
            return "idor"
        if (
            "ssrf" in combined
            or "server-side request" in combined
            or "server side request" in combined
        ):
            return "ssrf"
        if (
            "csrf" in combined
            or "cross-site request forgery" in combined
            or "cross site request forgery" in combined
        ):
            return "csrf"
        if (
            "nosql" in combined
            or "no-sql" in combined
            or "mongodb" in combined
            or "couchdb" in combined
            or "$where" in combined
        ):
            return "nosql_injection"
        if "sqli" in combined or "sql injection" in combined:
            return "sqli"
        if (
            "rce" in combined
            or "remote code execution" in combined
            or "command injection" in combined
        ):
            return "rce"
        if "redirect" in combined:
            return "open_redirect"
        if "graphql" in combined:
            return "graphql"
        if "race condition" in combined or "toctou" in combined or "time-of-check" in combined:
            return "race_condition"
        if "jwt" in combined or "json web token" in combined:
            return "jwt_abuse"
        if "oauth" in combined or "openid" in combined or "sso" in combined:
            return "oauth2"
        if (
            "s3" in combined
            or "aws" in combined
            or "bucket" in combined
            or "cloud storage" in combined
        ):
            return "cloud_vuln"
        if (
            "prototype pollution" in combined
            or "__proto__" in combined
            or "constructor.prototype" in combined
        ):
            return "prototype_pollution"
        if "cache poison" in combined or "cache deception" in combined or "web cache" in combined:
            return "cache_poisoning"
        if (
            "http/2" in combined
            or "h2c" in combined
            or "http2 desync" in combined
            or "request tunneling" in combined
        ):
            return "http2_desync"
        if "xxe" in combined or "xml external" in combined or "xml injection" in combined:
            return "xxe"
        if "deserialization" in combined or "insecure deserialization" in combined:
            return "deserialization"
        if (
            "path traversal" in combined
            or "directory traversal" in combined
            or "lfi" in combined
            or "local file inclusion" in combined
        ):
            return "path_traversal"
        if (
            "ssti" in combined
            or "server-side template" in combined
            or "template injection" in combined
        ):
            return "ssti"
        if "subdomain takeover" in combined or "dangling cname" in combined:
            return "subdomain_takeover"
        if (
            "business logic" in combined
            or "workflow abuse" in combined
            or "payment bypass" in combined
        ):
            return "business_logic"
        if (
            "information disclosure" in combined
            or "sensitive data" in combined
            or "data exposure" in combined
        ):
            return "info_disclosure"
        if "privilege escalation" in combined or "privesc" in combined:
            return "privesc"
        if "account takeover" in combined or "ato" in combined:
            return "ato"
        if "stored xss" in combined:
            return "stored_xss"
        if "dom xss" in combined or "dom-based xss" in combined:
            return "dom_xss"

        return "unknown"

    async def sync_outcomes(self, engagement_id: str) -> List[OutcomeRecord]:
        """
        Fetch latest outcomes from external platforms for a specific engagement.
        """
        # No credentials at all -> nothing to sync (live or simulated).
        if not (self.h1_api_key or self.bc_api_key):
            logger.info(
                f"No bug-bounty API credentials configured. Skipping sync for {engagement_id}."
            )
            return []

        # Simulation: deterministic synthetic data, no network.
        if self.simulation_mode:
            logger.info(
                f"Bug-bounty simulation mode: returning synthetic outcomes for {engagement_id}."
            )
            return self._simulated_outcomes(engagement_id)

        auth = self._get_h1_auth()
        if not auth:
            logger.warning(
                "HackerOne key present but identifier missing; cannot perform live sync."
            )
            return []

        # Real API sync with HackerOne
        outcomes = []
        try:
            async with httpx.AsyncClient(auth=auth, timeout=10.0) as client:
                # Fetch recent reports created by this integration
                # Note: In a real scenario, you'd filter by program or a specific tag/reference
                # For this implementation, we pull recent reports
                resp = await client.get(f"{self.h1_base_url}/reports")
                if resp.status_code == 200:
                    data = resp.json()
                    reports = data.get("data", [])
                    for report in reports:
                        attrs = report.get("attributes", {})

                        # Map H1 status to our OutcomeStatus
                        h1_state = attrs.get("state", "new")
                        if h1_state == "resolved":
                            status = OutcomeStatus.PAID
                        elif h1_state in ["triaged", "new"]:
                            status = OutcomeStatus.TRIAGED
                        else:
                            status = OutcomeStatus.REJECTED

                        payout = attrs.get("bounty_amount")
                        try:
                            payout_float = float(payout) if payout else 0.0
                        except ValueError:
                            payout_float = 0.0

                        # Try to map back to our internal tracking if we stored it in the title/reference
                        # Defaulting to external sync mapping
                        outcomes.append(
                            OutcomeRecord(
                                finding_id=f"synced-{report['id']}",
                                finding_type=self._parse_finding_type_from_h1_report(report),
                                status=status,
                                severity=attrs.get("severity", {}).get("rating", "medium"),
                                cost_total=0.0,  # Not tracked by H1
                                time_to_finding_seconds=0,
                                agent_id_responsible="external-sync",
                                program_name="HackerOne Program",
                                external_report_id=f"H1-{report['id']}",
                                program_payout=payout_float,
                                is_accepted=(status in [OutcomeStatus.PAID, OutcomeStatus.TRIAGED]),
                                engagement_id=engagement_id,
                            )
                        )
                else:
                    logger.error(f"HackerOne sync failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.error(f"Error during HackerOne sync: {e}")

        return outcomes

    async def submit_finding(
        self,
        finding: Dict[str, Any],
        platform: str = "h1",
        *,
        live_submit_approved: bool = False,
    ) -> Dict[str, Any]:
        """
        Submit a verified finding to an external platform.

        Live submission is FAIL-CLOSED: submitting an AI-generated report to a real
        program requires ``live_submit_approved=True`` (an explicit operator decision),
        never merely "simulation off + credentials present" (AIOSOP-BB-SAFETY-001).
        """
        logger.info(f"Submitting finding {finding.get('id', 'unknown')} to {platform}...")

        if platform.lower() == "h1":
            # Simulation: never submit to a live program. Return a synthetic accept.
            if self.simulation_mode:
                logger.info("Bug-bounty simulation mode: simulating H1 submission (no network).")
                return {
                    "status": "submitted",
                    "external_id": f"H1-SIM-{finding.get('id', 'unknown')}",
                    "platform": "h1",
                    "simulated": True,
                    "timestamp": datetime.utcnow().isoformat(),
                }

            # AIOSOP-BB-SAFETY-001 (2026-07-03): fail closed. Live submission of an
            # AI-generated report to a real program requires an EXPLICIT per-call
            # operator approval — never just "simulation off + credentials present".
            # Without this, a wired-in or future autonomous caller could spam a live
            # bug-bounty program with unreviewed reports. (No production caller today.)
            if not live_submit_approved:
                logger.error(
                    f"live_submit_blocked_no_approval finding_id={finding.get('id', 'unknown')} "
                    f"platform={platform}"
                )
                return {
                    "status": "blocked",
                    "error": "live submission requires explicit operator approval "
                    "(live_submit_approved=True)",
                    "platform": "h1",
                }

            auth = self._get_h1_auth()
            if not auth:
                logger.error("HackerOne API credentials missing.")
                return {"status": "error", "error": "Credentials missing"}

            # Requires program handle; fall back to a default or extract from finding
            program_handle = finding.get("program_handle", "security")

            payload = {
                "data": {
                    "type": "report",
                    "attributes": {
                        "team_handle": program_handle,
                        "title": finding.get("title", "Automated AI-OSOP Vulnerability Report"),
                        "vulnerability_information": finding.get(
                            "description", "No description provided."
                        ),
                        "impact": finding.get("impact", "Not specified"),
                    },
                }
            }

            try:
                async with httpx.AsyncClient(auth=auth, timeout=15.0) as client:
                    resp = await client.post(
                        f"{self.h1_base_url}/reports",
                        json=payload,
                        headers={"Content-Type": "application/json", "Accept": "application/json"},
                    )

                    if resp.status_code in [200, 201]:
                        data = resp.json()
                        report_id = data.get("data", {}).get("id", "unknown")
                        return {
                            "status": "submitted",
                            "external_id": f"H1-{report_id}",
                            "platform": "h1",
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    else:
                        logger.error(
                            f"HackerOne submission failed: {resp.status_code} - {resp.text}"
                        )
                        return {"status": "error", "error": resp.text}
            except Exception as e:
                logger.error(f"Error submitting to HackerOne: {e}")
                return {"status": "error", "error": str(e)}

        # Bugcrowd or other platforms can be added here

        return {
            "status": "error",
            "error": f"Platform {platform} not supported or implemented yet.",
        }
