"""
Bug Bounty Platform Adapter
Interfaces with external bug bounty platforms (HackerOne, Bugcrowd)
to sync mission outcomes, triage status, and payouts.
"""

import base64
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
        # AIOSOP-AUDIT-2026-06-16: simulation is the safe default. When on, the
        # adapter NEVER performs live network calls — protecting against accidental
        # submission of AI-generated reports to a live program and making CI/tests
        # deterministic. Disable explicitly via OSOP_BUG_BOUNTY_SIMULATION=false.
        self.simulation_mode = getattr(settings, "bug_bounty_simulation", True)

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
                                finding_type="unknown",  # Would need parsing from report
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

    async def submit_finding(self, finding: Dict[str, Any], platform: str = "h1") -> Dict[str, Any]:
        """
        Submit a verified finding to an external platform.
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
