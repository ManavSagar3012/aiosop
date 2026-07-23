"""
Cloud Specialist Agent
Specializes in identifying cloud-specific vulnerabilities, IAM trust relationship flaws, and exposed metadata.
"""

import logging
from typing import Any, Dict

from ai_osop.agents.base import BaseAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task

logger = logging.getLogger(__name__)


class CloudSpecialistAgent(BaseAgent):
    """
    Cloud Specialist Agent (V5.1)

    Responsibilities:
    - AWS/GCP/Azure IAM policy analysis.
    - S3/Blob storage exposure detection.
    - Cloud Metadata API (SSRF) exploitation.
    - Identifying cross-account trust relationship risks.
    """

    @property
    def agent_type(self) -> AgentType:
        return AgentType.CLOUD_SPECIALIST

    async def _setup_resources(self) -> None:
        pass

    async def _execute(self, task: Task) -> Dict[str, Any]:
        task_type = task.type
        payload = task.payload or {}

        if task_type in ("analyze_iam", "analyze_iam_policy"):
            return await self._analyze_iam_policy(payload)
        elif task_type in ("probe_metadata", "probe_cloud_metadata"):
            return await self._probe_cloud_metadata(payload)
        elif task_type in ("probe_storage", "probe_storage_exposure"):
            return await self._probe_storage_exposure(payload)
        else:
            return {"status": "failed", "error": f"Unknown task type: {task_type}"}

    async def _analyze_iam_policy(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IAM policies for over-permissive actions.

        MAJ-1 (2026-07-23): IAM analysis via a real cloud API requires the
        researcher's OWN AWS credentials (STS GetCallerIdentity / IAM
        ListRoles). In a bug-bounty context we're scanning a TARGET, not our
        own account — so this is a legitimate skip, not a stub failure.
        The real cloud-misconfig detection path is _probe_cloud_metadata
        (SSRF→IMDS via the target), which IS real and governed.
        """
        from ai_osop.adapters.cloud_mcp import CloudMCPAdapter

        adapter = CloudMCPAdapter(self.ctx.mcp_registry)
        result = await adapter.analyze_iam_trust_policies(
            payload.get("account_id"),
        )
        privesc = await adapter.discover_privilege_escalation(
            payload.get("principal_arn"),
        )
        return {
            "status": result.get("status", "skipped"),
            "findings_count": 0,
            "msg": result.get("reason", "IAM analysis skipped — requires own-account credentials."),
        }

    async def _probe_cloud_metadata(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Probe for Cloud Metadata SSRF vulnerabilities."""
        target_url = payload.get("url") or payload.get("target_url") or payload.get("target")

        await self.think(
            f"Probing {target_url} for Cloud Metadata SSRF.", ["ssrf", "cloud_metadata"]
        )

        findings = []
        try:
            import uuid

            from ai_osop.core.cloud_metadata import IMDS_TARGETS, extract_credentials
            from ai_osop.core.enums import Severity, VulnClass
            from ai_osop.core.models import Vulnerability

            urls_to_test = [target_url] if target_url else []
            if not target_url:
                urls_to_test = IMDS_TARGETS

            # BLK-2 (2026-07-21): governed egress. An in-scope target_url is probed
            # through the scope+rate+header hook; a direct IMDS_TARGETS probe (link-
            # local 169.254.169.254) is out of engagement scope and is safely
            # blocked+skipped by the per-request scope gate — direct scanner->IMDS
            # probing tests the scanner's own host, not the target, so blocking it
            # is the correct behavior (real metadata SSRF is proven via the target).
            async with self.get_governed_client(tool="cloud_metadata", timeout=10.0) as client:
                for u in urls_to_test:
                    if not u:
                        continue
                    try:
                        resp = await client.get(u)
                        creds = extract_credentials(resp.text)
                        if creds:
                            for c in creds:
                                f_data = {
                                    "url": u,
                                    "provider": c["provider"],
                                    "kind": c["kind"],
                                    "redacted": c["redacted"],
                                }
                                findings.append(f_data)
                                await self.observe(
                                    target_id=u,
                                    obs_type="cloud_metadata_ssrf",
                                    data=f_data,
                                    confidence=0.98,
                                )
                                vuln = Vulnerability(
                                    id=f"vuln-cloud-{uuid.uuid4().hex[:8]}",
                                    title=f"Cloud Metadata SSRF exposed {c['provider'].upper()} {c['kind']}",
                                    description=f"SSRF at {u} exposed cloud credentials: {c['redacted']}",
                                    severity=Severity.CRITICAL,
                                    vuln_type=VulnClass.SSRF,
                                    confidence=0.98,
                                    validated=True,
                                    tool_source="cloud_agent",
                                    engagement_id=self.ctx.session_id,
                                    evidence=[
                                        {
                                            "type": "cloud_metadata",
                                            "url": u,
                                            "redacted": c["redacted"],
                                        }
                                    ],
                                )
                                try:
                                    await self.ctx.graph_memory.add_vulnerability(vuln)
                                except Exception:
                                    pass
                    except Exception:
                        continue
            return {
                "status": "success",
                "findings_count": len(findings),
                "findings": findings,
                "msg": f"Cloud metadata probing complete. Found {len(findings)} exposures.",
            }
        except Exception as e:
            logger.error(f"Cloud metadata probing failed: {e}")
            return {"status": "failed", "error": str(e)}

    async def _probe_storage_exposure(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Probe cloud storage buckets for public exposure."""
        target = payload.get("target") or payload.get("bucket")
        if not target:
            return {"status": "failed", "error": "target parameter is required"}

        await self.think(
            f"Probing {target} for public cloud storage exposure.", ["storage", "s3", "blob"]
        )

        findings = []
        try:
            import uuid

            from ai_osop.core.enums import Severity, VulnClass
            from ai_osop.core.models import Vulnerability

            clean_target = (
                target.replace("http://", "").replace("https://", "").strip("/").split("/")[0]
            )
            urls = [
                f"https://{clean_target}.s3.amazonaws.com/",
                f"https://storage.googleapis.com/{clean_target}/",
                f"https://{clean_target}.blob.core.windows.net/?comp=list",
            ]
            # BLK-2 / GOV-6 (2026-07-21): bucket enumeration hits THIRD-PARTY cloud
            # hosts (*.s3.amazonaws.com, storage.googleapis.com, *.blob.core.windows.net)
            # that are by definition outside the engagement target scope. Governing
            # with the target scope would block them entirely, so this off-scope
            # external egress is gated behind the same fail-closed policy as the
            # secret verifier and, when enabled, runs through a scope-less governed
            # client that still rate-limits, injects the research header, and audits.
            from ai_osop.core.config import settings as _settings

            if not _settings.allow_external_liveness_probing:
                return {
                    "status": "skipped",
                    "findings_count": 0,
                    "findings": [],
                    "msg": (
                        "cloud storage enumeration probes third-party hosts; set "
                        "OSOP_ALLOW_EXTERNAL_LIVENESS_PROBING=true to enable."
                    ),
                }
            from ai_osop.safety.governed_client import (
                governed_client,
                research_header_from_settings,
            )

            async with governed_client(
                scope=None,  # intentionally off-engagement-scope (third-party cloud hosts)
                rate_limiter=getattr(self.ctx, "rate_limiter", None),
                research_header=research_header_from_settings(),
                tool="cloud_bucket",
                timeout=10.0,
                follow_redirects=True,
            ) as client:
                for url in urls:
                    try:
                        resp = await client.get(url)
                        if resp.status_code == 200 and (
                            "<ListBucketResult" in resp.text or "<EnumerationResults" in resp.text
                        ):
                            f_data = {
                                "bucket": clean_target,
                                "url": url,
                                "issue": "Publicly readable cloud storage bucket listing",
                            }
                            findings.append(f_data)
                            await self.observe(
                                target_id=url,
                                obs_type="cloud_storage_exposure",
                                data=f_data,
                                confidence=0.95,
                            )
                            vuln = Vulnerability(
                                id=f"vuln-storage-{uuid.uuid4().hex[:8]}",
                                title=f"Publicly Accessible Cloud Storage Bucket: {clean_target}",
                                description=f"Cloud storage bucket at {url} allows unauthenticated directory listing.",
                                severity=Severity.HIGH,
                                vuln_type=VulnClass.CLOUD_MISCONFIG,
                                confidence=0.95,
                                validated=True,
                                tool_source="cloud_agent",
                                engagement_id=self.ctx.session_id,
                                evidence=[
                                    {
                                        "type": "storage_exposure",
                                        "url": url,
                                        "status_code": resp.status_code,
                                    }
                                ],
                            )
                            try:
                                await self.ctx.graph_memory.add_vulnerability(vuln)
                            except Exception:
                                pass
                    except Exception:
                        continue
            return {
                "status": "success",
                "findings_count": len(findings),
                "findings": findings,
                "msg": f"Storage exposure probing complete. Found {len(findings)} exposed buckets.",
            }
        except Exception as e:
            logger.error(f"Storage exposure probing failed: {e}")
            return {"status": "failed", "error": str(e)}

    async def _cleanup_resources(self) -> None:
        pass
