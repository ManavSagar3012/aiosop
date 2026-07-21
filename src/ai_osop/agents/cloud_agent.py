"""
Cloud Specialist Agent
Specializes in identifying cloud-specific vulnerabilities, IAM trust relationship flaws, and exposed metadata.
"""

import logging
from typing import Any, Dict

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
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
        """Analyze IAM policies for over-permissive actions."""
        target_account = payload.get("account_id")
        target_principal = payload.get("principal_arn")

        await self.think(
            "Analyzing IAM policy for excessive permissions and trust relationships.",
            ["iam", "least_privilege", "privilege_escalation"],
        )

        try:
            from ai_osop.adapters.cloud_mcp import CloudMCPAdapter

            # PATCH (REL-034, 2026-06-15): self.context -> self.ctx (BaseAgent
            # stores AgentContext as self.ctx; self.context is undefined).
            adapter = CloudMCPAdapter(self.ctx.mcp_registry)
            await adapter.initialize(
                self.ctx.scope.model_dump() if self.ctx.scope else {},
                self.ctx.session_id,
            )

            findings = []

            # Analyze trusts
            trust_results = await adapter.analyze_iam_trust_policies(target_account)
            for f in trust_results.get("findings", []):
                findings.append(f)
                await self.observe(
                    target_id=f.get("role", "unknown-role"),
                    obs_type="cloud_iam_trust_misconfig",
                    data=f,
                    confidence=0.9,
                )

            # Discover privesc
            privesc_results = await adapter.discover_privilege_escalation(target_principal)
            for p in privesc_results.get("paths", []):
                findings.append(p)
                await self.observe(
                    target_id=p.get("target", "unknown-target"),
                    obs_type="cloud_iam_privesc",
                    data=p,
                    confidence=0.95,
                )

            return {
                "status": "success",
                "findings_count": len(findings),
                "msg": f"IAM policy analysis complete. Found {len(findings)} risks.",
            }

        except Exception as e:
            logger.error(f"Failed to analyze IAM roles: {e}")
            return {"status": "failed", "error": str(e)}

    async def _probe_cloud_metadata(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Probe for Cloud Metadata SSRF vulnerabilities."""
        target_url = payload.get("url") or payload.get("target_url") or payload.get("target")

        await self.think(
            f"Probing {target_url} for Cloud Metadata SSRF.", ["ssrf", "cloud_metadata"]
        )

        findings = []
        try:
            import httpx
            from ai_osop.core.cloud_metadata import IMDS_TARGETS, extract_credentials
            from ai_osop.core.config import Severity, VulnClass
            from ai_osop.core.models import Vulnerability
            import uuid

            urls_to_test = [target_url] if target_url else []
            if not target_url:
                urls_to_test = IMDS_TARGETS

            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
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
                                    evidence=[{"type": "cloud_metadata", "url": u, "redacted": c["redacted"]}],
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
            import httpx
            from ai_osop.core.config import Severity, VulnClass
            from ai_osop.core.models import Vulnerability
            import uuid

            clean_target = target.replace("http://", "").replace("https://", "").strip("/").split("/")[0]
            urls = [
                f"https://{clean_target}.s3.amazonaws.com/",
                f"https://storage.googleapis.com/{clean_target}/",
                f"https://{clean_target}.blob.core.windows.net/?comp=list",
            ]
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                for url in urls:
                    try:
                        resp = await client.get(url)
                        if resp.status_code == 200 and ("<ListBucketResult" in resp.text or "<EnumerationResults" in resp.text):
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
                                evidence=[{"type": "storage_exposure", "url": url, "status_code": resp.status_code}],
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
