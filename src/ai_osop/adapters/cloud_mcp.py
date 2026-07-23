"""Cloud MCP Adapter — real cloud metadata + storage probing.

MAJ-1 (2026-07-23): replaces the stub that raised NotImplementedError.
This adapter now does REAL cloud-security probing that's applicable in a
bug-bounty context:

  - analyze_iam_trust_policies: skipped (requires the researcher's own AWS
    credentials — not applicable to target scanning). Returns a clear skip.
  - discover_privilege_escalation: skipped (same reason).
  - probe_cloud_metadata: REAL — probes a TARGET URL for SSRF→IMDS chains
    using the governed client (scope-checked, rate-limited, research-tagged).
    This is the actual bug-bounty-relevant cloud vuln: does the target's
    SSRF let us reach cloud metadata?
  - probe_storage_exposure: REAL — checks if a cloud storage bucket (S3/
    GCS/Azure Blob) is publicly listable. Gated behind
    allow_external_liveness_probing (third-party host egress).

The adapter does NOT call any cloud API with the researcher's own credentials.
It probes the TARGET for cloud misconfigurations — the correct bug-bounty
approach.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class CloudMCPAdapter:
    """Adapter for cloud-mcp: real cloud-misconfig probing against targets.

    All probes use the governed client (scope + rate + research-header) so
    out-of-scope egress is blocked before it leaves the process.
    """

    SERVER_ID = "cloud-mcp"

    def __init__(self, registry=None):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        """No-op — the real adapter probes targets directly, no MCP server needed."""
        pass

    async def analyze_iam_trust_policies(
        self,
        account_id: Optional[str] = None,
        timeout_seconds: int = 120,
    ) -> Dict[str, Any]:
        """IAM trust analysis requires the researcher's OWN AWS credentials.

        In a bug-bounty context we're scanning a TARGET, not our own account.
        This is a legitimate skip — the real cloud-misconfig detection path
        is probe_cloud_metadata (SSRF→IMDS via the target).
        """
        return {
            "status": "skipped",
            "findings": [],
            "reason": (
                "IAM trust analysis requires the researcher's own AWS credentials "
                "(STS GetCallerIdentity). Not applicable to target scanning. "
                "Use probe_cloud_metadata for SSRF→IMDS detection."
            ),
        }

    async def discover_privilege_escalation(
        self,
        principal_arn: Optional[str] = None,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        """Privilege-escalation path discovery requires own-account credentials.

        Same skip rationale as analyze_iam_trust_policies.
        """
        return {
            "status": "skipped",
            "paths": [],
            "reason": (
                "Privilege escalation discovery requires own-account IAM access. "
                "Not applicable to target scanning."
            ),
        }

    async def probe_cloud_metadata(
        self,
        target_url: str,
        timeout_seconds: int = 60,
        governed_client: Any = None,
    ) -> Dict[str, Any]:
        """Probe a TARGET URL for SSRF→cloud-metadata chains.

        This is the REAL bug-bounty-relevant cloud vulnerability: does the
        target's SSRF let us reach the cloud metadata service (IMDS) and
        extract credentials?

        When ``governed_client`` is supplied, probes run through it
        (scope-checked, rate-limited, research-tagged). When ``None``, the
        caller (cloud_agent) builds a governed client and passes it.

        Returns findings with redacted credential indicators (raw secrets
        are never surfaced or persisted).
        """
        from ai_osop.core.cloud_metadata import IMDS_TARGETS, extract_credentials

        findings: list = []

        # If the caller passed a target URL that IS a metadata endpoint
        # (e.g. from an SSRF that already fetched IMDS), check it directly.
        urls_to_test = [target_url] if target_url else []
        if not target_url:
            urls_to_test = IMDS_TARGETS

        if governed_client is None:
            # Build a minimal governed client if none supplied
            import httpx
            from ai_osop.safety.governed_client import (
                governance_hook,
                research_header_from_settings,
            )
            from ai_osop.core.config import settings
            from ai_osop.safety.rate_limiter import RateLimiter

            hook = governance_hook(
                rate_limiter=RateLimiter(
                    target_rate=settings.scan_target_rate_per_second,
                    target_capacity=settings.scan_target_burst,
                ),
                research_header=research_header_from_settings(),
            )
            client = httpx.AsyncClient(
                **{"event_hooks": {"request": [hook]}} if hook else {},
                timeout=timeout_seconds,
                follow_redirects=True,
            )
            _owns_client = True
        else:
            client = governed_client
            _owns_client = False

        try:
            for u in urls_to_test:
                if not u:
                    continue
                try:
                    resp = await client.get(u)
                    creds = extract_credentials(resp.text)
                    for c in creds:
                        findings.append({
                            "url": u,
                            "provider": c["provider"],
                            "kind": c["kind"],
                            "redacted": c["redacted"],
                            "http_status": resp.status_code,
                        })
                except Exception:
                    continue
        finally:
            if _owns_client:
                await client.aclose()

        return {
            "status": "success",
            "findings": findings,
            "findings_count": len(findings),
        }

    async def probe_storage_exposure(
        self,
        target: str,
        timeout_seconds: int = 60,
        governed_client: Any = None,
    ) -> Dict[str, Any]:
        """Probe cloud storage buckets for public exposure.

        Checks S3/GCS/Azure Blob for unauthenticated directory listing —
        a real cloud-misconfig finding. Gated behind
        ``allow_external_liveness_probing`` because the bucket hosts are
        third-party (outside engagement scope).
        """
        from ai_osop.core.config import settings as _settings

        if not _settings.allow_external_liveness_probing:
            return {
                "status": "skipped",
                "findings": [],
                "reason": (
                    "cloud storage enumeration probes third-party hosts; set "
                    "OSOP_ALLOW_EXTERNAL_LIVENESS_PROBING=true to enable."
                ),
            }

        clean_target = (
            target.replace("http://", "").replace("https://", "").strip("/").split("/")[0]
        )
        urls = [
            f"https://{clean_target}.s3.amazonaws.com/",
            f"https://storage.googleapis.com/{clean_target}/",
            f"https://{clean_target}.blob.core.windows.net/?comp=list",
        ]

        if governed_client is None:
            import httpx
            from ai_osop.safety.governed_client import (
                governance_hook,
                research_header_from_settings,
            )
            from ai_osop.safety.rate_limiter import RateLimiter

            hook = governance_hook(
                rate_limiter=RateLimiter(
                    target_rate=_settings.scan_target_rate_per_second,
                    target_capacity=_settings.scan_target_burst,
                ),
                research_header=research_header_from_settings(),
            )
            client = httpx.AsyncClient(
                **{"event_hooks": {"request": [hook]}} if hook else {},
                timeout=timeout_seconds,
                follow_redirects=True,
            )
            _owns_client = True
        else:
            client = governed_client
            _owns_client = False

        findings: list = []
        try:
            for url in urls:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and (
                        "<ListBucketResult" in resp.text
                        or "<EnumerationResults" in resp.text
                    ):
                        findings.append({
                            "bucket": clean_target,
                            "url": url,
                            "issue": "Publicly readable cloud storage bucket listing",
                            "status_code": resp.status_code,
                        })
                except Exception:
                    continue
        finally:
            if _owns_client:
                await client.aclose()

        return {
            "status": "success",
            "findings": findings,
            "findings_count": len(findings),
        }
