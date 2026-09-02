"""ServiceAssessmentAgent — Tier-1 network/TLS/SSH specialist.

Charter alignment:
  * services become FIRST-CLASS graph nodes (Asset type=service) so chains like
    internet -> exposed-redis -> no-auth can later be reasoned over
  * probe output flows through the Finding Intelligence Layer: fingerprints are
    OBSERVATIONS; rule matches (legacy TLS, expired cert, EOL SSH) enter as
    WEAKNESS CANDIDATES — never auto-labeled vulnerabilities
  * level hierarchy DETECTED<CANDIDATE<VALIDATED enforced on every finding
"""

import logging
from typing import Any, Dict

from ai_osop.agents.base import BaseAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Asset, Severity, Task, VulnClass, Vulnerability
from ai_osop.core import service_intel as si

logger = logging.getLogger(__name__)


def _tls_vuln_class():
    from ai_osop.core.models import VulnClass

    return getattr(VulnClass, "SSL_TLS_MISCONFIGURATION", VulnClass.NETWORK_ANOMALY)


_TASK_TYPES = {"assess_services", "tls_audit", "ssh_audit"}


class ServiceAssessmentAgent(BaseAgent):
    """DISCOVER->FINGERPRINT->CHECK for network services (Tier 1)."""

    def __init__(self, ctx):
        super().__init__(context=ctx)  # FIX: BaseAgent takes the AgentContext
        self.ctx = ctx

    # FIX (abstract-impl-2026-08-24): BaseAgent declares these as abstract;
    # without implementations the class cannot instantiate and the API lifespan
    # agent bootstrap aborted at this point, killing ALL downstream agents.
    @property
    def agent_type(self) -> AgentType:
        return self._agent_type

    async def _setup_resources(self) -> None:
        pass  # no additional resources beyond base context

    async def _cleanup_resources(self) -> None:
        pass  # no additional resources to clean up

    DETERMINISTIC_TASK_TYPES: frozenset = frozenset({"assess_services", "tls_audit", "ssh_audit"})

    async def _execute(self, task: Task) -> Dict[str, Any]:
        task_type = task.type
        payload = task.payload or {}
        engagement_id = task.engagement_id

        host = payload.get("host") or payload.get("domain") or payload.get("target")
        if not host:
            return {"status": "failed", "error": "service assessment requires host/domain"}

        results: Dict[str, Any] = {
            "status": "success",
            "agent": "service_assessment",
            "host": host,
            "services": [],
            "findings_count": 0,
        }

        # ---- TLS -----------------------------------------------------------
        if task_type in ("assess_services", "tls_audit"):
            tls = await self._off_network(lambda: si.assess_tls(host))
            if tls.get("reachable"):
                svc_id = await self._persist_service(
                    engagement_id, host, tls["port"], "https", evidence=tls
                )
                results["services"].append(svc_id)
                for issue in tls.get("issues", []):
                    await self._emit(
                        engagement_id, host, svc_id, issue, detector="tls-probe", evidence=tls
                    )
                    results["findings_count"] += 1
            results["tls"] = {k: v for k, v in tls.items() if k != "certificate"} | {
                "cert_days": (tls.get("certificate") or {}).get("days_remaining"),
            }

        # ---- SSH -----------------------------------------------------------
        if task_type in ("assess_services", "ssh_audit"):
            ssh = await self._off_network(lambda: si.assess_ssh(host))
            if ssh.get("reachable"):
                svc_id = await self._persist_service(
                    engagement_id, host, ssh["port"], "ssh", evidence={"banner": ssh["banner"]}
                )
                results["services"].append(svc_id)
                for issue in ssh.get("issues", []):
                    await self._emit(
                        engagement_id, host, svc_id, issue, detector="ssh-banner", evidence=ssh
                    )
                    results["findings_count"] += 1
            results["ssh_banner"] = ssh.get("banner")

        return results

    # -- helpers -------------------------------------------------------------

    async def _off_network(self, fn):
        """Blocking socket work off the event loop."""
        import asyncio

        return await asyncio.to_thread(fn)

    async def _persist_service(
        self, engagement_id: str, host: str, port: int, proto: str, evidence: Dict[str, Any]
    ) -> str:
        asset = Asset(
            id=f"svc-{engagement_id[:18]}-{host}-{port}",
            type="service",
            value=f"{proto}://{host}:{port}",
            engagement_id=engagement_id,
        )
        try:
            await self.ctx.graph_memory.add_asset(asset)
        except Exception as e:  # noqa: BLE001 - service node is best-effort
            logger.warning(f"service_node_persist_failed id={asset.id} error={e}")
        return asset.id

    async def _emit(
        self,
        engagement_id: str,
        host: str,
        service_id: str,
        issue: Dict[str, Any],
        detector: str,
        evidence: Dict[str, Any],
    ):
        vuln = Vulnerability(
            title=issue["title"],
            description=(
                f"{issue['title']} on {host}. Detection level: {issue['level']}. "
                f"Why it matters: {issue.get('why_it_matters', 'configuration risk')}."
            ),
            vuln_type=_tls_vuln_class() if detector == "tls-probe" else VulnClass.UNKNOWN,
            severity=Severity.LOW if issue["level"] == si.CANDIDATE else Severity.INFO,
            tool_source=detector,
            asset_id=service_id,
            confidence=0.7 if issue["level"] == si.CANDIDATE else 0.4,
            engagement_id=engagement_id,
            evidence=[
                {
                    "provenance": "probe",
                    **{
                        k: v
                        for k, v in evidence.items()
                        if k in ("banner", "versions", "legacy_versions_accepted")
                    },
                }
            ],
        )
        from ai_osop.core.finding_intelligence import classify_finding

        vclass = classify_finding(vuln)
        vuln.yield_metadata = {
            "finding_class": vclass,
            "detection_level": issue["level"],
            "issue_id": issue["id"],
        }
        si.assert_level_transition(si.DETECTED, issue["level"])
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:  # noqa: BLE001
            logger.warning(f"service_finding_persist_failed error={e}")
