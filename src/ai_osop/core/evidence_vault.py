import hashlib
import json
import os
from typing import Any, Dict, Optional

import structlog

from ai_osop.core.config import settings
from ai_osop.core.models import EvidencePackage

logger = structlog.get_logger("ai_osop.evidence_vault")


class EvidenceVaultService:
    """
    V6.2: Evidence Vault Integrity Service.
    Handles artifact bundling, hashing, and repository-wide integrity audits.
    """

    def __init__(self, storage_root: str = "evidence_vault"):
        self.storage_root = storage_root
        os.makedirs(self.storage_root, exist_ok=True)

    def generate_package_hash(self, package: EvidencePackage) -> str:
        """Calculate a deterministic SHA-256 hash for the entire evidence package."""
        payload = {
            "requests": package.raw_requests,
            "responses": package.raw_responses,
            "screenshots": package.screenshots,
            "workflow": package.workflow_trace,
            "finding_id": package.finding_id,
        }
        dump = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(dump.encode()).hexdigest()

    async def audit_vault_integrity(self, session_id: str, graph_memory: Any) -> Dict[str, Any]:
        """
        Performs a repository-wide integrity audit.
        Ensures all packages are complete, hashes match, and no MOCK data is present.
        """
        audit_results = {
            "total_packages": 0,
            "corrupted_hashes": [],
            "missing_artifacts": [],
            "mock_contamination": [],
            "integrity_score": 100.0,
        }

        # Query all packages for the engagement
        query = "MATCH (p:EvidencePackage) WHERE p.engagement_id = $eid RETURN p"
        records = await graph_memory.run_read_query(query, {"eid": session_id})
        for record in records:
            audit_results["total_packages"] += 1
            pkg_data = record.get("p")
            if pkg_data:
                pkg = EvidencePackage(**pkg_data)

                # 1. Hash Validation
                current_hash = self.generate_package_hash(pkg)
                if current_hash != pkg.integrity_hash:
                    audit_results["corrupted_hashes"].append(pkg.id)

                # 2. Artifact Check
                if not pkg.raw_requests or not pkg.raw_responses:
                    audit_results["missing_artifacts"].append(pkg.id)

                # 3. Mock Contamination Sweep
                pkg_str = json.dumps(pkg.model_dump()).upper()
                if any(m in pkg_str for m in ["MOCK", "SIMULATED", "PLACEHOLDER", "FAKE"]):
                    audit_results["mock_contamination"].append(pkg.id)

        # Calculate final score
        failures = (
            len(audit_results["corrupted_hashes"])
            + len(audit_results["missing_artifacts"])
            + len(audit_results["mock_contamination"])
        )

        if audit_results["total_packages"] > 0:
            audit_results["integrity_score"] = max(
                0.0, 100.0 - (failures / audit_results["total_packages"]) * 100
            )

        return audit_results


class ReplayabilityTruthEngine:
    """
    V6.2: Replayability Truth Engine.
    Re-executes a finding's replay script in a real sandbox to prove it still
    reproduces. This is a TRUTH engine: it never fabricates a result. If a real
    sandbox runtime is not configured it returns an honest ``unverified`` verdict
    (and never claims success), because a fabricated "replay succeeded" is worse
    than no replay at all — it would mislead a triager and burn researcher trust.

    Inject a SandboxManager for testing; by default a real one is created lazily.
    """

    def __init__(self, sandbox_manager: Optional[Any] = None):
        self._sandbox_manager = sandbox_manager

    async def execute_replay(self, package: EvidencePackage) -> Dict[str, Any]:
        """Re-run the package's replay script in a sandbox and report the truth.

        Returns a dict with ``verified`` (bool) and a ``provenance`` of:
          - ``unverified`` — no replay script, or no real sandbox runtime available
          - ``live``       — the script actually ran in a sandbox; ``verified``
                             reflects its real exit status (never assumed)
        """
        if not package.replay_script:
            return {
                "verified": False,
                "provenance": "unverified",
                "reason": "No replay script provided",
            }

        # Fail closed: without a real sandbox runtime we do NOT run and we do NOT
        # pretend. An honest 'unverified' keeps fabricated proof out of reports.
        if getattr(settings, "sandbox_runtime", "mock") == "mock":
            logger.warning(
                "replay_unverified_no_runtime",
                finding_id=package.finding_id,
                reason="sandbox_runtime is 'mock'; refusing to fabricate a replay result",
            )
            return {
                "verified": False,
                "provenance": "unverified",
                "reason": "No real sandbox runtime configured (sandbox_runtime='mock')",
            }

        # Real re-execution in an isolated sandbox (no egress except DNS), mirroring
        # the exploit-validation path. We trust the actual exit status, not a guess.
        from ai_osop.safety.scope import SandboxManager

        sandbox_mgr = self._sandbox_manager or SandboxManager()
        sandbox_id = f"replay-{package.finding_id[:8]}-{package.id[:8]}"
        try:
            await sandbox_mgr.create_sandbox(
                sandbox_id=sandbox_id,
                network_policy={"egress": {"allowed_domains": [], "allowed_ips": []}},
                resources={
                    "cpu": getattr(settings, "sandbox_cpu_limit", "1"),
                    "memory": getattr(settings, "sandbox_memory_limit", "256m"),
                },
            )
            result = await sandbox_mgr.execute_in_sandbox(
                sandbox_id=sandbox_id,
                command=list(package.replay_script),
                timeout=int(getattr(settings, "sandbox_timeout_seconds", 30)),
            )
        except Exception as e:  # noqa: BLE001 - a replay failure is 'unverified', not success
            logger.warning("replay_execution_error", finding_id=package.finding_id, error=str(e))
            return {
                "verified": False,
                "provenance": "unverified",
                "reason": f"Sandbox replay errored: {e}",
            }
        finally:
            try:
                await sandbox_mgr.destroy_sandbox(sandbox_id)
            except Exception:  # noqa: BLE001 - cleanup best-effort
                pass

        verified = result.get("status") == "success" and result.get("exit_code") == 0
        return {
            "verified": verified,
            "provenance": "live",
            "exit_code": result.get("exit_code"),
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "execution_time": result.get("execution_time"),
        }
