"""Read-only operator resource organization derived from immutable Flow bytes.

PentAGI resource/flow-file CRUD writes folders and mirrors files into workers.
AI-OSOP does neither: absent a dedicated migrated alias ledger, a synthetic
virtual folder is a deterministic *view*, NOT a persisted rename/move/copy.
Every request revalidates the signed, tenant-owned PG Flow snapshot. Explicit
Task eligibility additionally requires the original, approved/leased signed
Task and its SHA-pinned inert artifact through the production resource gate.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Dict, List

from ai_osop.memory.authoritative_task_resources import PostgresApprovedTaskResourceVerifier
from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore
from ai_osop.memory.flow_resource_exports import FlowResourceExports
from ai_osop.memory.flow_resource_materialization import (
    ResourceAdmissionDenied,
    SignedFlowTaskResources,
    TaskResourceBinding,
)

_ARTIFACT_ID = re.compile(r"artifact-[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FOLDERS = {"utf8_inert_text": "text", "utf8_inert_source": "source"}


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _catalog(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Expose fixed, collision-free aliases without mutating any stored name."""
    if (
        not isinstance(manifest, dict)
        or manifest.get("format") != "ai-osop-inert-flow-resources-v1"
        or manifest.get("read_only") is not True
        or manifest.get("host_files_created") is not False
        or manifest.get("content_executed") is not False
        or manifest.get("artifact_bytes_untrusted") is not True
        or not _digest(manifest.get("manifest_sha256"))
        or type(manifest.get("count")) is not int
        or not isinstance(manifest.get("items"), list)
        or manifest["count"] != len(manifest["items"])
    ):
        raise ArtifactDenied(503, "Signed immutable Flow resource manifest unavailable")
    aliases: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in manifest["items"]:
        if not isinstance(item, dict) or item.get("classification") not in _FOLDERS:
            raise ArtifactDenied(503, "Inert Flow resource classification unavailable")
        name, artifact_id, sha = item.get("name"), item.get("artifact_id"), item.get("sha256")
        if (
            not isinstance(name, str)
            or not isinstance(artifact_id, str)
            or not _ARTIFACT_ID.fullmatch(artifact_id)
            or not _digest(sha)
            or item.get("resource_path") != "resources/" + name
            or type(item.get("size_bytes")) is not int
            or item["size_bytes"] <= 0
            or artifact_id in seen
        ):
            raise ArtifactDenied(503, "Flow resource identity or metadata changed")
        seen.add(artifact_id)
        folder = _FOLDERS[item["classification"]]
        # IDs, not supplied path segments, guarantee uniqueness. The artifact
        # name is still shown separately as immutable source metadata.
        alias = f"virtual/{folder}/{artifact_id}/{name}"
        aliases.append(
            {
                "artifact_id": artifact_id,
                "original_name": name,
                "alias_path": alias,
                "virtual_folder": f"virtual/{folder}",
                "classification": item["classification"],
                "sha256": sha,
                "size_bytes": item["size_bytes"],
                "available_as_inert_data_only": True,
                "approved_for_task": False,
                "approved_for_agent_instructions": False,
                "executed": False,
            }
        )
    aliases.sort(key=lambda item: item["alias_path"])
    return {
        "format": "ai-osop-derived-flow-resource-aliases-v1",
        "flow_id": manifest["flow_id"],
        "flow_revision": manifest["flow_revision"],
        "authorization_version": manifest["authorization_version"],
        "source_manifest_sha256": manifest["manifest_sha256"],
        "folders": [
            {
                "path": f"virtual/{folder}",
                "count": sum(
                    1 for item in aliases if item["virtual_folder"] == f"virtual/{folder}"
                ),
            }
            for folder in ("text", "source")
        ],
        "items": aliases,
        "count": len(aliases),
        "aliases_persisted": False,
        "virtual_folders_persisted": False,
        "read_only": True,
        "host_files_created": False,
        "container_resource_sync_performed": False,
        "artifact_bytes_untrusted": True,
    }


class FlowResourceAliases:
    """Authenticated Flow resource catalog and explicit signed Task preflight.

    The constructor owns the actual production resource admission interface;
    route clients cannot nominate a verifier, a signed trust assertion, or
    alternative storage. No file bytes are returned to an API caller.
    """

    def __init__(self, artifacts: FlowArtifactStore) -> None:
        if type(artifacts) is not FlowArtifactStore:
            raise ArtifactDenied(503, "Production immutable Flow artifact store required")
        self.artifacts = artifacts
        self.task_resources = SignedFlowTaskResources(
            artifacts,
            PostgresApprovedTaskResourceVerifier(artifacts.session_memory),
        )

    async def _current(
        self, flow_id: str, owner: str, revision: int, version: int
    ) -> Dict[str, Any]:
        manifest, _ = await FlowResourceExports(self.artifacts).prepare(
            flow_id,
            owner,
            revision,
            version,
        )
        return _catalog(manifest)

    async def list(self, flow_id: str, owner: str, revision: int, version: int) -> Dict[str, Any]:
        return await self._current(flow_id, owner, revision, version)

    async def preview(
        self,
        flow_id: str,
        owner: str,
        revision: int,
        version: int,
        artifact_id: str,
        expected_manifest_sha256: str,
    ) -> Dict[str, Any]:
        """Read-only classification of ONE immutable, SHA-checked resource."""
        if not isinstance(artifact_id, str) or not _ARTIFACT_ID.fullmatch(artifact_id):
            raise ArtifactDenied(404, "Flow artifact not found")
        if not _digest(expected_manifest_sha256):
            raise ArtifactDenied(422, "Explicit current manifest SHA required")
        before = await self._current(flow_id, owner, revision, version)
        if not hmac.compare_digest(before["source_manifest_sha256"], expected_manifest_sha256):
            raise ArtifactDenied(409, "Flow resource manifest changed")
        matched = [item for item in before["items"] if item["artifact_id"] == artifact_id]
        if len(matched) != 1:
            raise ArtifactDenied(404, "Flow resource not present in signed manifest")
        # Recheck after the awaited source read: no stale operator decision or
        # signed ROE is inferred from an earlier cached catalog.
        after = await self._current(flow_id, owner, revision, version)
        if after != before:
            raise ArtifactDenied(409, "Flow resources changed during preview")
        return {
            **matched[0],
            "flow_id": flow_id,
            "flow_revision": revision,
            "authorization_version": version,
            "source_manifest_sha256": expected_manifest_sha256,
            "preview_contains_artifact_bytes": False,
            "replayable_or_executable": False,
        }

    async def task_preview(
        self,
        flow_id: str,
        owner: str,
        revision: int,
        version: int,
        *,
        engagement_id: str,
        task_id: str,
        artifact_id: str,
        artifact_sha256: str,
        authorization_sha256: str,
        expected_manifest_sha256: str,
    ) -> Dict[str, Any]:
        """Preflight CURRENT approved Task against the immutable inert source.

        The existing task verifier checks signed ROE, tenant/owner, running
        Task/Flow/Subtask, exact pinned human approval, active lease and
        command digest before and after the SHA-verified byte read. Success is
        not execution, resource transfer, folder creation, or sync.
        """
        if not all(
            _digest(item)
            for item in (
                artifact_sha256,
                authorization_sha256,
                expected_manifest_sha256,
            )
        ):
            raise ArtifactDenied(422, "Exact signed Task/resource digests required")
        before = await self._current(flow_id, owner, revision, version)
        if not hmac.compare_digest(before["source_manifest_sha256"], expected_manifest_sha256):
            raise ArtifactDenied(409, "Flow resource manifest changed")
        candidates = [item for item in before["items"] if item["artifact_id"] == artifact_id]
        if len(candidates) != 1 or not hmac.compare_digest(
            candidates[0]["sha256"], artifact_sha256
        ):
            raise ArtifactDenied(409, "Approved resource not in current Flow snapshot")
        binding = TaskResourceBinding(
            engagement_id=engagement_id,
            flow_id=flow_id,
            owner_id=owner,
            task_id=task_id,
            flow_revision=revision,
            authorization_version=version,
            authorization_sha256=authorization_sha256,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
        )
        try:
            # Pin the approved exact command across the additional final
            # catalog read; a different approved command is NOT equivalent.
            before_task = await self.task_resources.verify_approved_task(binding)
            command_sha256 = before_task.get("approved_command_sha256")
            if (
                before_task.get("approved") is not True
                or before_task.get("active") is not True
                or any(
                    before_task.get(field) != getattr(binding, field)
                    for field in (
                        "engagement_id",
                        "flow_id",
                        "owner_id",
                        "task_id",
                        "flow_revision",
                        "authorization_version",
                        "authorization_sha256",
                    )
                )
                or not _digest(command_sha256)
            ):
                raise ResourceAdmissionDenied("Current approved command unavailable")
            metadata, content = await self.task_resources.read(binding)
        except ResourceAdmissionDenied as exc:
            raise ArtifactDenied(403, "Approved signed Task resource unavailable") from exc
        if (
            not isinstance(content, bytes)
            or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), artifact_sha256)
            or metadata.get("artifact_id") != artifact_id
            or metadata.get("kind") != candidates[0]["classification"]
            or metadata.get("size_bytes") != candidates[0]["size_bytes"]
        ):
            raise ArtifactDenied(503, "Task resource bytes or classification inconsistent")
        after = await self._current(flow_id, owner, revision, version)
        if after != before:
            raise ArtifactDenied(409, "Flow resource manifest changed during Task preview")
        # An API preview is NOT a claim for future tool use. Revalidate the
        # signed Task admission after the final awaited catalog read as well.
        try:
            current = await self.task_resources.verify_approved_task(binding)
        except Exception as exc:
            raise ArtifactDenied(403, "Task approval changed during preview") from exc
        if (
            not isinstance(current, dict)
            or current.get("approved") is not True
            or current.get("active") is not True
            or any(
                current.get(field) != getattr(binding, field)
                for field in (
                    "engagement_id",
                    "flow_id",
                    "owner_id",
                    "task_id",
                    "flow_revision",
                    "authorization_version",
                    "authorization_sha256",
                )
            )
            or not _digest(current.get("approved_command_sha256"))
            or not hmac.compare_digest(current["approved_command_sha256"], command_sha256)
        ):
            raise ArtifactDenied(403, "Task admission no longer current")
        return {
            **candidates[0],
            "flow_id": flow_id,
            "flow_revision": revision,
            "authorization_version": version,
            "source_manifest_sha256": expected_manifest_sha256,
            "task_id": task_id,
            "signed_task_currently_approved": True,
            "approved_command_sha256": current["approved_command_sha256"],
            "approved_for_agent_instructions": False,
            "preview_contains_artifact_bytes": False,
            "resource_transferred_to_worker": False,
            "container_resource_sync_performed": False,
            "execution_started_by_preview": False,
        }
