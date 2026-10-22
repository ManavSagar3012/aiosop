"""Read-only per-task access to original, signed Flow artifact bytes.

This is an in-memory protocol. Callers must provide an independently verified
durable task admission callback; no host path, archive, or agent prompt is made.
Every read rechecks that admission and the signed artifact store fence.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Awaitable, Callable, Mapping

from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore
from ai_osop.memory.flow_resource_exports import _kind_and_validate

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_TASK_RESOURCE_BYTES = 2 * 1024 * 1024


class ResourceAdmissionDenied(Exception):
    """The signed durable task or original artifact failed verification."""


@dataclass(frozen=True)
class TaskResourceBinding:
    engagement_id: str
    flow_id: str
    owner_id: str
    task_id: str
    flow_revision: int
    authorization_version: int
    authorization_sha256: str
    artifact_id: str
    artifact_sha256: str

    def validate(self) -> None:
        for value in (self.engagement_id, self.flow_id, self.owner_id, self.task_id):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ResourceAdmissionDenied("Invalid durable task identity")
        if not isinstance(self.artifact_id, str) or not re.fullmatch(
            r"artifact-[0-9a-f]{32}", self.artifact_id
        ):
            raise ResourceAdmissionDenied("Invalid original artifact identity")
        if any(
            not isinstance(x, str) or not _SHA.fullmatch(x)
            for x in (self.authorization_sha256, self.artifact_sha256)
        ):
            raise ResourceAdmissionDenied("Invalid signed digest binding")
        if (
            type(self.flow_revision) is not int
            or self.flow_revision < 0
            or type(self.authorization_version) is not int
            or self.authorization_version < 1
        ):
            raise ResourceAdmissionDenied("Invalid signed revision binding")


AdmissionVerifier = Callable[[TaskResourceBinding], Awaitable[Mapping[str, object]]]


class SignedFlowTaskResources:
    """Accept a verified admission assertion and return immutable in-memory bytes.

    The verifier must obtain the original approved TaskORM and signed policy
    from authoritative PostgreSQL on every call. Its response binds the exact
    immutable fields and `approved=True`, `active=True`; mere task IDs or
    graph/provider assertions do not grant access.
    """

    def __init__(self, artifacts: FlowArtifactStore, verify_approved_task: AdmissionVerifier):
        if not callable(verify_approved_task):
            raise ResourceAdmissionDenied("Durable task verifier required")
        self.artifacts = artifacts
        self.verify_approved_task = verify_approved_task

    async def read(self, binding: TaskResourceBinding) -> tuple[dict[str, object], bytes]:
        if not isinstance(binding, TaskResourceBinding):
            raise ResourceAdmissionDenied("Explicit task resource binding required")
        binding.validate()
        try:
            admission = await self.verify_approved_task(binding)
        except Exception as exc:
            raise ResourceAdmissionDenied("Durable task admission unavailable") from exc
        if not isinstance(admission, Mapping):
            raise ResourceAdmissionDenied("Durable task admission unavailable")
        fields = (
            "engagement_id",
            "flow_id",
            "owner_id",
            "task_id",
            "flow_revision",
            "authorization_version",
            "authorization_sha256",
        )
        if (
            admission.get("approved") is not True
            or admission.get("active") is not True
            or any(admission.get(name) != getattr(binding, name) for name in fields)
        ):
            raise ResourceAdmissionDenied("Task approval or signed scope changed")
        # The immutable resource binding alone does not pin which exact argv
        # the human reviewed. Do not accept a missing or malformed command
        # digest from a supposed signed Task admission response.
        approved_command_sha256 = admission.get("approved_command_sha256")
        if (
            type(approved_command_sha256) is not str
            or _SHA.fullmatch(approved_command_sha256) is None
        ):
            raise ResourceAdmissionDenied("Approved Task command digest unavailable")
        try:
            metadata, original = await self.artifacts.read(
                binding.flow_id,
                binding.artifact_id,
                binding.owner_id,
                binding.flow_revision,
                binding.authorization_version,
            )
        except ArtifactDenied as exc:
            raise ResourceAdmissionDenied("Original signed artifact unavailable") from exc
        if not isinstance(original, bytes) or not 0 < len(original) <= MAX_TASK_RESOURCE_BYTES:
            raise ResourceAdmissionDenied("Original artifact exceeds task resource limit")
        observed = hashlib.sha256(original).hexdigest()
        if (
            not hmac.compare_digest(observed, binding.artifact_sha256)
            or metadata.get("sha256") != observed
            or metadata.get("id") != binding.artifact_id
            or metadata.get("flow_id") != binding.flow_id
            or metadata.get("authorization_version") != binding.authorization_version
            or metadata.get("flow_revision") != binding.flow_revision
        ):
            raise ResourceAdmissionDenied("Original artifact lineage or digest changed")
        try:
            kind = _kind_and_validate(metadata.get("name"), original)
        except (ArtifactDenied, TypeError, ValueError) as exc:
            raise ResourceAdmissionDenied("Original resource is not inert text") from exc
        # ArtifactStore.read holds its own signed PG transaction, not the
        # Task/human-approval/lease transaction above. The lease or approval can
        # be revoked while we await artifact bytes. scope.py otherwise passes
        # these bytes into Docker's tmpfs *before* its post-transfer reread;
        # fail here to avoid handing revoked bytes to the daemon even briefly.
        try:
            current = await self.verify_approved_task(binding)
        except Exception as exc:
            raise ResourceAdmissionDenied(
                "Durable task admission changed during resource read"
            ) from exc
        if (
            not isinstance(current, Mapping)
            or current.get("approved") is not True
            or current.get("active") is not True
            or any(current.get(name) != getattr(binding, name) for name in fields)
            or type(current.get("approved_command_sha256")) is not str
            or not hmac.compare_digest(current["approved_command_sha256"], approved_command_sha256)
        ):
            raise ResourceAdmissionDenied(
                "Task approval or command digest changed during resource read"
            )
        return (
            {
                "artifact_id": binding.artifact_id,
                "sha256": observed,
                "size_bytes": len(original),
                "name": metadata["name"],
                "kind": kind,
                "classification": "untrusted_original_flow_artifact",
                "approved_for_agent_instructions": False,
            },
            original,
        )
