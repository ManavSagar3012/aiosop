"""Signed and reviewed Flow resource snapshot, returned exclusively as inert bytes.

This is a handoff protocol, not a host mount, archive extraction, or agent
instruction channel. Review and task authorization must be rechecked by the
caller immediately before subsequent use.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore, _identity
from ai_osop.memory.flow_resource_exports import make_manifest


class SnapshotDenied(ValueError):
    """A current signed, reviewed, immutable resource handoff is unavailable."""


@dataclass(frozen=True)
class SnapshotBinding:
    engagement_id: str
    flow_id: str
    owner_id: str
    flow_revision: int
    authorization_version: int
    authorization_id: str
    authorization_sha256: str


@dataclass(frozen=True)
class SnapshotResource:
    artifact_id: str
    name: str
    sha256: str
    content: bytes
    classification: str = "untrusted_reviewed_flow_data"


@dataclass(frozen=True)
class SealedFlowSnapshot:
    binding: SnapshotBinding
    resources: tuple[SnapshotResource, ...]
    manifest_sha256: str
    approved_for_agent_instructions: bool = False


Reviewer = Callable[..., Awaitable[Mapping[str, Any] | None]]


class FlowResourceSnapshot:
    """Recheck PostgreSQL signed source and independent senior reviews.

    `review_approval` must be the real FlowArtifactReviewStore.read_verified_approval
    or a compatible trusted reviewer; it must perform its own durable signed
    authorization and reviewer revocation guard. The caller must arrange a
    current approved-task check separately before consuming returned bytes.
    """

    def __init__(self, artifact_store: FlowArtifactStore, review_approval: Reviewer):
        if not callable(review_approval):
            raise SnapshotDenied("Independent durable reviewer required")
        self.artifacts = artifact_store
        self.review_approval = review_approval

    async def read(self, binding: SnapshotBinding) -> SealedFlowSnapshot:
        if not isinstance(binding, SnapshotBinding):
            raise SnapshotDenied("Explicit signed Flow binding required")
        try:
            _identity(binding.flow_id, binding.owner_id, binding.flow_revision,
                      binding.authorization_version)
        except ArtifactDenied as exc:
            raise SnapshotDenied("Invalid Flow identity") from exc
        if (not isinstance(binding.engagement_id, str) or not binding.engagement_id
                or not isinstance(binding.authorization_id, str) or not binding.authorization_id
                or not isinstance(binding.authorization_sha256, str)
                or len(binding.authorization_sha256) != 64
                or any(ch not in "0123456789abcdef" for ch in binding.authorization_sha256)):
            raise SnapshotDenied("Invalid tenant or signed policy binding")
        try:
            # Single transaction for the whole original signed-byte snapshot.
            originals = await self.artifacts.read_resource_snapshot(
                binding.flow_id, binding.owner_id, binding.flow_revision,
                binding.authorization_version)
            manifest = make_manifest(binding.flow_id, binding.flow_revision,
                                     binding.authorization_version, originals)
            indexed = {item["artifact_id"]: item for item in manifest["items"]}
            resources = []
            for meta, content in originals:
                file = indexed.get(meta["id"])
                if file is None or not isinstance(content, bytes):
                    raise SnapshotDenied("Original artifact missing from checked manifest")
                receipt = await self.review_approval(
                    flow_id=binding.flow_id, artifact_id=meta["id"],
                    revision=binding.flow_revision, version=binding.authorization_version,
                    sha256=file["sha256"], authorization_id=binding.authorization_id,
                    authorization_sha256=binding.authorization_sha256)
                if (not isinstance(receipt, Mapping)
                        or receipt.get("verified_review") is not True
                        or receipt.get("approved") is not True
                        or receipt.get("artifact_id") != meta["id"]):
                    raise SnapshotDenied("Current independent artifact review required")
                if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), file["sha256"]):
                    raise SnapshotDenied("Artifact bytes changed")
                resources.append(SnapshotResource(meta["id"], file["name"],
                                                  file["sha256"], content))
            # Re-read the original signed source after review checks, denying
            # revoked, replaced or changed rows across separate transactions.
            current = await self.artifacts.read_resource_snapshot(
                binding.flow_id, binding.owner_id, binding.flow_revision,
                binding.authorization_version)
            fresh = make_manifest(binding.flow_id, binding.flow_revision,
                                  binding.authorization_version, current)
            if fresh != manifest:
                raise SnapshotDenied("Signed Flow resource snapshot changed during reviews")
            # Revalidate each independent approval after the second source
            # fence, closing the straightforward review/revocation gap.
            for resource in resources:
                fresh_receipt = await self.review_approval(
                    flow_id=binding.flow_id, artifact_id=resource.artifact_id,
                    revision=binding.flow_revision, version=binding.authorization_version,
                    sha256=resource.sha256, authorization_id=binding.authorization_id,
                    authorization_sha256=binding.authorization_sha256)
                if (not isinstance(fresh_receipt, Mapping)
                        or fresh_receipt.get("verified_review") is not True
                        or fresh_receipt.get("approved") is not True
                        or fresh_receipt.get("artifact_id") != resource.artifact_id):
                    raise SnapshotDenied("Artifact review revoked during snapshot")
            return SealedFlowSnapshot(binding, tuple(resources), manifest["manifest_sha256"])
        except SnapshotDenied:
            raise
        except Exception as exc:
            raise SnapshotDenied("Signed Flow resource snapshot unavailable") from exc
