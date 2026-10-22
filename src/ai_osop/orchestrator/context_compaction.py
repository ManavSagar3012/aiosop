"""Deterministic, extractive context for bounded long-running agent workflows.

Unlike model-generated text, this is a *non-authoritative*, replayable index of
durable source records. The caller MUST independently verify its signed ROE,
flow/task revisions and ownership before supplying a boundary or source loader.
This module never changes approval state, signed policies, or original evidence.
It deliberately emits no source payload, LLM prose, free-text description,
target, credential or raw evidence into the downstream prompt.

PentAGI's flow/task-scoped summarizer motivated explicit partitioning here; its
LLM summaries are NOT treated as a security/authentication authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Mapping, Sequence

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_SOURCE_ID = re.compile(r"(?:task|evt|action|vuln)-[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_TASK_ID = re.compile(r"task-[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SOURCES = frozenset({"durable_task", "durable_event", "durable_tool_receipt", "validated_finding"})
_STATUSES = frozenset(
    {
        "pending",
        "running",
        "completed",
        "failed",
        "cancelled",
        "blocked",
        "unknown",
        "paused",
        "rejected",
        "approved",
        "revoked",
    }
)
_MAX_SOURCE_SIZE = 16_384
_MAX_SOURCES = 256
_MAX_CONTEXT_ITEMS = 32


class ContextCompactionDenied(ValueError):
    """Source provenance, boundary, budget or replay verification failed."""


def _canonical(value: Any) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise ContextCompactionDenied("Source record is not canonical JSON") from exc
    if len(payload) > _MAX_SOURCE_SIZE:
        raise ContextCompactionDenied("Source record exceeds context input bound")
    return payload


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_sha256(authoritative_source: Mapping[str, Any]) -> str:
    """Hash the *entire* durable original source, never a synthesized excerpt."""
    if not isinstance(authoritative_source, Mapping):
        raise ContextCompactionDenied("Durable source is unavailable")
    return _hash(_canonical(dict(authoritative_source)))


def task_assignment_sha256(task: Any) -> str:
    """Hash durable task assignment, ignoring ordinary lifecycle status updates.

    The compaction producer transitions running -> completed after persisting
    its snapshot. That does not change its assignment; check producer status
    separately at consumption. This fingerprint is not a monotonic revision.
    """
    return source_sha256(
        {
            "id": task.id,
            "engagement_id": task.engagement_id,
            "flow_id": task.flow_id,
            "type": task.type,
            "payload": task.payload,
            "approval_required": task.approval_required,
            "scope_check": task.scope_check,
        }
    )


def durable_task_sources(tasks: Sequence[Any]) -> Dict[str, Dict[str, Any]]:
    """Create canonical, bounded records from authoritative Task model instances.

    Both producer and consumer MUST use this same extractor; never synthesize
    provenance from the cached snapshot or trust task text as authority.
    """
    if not isinstance(tasks, (list, tuple)) or len(tasks) > 64:
        raise ContextCompactionDenied("Durable task source count exceeds bound")
    ordered = sorted(tasks, key=lambda item: (item.created_at, item.id))
    source_map: Dict[str, Dict[str, Any]] = {}
    for sequence, task in enumerate(ordered):
        if task.id in source_map:
            raise ContextCompactionDenied("Duplicate durable task source")
        source_map[task.id] = {
            "source_id": task.id,
            "engagement_id": task.engagement_id,
            "flow_id": task.flow_id,
            "source_task_id": task.id,
            "source_type": "durable_task",
            "status": task.status,
            "sequence": sequence,
            # Full source is hashed, but never emitted into compacted context.
            "payload": task.model_dump(mode="json"),
        }
    return source_map


@dataclass(frozen=True)
class ContextBoundary:
    """Explicit authorization/flow/current-task fence; not an authorization.

    task_state_sha256 fingerprints authoritative producer task assignment,
    not mutable result/status timestamps or a fabricated monotonic revision.
    """

    engagement_id: str
    flow_id: str
    flow_revision: int
    task_id: str
    task_state_sha256: str
    authorization_id: str
    authorization_version: int
    authorization_sha256: str

    def validate(self) -> None:
        for value in (self.engagement_id, self.flow_id, self.task_id, self.authorization_id):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ContextCompactionDenied("Context boundary identifier is invalid")
        if (
            not self.engagement_id.startswith("eng-")
            or not self.flow_id.startswith("flow-")
            or not self.task_id.startswith("task-")
        ):
            raise ContextCompactionDenied("Context boundary entity type invalid")
        for value in (self.task_state_sha256, self.authorization_sha256):
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ContextCompactionDenied("Context boundary digest is invalid")
        if (
            type(self.flow_revision) is not int
            or self.flow_revision < 0
            or type(self.authorization_version) is not int
            or self.authorization_version < 1
        ):
            raise ContextCompactionDenied("Context boundary revision is invalid")


def _extract(
    requested_id: str,
    authoritative: Mapping[str, Any],
    boundary: ContextBoundary,
) -> Dict[str, Any]:
    if not isinstance(authoritative, Mapping):
        raise ContextCompactionDenied("Durable context record missing")
    record = dict(authoritative)
    if set(record) != {
        "source_id",
        "engagement_id",
        "flow_id",
        "source_task_id",
        "source_type",
        "status",
        "sequence",
        "payload",
    }:
        raise ContextCompactionDenied("Unrecognized durable source schema")
    if (
        not isinstance(record["source_id"], str)
        or not _SOURCE_ID.fullmatch(record["source_id"])
        or not isinstance(record["source_task_id"], str)
        or not _TASK_ID.fullmatch(record["source_task_id"])
    ):
        raise ContextCompactionDenied("Durable source identity invalid")
    if record["source_id"] != requested_id:
        raise ContextCompactionDenied("Durable source identity mismatch")
    if record["engagement_id"] != boundary.engagement_id or record["flow_id"] != boundary.flow_id:
        raise ContextCompactionDenied("Cross-engagement or cross-flow source denied")
    if (
        not isinstance(record["source_type"], str)
        or not isinstance(record["status"], str)
        or record["source_type"] not in _SOURCES
        or record["status"] not in _STATUSES
    ):
        raise ContextCompactionDenied("Unsupported context source claim")
    prefix = {
        "durable_task": "task-",
        "durable_event": "evt-",
        "durable_tool_receipt": "action-",
        "validated_finding": "vuln-",
    }[record["source_type"]]
    if not record["source_id"].startswith(prefix):
        raise ContextCompactionDenied("Context source type identity mismatch")
    if type(record["sequence"]) is not int or not 0 <= record["sequence"] <= 2**53:
        raise ContextCompactionDenied("Source sequence is invalid")
    if not isinstance(record["payload"], Mapping):
        raise ContextCompactionDenied("Durable source payload missing")
    # Hash the full source before suppressing all freeform body fields.
    digest = source_sha256(record)
    return {
        "source_id": requested_id,
        "source_task_id": record["source_task_id"],
        "source_type": record["source_type"],
        "status": record["status"],
        "sequence": record["sequence"],
        "source_sha256": digest,
    }


def _select(items: List[Dict[str, Any]], max_items: int) -> List[Dict[str, Any]]:
    """Preserve newest entries and the last older unresolved state per type."""
    sorted_items = sorted(items, key=lambda x: (x["sequence"], x["source_id"]))
    latest = sorted_items[-max_items:]
    kept = {item["source_id"]: item for item in latest}
    if len(items) > max_items:
        # Keep bounded older unresolved failures, but not at the expense of
        # replacing newer statuses with an unbounded historical dump.
        critical = [
            item
            for item in sorted_items[:-max_items]
            if item["status"] in {"blocked", "failed", "unknown", "revoked"}
        ]
        for item in critical[-min(4, max_items // 4) :]:
            if item["source_id"] not in kept:
                oldest = min(
                    (
                        value
                        for value in kept.values()
                        if value["status"] not in {"blocked", "failed", "unknown", "revoked"}
                    ),
                    key=lambda value: (value["sequence"], value["source_id"]),
                    default=None,
                )
                if oldest is not None:
                    del kept[oldest["source_id"]]
                    kept[item["source_id"]] = item
    return sorted(kept.values(), key=lambda x: (x["sequence"], x["source_id"]))


def compact_context(
    *,
    boundary: ContextBoundary,
    source_ids: Sequence[str],
    durable_source_loader: Callable[[str], Mapping[str, Any]],
    max_items: int = 24,
) -> Dict[str, Any]:
    """Build a small, deterministic, non-authoritative context snapshot.

    Source loader MUST read independent authoritative records, NOT LLM output,
    a browser payload, a user-supplied dict or a cache used for authorization.
    Only safe enumerations and opaque IDs reach the summary. SHA-256 permits
    replay detection; it is NOT a signature or proof of current authorization.
    """
    if not isinstance(boundary, ContextBoundary):
        raise ContextCompactionDenied("Verified context boundary required")
    boundary.validate()
    if (
        type(max_items) is not int
        or not 1 <= max_items <= _MAX_CONTEXT_ITEMS
        or not isinstance(source_ids, (list, tuple))
        or len(source_ids) > _MAX_SOURCES
        or not callable(durable_source_loader)
    ):
        raise ContextCompactionDenied("Compaction budget or source loader invalid")
    for source_id in source_ids:
        if not isinstance(source_id, str) or not _SOURCE_ID.fullmatch(source_id):
            raise ContextCompactionDenied("Source ID invalid")
    if len(set(source_ids)) != len(source_ids):
        raise ContextCompactionDenied("Duplicate source ID")
    observations = []
    for source_id in source_ids:
        try:
            authoritative = durable_source_loader(source_id)
        except Exception as exc:
            raise ContextCompactionDenied("Authoritative context source unavailable") from exc
        observations.append(_extract(source_id, authoritative, boundary))
    selected = _select(observations, max_items)
    display = [f"{item['source_type']}:{item['status']} [{item['source_id']}]" for item in selected]
    summary = (
        "NON-AUTHORITATIVE CONTEXT ONLY. Validate signed ROE and current task/flow "
        "revision again before any execution. Original evidence remains in its "
        "durable store. " + "; ".join(display)
    )
    if len(summary.encode("utf-8")) > 6000:
        raise ContextCompactionDenied("Compacted prompt exceeds byte budget")
    snapshot = {
        "schema": "ai-osop-deterministic-context-v1",
        "authority": "none_not_signed",
        "source_loader": "caller_supplied_authoritative_reader",
        "original_evidence_preserved_externally": True,
        "llm_output_accepted_as_authority": False,
        "boundary": asdict(boundary),
        "summary": summary,
        "source_count": len(observations),
        "retained_count": len(selected),
        "omitted_count": len(observations) - len(selected),
        "items": selected,
    }
    snapshot["snapshot_sha256"] = _hash(_canonical(snapshot))
    return snapshot


def verify_compacted_context(
    snapshot: Mapping[str, Any],
    *,
    boundary: ContextBoundary,
    source_ids: Sequence[str],
    durable_source_loader: Callable[[str], Mapping[str, Any]],
    max_items: int = 24,
) -> bool:
    """Recompute from original durable sources before reuse, without trust by hash alone."""
    if not isinstance(snapshot, Mapping):
        return False
    try:
        expected = compact_context(
            boundary=boundary,
            source_ids=source_ids,
            durable_source_loader=durable_source_loader,
            max_items=max_items,
        )
        return _canonical(dict(snapshot)) == _canonical(expected)
    except ContextCompactionDenied:
        return False
