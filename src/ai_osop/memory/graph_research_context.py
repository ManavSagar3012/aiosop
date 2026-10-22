"""Signed tenant/Flow-fenced graph research hints, never prompt authority.

PentAGI's optional Graphiti search exposes episodic prior tool/context
relationships. This narrower read-only analogue deliberately requires durable
signed ROE and independently replay-verifiable source Task results. Legacy
Neo4j findings and tool summaries without these markers are NOT qualified.

Only controlled category labels, terminal outcome and SHA-256 prefixes reach
the model. Raw finding evidence, commands, URLs, prior tool outputs, graph
titles, agent text and user-defined node properties are never emitted. No
embedding provider, graph mutation, exploitation or target-side call occurs.
"""

import asyncio
import hashlib
import hmac
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ai_osop.core.models import FlowRecord, Task
from ai_osop.orchestrator.context_compaction import (
    source_sha256, task_assignment_sha256,
)


class GraphResearchDenied(RuntimeError):
    """Unverified signed boundary, graph failure or provenance mismatch."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID = re.compile(r"task-[A-Za-z0-9._-]{1,78}\Z")
_FINDING_ID = re.compile(r"vuln-[A-Za-z0-9._-]{1,78}\Z")
_ACTION_ID = re.compile(r"action-[A-Za-z0-9._-]{1,78}\Z")
_VOCABULARY = frozenset({
    "sqli", "xss", "ssrf", "csrf", "idor", "bola", "rce", "lfi", "xxe",
    "deserialization", "graphql", "jwt", "oauth2", "tls", "iam", "sca",
    "authentication", "authorization", "recon", "http", "browser", "mcp",
    "scanner", "probe", "analysis", "code", "dns", "network", "cloud",
    "credential", "inventory", "dependency", "vulnerability", "security",
})
_ALIASES = {
    "injection": "sqli", "sql": "sqli", "crosssite": "xss",
    "forgery": "csrf", "request": "ssrf", "access": "idor",
    "traversal": "lfi", "object": "bola", "exploit": "vulnerability",
}
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_TOOL_KINDS = frozenset({
    "http", "browser", "mcp", "scanner", "probe", "analysis", "recon",
    "code", "dns", "network", "cloud", "inventory",
})
_MAX_GRAPH_CANDIDATES = 12
_MAX_CONTEXT_ITEMS = 4


def research_enabled() -> bool:
    """Explicit opt-in until a signed-provenance graph writer is qualified."""
    raw = os.environ.get("OSOP_GRAPH_RESEARCH_CONTEXT_ENABLED", "").strip().lower()
    if raw in {"", "0", "false", "no"}:
        return False
    if raw in {"1", "true", "yes"}:
        return True
    raise GraphResearchDenied("Graph research configuration invalid")


def _fingerprint_result(result: Any) -> str:
    if not isinstance(result, dict):
        raise GraphResearchDenied("Durable tool/action result missing")
    try:
        canonical = json.dumps(
            result, sort_keys=True, ensure_ascii=False, allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise GraphResearchDenied("Durable tool result invalid") from exc
    if not canonical or len(canonical) > 16384:
        raise GraphResearchDenied("Durable tool result size invalid")
    return hashlib.sha256(canonical).hexdigest()


def _terms(topic: str) -> frozenset:
    # No opaque user text or payload is sent as a Neo4j query parameter.
    # Limited lexical/taxonomy matching, NOT embedding-vector similarity.
    if not isinstance(topic, str):
        return frozenset()
    words = re.findall(r"[a-z]{2,16}", topic[:4096].lower())[:128]
    return frozenset(
        normalized for word in words
        if (normalized := _ALIASES.get(word, word)) in _VOCABULARY
    )


async def _bounded(awaitable: Any) -> Any:
    return await asyncio.wait_for(awaitable, timeout=3.0)


async def _authority(memory: Any, current: Task, sid: str) -> Tuple[Any, FlowRecord, Task]:
    if (
        not isinstance(current, Task) or current.engagement_id != sid
        or not current.flow_id or current.status != "running"
        or not isinstance(current.payload, dict)
        or type(current.payload.get("_authorization_version")) is not int
        or current.payload["_authorization_version"] < 1
    ):
        raise GraphResearchDenied("Running signed Flow task required")
    try:
        signed = await _bounded(memory.assert_signed_authorization(
            sid, expected_version=current.payload["_authorization_version"],
        ))
        flow = await _bounded(memory.load_flow(current.flow_id))
        authoritative = await _bounded(memory.load_task_authoritative(current.id))
        if (
            type(getattr(signed, "version", None)) is not int
            or signed.version != current.payload["_authorization_version"]
            or not isinstance(getattr(signed, "policy_sha256", None), str)
            or not _DIGEST.fullmatch(signed.policy_sha256)
            or not isinstance(getattr(signed, "authorization_id", None), str)
            or not signed.authorization_id
            or not isinstance(flow, FlowRecord)
            or flow.id != current.flow_id or flow.engagement_id != sid
            or flow.status not in {"pending", "running"}
            or type(flow.revision) is not int or flow.revision < 0
            or not isinstance(authoritative, Task)
            or authoritative.id != current.id
            or authoritative.engagement_id != sid
            or authoritative.flow_id != flow.id
            or authoritative.status != "running"
            or authoritative.payload.get("_authorization_version") != signed.version
            or source_sha256(authoritative.model_dump(mode="json"))
            != source_sha256(current.model_dump(mode="json"))
        ):
            raise GraphResearchDenied("Signed Flow research authority changed")
        return signed, flow, authoritative
    except GraphResearchDenied:
        raise
    except Exception as exc:
        raise GraphResearchDenied("Signed Flow research authority unavailable") from exc


def _candidate(
    candidate: Dict[str, Any], source: Task,
    *, engagement_id: str, flow_id: str, flow_revision: int,
    version: int, digest: str,
) -> Tuple[str, str, str]:
    """Verify one graph candidate against independently loaded TaskORM data.

    Returns only allowlisted type, kind and original digest. NEVER returns
    a graph-supplied string verbatim into model context.
    """
    if not isinstance(candidate, dict):
        raise GraphResearchDenied("Invalid graph candidate")
    kind = candidate.get("kind")
    identifier = candidate.get("id")
    source_id = candidate.get("source_task_id")
    graph_digest = candidate.get("authorization_sha256")
    if (
        # A validated Neo4j Vulnerability flag plus a Task result digest is
        # insufficient to establish independent evidence-source authenticity.
        # Until a verified finding-source writer exists, only signed MCP
        # ToolAction events can reach the model-facing research index.
        kind != "action"
        or not isinstance(identifier, str)
        or not _ACTION_ID.fullmatch(identifier)
        or not isinstance(source_id, str) or not _TASK_ID.fullmatch(source_id)
        or candidate.get("engagement_id") != engagement_id
        or candidate.get("flow_id") != flow_id
        or type(candidate.get("flow_revision")) is not int
        or candidate["flow_revision"] != flow_revision
        or type(candidate.get("authorization_version")) is not int
        or candidate["authorization_version"] != version
        or not isinstance(graph_digest, str) or not _DIGEST.fullmatch(graph_digest)
        or not hmac.compare_digest(graph_digest, digest)
        or not isinstance(source, Task) or source.id != source_id
        or source.engagement_id != engagement_id or source.flow_id != flow_id
        or source.status != "completed"
        or not isinstance(source.payload, dict)
        or type(source.payload.get("_authorization_version")) is not int
        or source.payload["_authorization_version"] != version
    ):
        raise GraphResearchDenied("Cross-tenant, unsigned or stale graph provenance")
    source_digest = candidate.get("source_task_sha256")
    if (
        not isinstance(source_digest, str) or not _DIGEST.fullmatch(source_digest)
        or not hmac.compare_digest(source_digest, task_assignment_sha256(source))
    ):
        raise GraphResearchDenied("Graph source assignment fingerprint mismatch")
    classification = candidate.get("classification")
    if not isinstance(classification, str):
        raise GraphResearchDenied("Invalid graph research classification")
    classification = classification.lower()
    if (
        classification not in _TOOL_KINDS
        or candidate.get("outcome") != "succeeded"
        or not isinstance(source.result, dict)
        or source.result.get("status") not in {"success", "succeeded"}
        # Legacy Task results often omit tool_kind. The source signed MCP
        # event independently establishes the generic mcp classification.
        or (classification != "mcp" and source.result.get("tool_kind") != classification)
    ):
        raise GraphResearchDenied("Tool/action success receipt unverified")
    receipt_sha = candidate.get("receipt_sha256")
    if (
        not isinstance(receipt_sha, str) or not _DIGEST.fullmatch(receipt_sha)
        or not hmac.compare_digest(_fingerprint_result(source.result), receipt_sha)
        or not isinstance(candidate.get("source_event_id"), str)
        or not re.fullmatch(r"evt-[A-Za-z0-9._-]{1,60}", candidate["source_event_id"])
        or not isinstance(candidate.get("provider_receipt_sha256"), str)
        or not _DIGEST.fullmatch(candidate["provider_receipt_sha256"])
        or not isinstance(candidate.get("provider_server_id"), str)
        or not isinstance(candidate.get("provider_signing_kid"), str)
        or not isinstance(candidate.get("provider_signer_key_sha256"), str)
        or not _DIGEST.fullmatch(candidate["provider_signer_key_sha256"])
    ):
        raise GraphResearchDenied("Tool/action signed receipt provenance mismatch")
    # Pin the *public key bytes*, not only its reusable KID. Old projections
    # fail after same-KID signing-key rotation/restart, even if the durable
    # signed receipt is still a valid historical assertion.
    from ai_osop.memory.graph_research_projection import _provider_key_fingerprint

    actual_signer = _provider_key_fingerprint(
        candidate["provider_server_id"], candidate["provider_signing_kid"],
    )
    if not actual_signer or not hmac.compare_digest(
        actual_signer, candidate["provider_signer_key_sha256"],
    ):
        raise GraphResearchDenied("Graph research provider signer changed or retired")
    return kind, classification, receipt_sha


async def verified_graph_research_context(
    *, memory: Any, graph: Any, current_task: Task, engagement_id: str,
    topic: str,
) -> str:
    """Retrieve bounded read-only graph hints bound to current signed Flow.

    No inference/evidence-certification or authorization can be derived from
    the model-facing text. An uncertain graph/ROE/provenance denies the model
    boundary rather than silently using unsourced facts.
    """
    signed, flow, authoritative = await _authority(memory, current_task, engagement_id)
    if graph is None or not callable(getattr(graph, "read_signed_research_candidates", None)):
        raise GraphResearchDenied("Signed tenant graph research unavailable")
    tokens = _terms(topic)
    try:
        rows = await _bounded(graph.read_signed_research_candidates(
            engagement_id, flow.id, signed.version, signed.policy_sha256,
            limit=_MAX_GRAPH_CANDIDATES,
            topics=sorted(tokens)[:24],
        ))
    except Exception as exc:
        raise GraphResearchDenied("Signed tenant graph research unavailable") from exc
    if not isinstance(rows, list) or len(rows) > _MAX_GRAPH_CANDIDATES:
        raise GraphResearchDenied("Unbounded graph research result")

    observations: List[Tuple[str, str, str]] = []
    source_fingerprints: Dict[str, str] = {}
    action_proofs: List[Tuple[str, str, str]] = []
    identifiers = set()
    for row in rows:
        if not isinstance(row, dict):
            raise GraphResearchDenied("Invalid graph research result")
        source_id = row.get("source_task_id")
        if not isinstance(source_id, str) or not _TASK_ID.fullmatch(source_id):
            raise GraphResearchDenied("Untrusted research source identity")
        if row.get("id") in identifiers or source_id == current_task.id:
            raise GraphResearchDenied("Untrusted research source replay")
        identifiers.add(row.get("id"))
        try:
            source = await _bounded(memory.load_task_authoritative(source_id))
            observation = _candidate(
                row, source, engagement_id=engagement_id, flow_id=flow.id,
                flow_revision=flow.revision, version=signed.version,
                digest=signed.policy_sha256,
            )
            # Neither a graph-stored signature fingerprint nor a source Task
            # result proves a signed success. Read original PostgreSQL event
            # and its dispatch identity through the existing real API.
            verifier = getattr(memory, "verify_signed_graph_action", None)
            if not callable(verifier) or not await _bounded(verifier(
                engagement_id, source_id, row["source_event_id"],
                row["provider_receipt_sha256"], signed.version,
            )):
                raise GraphResearchDenied("Graph action lacks signed PostgreSQL receipt")
            action_proofs.append((
                source_id, row["source_event_id"], row["provider_receipt_sha256"],
            ))
            source_fingerprints[source_id] = source_sha256(source.model_dump(mode="json"))
            observations.append(observation)
        except GraphResearchDenied:
            raise
        except Exception as exc:
            raise GraphResearchDenied("Verified graph research source unavailable") from exc

    # Read-after-check: do not return graph facts from a revoked/rotated ROE,
    # paused/advanced Flow, changed active Task, or mutated historical result.
    renewed_signed, renewed_flow, renewed_task = await _authority(
        memory, current_task, engagement_id,
    )
    if (
        renewed_signed.authorization_id != signed.authorization_id
        or renewed_signed.policy_sha256 != signed.policy_sha256
        or renewed_signed.version != signed.version
        or renewed_flow.revision != flow.revision
        or source_sha256(renewed_task.model_dump(mode="json"))
        != source_sha256(authoritative.model_dump(mode="json"))
    ):
        raise GraphResearchDenied("Graph research signed Flow changed")
    for source_id, fingerprint in source_fingerprints.items():
        try:
            fresh = await _bounded(memory.load_task_authoritative(source_id))
            if not isinstance(fresh, Task) or source_sha256(fresh.model_dump(mode="json")) != fingerprint:
                raise GraphResearchDenied("Graph source changed after verification")
        except GraphResearchDenied:
            raise
        except Exception as exc:
            raise GraphResearchDenied("Graph source recheck unavailable") from exc
    # The initial signed receipt may expire in the trust registry while graph
    # retrieval/revalidation awaits, or the original dispatch can change.
    # Recheck it after source reads, and pin the in-memory signer fingerprint
    # again using the same graph candidate before returning to BaseAgent.
    for source_id, event_id, receipt_hash in action_proofs:
        row = next(
            (item for item in rows if item["source_task_id"] == source_id
             and item["source_event_id"] == event_id), None,
        )
        if row is None:
            raise GraphResearchDenied("Signed graph action disappeared")
        from ai_osop.memory.graph_research_projection import _provider_key_fingerprint

        now_fingerprint = _provider_key_fingerprint(
            row["provider_server_id"], row["provider_signing_kid"],
        )
        if not now_fingerprint or not hmac.compare_digest(
            now_fingerprint, row["provider_signer_key_sha256"],
        ):
            raise GraphResearchDenied("Graph research provider signer changed or retired")
        verifier = getattr(memory, "verify_signed_graph_action", None)
        try:
            if not callable(verifier) or not await _bounded(verifier(
                engagement_id, source_id, event_id, receipt_hash, signed.version,
            )):
                raise GraphResearchDenied("Signed graph receipt changed before inference")
        except GraphResearchDenied:
            raise
        except Exception as exc:
            raise GraphResearchDenied("Signed graph receipt recheck unavailable") from exc

    selected = sorted(
        observations,
        key=lambda item: (-(int(item[1] in tokens)), item[0], item[1], item[2]),
    )[:_MAX_CONTEXT_ITEMS]
    if not selected:
        return ""
    # Every emitted word comes from our fixed allowlists and hash prefixes;
    # never paste graph text as LLM instructions, even as a quoted block.
    lines = [
        f"{kind}:{category}:receipt-sha256={sha[:16]}"
        for kind, category, sha in selected
    ]
    return (
        "NON-AUTHORITATIVE VERIFIED-SOURCE GRAPH INDEX ONLY. No target/evidence "
        "text, no exploit-success claim and no permission to execute. "
        "Recheck active signed ROE and task approval before any action. "
        + "; ".join(lines)
    )
