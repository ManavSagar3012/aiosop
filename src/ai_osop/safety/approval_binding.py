"""Immutable, redacted fingerprint of exactly what a human approved.

This binds the *entire* serialized task payload, including nested technique
parameters, not only its top-level destination. No raw payload, credentials,
or URL is written into approval evidence by this helper.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

_KIND = "task_payload_sha256_v1"
_MAX_BYTES = 262144
_GRANT_FIELDS = frozenset(("approval_id", "operator_approved"))


def task_payload_sha256(payload: Any) -> str:
    """Canonical SHA-256 excluding only two *server-added* approval grant keys."""
    if not isinstance(payload, dict) or not all(isinstance(k, str) for k in payload):
        raise ValueError("An object payload is required for task approval")
    sanitized = {key: value for key, value in payload.items() if key not in _GRANT_FIELDS}
    try:
        encoded = json.dumps(
            sanitized, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    except (ValueError, TypeError, OverflowError, UnicodeError) as exc:
        raise ValueError("Task payload cannot be bound canonically") from exc
    if not encoded or len(encoded) > _MAX_BYTES:
        raise ValueError("Task approval payload exceeds canonical bounds")
    return hashlib.sha256(encoded).hexdigest()


def pinned_evidence(evidence: Any, payload: Any) -> list[dict[str, Any]]:
    """Server-generated receipt replaces any client-forged binding marker."""
    if not isinstance(evidence, list) or len(evidence) > 64:
        raise ValueError("Invalid approval evidence")
    if any(not isinstance(entry, dict) for entry in evidence):
        raise ValueError("Invalid approval evidence record")
    clean = [entry for entry in evidence if entry.get("kind") != _KIND]
    return [*clean, {"kind": _KIND, "sha256": task_payload_sha256(payload)}]


def matches_pinned_payload(evidence: Any, payload: Any) -> bool:
    """Legacy approvals with no server-created receipt fail closed."""
    if not isinstance(evidence, list):
        return False
    records = [entry for entry in evidence
               if isinstance(entry, dict) and entry.get("kind") == _KIND]
    if len(records) != 1:
        return False
    claimed = records[0].get("sha256")
    if not isinstance(claimed, str) or len(claimed) != 64:
        return False
    try:
        return hmac.compare_digest(claimed, task_payload_sha256(payload))
    except ValueError:
        return False
