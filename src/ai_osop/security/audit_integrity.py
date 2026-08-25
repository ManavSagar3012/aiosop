"""
Audit Chain Integrity — Tamper Detection for Audit Logs

Implements an HMAC hash chain over audit events so any tampering
with the audit trail is detectable. Each event's integrity_hash is
computed over: HMAC(previous_hash || event_bytes).

Phase 6: Enterprise Hardening — proves the audit trail is tamper-evident.
"""

import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.config import scope_signing_key

logger = structlog.get_logger("ai_osop.audit_integrity")

# Genesis hash — the chain starts here
GENESIS_HASH = "0" * 64


class AuditChainVerifier:
    """Verifies the integrity of the audit event chain.

    The chain is: genesis → event_1 → event_2 → ... → event_n
    Each event stores: integrity_hash = HMAC-SHA256(prev_hash, canonical(event))
    """

    def __init__(self, secret_key: Optional[bytes] = None):
        self._secret_key = secret_key or scope_signing_key()
        self._chain: List[Dict[str, Any]] = []
        self._last_hash: str = GENESIS_HASH

    @staticmethod
    def _canonical_form(event: Dict[str, Any]) -> bytes:
        """Produce a deterministic byte representation of an audit event.

        Strips the integrity_hash field (which is what we're computing)
        and sorts keys for reproducibility.
        """
        stripped = {k: v for k, v in event.items() if k != "integrity_hash"}
        return json.dumps(stripped, sort_keys=True, default=str).encode("utf-8")

    def compute_hash(self, event: Dict[str, Any], previous_hash: str) -> str:
        """Compute HMAC-SHA256 integrity hash for an event."""
        canonical = self._canonical_form(event)
        return hmac.new(
            self._secret_key,
            previous_hash.encode("utf-8") + canonical,
            hashlib.sha256,
        ).hexdigest()

    def append_event(self, event: Dict[str, Any]) -> str:
        """Append an event to the chain and return its integrity hash.

        Call this when writing a new audit event. The returned hash
        should be stored in the event's integrity_hash field.
        """
        integrity_hash = self.compute_hash(event, self._last_hash)
        self._last_hash = integrity_hash
        self._chain.append(
            {
                "event": event,
                "integrity_hash": integrity_hash,
                "previous_hash": self._chain[-1]["integrity_hash"]
                if self._chain
                else GENESIS_HASH,
            }
        )
        return integrity_hash

    def verify_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Verify an entire audit chain for tampering.

        Returns a verification report with:
        - valid: bool — whether the chain is intact
        - total_events: int
        - tampered_events: list of indices where tampering was detected
        - first_tampered_event: index of first tampered event, or None
        """
        if not events:
            return {
                "valid": True,
                "total_events": 0,
                "tampered_events": [],
                "first_tampered_event": None,
            }

        tampered: List[int] = []
        prev_hash = GENESIS_HASH

        for i, event in enumerate(events):
            stored_hash = event.get("integrity_hash", "")
            computed_hash = self.compute_hash(event, prev_hash)

            if not hmac.compare_digest(stored_hash, computed_hash):
                tampered.append(i)
                logger.warning(
                    "audit_tamper_detected",
                    event_index=i,
                    event_id=event.get("event_id", "unknown"),
                    stored_hash=stored_hash[:16] + "...",
                    computed_hash=computed_hash[:16] + "...",
                )

            # Advance the chain regardless (to detect cascading tampering)
            prev_hash = stored_hash if stored_hash else computed_hash

        return {
            "valid": len(tampered) == 0,
            "total_events": len(events),
            "tampered_events": tampered,
            "first_tampered_event": tampered[0] if tampered else None,
        }

    def get_chain_state(self) -> Dict[str, Any]:
        """Return current chain state for observability."""
        return {
            "chain_length": len(self._chain),
            "last_hash": self._last_hash[:16] + "...",
            "genesis_hash": GENESIS_HASH[:16] + "...",
        }
