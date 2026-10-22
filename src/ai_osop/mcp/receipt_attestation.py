"""Verify provider-origin MCP terminal status without trusting a boolean.

The provider must sign a *fresh*, canonical execution-status receipt using a
pre-enrolled Ed25519 key. Configuration is held by the operator and is never
taken from the HTTP response. A signed receipt proves which trusted provider
key asserted an outcome, not that an independent observer saw the tool stop.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import time
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_B64_SIG = re.compile(r"[A-Za-z0-9_-]{86}\Z")
_KID = re.compile(r"[A-Za-z0-9_.:@-]{1,96}\Z")
_STATUS_FIELDS = frozenset({
    "request_id", "engagement_id", "task_id", "server_id", "status",
    "verified", "stopped", "issued_at",
})
_OUTCOMES = frozenset({
    "cancelled", "canceled", "confirmed_stopped", "finished", "completed",
    "succeeded", "failed", "running", "pending",
})


def _canonical(status: Dict[str, Any]) -> bytes:
    return json.dumps(
        status, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def provider_receipt_is_signed(
    receipt: Any, server_id: str, request_id: str,
    engagement_id: str, task_id: str, *, now: int | None = None,
) -> bool:
    """Allow only a complete, exact-identity, fresh Ed25519 assertion.

    A receipt signed by a provider that does not retain the original dispatch
    tuple cannot independently establish whether the original action ran.
    Deployment operators must therefore enable this only on providers that
    attest stored original executions, not echo arbitrary query parameters.
    """
    if not isinstance(receipt, dict):
        return False
    proof = receipt.get("attestation")
    if not isinstance(proof, dict) or set(proof) != {"kid", "signature"}:
        return False
    claims = {name: value for name, value in receipt.items() if name != "attestation"}
    if set(claims) != _STATUS_FIELDS:
        return False
    if any(
        not isinstance(expected, str) or not expected
        or claims[name] != expected
        for name, expected in (
            ("server_id", server_id), ("request_id", request_id),
            ("engagement_id", engagement_id), ("task_id", task_id),
        )
    ):
        return False
    if (
        type(claims["status"]) is not str
        or claims["status"] not in _OUTCOMES
        or type(claims["verified"]) is not bool
        or type(claims["stopped"]) is not bool
        or type(claims["issued_at"]) is not int
        or abs((int(time.time()) if now is None else now) - claims["issued_at"]) > 120
        or not isinstance(proof["kid"], str)
        or not _KID.fullmatch(proof["kid"])
        or not isinstance(proof["signature"], str)
        or not _B64_SIG.fullmatch(proof["signature"])
    ):
        return False
    try:
        configured = json.loads(os.environ.get("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", ""))
        if not isinstance(configured, dict):
            return False
        server_keys = configured.get(server_id)
        if not isinstance(server_keys, dict) or len(server_keys) > 32:
            return False
        encoded_key = server_keys.get(proof["kid"])
        if not isinstance(encoded_key, str):
            return False
        key = base64.b64decode(encoded_key, validate=True)
        signature = base64.urlsafe_b64decode(proof["signature"] + "==")
        if len(key) != 32 or len(signature) != 64:
            return False
        if base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=") != proof["signature"]:
            # Ed25519 has one-byte remainder in base64url; unused trailing
            # bits must not create alternate encodings for the same signature.
            return False
        Ed25519PublicKey.from_public_bytes(key).verify(signature, _canonical(claims))
        return True
    except (ValueError, TypeError, KeyError, InvalidSignature, UnicodeError, binascii.Error):
        return False
