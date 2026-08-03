"""Pydantic schemas for exploit receipts and content-addressed artifacts."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ReceiptArtifact(BaseModel):
    artifact_id: str  # "art-<sha256[:12]>" content-addressed
    kind: (
        str  # "http_request" | "http_response" | "screenshot" | "oast_interaction" | "console_log"
    )
    sha256: str
    blob_path: str  # relative to the evidence root
    redaction_map: Dict[str, str] = Field(default_factory=dict)
    captured_at: datetime = Field(default_factory=datetime.utcnow)


class ExploitReceipt(BaseModel):
    receipt_id: str  # "rcpt-<uuid>"
    engagement_id: str
    vuln_id: str
    approval_id: str
    hop_idx: Optional[int] = None  # None for standalone validations
    chain_id: Optional[str] = None
    verdict: str  # "confirmed" | "not_confirmed" | "inconclusive"
    confidence: float
    confirmation_note: str
    oracle_signals: Dict[str, Any] = Field(default_factory=dict)
    artifacts: List[ReceiptArtifact] = Field(default_factory=list)
    request_summary: Dict[str, Any] = Field(default_factory=dict)
    response_summary: Dict[str, Any] = Field(default_factory=dict)
    scope_hash: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    prev_receipt_hash: str = ""
    integrity_sig: str = ""
    simulated: bool = False  # mirrors Vulnerability.is_simulated gate
