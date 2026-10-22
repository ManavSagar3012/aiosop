"""
AI-OSOP Qualification Failure Ledger.
Provides structured recording of qualification anomalies, recovery events,
and scope enforcement verification for baseline and parity scorecard tracking.
"""

from __future__ import annotations

import json
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

LOGS_DIR = Path(__file__).parent.parent.parent / "logs"
DEFAULT_LEDGER_PATH = LOGS_DIR / "qualification_failure_ledger.jsonl"


class FailureRecord(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    engagement_id: str
    stage: str
    task_id: Optional[str] = None
    event_type: str = "FAILURE"  # FAILURE, RECOVERY, SCOPE_VERIFICATION, MILESTONE_PASS
    failure_class: Optional[str] = None
    details: str
    recovered: bool = False
    environment: Dict[str, Any] = Field(
        default_factory=lambda: {
            "os": platform.system(),
            "python": platform.python_version(),
            "processor": platform.processor(),
        }
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FailureLedger:
    """Manages appending and querying qualification failure ledger events."""

    def __init__(self, ledger_file: Optional[Path] = None):
        self.ledger_file = ledger_file or DEFAULT_LEDGER_PATH
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)

    def record_event(
        self,
        engagement_id: str,
        stage: str,
        details: str,
        task_id: Optional[str] = None,
        event_type: str = "FAILURE",
        failure_class: Optional[str] = None,
        recovered: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> FailureRecord:
        record = FailureRecord(
            engagement_id=engagement_id,
            stage=stage,
            task_id=task_id,
            event_type=event_type,
            failure_class=failure_class,
            details=details,
            recovered=recovered,
            metadata=metadata or {},
        )
        line = record.model_dump_json() + "\n"
        with open(self.ledger_file, "a", encoding="utf-8") as f:
            f.write(line)
        return record

    def load_events(self, engagement_id: Optional[str] = None) -> List[FailureRecord]:
        if not self.ledger_file.exists():
            return []
        events: List[FailureRecord] = []
        with open(self.ledger_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    rec = FailureRecord(**data)
                    if engagement_id is None or rec.engagement_id == engagement_id:
                        events.append(rec)
                except Exception:
                    continue
        return events

    def get_summary(self, engagement_id: Optional[str] = None) -> Dict[str, Any]:
        events = self.load_events(engagement_id)
        failures = [e for e in events if e.event_type == "FAILURE"]
        recoveries = [e for e in events if e.event_type == "RECOVERY"]
        passes = [e for e in events if e.event_type == "MILESTONE_PASS"]
        return {
            "total_events": len(events),
            "total_failures": len(failures),
            "recovered_failures": len([f for f in failures if f.recovered]),
            "unrecovered_failures": len([f for f in failures if not f.recovered]),
            "recoveries_logged": len(recoveries),
            "milestone_passes": len(passes),
        }
