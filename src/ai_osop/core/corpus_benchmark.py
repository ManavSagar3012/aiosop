"""B1: Vulnerability corpus benchmark — declares ground truth labels + verifies scoring."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

GroundTruthEntries = List[Dict[str, Any]]


@dataclass
class GroundTruthEntry:
    id: str
    vuln_class: str
    endpoint: str
    method: str
    expected_result: str  # accepted | rejected
    reference_exploit: Dict[str, Any]
    severity_expected: str
    confidence: float = 1.0
    withdrawn: bool = False

    def __post_init__(self):
        if self.expected_result not in ("accepted", "rejected"):
            raise ValueError("expected_result must be 'accepted' or 'rejected'")


class CorpusBenchmark:
    """Grounds detector validation in a labeled local corpus."""

    def __init__(self, entries: List[GroundTruthEntry]):
        self.entries = list(entries)

    def count(self) -> int:
        return sum(1 for e in self.entries if not e.withdrawn)

    async def score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute precision/recall of observed findings against ground truth.

        findings: list of {"id": <entry_id>, "outcome": "accepted"|"rejected"}.
        TP = expected accepted and got accepted.
        FP = expected rejected and got accepted.
        FN = expected accepted and got rejected / missing.
        Withdrawn entries are excluded from scoring.
        """
        by_id = {f["id"]: f["outcome"] for f in findings}
        tp = fp = fn = 0
        per_class: Dict[str, Dict[str, int]] = {}
        active = [e for e in self.entries if not e.withdrawn]
        for e in active:
            got = by_id.get(e.id)
            bucket = per_class.setdefault(e.vuln_class, {"tp": 0, "fp": 0, "fn": 0})
            if e.expected_result == "accepted" and got == "accepted":
                tp += 1
                bucket["tp"] += 1
            elif e.expected_result == "rejected" and got == "accepted":
                fp += 1
                bucket["fp"] += 1
            elif e.expected_result == "accepted":
                fn += 1
                bucket["fn"] += 1
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        return {
            "precision": precision,
            "recall": recall,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "per_class": per_class,
            "evaluated": len(active),
        }

    @property
    def classes(self) -> set:
        return {entry.vuln_class for entry in self.entries}

    def contracts(self) -> Dict[str, Any]:
        return {
            "version": "1.0.0",
            "benchmarks": {
                e.id: {
                    "expected_class": e.vuln_class,
                    "endpoint": e.endpoint,
                    "method": e.method,
                    "expected_result": e.expected_result,
                }
                for e in self.entries
            },
        }

    async def run(self, agent_runner=None, dry_run: bool = False) -> List[Dict[str, Any]]:
        """Execute the corpus reference facts and verify the scoring contract.

        - ``agent_runner`` provided: call run(reference_exploit) and treat the output
          as the corpus decision for that entry (real benchmark mode).
        - ``dry_run=True``: synthesize the expected discoveries so a harness can
          answer its own contract deterministically (explicit self-echo only).
        - Neither: refuse — a benchmark that silently self-certifies is theater.
        """
        results = []
        for entry in self.entries:
            if agent_runner is None:
                if not dry_run:
                    raise ValueError(
                        "CorpusBenchmark.run requires findings/agent_runner for scoring; "
                        "pass dry_run=True for explicit self-echo"
                    )
                matched = self._matches_expected(entry)
                results.append(
                    {
                        "id": entry.id,
                        "expected_class": entry.vuln_class,
                        "matched": matched,
                        "reference": entry.reference_exploit,
                    }
                )
            else:
                candidate = await agent_runner(entry.reference_exploit)
                if candidate is None:
                    raise AssertionError("agent_runner returned no output")
                results.append(candidate)
        return results

    def _matches_expected(self, entry: GroundTruthEntry) -> bool:
        # Offline truthful assertion: a well-designed oracle would match the reference
        # exploit structure for controlled input signals.
        status = entry.reference_exploit.get("expected_status")
        if entry.expected_result == "accepted":
            return status in (200, 201)
        if entry.expected_result == "rejected":
            return status in (400, 401, 403, 404)
        return True
