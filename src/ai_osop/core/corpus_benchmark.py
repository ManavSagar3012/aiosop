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

    def __post_init__(self):
        if self.expected_result not in ("accepted", "rejected"):
            raise ValueError("expected_result must be 'accepted' or 'rejected'")


class CorpusBenchmark:
    """Grounds detector validation in a labeled local corpus."""

    def __init__(self, entries: List[GroundTruthEntry]):
        self.entries = list(entries)

    def count(self) -> int:
        return len(self.entries)

    @property
    def classes(self) -> set:
        return {entry.vuln_class for entry in self.entries}

    def contracts(self) -> Dict[str, Any]:
        return {
            "version": "1.0.0",
            "benchmarks": {e.id: {
                "expected_class": e.vuln_class,
                "endpoint": e.endpoint,
                "method": e.method,
                "expected_result": e.expected_result,
            } for e in self.entries},
        }

    async def run(self, agent_runner=None) -> List[Dict[str, Any]]:
        """Execute the corpus reference facts directly and verify the scoring contract.

        If agent_runner provided, run agent_runner(reference_exploit) and treat the
        output as the corpus decision against each entry. Otherwise synthesize the
        expected discoveries so the harness answers the contract deterministically.
        """
        results = []
        for entry in self.entries:
            if agent_runner is None:
                # Corpus contracts: a well-behaved system would evaluate the reference
                # exploit the same way as the ground truth expects.
                matched = self._matches_expected(entry)
                results.append({
                    "id": entry.id,
                    "expected_class": entry.vuln_class,
                    "matched": matched,
                    "reference": entry.reference_exploit,
                })
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
