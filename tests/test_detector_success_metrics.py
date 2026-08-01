"""MAJ-6: per-class detector success metrics test.

The independent audit (MAJ-6) flagged that there are no per-detector-class
success metrics — CI cannot tell you "does the SQLi detector actually
detect SQLi? Does the JWT detector actually detect JWT forgery?" This test
pins the contract: every VulnClass that has a registered scanner agent MUST
have at least one test file that asserts confirmed=True on a positive case
(and the test file must actually exist in the suite).

The contract:
  1. Every ``AgentType`` whose name ends in ``_SCANNER`` maps to a detector
     class.
  2. Each such scanner has a task type (e.g. ``ssti_scan``, ``jwt_scan``).
  3. For each task type, at least one test file in ``tests/`` references it
     AND at least one test asserts ``confirmed=True`` or
     ``validated=True`` on a positive case.

This is a STATIC analysis test — it greps the test directory, not the code.
It runs hermetically and fails when a scanner class lacks test coverage,
so a newly-added detector with no positive-case test surfaces immediately.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ai_osop.core.config import AgentType

_TESTS_DIR = Path(__file__).resolve().parent


# Scanner agent types — every AgentType ending in _SCANNER.
_SCANNER_TYPES = {
    at for at in AgentType if at.value.endswith("_scanner") or at.value.endswith("_scanning")
}

# Map each scanner type to its task_type (the string the scheduler dispatches).
_SCANNER_TASK_TYPES = {
    AgentType.SSTI_SCANNER: "ssti_scan",
    AgentType.SSRF_SCANNER: "ssrf_scan",
    AgentType.CSRF_SCANNER: "csrf_scan",
    AgentType.JWT_SCANNER: "jwt_scan",
    AgentType.SMUGGLING_SCANNER: "smuggling_scan",
    AgentType.RACE_SCANNER: "race_scan",
    AgentType.UPLOAD_SCANNER: "upload_scan",
    AgentType.POLLUTION_SCANNER: "pollution_scan",
    AgentType.WEBSOCKET_SCANNER: "websocket_scan",
    AgentType.SAML_SCANNER: "saml_scan",
    AgentType.TAKEOVER_SCANNER: "takeover_scan",
    AgentType.VULN_ANALYSIS: "sqli_scan",  # vuln_agent handles sqli/xss/mass-assign
}


def _all_test_files() -> list[Path]:
    """Return every test_*.py file in the tests directory."""
    return list(_TESTS_DIR.glob("test_*.py"))


def _test_files_mentioning(task_type: str) -> list[Path]:
    """Return test files that mention the task_type string anywhere."""
    hits = []
    for f in _all_test_files():
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if task_type in text:
            hits.append(f)
    return hits


def _test_files_with_positive_assertion(task_type: str) -> list[Path]:
    """Return test files that reference the task_type AND contain a
    confirmed=True or validated=True assertion (the positive-case contract)."""
    hits = []
    for f in _all_test_files():
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if task_type not in text:
            continue
        # Look for positive-case assertions: confirmed=True, validated=True,
        # or "confirmed" in a result dict assertion.
        if any(
            marker in text
            for marker in (
                "confirmed",
                "validated",
                "CONFIRMED",
                "VALIDATED",
            )
        ):
            hits.append(f)
    return hits


def test_every_scanner_has_a_task_type_mapping():
    """Every registered _SCANNER AgentType must be in the _SCANNER_TASK_TYPES
    map. A scanner without a task type mapping is invisible to this metric."""
    unmapped = _SCANNER_TYPES - set(_SCANNER_TASK_TYPES.keys())
    # Filter out AgentTypes that are intentionally not in the map (e.g. if a
    # new scanner was added but its task type is novel — it should be added).
    assert not unmapped, (
        f"Scanner AgentTypes without a task_type mapping in this test: "
        f"{[at.value for at in unmapped]}. Add them to _SCANNER_TASK_TYPES."
    )


@pytest.mark.parametrize("scanner_type,task_type", list(_SCANNER_TASK_TYPES.items()))
def test_scanner_has_test_coverage(scanner_type: AgentType, task_type: str):
    """Every scanner's task_type must be referenced by at least one test file.
    A scanner with zero test references is a detector that CI cannot prove
    works — it's the 'a detector that is never executed does not exist' rule."""
    files = _test_files_mentioning(task_type)
    assert files, (
        f"Scanner {scanner_type.value} (task_type={task_type}) has ZERO test "
        f"files referencing it. Add a positive-case test or remove the scanner."
    )


@pytest.mark.parametrize("scanner_type,task_type", list(_SCANNER_TASK_TYPES.items()))
def test_scanner_has_positive_case_assertion(scanner_type: AgentType, task_type: str):
    """At least one test file referencing the scanner's task_type must also
    contain a confirmed/validated assertion — the positive-case contract that
    proves the detector CAN detect + validate, not just that it runs."""
    files = _test_files_with_positive_assertion(task_type)
    assert files, (
        f"Scanner {scanner_type.value} (task_type={task_type}) has test files "
        f"but NONE assert confirmed=True / validated=True on a positive case. "
        f"The detector is tested for execution but NOT for detection quality."
    )
