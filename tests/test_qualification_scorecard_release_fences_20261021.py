"""Test-score reporters must never manufacture production release approval."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _module(filename: str):
    path = ROOT / "scripts" / "qualification" / filename
    spec = importlib.util.spec_from_file_location(
        "osop_release_safety_" + filename.replace(".", "_"), path
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_local_suite_success_is_not_a_release_signoff():
    orchestrator = _module("run_qualification.py")
    results = [
        {
            "script": "safe_local_suite.py",
            "returncode": 0,
            "passed": 100,
            "failed": 0,
            "stdout": "[PASS] deterministic isolated contract\n",
            "stderr": "",
        }
    ]
    report = orchestrator.generate_report(results)
    assert "LOCAL SUITES PASSED" in report
    assert "NOT PRODUCTION CERTIFIED / NOT READY" in report
    assert "RELEASE_CERTIFICATE.md" not in report
    assert "**QUALIFICATION PASSED**" not in report
    assert "**APPROVED**" not in report


def test_empty_or_zero_count_suite_is_not_reported_as_passed():
    orchestrator = _module("run_qualification.py")
    for records in (
        [],
        [
            {
                "script": "no-tests",
                "returncode": 0,
                "passed": 0,
                "failed": 0,
                "stdout": "",
                "stderr": "",
            }
        ],
    ):
        result = orchestrator.generate_report(records)
        assert "LOCAL SUITES PASSED" not in result
        assert "LOCAL SUITES INCOMPLETE OR FAILED" in result
        assert "NOT PRODUCTION CERTIFIED / NOT READY" in result


def test_hundred_percent_local_score_cannot_become_production_ready(monkeypatch, tmp_path):
    report = _module("generate_report.py")
    monkeypatch.chdir(tmp_path)
    fixture_suite = tmp_path / "suite.py"
    fixture_suite.write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr(report, "SUITES", [("Synthetic", str(fixture_suite))])

    async def synthetic(_name: str, _path: str) -> dict:
        return {
            "name": "Synthetic",
            "passed": 100,
            "failed": 0,
            "errors": 0,
            "output": "  PASS\n" * 100,
            "exit_code": 0,
        }

    monkeypatch.setattr(report, "run_suite", synthetic)
    asyncio.run(report.main())
    text = (tmp_path / "PRODUCTION_READINESS_REPORT.md").read_text(encoding="utf-8")
    assert "Local suite outcome score" in text
    assert "100%" in text
    assert "Production Ready** | NO" in text
    assert text.count("NOT PRODUCTION CERTIFIED / NOT READY") == 2
    assert "Score >= 90%" not in text
    assert not (tmp_path / "RELEASE_CERTIFICATE.md").exists()


def test_original_legacy_certificate_has_prominent_noncertified_disclaimer():
    historical = (ROOT / "RELEASE_CERTIFICATE.md").read_text(encoding="utf-8")
    assert historical.startswith(
        "# INVALID LEGACY CERTIFICATE — SUPERSEDED / NOT A PRODUCTION APPROVAL"
    )
    assert (
        "NOT PRODUCTION CERTIFIED / NOT READY"
        in historical.split("# Historical unverified content", 1)[0]
    )
    assert "original contents are retained" in historical
