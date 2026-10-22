"""Legacy release generator must never mint a fictitious certificate."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load():
    module_path = (
        Path(__file__).resolve().parents[1]
        / "scripts/qualification/generate_release_certificate.py"
    )
    spec = importlib.util.spec_from_file_location(
        "osop_noncertified_release_generator_test", module_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_emits_only_noncertified_draft_and_nonzero_gate(monkeypatch, tmp_path):
    generator = _load()
    monkeypatch.chdir(tmp_path)
    (tmp_path / "PRODUCTION_READINESS_REPORT.md").write_text(
        "**PRODUCTION CERTIFIED**\n**100% precision**\n", encoding="utf-8"
    )
    monkeypatch.setattr(generator, "get_git_sha", lambda: "abc123")
    monkeypatch.setattr(generator, "get_git_branch", lambda: "qual-only")
    monkeypatch.setattr(generator, "get_black_check", lambda: "PASS")
    monkeypatch.setattr(generator, "get_flake8_check", lambda: "PASS")
    monkeypatch.setattr(generator, "get_mypy_check", lambda: "PASS")
    monkeypatch.setattr(
        generator,
        "read_qualification_report",
        lambda: (_ for _ in ()).throw(AssertionError("Untrusted old score used")),
    )
    assert generator.main() == 2
    assert not (tmp_path / "RELEASE_CERTIFICATE.md").exists()
    draft = (tmp_path / "RELEASE_READINESS_DRAFT.md").read_text(encoding="utf-8")
    assert draft.count("NOT PRODUCTION CERTIFIED / NOT READY") == 2
    assert "Historical report present (not independently validated) | True" in draft
    assert "**100% precision**" not in draft
    assert "RELEASE CANDIDATE READY" not in draft
    assert "Independently authenticated, owner-of-record effect evidence" in draft
    assert "senior-signed" in draft


def test_generator_does_not_overwrite_preexisting_certificate(monkeypatch, tmp_path):
    generator = _load()
    monkeypatch.chdir(tmp_path)
    legacy = tmp_path / "RELEASE_CERTIFICATE.md"
    legacy.write_text("historical immutable provenance\n", encoding="utf-8")
    monkeypatch.setattr(generator, "get_git_sha", lambda: "abc123")
    monkeypatch.setattr(generator, "get_git_branch", lambda: "qual-only")
    for name in ("get_black_check", "get_flake8_check", "get_mypy_check"):
        monkeypatch.setattr(generator, name, lambda: "FAIL")
    assert generator.main() == 2
    assert legacy.read_text(encoding="utf-8") == "historical immutable provenance\n"
    draft = (tmp_path / "RELEASE_READINESS_DRAFT.md").read_text(encoding="utf-8")
    assert "Selected Black check | FAIL" in draft
    assert "NOT PRODUCTION CERTIFIED / NOT READY" in draft
