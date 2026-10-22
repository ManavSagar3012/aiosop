"""CLI submits the original envelope and exposes API failures to shell callers."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from click.testing import CliRunner

from ai_osop.cli import cli


def _envelope(tmp_path: Path) -> Path:
    policy = {
        "engagement_id": "eng-cli",
        "domains": ["lab.test"],
        "ips": [],
        "exclusions": [],
        "allowed_techniques": [],
        "restrictions": [],
        "approval_required_for": [],
        "testing_window_start": None,
        "testing_window_end": None,
        "roe": {},
        "authorization_id": "auth-test",
    }
    path = tmp_path / "roe.json"
    path.write_text(json.dumps({"version": 1, "policy": policy, "signature": "fixture-only"}))
    return path


def test_cli_preserves_envelope_for_server_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _envelope(tmp_path)
    captured = []

    def request(method: str, url: str, **kwargs: Any) -> httpx.Response:
        captured.append(kwargs["json"])
        return httpx.Response(200, json={"session_id": "eng-cli", "phase": "initialized"})

    monkeypatch.setattr("ai_osop.cli.httpx.request", request)
    result = CliRunner().invoke(
        cli, ["--token", "synthetic", "engagement", "create", "eng-cli", "--signed-roe", str(path)]
    )
    assert result.exit_code == 0, result.output
    assert captured[0]["signed_roe"] == json.loads(path.read_text())
    assert captured[0]["domains"] == ["lab.test"]


def test_cli_rejected_envelope_is_failure_without_echoing_server_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def request(*args: Any, **kwargs: Any) -> httpx.Response:
        return httpx.Response(403, text="sensitive upstream details")

    monkeypatch.setattr("ai_osop.cli.httpx.request", request)
    result = CliRunner().invoke(
        cli,
        [
            "--token",
            "synthetic",
            "engagement",
            "create",
            "eng-cli",
            "--signed-roe",
            str(_envelope(tmp_path)),
        ],
    )
    assert result.exit_code != 0
    assert "403" in result.output
    assert "sensitive upstream" not in result.output


def test_cli_domain_cannot_override_signed_scope(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "--token",
            "synthetic",
            "engagement",
            "create",
            "eng-cli",
            "--signed-roe",
            str(_envelope(tmp_path)),
            "--domain",
            "outside.test",
        ],
    )
    assert result.exit_code != 0
    assert "mismatched options" in result.output
