import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from ai_osop.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@patch("ai_osop.cli.httpx.post")
def test_create_engagement(mock_post, runner):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "session_id": "test-session-id",
        "phase": "initialized",
    }

    result = runner.invoke(
        cli,
        [
            "--api-url",
            "http://test",
            "--token",
            "test",
            "engagement",
            "create",
            "test-eng",
            "--domain",
            "test.com",
            "--approval-for",
            "rce",
        ],
    )

    assert result.exit_code == 0
    assert "Engagement created: test-session-id" in result.output
    assert "Phase: initialized" in result.output
    mock_post.assert_called_once()


def test_list_engagements(runner):
    # CLI command `engagement list` doesn't actually make an API call in the current implementation
    result = runner.invoke(
        cli, ["--api-url", "http://test", "--token", "test", "engagement", "list"]
    )

    assert result.exit_code == 0
    assert "Active engagements:" in result.output


@patch("ai_osop.cli.httpx.post")
def test_halt_engagement(mock_post, runner):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"status": "halted"}

    result = runner.invoke(
        cli,
        [
            "--api-url",
            "http://test",
            "--token",
            "test",
            "engagement",
            "halt",
            "test-eng",
            "--reason",
            "Testing",
        ],
    )

    assert result.exit_code == 0
    assert "Engagement test-eng halted" in result.output
    mock_post.assert_called_once()


@patch("ai_osop.cli.httpx.post")
def test_create_task(mock_post, runner):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"id": "task-1"}

    result = runner.invoke(
        cli,
        [
            "--api-url",
            "http://test",
            "--token",
            "test",
            "task",
            "create",
            "--type",
            "recon",
            "--agent-type",
            "recon",
            "--engagement",
            "eng1",
            "--payload",
            '{"test":"val"}',
        ],
    )

    assert result.exit_code == 0
    assert "Task created: task-1" in result.output
    mock_post.assert_called_once()


@patch("ai_osop.cli.httpx.get")
def test_list_agents(mock_get, runner):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = [
        {"agent_id": "a1", "agent_type": "t1", "status": "idle"}
    ]

    result = runner.invoke(cli, ["--api-url", "http://test", "--token", "test", "agent", "list"])

    assert result.exit_code == 0
    assert "a1" in result.output
    mock_get.assert_called_once()


@patch("ai_osop.cli.httpx.get")
def test_list_approvals(mock_get, runner):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = [
        {"id": "req-1", "action_type": "rce", "target": "test", "risk_assessment": "High"}
    ]

    result = runner.invoke(cli, ["--api-url", "http://test", "--token", "test", "approval", "list"])

    assert result.exit_code == 0
    assert "req-1" in result.output
    mock_get.assert_called_once()


@patch("ai_osop.cli.httpx.post")
def test_resolve_approval(mock_post, runner):
    mock_post.return_value.status_code = 200

    result = runner.invoke(
        cli,
        ["--api-url", "http://test", "--token", "test", "approval", "resolve", "req-1", "approved"],
    )

    assert result.exit_code == 0
    assert "Approval req-1 approved" in result.output
    mock_post.assert_called_once()


@patch("ai_osop.cli.httpx.post")
def test_api_error_handling(mock_post, runner):
    mock_post.return_value.status_code = 400
    mock_post.return_value.text = "Bad Request"

    result = runner.invoke(
        cli,
        [
            "--api-url",
            "http://test",
            "--token",
            "test",
            "engagement",
            "create",
            "test-eng",
            "--domain",
            "test.com",
        ],
    )

    assert result.exit_code == 0
    assert "Error: 400 - Bad Request" in result.output
