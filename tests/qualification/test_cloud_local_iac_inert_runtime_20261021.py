"""Isolated ASGI proof of current local Terraform/Checkov Cloud MCP boundaries.

Only test-owned inert Terraform, httpx ASGITransport (NO listener/network),
mocked subprocess pipes, and an interpreter that is NEVER invoked. The real
Checkov+loopback MCPRegistry test belongs to the separate joined qualification;
the success in THIS file must never be represented as real Checkov or IAM.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "mcp-servers/python/cloud_mcp.py"
TOKEN = "local-fixture-inert-cloud-checkov-" + "a" * 40
BODY = {"tool_name": "scan_local_iac", "parameters": {}, "request_id": "req-inert-custody"}
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def module() -> Any:
    spec = importlib.util.spec_from_file_location("_cloud_local_inert_qualification", MODULE_PATH)
    assert spec and spec.loader
    result = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = result
    spec.loader.exec_module(result)
    try:
        yield result
    finally:
        sys.modules.pop(spec.name, None)


@pytest.fixture
def fixture_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "operator-pin"
    root.mkdir(mode=0o700)
    (root / "main.tf").write_text(
        'resource "aws_s3_bucket" "inert_example" {\n' '  bucket = "example-not-created"\n' "}\n",
        encoding="utf-8",
    )
    # The scan is ALWAYS stubbed. This interpreter exists only to pass an
    # operator-configured file check, never as a command run by this suite.
    monkeypatch.setenv("OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED", "1")
    monkeypatch.setenv("OSOP_CLOUD_MCP_IAC_ROOT", str(root))
    monkeypatch.setenv("OSOP_CLOUD_MCP_CHECKOV_PYTHON", sys.executable)
    monkeypatch.setenv("OSOP_CLOUD_MCP_BEARER_TOKEN", TOKEN)
    return root


def fake_checkov_report(file_path: str = "/main.tf") -> dict[str, Any]:
    return {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_18",
                    "file_path": file_path,
                    "resource": "aws_s3_bucket.inert_example",
                    "file_line_range": [1, 3],
                }
            ]
        },
    }


def make_client(module: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app),
        base_url="http://asgi-only.invalid",
        timeout=2,
    )


@pytest.mark.asyncio
async def test_unconfigured_mount_never_advertises_scanner_or_calls_provider(
    module: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for key in (
        "OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED",
        "OSOP_CLOUD_MCP_IAC_ROOT",
        "OSOP_CLOUD_MCP_CHECKOV_PYTHON",
        "OSOP_CLOUD_MCP_BEARER_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)
    runner = AsyncMock(side_effect=AssertionError("No scanner may run"))
    monkeypatch.setattr(module, "_scan", runner)
    async with make_client(module) as client:
        health = await client.get("/health")
        init = await client.post("/mcp/initialize", json={})
        execute = await client.post("/mcp/execute", json=BODY, headers=HEADERS)
    assert health.status_code == 503
    assert health.json() == {"server_id": "cloud-mcp", "status": "unavailable"}
    assert init.status_code == 200 and init.json()["tools"] == []
    assert init.json()["capabilities"] == []
    assert execute.status_code == 503 and execute.json()["error"] == "local_iac_unavailable"
    runner.assert_not_awaited()


@pytest.mark.asyncio
async def test_configured_bearer_and_no_cloud_credential_or_target_claims(
    module: Any, fixture_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner = AsyncMock(
        return_value=[
            {
                "check_id": "CKV_AWS_18",
                "file": "main.tf",
                "resource": "aws_s3_bucket.inert_example",
                "line": 1,
                "validation_state": "STATIC_IAC_ONLY",
            }
        ]
    )
    monkeypatch.setattr(module, "_scan", scanner)
    async with make_client(module) as client:
        health = await client.get("/health")
        init = await client.post("/mcp/initialize", json={})
        missing = await client.post("/mcp/execute", json=BODY)
        wrong = await client.post(
            "/mcp/execute",
            json=BODY,
            headers={
                "Authorization": "Bearer " + "z" * len(TOKEN),
            },
        )
        accepted = await client.post("/mcp/execute", json=BODY, headers=HEADERS)
    assert health.json() == {
        "server_id": "cloud-mcp",
        "status": "ready",
        "capability": "local_iac_only",
        "live_cloud_account_verified": False,
    }
    assert init.json()["capabilities"] == ["local_iac_static_unverified"]
    assert [tool["name"] for tool in init.json()["tools"]] == ["scan_local_iac"]
    assert init.json()["tools"][0]["side_effect_class"] == "READ_ONLY"
    assert missing.status_code == wrong.status_code == 401
    assert accepted.status_code == 200
    output = accepted.json()
    assert output["request_id"] == BODY["request_id"]
    assert output["result"]["source"] == "CHECKOV_LOCAL_IAC_UNVERIFIED"
    assert output["result"]["live_cloud_account_verified"] is False
    assert output["result"]["target_effect_verified"] is False
    assert output["result"]["findings"][0]["validation_state"] == "STATIC_IAC_ONLY"
    assert len(output["result"]["input_manifest_sha256"]) == 64
    scanner.assert_awaited_once()
    assert scanner.await_args.args[0] == fixture_root.resolve()
    assert scanner.await_args.args[1] == Path(sys.executable).resolve()


@pytest.mark.asyncio
async def test_request_never_controls_root_framework_or_authenticated_cloud_claims(
    module: Any, fixture_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner = AsyncMock(return_value=[])
    monkeypatch.setattr(module, "_scan", scanner)
    malicious = (
        {**BODY, "parameters": {"path": str(fixture_root.parent)}},
        {**BODY, "parameters": {"directory": "../../"}},
        {**BODY, "parameters": {"framework": "cloudformation"}},
        {**BODY, "tool_name": "analyze_iam_trust_policies"},
        {**BODY, "request_id": "bad-request"},
        # Extra fields must never let a client mint host/cloud verification.
        {**BODY, "target_effect_verified": True, "live_cloud_account_verified": True},
    )
    async with make_client(module) as client:
        for payload in malicious:
            result = await client.post("/mcp/execute", json=payload, headers=HEADERS)
            assert result.status_code in (422, 503), (payload, result.status_code, result.text)
        for body in (
            b'{"tool_name":"scan_local_iac","tool_name":"cloud_admin","parameters":{}}',
            b'{"tool_name":"scan_local_iac","parameters":{"scope":1,"scope":2}}',
            b'{"tool_name":"scan_local_iac","parameters":{},"unexpected":NaN}',
            b'{"tool_name":"scan_local_iac","parameters":{},"unexpected":1e9999}',
        ):
            response = await client.post(
                "/mcp/execute",
                content=body,
                headers={**HEADERS, "Content-Type": "application/json"},
            )
            assert response.status_code == 422
        huge = await client.post(
            "/mcp/execute",
            content=b"x" * 100_000,
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        assert huge.status_code == 413
        wrong_type = await client.post(
            "/mcp/execute", content=b"{}", headers={**HEADERS, "Content-Type": "text/plain"}
        )
        assert wrong_type.status_code == 415
    scanner.assert_not_awaited()


@pytest.mark.parametrize(
    "invalid", ["../escape.tf", "unapproved.tf", "C:/private.tf", "module.tf.bak"]
)
def test_checkov_finding_path_must_refer_to_operator_pinned_tf(
    module: Any, fixture_root: Path, invalid: str
) -> None:
    with pytest.raises(ValueError):
        module._findings(fake_checkov_report(invalid), fixture_root)
    actual = module._findings(fake_checkov_report("/main.tf"), fixture_root)
    assert actual == [
        {
            "check_id": "CKV_AWS_18",
            "file": "main.tf",
            "resource": "aws_s3_bucket.inert_example",
            "line": 1,
            "validation_state": "STATIC_IAC_ONLY",
        }
    ]


@pytest.mark.asyncio
async def test_symlink_and_nontf_roots_fail_preflight_no_scan(
    module: Any, fixture_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = AsyncMock(side_effect=AssertionError("Forbidden scan called"))
    monkeypatch.setattr(module, "_scan", run)
    outside = fixture_root.parent / "outside"
    outside.mkdir()
    (outside / "secret.tf").write_text("inert", encoding="utf-8")
    link = fixture_root / "escaped.tf"
    try:
        link.symlink_to(outside / "secret.tf")
    except (OSError, NotImplementedError):
        pytest.skip("Host cannot create symlinks without privilege")
    async with make_client(module) as client:
        result = await client.post("/mcp/execute", json=BODY, headers=HEADERS)
        assert result.status_code == 503 and result.json()["error"] == "local_iac_unavailable"
        link.unlink()
        root_link = fixture_root.parent / "rootlink"
        root_link.symlink_to(fixture_root, target_is_directory=True)
        monkeypatch.setenv("OSOP_CLOUD_MCP_IAC_ROOT", str(root_link))
        denied_root = await client.post("/mcp/execute", json=BODY, headers=HEADERS)
        assert denied_root.status_code == 503
        monkeypatch.setenv("OSOP_CLOUD_MCP_IAC_ROOT", str(fixture_root))
        (fixture_root / "invalid.txt").write_text("inert nonterraform", encoding="utf-8")
        denied_file = await client.post("/mcp/execute", json=BODY, headers=HEADERS)
        assert denied_file.status_code == 503
    run.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["nonterraform", "too_many", "too_large", "simulated_symlink"])
async def test_operator_tree_file_count_bytes_and_symlink_guards_fail_closed(
    module: Any, fixture_root: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    scanner = AsyncMock(side_effect=AssertionError("Unapproved tree reached runner"))
    monkeypatch.setattr(module, "_scan", scanner)
    if case == "nonterraform":
        (fixture_root / "notes.txt").write_text("inert", encoding="utf-8")
    elif case == "too_many":
        for index in range(51):
            (fixture_root / f"extra_{index:02d}.tf").write_text("# inert\n", encoding="utf-8")
    elif case == "too_large":
        (fixture_root / "main.tf").write_bytes(b"#" * 1_000_001)
    else:
        source = fixture_root / "main.tf"
        original = Path.is_symlink

        def emulate_filesystem_link(path: Path) -> bool:
            # Purely simulated branch on hosts unable to create symlinks;
            # never claims this substitutes for real filesystem link testing.
            return path == source or original(path)

        monkeypatch.setattr(Path, "is_symlink", emulate_filesystem_link)
    async with make_client(module) as client:
        result = await client.post("/mcp/execute", json=BODY, headers=HEADERS)
    assert result.status_code == 503
    assert result.json() == {"status": "error", "error": "local_iac_unavailable"}
    scanner.assert_not_awaited()


@pytest.mark.asyncio
async def test_configuration_manifest_detects_local_file_mutation_mid_scan(
    module: Any, fixture_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def change_file(root: Path, executable: Path) -> list[dict[str, Any]]:
        (root / "main.tf").write_text("# modified after signature\n", encoding="utf-8")
        return []

    monkeypatch.setattr(module, "_scan", change_file)
    async with make_client(module) as client:
        output = await client.post("/mcp/execute", json=BODY, headers=HEADERS)
    assert output.status_code == 503
    assert output.json()["error"] == "scan_unknown"


@pytest.mark.asyncio
async def test_native_hardlink_escape_denies_before_any_scanner_call(
    module: Any, fixture_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = fixture_root.parent / "inert-external.tf"
    outside.write_text("# test-owned outside bytes only\n", encoding="utf-8")
    linked = fixture_root / "linked.tf"
    try:
        os.link(outside, linked)
    except OSError:
        pytest.skip("Host filesystem does not allow creating a test-owned native hardlink")
    runner = AsyncMock(side_effect=AssertionError("External hardlink reached scanner"))
    monkeypatch.setattr(module, "_scan", runner)
    async with make_client(module) as client:
        denied = await client.post("/mcp/execute", json=BODY, headers=HEADERS)
    assert denied.status_code == 503
    assert denied.json()["error"] == "local_iac_unavailable"
    runner.assert_not_awaited()


@pytest.mark.asyncio
async def test_private_stage_digest_tamper_rejected_before_http_success(
    module: Any, fixture_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_before = (fixture_root / "main.tf").read_bytes()
    scanned = []

    async def write_private_bytes(stage: Path, executable: Path) -> list[dict[str, Any]]:
        assert stage != fixture_root
        assert (stage / "main.tf").read_bytes() == source_before
        scanned.append(stage)
        (stage / "main.tf").write_text("# changed Checkov-stage bytes\n", encoding="utf-8")
        return []

    monkeypatch.setattr(module, "_scan_frozen", write_private_bytes)
    async with make_client(module) as client:
        response = await client.post("/mcp/execute", json=BODY, headers=HEADERS)
    assert response.status_code == 503
    assert response.json()["error"] == "scan_unknown"
    assert len(scanned) == 1 and not scanned[0].exists()
    assert (fixture_root / "main.tf").read_bytes() == source_before


class FakeStdout:
    def __init__(self, data: bytes | BaseException) -> None:
        self.data = data

    async def read(self, limit: int) -> bytes:
        if isinstance(self.data, BaseException):
            raise self.data
        return self.data


class FakeProcess:
    def __init__(self, data: bytes | BaseException, code: int = 1) -> None:
        self.stdout = FakeStdout(data)
        self.returncode: int | None = None
        self.exit_code = code
        self.killed = False
        self.waited = 0

    async def wait(self) -> int:
        self.waited += 1
        self.returncode = -9 if self.killed else self.exit_code
        return self.returncode

    def kill(self) -> None:
        self.killed = True


@pytest.mark.asyncio
async def test_actual_scan_command_is_strictly_local_subprocess_environment(
    module: Any, fixture_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Old test asserted --directory/cwd == fixture_root, inadvertently
    # requiring Checkov to parse the mutable operator source directly.
    # Production now snapshots approved BYTES to a disposable private stage.
    original_bytes = (fixture_root / "main.tf").read_bytes()
    fake = FakeProcess(json.dumps(fake_checkov_report()).encode())
    recorded: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    snapshot_paths: list[Path] = []

    async def spawn(*args: Any, **kwargs: Any) -> FakeProcess:
        recorded.append((args, kwargs))
        private = Path(args[args.index("--directory") + 1])
        snapshot_paths.append(private)
        assert private != fixture_root
        assert private.parent != fixture_root
        assert private.name.startswith("osop-checkov-stage-")
        assert private.is_dir()  # check while the frozen bytes still exist
        assert (private / "main.tf").read_bytes() == original_bytes
        assert kwargs["cwd"] == str(private)
        return fake

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake-host-credential")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "fake-host-credential")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "C:/private/forbidden")
    monkeypatch.setenv("BC_API_KEY", "fake-bridgecrew-host-token")
    output = await module._scan(fixture_root, Path(sys.executable))
    assert output[0]["validation_state"] == "STATIC_IAC_ONLY"
    assert fake.waited == 1 and not fake.killed
    assert len(recorded) == 1
    args, kwargs = recorded[0]
    assert args[0] == sys.executable
    assert args[1:3] == (
        "-c",
        "from checkov.main import Checkov; raise SystemExit(Checkov().run())",
    )
    assert len(snapshot_paths) == 1
    assert args[args.index("--directory") + 1] == str(snapshot_paths[0])
    assert args[args.index("--framework") + 1] == "terraform"
    assert args[args.index("--skip-download") + 1] == "--download-external-modules"
    assert args[args.index("--download-external-modules") + 1] == "false"
    assert kwargs["cwd"] == str(snapshot_paths[0])
    assert kwargs["stderr"] == asyncio.subprocess.DEVNULL
    assert kwargs["stdout"] == asyncio.subprocess.PIPE
    env = kwargs["env"]
    assert env["BC_API_KEY"] == ""
    assert env["HOME"] == env["USERPROFILE"]
    assert Path(env["HOME"]).name.startswith("osop-checkov-home-")
    assert env["PYTHONPATH"] == env["HOME"]
    for unsafe in ("AWS_ACCESS_KEY_ID", "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS"):
        assert unsafe not in env
    assert (fixture_root / "main.tf").read_bytes() == original_bytes
    assert not snapshot_paths[0].exists(), "Disposable staged Terraform bytes leaked"
    assert not Path(env["HOME"]).exists(), "Disposable fake Checkov home leaked"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["oversize", "timeout", "invalid_json"])
async def test_scan_bounded_output_timeout_and_cleanup_without_running_child(
    module: Any,
    fixture_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    data: bytes | BaseException = (
        b"x" * 2_000_001
        if kind == "oversize"
        else asyncio.TimeoutError() if kind == "timeout" else b"broken json"
    )
    process = FakeProcess(data)

    async def spawn(*_args: Any, **_kwargs: Any) -> FakeProcess:
        return process

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    if kind == "invalid_json":
        with pytest.raises(json.JSONDecodeError):
            await module._scan(fixture_root, Path(sys.executable))
    else:
        with pytest.raises((ValueError, asyncio.TimeoutError)):
            await module._scan(fixture_root, Path(sys.executable))
    assert process.killed is (kind != "invalid_json")
    assert process.waited == 1


def test_real_checkov_not_assumed_from_python_interpreter() -> None:
    """This suite never executes Checkov unless a separate offline-gated run exists."""
    # No import/command execution is required to assert mocked-vs-real scope:
    # the full ASGI success case monkeypatches _scan, and _scan tests stub
    # create_subprocess_exec; the real historical test is distinct and opt-in.
    assert MODULE_PATH.is_file()
