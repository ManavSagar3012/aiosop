"""Fail-closed current-byte Cloud MCP checks, WITHOUT target/cloud/provider calls.

Checkov subprocess cases in this file are *fakes* and MUST NOT be described as
real scanner qualification. Separate real-Checkov loopback test owns that claim.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest


SOURCE = Path(__file__).resolve().parents[2] / "mcp-servers/python/cloud_mcp.py"
TOKEN = "cloud-static-test-bearer-" + "9" * 40
REQUEST = {"tool_name": "scan_local_iac", "parameters": {}, "request_id": "req-current-bytes"}


@pytest.fixture
def cloud():
    spec = importlib.util.spec_from_file_location("_cloud_current_bytes_20261021", SOURCE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    try:
        yield module
    finally:
        sys.modules.pop(spec.name, None)


@pytest.fixture
def root(tmp_path, monkeypatch):
    source = tmp_path / "operator-original"
    source.mkdir()
    (source / "main.tf").write_text('resource "aws_s3_bucket" "inert" {}\n', encoding="utf-8")
    monkeypatch.setenv("OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED", "1")
    monkeypatch.setenv("OSOP_CLOUD_MCP_IAC_ROOT", str(source))
    monkeypatch.setenv("OSOP_CLOUD_MCP_CHECKOV_PYTHON", sys.executable)
    monkeypatch.setenv("OSOP_CLOUD_MCP_BEARER_TOKEN", TOKEN)
    return source


@pytest.mark.asyncio
async def test_staged_scanner_opens_exact_private_bytes_not_mutable_operator_tree(
    cloud, root, monkeypatch
):
    before = (root / "main.tf").read_bytes()
    seen = []

    async def fake_frozen(directory, executable):
        seen.append((directory, executable, (directory / "main.tf").read_bytes()))
        assert directory != root and directory.resolve() != root.resolve()
        assert (directory / "main.tf").read_bytes() == before
        assert not (directory / "unexpected.tf").exists()
        return [
            {"check_id": "CKV_AWS_18", "file": "main.tf", "validation_state": "STATIC_IAC_ONLY"}
        ]

    monkeypatch.setattr(cloud, "_scan_frozen", fake_frozen)
    findings = await cloud._scan(root, Path(sys.executable))
    assert findings[0]["validation_state"] == "STATIC_IAC_ONLY"
    assert len(seen) == 1 and seen[0][1] == Path(sys.executable)
    assert not seen[0][0].exists(), "Frozen source stage must not persist"
    assert (root / "main.tf").read_bytes() == before


@pytest.mark.asyncio
async def test_mid_scan_original_mutation_is_unknown_not_verified_result(cloud, root, monkeypatch):
    async def mutate_when_frozen(directory, executable):
        assert (directory / "main.tf").read_text(encoding="utf-8").startswith("resource")
        (root / "main.tf").write_text("# changed during checkov\n", encoding="utf-8")
        return []

    monkeypatch.setattr(cloud, "_scan_frozen", mutate_when_frozen)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=cloud.app), base_url="http://asgi-only.invalid"
    ) as client:
        response = await client.post(
            "/mcp/execute", json=REQUEST, headers={"Authorization": f"Bearer {TOKEN}"}
        )
    assert response.status_code == 503
    assert response.json() == {"status": "error", "error": "scan_unknown"}


@pytest.mark.asyncio
async def test_mutated_private_stage_bytes_are_not_presented_as_original_manifest(
    cloud, root, monkeypatch
):
    async def rewrite_private_copy(directory, executable):
        (directory / "main.tf").write_text("# parser-mutated stage\n", encoding="utf-8")
        return []

    monkeypatch.setattr(cloud, "_scan_frozen", rewrite_private_copy)
    with pytest.raises(ValueError, match="Staged IaC bytes changed"):
        await cloud._scan(root, Path(sys.executable))
    assert (root / "main.tf").read_text(encoding="utf-8").startswith("resource")


@pytest.mark.asyncio
async def test_source_edit_mid_copy_denies_even_when_directory_filename_does_not_change(
    cloud, root, monkeypatch
):
    original = cloud._source_bytes
    changed = False

    def simulate_copy_race(directory):
        nonlocal changed
        blobs, manifest = original(directory)
        if directory == root and not changed:
            changed = True
            (root / "main.tf").write_text("# changed while source snapshot created\n")
        return blobs, manifest

    monkeypatch.setattr(cloud, "_source_bytes", simulate_copy_race)
    invoked = AsyncMock(side_effect=AssertionError("Scanner reached race"))
    monkeypatch.setattr(cloud, "_scan_frozen", invoked)
    with pytest.raises(ValueError, match="changed during staging"):
        await cloud._scan(root, Path(sys.executable))
    invoked.assert_not_awaited()


def test_hardlinks_and_nonregular_tree_entries_are_denied_before_checkov(cloud, root, tmp_path):
    outside = tmp_path / "outside.tf"
    outside.write_text("# inert external\n")
    linked = root / "outside.tf"
    try:
        os.link(outside, linked)
    except OSError:
        pytest.skip("Host forbids creating test hardlink")
    with pytest.raises(ValueError, match="independent regular"):
        cloud._configuration()


@pytest.mark.asyncio
async def test_strict_registry_timeout_field_and_caller_target_rejected(cloud, root, monkeypatch):
    scan = AsyncMock(return_value=[])
    monkeypatch.setattr(cloud, "_scan", scan)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=cloud.app), base_url="http://asgi-only.invalid"
    ) as client:
        accepted = await client.post(
            "/mcp/execute",
            json={**REQUEST, "timeout_override": None},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert accepted.status_code == 200
        for timeout in (-1, 0, 71, "100", True):
            denied = await client.post(
                "/mcp/execute",
                json={**REQUEST, "timeout_override": timeout},
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            assert denied.status_code in (422, 503)
        bad = await client.post(
            "/mcp/execute",
            json={**REQUEST, "parameters": {"target": "remote"}},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert bad.status_code == 422
    scan.assert_awaited_once()


@pytest.mark.asyncio
async def test_frozen_checkov_process_never_receives_live_root(cloud, root, monkeypatch):
    observed = {}

    class Output:
        async def read(self, limit):
            assert limit == cloud._MAX_OUTPUT + 1
            return json.dumps(
                {"check_type": "terraform", "results": {"failed_checks": []}}
            ).encode()

    class Process:
        stdout = Output()
        returncode = None

        async def wait(self):
            self.returncode = 0

        def kill(self):
            raise AssertionError("Healthy scanner must not be killed")

    async def fake_spawn(*args, **kwargs):
        directory = Path(args[args.index("--directory") + 1])
        assert directory != root
        assert directory.is_dir()
        assert (directory / "main.tf").read_bytes() == (root / "main.tf").read_bytes()
        observed["directory"] = directory
        observed["argv"] = args
        observed["env"] = kwargs["env"]
        assert kwargs["cwd"] == str(directory)
        return Process()

    monkeypatch.setattr(cloud.asyncio, "create_subprocess_exec", fake_spawn)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "fake-forbidden-to-forward")
    await cloud._scan(root, Path(sys.executable))
    assert "--skip-download" in observed["argv"]
    assert observed["argv"][observed["argv"].index("--download-external-modules") + 1] == "false"
    assert "AWS_ACCESS_KEY_ID" not in observed["env"]
    assert Path(observed["env"]["PYTHONPATH"], "sitecustomize.py").exists() is False
    assert not observed["directory"].exists()


@pytest.mark.asyncio
async def test_cancelled_scanner_kills_and_reaps_owned_child(cloud, root, monkeypatch):
    entered = asyncio.Event()
    gone = asyncio.Event()

    class BlockedOutput:
        async def read(self, limit):
            entered.set()
            await asyncio.Event().wait()

    class BlockedProcess:
        returncode = None
        stdout = BlockedOutput()

        async def wait(self):
            self.returncode = -9
            gone.set()
            return self.returncode

        def kill(self):
            assert self.returncode is None

    async def spawn(*_args, **_kwargs):
        return BlockedProcess()

    monkeypatch.setattr(cloud.asyncio, "create_subprocess_exec", spawn)
    task = asyncio.create_task(cloud._scan(root, Path(sys.executable)))
    await asyncio.wait_for(entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=3)
    assert gone.is_set(), "Child kill/reap must complete on cancellation"
