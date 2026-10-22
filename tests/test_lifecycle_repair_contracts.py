"""Regression checks for routing, immutable report storage and qualification."""

import importlib.util
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.experimental.graphql_agent import GraphQLAgent
from ai_osop.agents.experimental.mobile_agent import MobileAnalysisAgent
from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.reporting.artifact_store import publish_report_bundle


def test_specialists_are_not_claimed_by_generic_vulnerability_agent() -> None:
    generic = VulnAnalysisAgent.__new__(VulnAnalysisAgent)
    gql = GraphQLAgent.__new__(GraphQLAgent)
    mobile = MobileAnalysisAgent.__new__(MobileAnalysisAgent)
    assert generic.supports_task_type("nuclei_scan")
    assert not generic.supports_task_type("gql_discover_schema")
    assert gql.supports_task_type("gql_discover_schema")
    assert not gql.supports_task_type("nuclei_scan")
    assert not mobile.supports_task_type("analyze_deep_links")


def test_report_identity_never_overwrites_original_bytes(tmp_path: Path) -> None:
    report_id = "report-eng-test-v1"
    original = {"json": "original", "manifest": "original-manifest"}
    paths = publish_report_bundle(tmp_path, "eng-test", report_id, original)
    with pytest.raises(FileExistsError):
        publish_report_bundle(
            tmp_path, "eng-test", report_id, {"json": "changed", "manifest": "changed"}
        )
    assert Path(paths["json"]).read_text() == "original"
    assert Path(paths["manifest"]).read_text() == "original-manifest"
    assert publish_report_bundle(tmp_path, "eng-test", report_id, original) == paths


def test_competing_report_writers_cannot_mix_generations(tmp_path: Path) -> None:
    def publish(label: str) -> bool:
        try:
            publish_report_bundle(
                tmp_path, "eng-test", "report-eng-test-v1", {"json": label, "manifest": label}
            )
            return True
        except FileExistsError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, ["generation-a", "generation-b"]))
    assert sum(results) == 1
    directory = tmp_path / "eng-test"
    assert (directory / "report-eng-test-v1.json").read_bytes() == (
        directory / "report-eng-test-v1.manifest"
    ).read_bytes()


def test_partial_report_cannot_publish_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ai_osop.reporting.artifact_store as storage

    original_link = storage.os.link

    def interrupted(source: Any, destination: Path) -> None:
        if str(destination).endswith(".manifest"):
            raise OSError("Simulated interrupted publisher")
        original_link(source, destination)

    monkeypatch.setattr(storage.os, "link", interrupted)
    with pytest.raises(OSError):
        publish_report_bundle(
            tmp_path, "eng-test", "report-eng-test-v1", {"json": "test", "manifest": "test"}
        )
    assert not (tmp_path / "eng-test/report-eng-test-v1.manifest").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_suite,report_code", [(True, 0), (False, 1)])
async def test_qualification_failure_is_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_suite: bool, report_code: int
) -> None:
    path = Path(__file__).parents[1] / "scripts/qualification/run_all.py"
    spec = importlib.util.spec_from_file_location("audit_repair_qualification_runner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = tmp_path / "suite.py"
    if not missing_suite:
        suite.write_text("# inert fixture\n")
    module.SUITES = [str(suite)]
    report = SimpleNamespace(
        returncode=report_code, communicate=AsyncMock(return_value=(b"fixture", None))
    )
    successful_suite = SimpleNamespace(
        returncode=0, communicate=AsyncMock(return_value=(b"fixture", None))
    )
    launch = AsyncMock(side_effect=[report] if missing_suite else [successful_suite, report])
    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", launch)
    assert await module.main() == 1
