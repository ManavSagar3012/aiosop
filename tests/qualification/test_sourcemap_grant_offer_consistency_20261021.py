"""Isolated negative contracts for a future SourceMap 0029/0030 grant join.

No grant is issued or redeemed. Fake SQL readers only exercise DENIAL paths;
an in-memory SQLite CHECK demonstrates that 0036 schema admission alone is
not runtime permission. No app DB, native provider, Docker or targets are used.
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from ai_osop.memory import native_mcp_execution_grants as grants
from ai_osop.memory.flow_resource_exports import make_manifest
from ai_osop.memory.native_mcp_folder_stage import approved_folder_stage_plan
from ai_osop.memory.native_mcp_worker_supervision import NativeMCPWorkerSupervisionStore
from ai_osop.memory.sourcemap_source_authority import (
    SourceMapSourceAuthorityStore,
    SourceMapSourceDenied,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE = "source-map-mcp"
INSPECT = "inspect_local_original_sourcemap"
SHA = "a" * 64
ARTIFACT = "artifact-" + "c" * 32
ACTION = "action-" + "d" * 32


def _migration(number: str, filename: str) -> Any:
    path = ROOT / "migrations" / "versions" / f"{number}_{filename}.py"
    spec = importlib.util.spec_from_file_location("check_migration_" + number, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source_task(manifest: str, artifact_sha: str, command_sha: str) -> dict[str, Any]:
    """The actual SourceMap Task pin names; no unrelated native mcp_* pin."""
    return {
        "resource_artifact_id": ARTIFACT,
        "resource_artifact_sha256": artifact_sha,
        "resource_authorization_sha256": SHA,
        "resource_command_sha256": command_sha,
        "resource_manifest_sha256": manifest,
    }


def _source_action() -> dict[str, Any]:
    return {
        "action_id": ACTION,
        "engagement_id": "eng-fixture",
        "flow_id": "flow-fixture",
        "task_id": "task-fixture",
        "subtask_id": "subtask-fixture",
        "owner_id": "owner-fixture",
        "server_id": SOURCE,
        "tool_name": INSPECT,
        "side_effect_class": "READ_ONLY",
        "flow_revision": 1,
        "authorization_id": "auth-fixture",
        "authorization_version": 1,
        "authorization_sha256": SHA,
        "status": "unknown",
        "cancel_requested": False,
    }


class _Result:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def mappings(self) -> "_Result":
        return self

    def one_or_none(self) -> Any:
        return self.value

    def scalar_one_or_none(self) -> Any:
        return self.value

    def all(self) -> Any:
        return self.value


class _ReadOnlySQL:
    """Scripted isolated read responses; fail on ANY attempted mutation."""

    def __init__(self, responses: list[tuple[str, Any]]) -> None:
        self.responses = list(responses)
        self.executed: list[str] = []

    async def execute(self, query: Any, bindings: Any = None) -> _Result:
        sql = str(query)
        assert sql.lstrip().upper().startswith("SELECT "), sql
        self.executed.append(sql)
        assert self.responses, "Unexpected SQL after expected denial: " + sql[:150]
        signature, answer = self.responses.pop(0)
        assert signature in sql, (signature, sql)
        return _Result(answer)


def test_actual_0036_pair_is_schema_only_and_runtime_source_denies() -> None:
    migration = _migration("0036", "sourcemap_native_grant_pair")
    assert migration.down_revision == "0035"
    with sqlite3.connect(":memory:") as connection:
        connection.execute(
            "CREATE TABLE grant_identity (server_id TEXT NOT NULL, "
            "tool_name TEXT NOT NULL, side_effect_class TEXT NOT NULL, "
            "CHECK (" + migration._PAIRWISE + "))"
        )
        connection.execute(
            "INSERT INTO grant_identity VALUES (?, ?, ?)", (SOURCE, INSPECT, "READ_ONLY")
        )
        assert connection.execute("SELECT count(*) FROM grant_identity").fetchone() == (1,)
    with pytest.raises(grants.NativeMCPGrantDenied, match="resource offering"):
        grants._require_operational_pair(SOURCE, INSPECT, "READ_ONLY")
    # Even with a valid 0036 row shape, the original signed grant verifier must
    # not accept SourceMap as native provider permission.
    source = inspect.getsource(grants.NativeMCPExecutionGrantStore._original)
    assert "_require_operational_pair(" in source
    assert 'row.get("status") != "unknown"' in source
    assert 'row.get("cancel_requested") is not False' in source


def test_signed_0029_claims_do_not_encode_original_source_artifact_identity() -> None:
    # _CLAIMS is a strict 19-claim set but has neither 0013 artifact_id nor
    # source-proof ID. A digest alone cannot bind selected original bytes.
    assert len(grants._CLAIMS) == 19
    for required in ("resource_sha256", "parameters_sha256", "manifest_sha256", "action_id"):
        assert required in grants._CLAIMS
    for absent in ("resource_artifact_id", "preflight_id", "resource_command_sha256"):
        assert absent not in grants._CLAIMS
    assert (
        grants.DOMAIN
        != __import__("ai_osop.memory.sourcemap_source_authority", fromlist=["DOMAIN"]).DOMAIN
    )
    source = inspect.getsource(grants._validate_claims)
    assert 'hashlib.sha256(b"{}")' in source
    assert '_native_manifest_sha256(value["server_id"])' in source
    assert "Native grant cannot authorize this tool" in source


def test_0026_0029_0030_0033_0035_sql_schemas_have_no_signed_join() -> None:
    schemas = {
        key: (ROOT / "migrations" / "versions" / path).read_text(encoding="utf-8")
        for key, path in {
            "0013": "0013_flow_artifacts.py",
            "0026": "0026_flow_resource_folders.py",
            "0029": "0029_native_mcp_execution_grants.py",
            "0030": "0030_native_mcp_resource_delivery.py",
            "0031": "0031_pinned_native_folder_stage.py",
            "0033": "0033_native_worker_supervision.py",
            "0035": "0035_native_sourcemap_source_authority.py",
        }.items()
    }
    assert 'sa.Column("content", sa.LargeBinary(), nullable=False)' in schemas["0013"]
    assert "trg_flow_artifact_immutable" in schemas["0013"]
    assert "flow_resource_folder_assignments" in schemas["0026"]
    assert "flow_artifacts.id" in schemas["0026"]
    assert '"request_id", sa.String(80), nullable=False, unique=True' in schemas["0029"]
    assert '"native_mcp_execution_grants.grant_id"' in schemas["0030"]
    assert '"folder_staging_sha256"' in schemas["0031"]
    assert '"native_mcp_execution_grants.grant_id"' in schemas["0033"]
    assert "native_sourcemap_source_preflights" in schemas["0035"]
    assert "trg_native_sourcemap_source_immutable" in schemas["0035"]
    assert "native_sourcemap_source_preflights" not in schemas["0029"]
    assert "native_sourcemap_source_preflights" not in schemas["0030"]
    assert "native_sourcemap_source_preflights" not in schemas["0033"]
    assert "native_mcp_execution_grants.grant_id" not in schemas["0035"]
    assert "native_mcp_resource_offers" not in schemas["0035"]


def test_honest_manifest_digest_can_agree_without_signed_task_or_offer() -> None:
    # Classifications and canonical manifest can match. That does NOT equate
    # SourceMap's original Task resource_* fields to 0029's different mcp_*.
    contents = b"const example = 1;\n"
    digest = hashlib.sha256(contents).hexdigest()
    metadata = {
        "id": ARTIFACT,
        "name": "fixture.js",
        "size_bytes": len(contents),
        "sha256": digest,
        "flow_id": "flow-fixture",
        "flow_revision": 1,
        "authorization_version": 1,
    }
    full = make_manifest("flow-fixture", 1, 1, [(metadata, contents)])
    source = SourceMapSourceAuthorityStore._metadata_manifest("flow-fixture", 1, 1, [metadata])
    assert full["manifest_sha256"] == source
    payload = _source_task(source, digest, "b" * 64)
    assert set(payload) == {
        "resource_artifact_id",
        "resource_artifact_sha256",
        "resource_authorization_sha256",
        "resource_command_sha256",
        "resource_manifest_sha256",
    }
    assert "mcp_resource_sha256" not in payload
    assert "mcp_folder_staging_sha256" not in payload


@pytest.mark.asyncio
async def test_generic_task_manifest_sha_without_mcp_pin_is_rejected_before_bytes() -> None:
    manifest = "b" * 64
    db = _ReadOnlySQL(
        [("SELECT payload FROM tasks", {"payload": _source_task(manifest, SHA, SHA)})]
    )
    row = {**_source_action(), "server_id": "recon-mcp", "tool_name": "authority_status"}
    with pytest.raises(grants.NativeMCPGrantDenied, match="Resource digest missing"):
        await grants.NativeMCPExecutionGrantStore._resources(db, row, manifest)
    assert len(db.executed) == 1
    assert "flow_artifacts" not in db.executed[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("digest", [None, "b" * 64])
async def test_exact_source_resource_cannot_skip_0030_0013_by_nullable_digest(
    digest: str | None,
) -> None:
    db = _ReadOnlySQL([])
    with pytest.raises(grants.NativeMCPGrantDenied, match="resource offering"):
        await grants.NativeMCPExecutionGrantStore._resources(db, _source_action(), digest)
    assert db.executed == []


@pytest.mark.asyncio
async def test_source_task_without_0026_folder_pin_is_ram_only_not_host_stage() -> None:
    db = _ReadOnlySQL([("SELECT payload FROM tasks", {"payload": _source_task(SHA, SHA, SHA)})])
    plan = await approved_folder_stage_plan(
        db, _source_action(), {"manifest_sha256": SHA, "items": []}
    )
    assert plan is None
    assert len(db.executed) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra", [{"mcp_folder_catalog_revision": 1}, {"mcp_folder_staging_sha256": SHA}]
)
async def test_partial_folder_pins_are_rejected_without_catalog_read(extra: dict[str, Any]) -> None:
    db = _ReadOnlySQL(
        [("SELECT payload FROM tasks", {"payload": {**_source_task(SHA, SHA, SHA), **extra}})]
    )
    with pytest.raises(grants.NativeMCPGrantDenied, match="folder binding malformed"):
        await approved_folder_stage_plan(
            db, _source_action(), {"manifest_sha256": SHA, "items": []}
        )
    assert len(db.executed) == 1


def _original_row() -> dict[str, Any]:
    return {**_source_action(), "flow_revision": 1, "authorization_version": 1}


def _selected_artifact(*, swapped_bytes: bool = False) -> dict[str, Any]:
    data = b"const x = 1;\n"
    return {
        "id": ARTIFACT,
        "engagement_id": "eng-fixture",
        "flow_id": "flow-fixture",
        "owner_id": "owner-fixture",
        "name": "safe.js",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "flow_revision": 1,
        "authorization_version": 1,
        "authorization_sha256": SHA,
        "original_bytes_len": len(data),
        "original_bytes_sha256": ("f" * 64 if swapped_bytes else hashlib.sha256(data).hexdigest()),
    }


@pytest.mark.asyncio
async def test_sourcemap_original_bytea_hash_mismatch_denied_before_senior_review() -> None:
    artifact = _selected_artifact(swapped_bytes=True)
    db = _ReadOnlySQL([("encode(sha256(content),'hex')", [artifact])])
    with pytest.raises(SourceMapSourceDenied):
        await SourceMapSourceAuthorityStore._original_manifest(
            db, _original_row(), artifact["sha256"]
        )
    assert len(db.executed) == 1
    assert "flow_artifact_reviews" not in db.executed[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("reviewer_disabled", [None, True])
async def test_current_source_senior_review_denied_when_reviewer_not_enabled(
    reviewer_disabled: bool | None,
) -> None:
    artifact = _selected_artifact()
    review = {
        "artifact_id": ARTIFACT,
        "flow_id": "flow-fixture",
        "engagement_id": "eng-fixture",
        "uploader_sub": "owner-fixture",
        "reviewer_sub": "senior-fixture",
        "reviewer_role": "senior_operator",
        "decision": "approve",
        "artifact_sha256": artifact["sha256"],
        "flow_revision": 1,
        "authorization_id": "auth-fixture",
        "authorization_version": 1,
        "authorization_sha256": SHA,
    }
    db = _ReadOnlySQL(
        [
            ("encode(sha256(content),'hex')", [artifact]),
            ("FROM flow_artifact_reviews", review),
            ("FROM operator_subject_controls", reviewer_disabled),
        ]
    )
    # The final query is a *scalar disabled boolean*, not a signed grant.
    with pytest.raises(SourceMapSourceDenied):
        await SourceMapSourceAuthorityStore._original_manifest(
            db, _original_row(), artifact["sha256"]
        )
    assert len(db.executed) == 3
    assert db.responses == []


@pytest.mark.asyncio
async def test_0033_supervisor_refuses_offer_with_mismatched_resource_sha() -> None:
    grant = {
        "grant_id": "ngr-" + "1" * 32,
        "engagement_id": "eng-fixture",
        "flow_id": "flow-fixture",
        "action_id": ACTION,
        "request_id": "req-" + "2" * 48,
        "server_id": "recon-mcp",
        "resource_sha256": SHA,
    }
    mismatched = {
        **grant,
        "status": "offered",
        "manifest_sha256": "b" * 64,
    }
    db = _ReadOnlySQL(
        [
            ("SELECT * FROM native_mcp_resource_offers", mismatched),
            ("SELECT * FROM native_mcp_stage_receipts", None),
        ]
    )
    with pytest.raises(grants.NativeMCPGrantDenied, match="Stale original source resource offer"):
        await NativeMCPWorkerSupervisionStore._auxiliary(db, grant)
    assert len(db.executed) == 2


def test_finite_0029_0033_and_0035_live_gates_are_distinct() -> None:
    from ai_osop.memory import native_mcp_resource_delivery as delivery
    from ai_osop.memory import sourcemap_source_authority as source

    assert "_verify(token)" in inspect.getsource(delivery.NativeMCPResourceDelivery.offer)
    assert 'observed["status"] != "redeemed"' in inspect.getsource(
        delivery.NativeMCPResourceDelivery.offer
    )
    assert "approved_folder_stage_plan(db, original, manifest)" in inspect.getsource(
        delivery.NativeMCPResourceDelivery.offer
    )
    assert "ON CONFLICT DO NOTHING RETURNING grant_id" in inspect.getsource(
        delivery.NativeMCPResourceDelivery.offer
    )
    assert "_verify(token)" in inspect.getsource(NativeMCPWorkerSupervisionStore.record)
    assert "_verify_observation(" in inspect.getsource(NativeMCPWorkerSupervisionStore.record)
    assert "SELECT nextval('native_mcp_worker_epoch_seq')" in inspect.getsource(
        NativeMCPWorkerSupervisionStore.record
    )
    assert "expected_revision" in inspect.getsource(NativeMCPWorkerSupervisionStore.record)
    assert "_metadata_manifest" in inspect.getsource(source.SourceMapSourceAuthorityStore)
    assert "ON CONFLICT DO NOTHING RETURNING preflight_id" in inspect.getsource(
        source.SourceMapSourceAuthorityStore.admit
    )
    assert source.DOMAIN != grants.DOMAIN
