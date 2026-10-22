"""Read-only source-contract qualification for the CURRENT SourceMap/0029 blocker.

These tests inspect the installed migration and runtime source and exercise the
literal 0029 CHECK expression in isolated in-memory SQLite. SQLite is only a
predicate test harness: no PostgreSQL migration or actual grant is executed.
Every positive proposed-policy example is a *design example*, not production
SourceMap admission or certification.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import sqlite3
from pathlib import Path

import pytest

from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPGrantDenied,
    _native_manifest_sha256,
    _validate_claims,
)
from ai_osop.memory import native_mcp_execution_grants as grants
from ai_osop.memory import native_mcp_worker_supervision as supervision
from ai_osop.memory import sourcemap_source_authority as sourcemap
from ai_osop.memory import sourcemap_status_authority as status
from ai_osop.orchestrator import flow_mcp_action_executor as executor


ROOT = Path(__file__).resolve().parents[2]
MIGRATION_DIR = ROOT / "migrations" / "versions"
GO_SERVICES = (
    "recon-mcp",
    "payload-mcp",
    "nuclei-mcp",
    "shodan-mcp",
    "threat-intel-mcp",
    "security-bridge",
)
SOURCE_TOOL = "inspect_local_original_sourcemap"
SOURCE_SERVER = "source-map-mcp"


def _read_migration(name: str) -> str:
    path = MIGRATION_DIR / name
    assert path.is_file(), f"Expected reviewed migration missing: {name}"
    return path.read_text(encoding="utf-8")


def _check_expression(module_source: str, constraint_name: str) -> str:
    """Parse the real Alembic SQL literal, including split adjacent strings."""
    found = []
    for node in ast.walk(ast.parse(module_source)):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "CheckConstraint":
            continue
        keywords = {key.arg: key.value for key in node.keywords}
        label = keywords.get("name")
        if label is None or ast.literal_eval(label) != constraint_name:
            continue
        assert node.args, "A named constraint must include an SQL predicate"
        found.append(ast.literal_eval(node.args[0]))
    assert len(found) == 1, f"Expected one precise {constraint_name} CHECK; found {len(found)}"
    return found[0]


def _accepts_sql(predicate: str, server: str, tool: str, effect: str) -> bool:
    """Run only a bounded CHECK expression against an in-memory SQL table."""
    # The name CHECK comes from the migration AST, never from a user input.
    with sqlite3.connect(":memory:") as db:
        db.execute(
            "CREATE TABLE admission (server_id TEXT NOT NULL, tool_name TEXT NOT NULL, "
            "side_effect_class TEXT NOT NULL, CHECK (" + predicate + "))"
        )
        try:
            db.execute(
                "INSERT INTO admission (server_id,tool_name,side_effect_class) VALUES (?,?,?)",
                (server, tool, effect),
            )
        except sqlite3.IntegrityError:
            return False
        return True


def _valid_inert_claims(server: str) -> dict[str, object]:
    return {
        "version": 1,
        "grant_id": "ngr-" + "a" * 32,
        "request_id": "req-" + "b" * 48,
        "engagement_id": "eng-contract",
        "flow_id": "flow-contract",
        "task_id": "task-contract",
        "subtask_id": "subtask-contract",
        "action_id": "action-" + "c" * 32,
        "server_id": server,
        "tool_name": "authority_status",
        "parameters_sha256": hashlib.sha256(b"{}").hexdigest(),
        "manifest_sha256": _native_manifest_sha256(server),
        "authorization_version": 1,
        "authorization_sha256": "d" * 64,
        "lease_id": "lease-contract",
        "resource_sha256": None,
        "issued_at": 1234567890,
        "expires_at": 1234567900,
        "side_effect_class": "READ_ONLY",
    }


def test_0029_actual_db_check_blocks_sourcemap_even_when_read_only() -> None:
    original = _read_migration("0029_native_mcp_execution_grants.py")
    predicate = _check_expression(original, "ck_native_mcp_grant_inert_tool")
    assert predicate == "tool_name='authority_status' AND side_effect_class='READ_ONLY'"
    assert _accepts_sql(predicate, "recon-mcp", "authority_status", "READ_ONLY")
    for effect in ("READ_ONLY", "RECON_ACTIVE", "INVASIVE_EXPLOIT"):
        assert not _accepts_sql(predicate, SOURCE_SERVER, SOURCE_TOOL, effect)
    assert not _accepts_sql(predicate, "recon-mcp", "fetch_and_parse_sourcemap", "READ_ONLY")
    assert not _accepts_sql(predicate, "recon-mcp", "authority_status", "RECON_ACTIVE")
    # The database CHECK alone does NOT bind server identity; other layers do.
    assert _accepts_sql(predicate, SOURCE_SERVER, "authority_status", "READ_ONLY")


def test_actual_python_grant_validator_denies_source_map_before_signature_or_db() -> None:
    accepted = _valid_inert_claims("recon-mcp")
    assert _validate_claims(accepted) is accepted
    modified = {**_valid_inert_claims(SOURCE_SERVER), "tool_name": SOURCE_TOOL}
    with pytest.raises(NativeMCPGrantDenied, match="cannot authorize this tool"):
        _validate_claims(modified)
    assert _validate_claims(_valid_inert_claims(SOURCE_SERVER))["tool_name"] == "authority_status"
    # The last call is a *claim-shape* result, never a source admission: the
    # executor and original Action source reject this pairing independently.


def test_grant_store_cannot_make_source_map_original_a_native_grant() -> None:
    original_source = inspect.getsource(grants.NativeMCPExecutionGrantStore._original)
    bound_source = inspect.getsource(grants.NativeMCPExecutionGrantStore._source)
    assert 'row.get("tool_name") != "authority_status"' in original_source
    assert 'row.get("status") != "unknown"' in original_source
    assert 'row.get("cancel_requested") is not False' in original_source
    assert "kind='dispatch_attempted' AND status='unknown'" in original_source
    assert "_NATIVE_BUILTIN" in bound_source
    assert "self.actions._approved_task(" in bound_source
    assert "self.actions._authority(" in bound_source


def test_dispatch_grant_branch_is_exact_inert_go_subset_only() -> None:
    source = inspect.getsource(executor)
    for server in GO_SERVICES:
        assert f'"{server}"' in source
    mark = source.index("sent = await self.store.mark_dispatched(")
    issue_gate = source.index('if tool_name == "authority_status":', mark)
    issuer = source.index("await NativeMCPExecutionGrantStore(self.store).issue(", issue_gate)
    transport = source.index("result = await self.registry.execute_tool(", issuer)
    assert mark < issue_gate < issuer < transport
    assert 'if tool_name == "authority_status":' in source[mark:transport]
    assert '"Only inert native status is permitted"' in source[issue_gate:transport]
    # The full source keeps the distinct SourceMap action, but does not pass
    # the native grant header for that tool.
    assert (
        'server_id == "source-map-mcp" and tool_name == "inspect_local_original_sourcemap"'
        in source
    )
    assert "native_grant: Optional[str] = None" in source


def test_0033_requires_a_real_0029_grant_and_immutable_running_event() -> None:
    schema = _read_migration("0033_native_worker_supervision.py")
    state = inspect.getsource(supervision.NativeMCPWorkerSupervisionStore.record)
    assert 'sa.ForeignKey("native_mcp_execution_grants.grant_id", ondelete="RESTRICT")' in schema
    assert '"native_mcp_worker_supervision_events"' in schema
    assert "trg_native_worker_supervision_events_immutable" in schema
    assert "token_claims, grant_kid, grant_digest, grant_signature = _verify(token)" in state
    assert "original = await self.grants._source(" in state
    assert 'claims["state"] == "running" and locked["status"] != "redeemed"' in state
    assert "revision=revision+1,state=:state" in state
    assert 'row["revision"] + 1' in state
    assert "await self._event(db, row, claims, kid, digest, signature)" in state
    assert 'sa.Column("signature", ' not in schema
    assert 'sa.Column("claims", ' not in schema


def test_0030_0031_have_one_use_offer_and_no_implicit_folder_permission() -> None:
    m30 = _read_migration("0030_native_mcp_resource_delivery.py")
    m31 = _read_migration("0031_pinned_native_folder_stage.py")
    from ai_osop.memory.native_mcp_resource_delivery import NativeMCPResourceDelivery
    from ai_osop.memory.native_mcp_folder_stage import approved_folder_stage_plan

    offer = inspect.getsource(NativeMCPResourceDelivery.offer)
    folder = inspect.getsource(approved_folder_stage_plan)
    assert '"grant_id",' in m30 and "primary_key=True" in m30
    assert 'sa.Column("request_id", sa.String(80), nullable=False, unique=True)' in m30
    assert "trg_native_resource_offer_immutable" in m30
    assert "folder_staging_sha256" in m31
    assert "ck_native_resource_offer_folder_sha" in m31
    assert "ON CONFLICT DO NOTHING RETURNING" in offer
    assert "approved_folder_stage_plan(db, original, manifest)" in offer
    assert "if revision is None and pin is None:" in folder
    assert "return None" in folder


def test_native_resource_and_source_map_manifests_are_distinct_authorities() -> None:
    from ai_osop.memory.native_mcp_folder_stage import approved_folder_stage_plan

    generic_resources = inspect.getsource(grants.NativeMCPExecutionGrantStore._resources)
    source_resources = inspect.getsource(sourcemap.SourceMapSourceAuthorityStore._source)
    approved_folder = inspect.getsource(approved_folder_stage_plan)
    assert 'get("mcp_resource_sha256")' in generic_resources
    assert "make_manifest(" in generic_resources
    assert 'payload.get("resource_artifact_id")' in source_resources
    assert 'payload.get("resource_manifest_sha256")' in source_resources
    assert "self._original_manifest(" in source_resources
    assert 'manifest["items"]' in approved_folder
    # The 0035 _original_manifest returns an SHA and selected artifact ID,
    # not the generic make_manifest value with an items list.
    actual_metadata = inspect.getsource(sourcemap.SourceMapSourceAuthorityStore._original_manifest)
    assert 'return digest, selected[0]["id"]' in actual_metadata


def test_current_db_witness_demands_0029_tool_which_live_schema_rejects() -> None:
    from ai_osop.memory.sourcemap_supervisor_current_db_witness import (
        SourceMapSupervisorCurrentDBWitness,
    )

    witness = inspect.getsource(SourceMapSupervisorCurrentDBWitness.issue)
    assert 'grant.get("tool_name") != "inspect_local_original_sourcemap"' in witness
    assert 'grant.get("status") != "redeemed"' in witness
    assert 'grant.get("resource_sha256") != manifest' in witness
    predicate = _check_expression(
        _read_migration("0029_native_mcp_execution_grants.py"),
        "ck_native_mcp_grant_inert_tool",
    )
    assert not _accepts_sql(predicate, SOURCE_SERVER, SOURCE_TOOL, "READ_ONLY")


def test_0027_0035_sourcemap_have_distinct_one_use_authority_and_status_only_recheck() -> None:
    m27 = _read_migration("0027_flow_mcp_action_dispatch.py")
    m35 = _read_migration("0035_native_sourcemap_source_authority.py")
    source = inspect.getsource(sourcemap.SourceMapSourceAuthorityStore)
    status_source = inspect.getsource(status.SourceMapStatusAuthorityStore.admit)
    assert '"flow_mcp_action_dispatches"' in m27
    assert "uq_flow_mcp_action_event_revision" in m27
    assert 'sa.Column("request_id", sa.String(80), nullable=False, unique=True)' in m27
    assert "ck_native_sourcemap_source_identity" in m35
    assert "tool_name='inspect_local_original_sourcemap'" in m35
    assert '"action_id",' in m35 and "unique=True" in m35
    assert 'sa.Column("request_id", sa.String(80), nullable=False, unique=True)' in m35
    assert "trg_native_sourcemap_source_immutable" in m35
    assert 'current.get("status") != "unknown"' in source
    assert 'current.get("cancel_requested") is not False' in source
    assert "kind='dispatch_attempted' AND status='unknown'" in source
    assert "_original_manifest(" in source
    assert "SELECT * FROM native_sourcemap_source_preflights" in status_source
    assert "self.sources._source(db, request)" in status_source
    assert '"issued_at": now' in status_source and '"expires_at": now + 5' in status_source
    assert "INSERT INTO" not in status_source
    assert "UPDATE native_" not in status_source


# Proposed migration's SQL truth table is a finite design safety gate. It is
# not being deployed and cannot bypass the CURRENT production 0029 constraint.
PROPOSED_PAIRING = (
    "side_effect_class='READ_ONLY' AND (("
    "server_id IN ('recon-mcp','payload-mcp','nuclei-mcp','shodan-mcp',"
    "'threat-intel-mcp','security-bridge') AND tool_name='authority_status'"
    ") OR (server_id='source-map-mcp' AND tool_name='inspect_local_original_sourcemap'))"
)


@pytest.mark.parametrize(
    ("server", "tool", "effect", "admitted_in_design"),
    [
        ("recon-mcp", "authority_status", "READ_ONLY", True),
        ("security-bridge", "authority_status", "READ_ONLY", True),
        (SOURCE_SERVER, SOURCE_TOOL, "READ_ONLY", True),
        (SOURCE_SERVER, SOURCE_TOOL, "RECON_ACTIVE", False),
        (SOURCE_SERVER, "authority_status", "READ_ONLY", False),
        ("recon-mcp", SOURCE_TOOL, "READ_ONLY", False),
        ("browser-mcp", SOURCE_TOOL, "READ_ONLY", False),
        ("recon-mcp", "fetch_and_parse_sourcemap", "READ_ONLY", False),
        ("evil-mcp", SOURCE_TOOL, "READ_ONLY", False),
        ("evil-mcp", "authority_status", "READ_ONLY", False),
    ],
)
def test_future_pairwise_check_must_not_mint_broad_grants(
    server: str, tool: str, effect: str, admitted_in_design: bool
) -> None:
    assert _accepts_sql(PROPOSED_PAIRING, server, tool, effect) is admitted_in_design
    if server == SOURCE_SERVER and tool == SOURCE_TOOL and admitted_in_design:
        current = _check_expression(
            _read_migration("0029_native_mcp_execution_grants.py"),
            "ck_native_mcp_grant_inert_tool",
        )
        assert not _accepts_sql(current, server, tool, effect)


def test_all_current_migration_heads_are_an_additive_chain() -> None:
    ancestors = (
        ("0027_flow_mcp_action_dispatch.py", "0026"),
        ("0029_native_mcp_execution_grants.py", "0028"),
        ("0030_native_mcp_resource_delivery.py", "0029"),
        ("0031_pinned_native_folder_stage.py", "0030"),
        ("0033_native_worker_supervision.py", "0032"),
        ("0035_native_sourcemap_source_authority.py", "0034"),
    )
    for path, prior in ancestors:
        code = _read_migration(path)
        module = ast.parse(code)
        ancestry = [
            statement.value.value
            for statement in module.body
            if isinstance(statement, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "down_revision"
                for target in statement.targets
            )
            and isinstance(statement.value, ast.Constant)
        ]
        assert ancestry == [prior], path
