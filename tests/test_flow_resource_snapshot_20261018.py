"""Offline source-contract checks for reviewed Flow byte handoff."""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "src/ai_osop/memory"
SOURCE = (ROOT / "flow_resource_snapshot.py").read_text(encoding="utf-8")


def test_source_has_no_host_or_archive_side_effects():
    for forbidden in ("subprocess", "extractall(", "write_bytes(", "os.open(",
                      "docker", "operator_knowledge", "eval(", "exec("):
        assert forbidden not in SOURCE
    assert "@dataclass(frozen=True)" in SOURCE
    assert 'approved_for_agent_instructions: bool = False' in SOURCE


def test_review_each_artifact_against_current_signed_source():
    assert "await self.artifacts.read_resource_snapshot(" in SOURCE
    assert "await self.review_approval(" in SOURCE
    for field in ("flow_id=binding.flow_id", "revision=binding.flow_revision",
                  "version=binding.authorization_version", "authorization_id=binding.authorization_id",
                  "authorization_sha256=binding.authorization_sha256"):
        assert field in SOURCE
    assert 'receipt.get("verified_review") is not True' in SOURCE
    assert 'receipt.get("approved") is not True' in SOURCE


def test_digest_active_text_and_recheck_guards():
    assert "make_manifest(" in SOURCE
    assert "hmac.compare_digest(hashlib.sha256(content).hexdigest(), file[\"sha256\"])" in SOURCE
    assert "if fresh != manifest:" in SOURCE
    exports = (ROOT / "flow_resource_exports.py").read_text(encoding="utf-8")
    for guard in ("_kind_and_validate(name, blob)", "MAX_EXPORT_FILES", "MAX_EXPORT_TOTAL_BYTES",
                  "safe_filename(name)", "_HTML_MARKUP.search(source)"):
        assert guard in exports


def test_snapshot_does_not_claim_task_or_sandbox_authority():
    tree = ast.parse(SOURCE)
    names = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    assert {"SnapshotBinding", "SnapshotResource", "SealedFlowSnapshot", "FlowResourceSnapshot"} <= names
    assert "provision_approved_flow_resource" not in SOURCE
    assert "approved_task" not in SOURCE
