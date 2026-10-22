"""Adversarial immutable resource protocol tests, without an application DB."""

import ast
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "src/ai_osop/memory/flow_resource_materialization.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def _method(name):
    klass = next(n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name == "SignedFlowTaskResources")
    return ast.get_source_segment(SOURCE, next(n for n in klass.body if isinstance(n, ast.AsyncFunctionDef) and n.name == name))


def test_task_admission_verified_on_every_read():
    method = _method("read")
    assert "await self.verify_approved_task(binding)" in method
    assert 'admission.get("approved") is not True' in method
    assert 'admission.get("active") is not True' in method
    assert 'admission.get(name) != getattr(binding, name)' in method


def test_original_flow_artifacts_reread_with_signed_fence():
    method = _method("read")
    assert "await self.artifacts.read(" in method
    for field in ("binding.flow_id", "binding.artifact_id", "binding.owner_id", "binding.flow_revision", "binding.authorization_version"):
        assert field in method
    assert "hashlib.sha256(original).hexdigest()" in method
    assert "hmac.compare_digest(observed, binding.artifact_sha256)" in method


def test_no_host_write_archive_extraction_or_agent_context():
    method = _method("read")
    for forbidden in ("open(", "write_bytes(", "extractall(", "subprocess", "exec(", "eval(", "operator_knowledge"):
        assert forbidden not in SOURCE
    assert "_kind_and_validate(metadata.get(\"name\"), original)" in method
    assert '"approved_for_agent_instructions": False' in method


def test_revocation_and_digest_fail_closed():
    method = _method("read")
    for phrase in ("Task approval or signed scope changed", "Original signed artifact unavailable", "Original artifact lineage or digest changed", "Original resource is not inert text"):
        assert phrase in method
    assert "ResourceAdmissionDenied" in method


def test_task_resource_is_bounded_and_immutable():
    assert "MAX_TASK_RESOURCE_BYTES = 2 * 1024 * 1024" in SOURCE
    assert "@dataclass(frozen=True)" in SOURCE
    assert "isinstance(original, bytes)" in _method("read")
