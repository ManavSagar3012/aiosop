"""Read-only archive inspection denies stale, absent and cross-tenant evidence."""

import base64
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.core import target_authority_corroboration as audits
from ai_osop.core import target_authority_proof as proof
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory import target_finding_evidence as inspector
from ai_osop.safety.approval_binding import pinned_evidence
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _pub(signer):
    return base64.b64encode(
        signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def _sign(signer, domain, value):
    return base64.urlsafe_b64encode(signer.sign(domain + value)).decode().rstrip("=")


class Rows:
    def __init__(self, value=None, multiple=None):
        self.value = value
        self.multiple = multiple

    def scalar_one_or_none(self):
        return self.value

    def one_or_none(self):
        return self.value

    def all(self):
        return self.multiple

    def mappings(self):
        return self

    def scalars(self):
        return self


class PGReadOnly:
    """A minimal AsyncSession query backend; no application DB or targets."""

    def __init__(self, case, assertion, parent, flow):
        self.case = case
        self.assertion = assertion
        self.parent = parent
        self.flow = flow
        self.owned = True
        self.nonce_present = True
        self.grants_valid = True
        self.calls = []

    def in_transaction(self):
        return True

    async def execute(self, statement, params=None):
        sql = str(statement)
        upper = sql.upper()
        assert upper.lstrip().startswith("SELECT")
        assert "INSERT" not in upper and "DELETE" not in upper and "UPDATE " not in upper
        assert "FOR SHARE" in upper or "FOR UPDATE" in upper
        self.calls.append((sql, params))
        if "FROM session_states" in sql:
            return Rows(self.case.owner)
        if "FROM target_authority_assertions" in sql:
            if params != {
                "eng": self.case.flow.engagement_id,
                "flow": self.case.flow.id,
                "original": self.case.original.id,
                "source": self.case.source.id,
                "target": self.case.target.id,
                "proof": self.assertion["proof_sha256"],
            }:
                return Rows()
            return Rows(self.assertion)
        if "FROM execution_flows" in sql:
            return Rows(self.flow)
        if "FROM tasks" in sql:
            if " IN " in sql:
                return Rows(multiple=[self.case.original, self.case.source, self.case.target])
            return Rows(self.parent)
        if "FROM approval_requests" in sql:
            compiled = statement.compile()
            approval_id = compiled.params.get("id_1")
            task_id = compiled.params.get("task_id_1")
            selected = {
                self.case.source.id: self.case.source,
                self.case.target.id: self.case.target,
                self.parent.id: self.parent,
            }.get(task_id)
            if (
                not self.grants_valid
                or selected is None
                or selected.payload.get("approval_id") != approval_id
            ):
                return Rows()
            return Rows(SimpleNamespace(evidence=pinned_evidence([], selected.payload)))
        if "FROM target_authority_nonce_receipts" in sql:
            if not self.nonce_present:
                return Rows()
            return Rows(params["id"])
        raise AssertionError("Unexpected inspection query " + sql)


@pytest.fixture
def archived_case(proof_case, monkeypatch):
    case = proof_case
    blob, signature = case.signed_bytes()
    proof_digest = hashlib.sha256(
        proof._DOMAIN + blob + base64.urlsafe_b64decode(signature + "==")
    ).hexdigest()
    ownership_signer = Ed25519PrivateKey.from_private_bytes(bytes(range(35, 67)))
    access_signer = Ed25519PrivateKey.from_private_bytes(bytes(range(68, 100)))
    config = {
        "version": 1,
        "engagement_id": case.flow.engagement_id,
        "flow_id": case.flow.id,
        "origin": case.key_row["origin"],
        "keys": {"ownership": _pub(ownership_signer), "access": _pub(access_signer)},
    }
    monkeypatch.setenv("OSOP_TARGET_AUDIT_KEYS_JSON", _canonical(config).decode())

    common = {field: case.claims[field] for field in audits._MATCHED_FIELDS}

    def audit_record(role, nonce):
        return {
            **common,
            "schema": "ai-osop.target-independent-audit.v1",
            "role": role,
            "resource_id": "123",
            "source_access_allowed": True,
            "target_proof_sha256": proof_digest,
            "nonce": nonce,
            "issued_at": case.claims["issued_at"],
            "expires_at": case.claims["expires_at"],
        }

    ownership = _canonical(audit_record("ownership", "o" * 32))
    access = _canonical(audit_record("access", "a" * 32))
    ownership_signature = _sign(ownership_signer, audits._DOMAIN, ownership)
    access_signature = _sign(access_signer, audits._DOMAIN, access)
    audit_digest = hashlib.sha256(
        audits._DOMAIN
        + ownership
        + access
        + ownership_signature.encode()
        + access_signature.encode()
    ).hexdigest()
    assertion = {
        "id": "tproof-" + proof_digest[:32],
        "engagement_id": case.flow.engagement_id,
        "flow_id": case.flow.id,
        "original_source_task_id": case.original.id,
        "source_task_id": case.source.id,
        "target_task_id": case.target.id,
        "key_id": case.key_row["key_id"],
        "authorization_version": case.signed.version,
        "flow_revision": case.flow.revision,
        "proof_sha256": proof_digest,
        "audit_corroboration_sha256": audit_digest,
        "target_claims_json": blob,
        "target_signature_b64url": signature,
        "ownership_audit_json": ownership,
        "ownership_audit_signature": ownership_signature,
        "access_audit_json": access,
        "access_audit_signature": access_signature,
        "proof_received_at_epoch": case.claims["issued_at"] + 1,
    }
    parent = Task(
        id=case.source.parent_task_id,
        engagement_id=case.flow.engagement_id,
        flow_id=case.flow.id,
        type="replay_for_diff_auth",
        agent_type=AgentType.RECON,
        status="completed",
        parent_task_id=case.original.id,
        approval_required=True,
        payload={"approval_id": "apr-parent"},
    )
    db = PGReadOnly(case, assertion, parent, case.flow)
    signed = SimpleNamespace(
        session_id=case.flow.engagement_id,
        authorization_id=case.signed.authorization_id,
        version=case.signed.version,
        policy_sha256=case.signed.policy_sha256,
        policy={"created_by": case.owner},
    )
    monkeypatch.setattr(inspector, "guard_sql", AsyncMock(return_value=signed))
    kwargs = {
        "engagement_id": case.flow.engagement_id,
        "flow_id": case.flow.id,
        "original_source_task_id": case.original.id,
        "source_task_id": case.source.id,
        "target_task_id": case.target.id,
        "proof_sha256": proof_digest,
        "audit_sha256": audit_digest,
        "authorization_version": case.signed.version,
        "flow_revision": case.flow.revision,
        "trusted_current_verifier": AsyncMock(return_value=True),
    }
    return SimpleNamespace(db=db, case=case, kwargs=kwargs, signed=signed)


@pytest.mark.asyncio
async def test_exact_signed_archive_is_read_only_candidate_only(archived_case):
    fixture = archived_case
    result = await inspector.inspect_target_finding_evidence(fixture.db, **fixture.kwargs)
    assert result["status"] == "candidate_only", result
    assert result["proof_sha256"] == fixture.kwargs["proof_sha256"]
    assert result["audit_corroboration_sha256"] == fixture.kwargs["audit_sha256"]
    assert result["authorization_version"] == fixture.kwargs["authorization_version"]
    assert result["finding_verified"] is False
    assert result["authorization_violation_verified"] is False
    assert result["finding_release_eligible"] is False
    assert result["report_release_approved"] is False
    assert "target_claims_json" not in result and "payload" not in result
    assert len(fixture.db.calls) >= 9
    assert fixture.kwargs["trusted_current_verifier"].await_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack",
    [
        "foreign_tenant",
        "wrong_flow",
        "wrong_original",
        "swapped_task",
        "wrong_proof",
        "wrong_audit",
        "wrong_roe_version",
        "wrong_flow_revision",
        "missing_callback",
        "denied_callback",
        "missing_transaction",
        "missing_archive",
        "missing_claim_bytes",
        "missing_audit_bytes",
        "missing_access_signature",
        "tampered_target_signature",
        "tampered_audit_signature",
        "changed_archive_version",
        "changed_archive_proof",
        "changed_archive_audit",
        "changed_archive_key",
        "changed_archive_task",
        "changed_owner",
        "revoked_flow",
        "revoked_parent",
        "missing_grant",
        "missing_nonce",
        "changed_session_fingerprint",
        "expired_roe",
    ],
)
async def test_missing_replayed_or_inconsistent_source_is_unknown(
    archived_case, monkeypatch, attack
):
    fixture = archived_case
    args = dict(fixture.kwargs)
    row = fixture.db.assertion
    if attack == "foreign_tenant":
        args["engagement_id"] = "eng-foreign"
    elif attack == "wrong_flow":
        args["flow_id"] = "flow-foreign"
    elif attack == "wrong_original":
        args["original_source_task_id"] = "task-other"
    elif attack == "swapped_task":
        args["source_task_id"], args["target_task_id"] = (
            args["target_task_id"],
            args["source_task_id"],
        )
    elif attack == "wrong_proof":
        args["proof_sha256"] = "f" * 64
    elif attack == "wrong_audit":
        args["audit_sha256"] = "f" * 64
    elif attack == "wrong_roe_version":
        args["authorization_version"] += 1
    elif attack == "wrong_flow_revision":
        args["flow_revision"] += 1
    elif attack == "missing_callback":
        args["trusted_current_verifier"] = None
    elif attack == "denied_callback":
        args["trusted_current_verifier"] = AsyncMock(return_value=False)
    elif attack == "missing_transaction":
        fixture.db.in_transaction = lambda: False
    elif attack == "missing_archive":
        fixture.db.assertion = None
    elif attack == "missing_claim_bytes":
        row["target_claims_json"] = None
    elif attack == "missing_audit_bytes":
        row["ownership_audit_json"] = None
    elif attack == "missing_access_signature":
        row["access_audit_signature"] = None
    elif attack == "tampered_target_signature":
        row["target_signature_b64url"] = "A" * 86
    elif attack == "tampered_audit_signature":
        row["ownership_audit_signature"] = "A" * 86
    elif attack == "changed_archive_version":
        row["authorization_version"] += 1
    elif attack == "changed_archive_proof":
        row["proof_sha256"] = "e" * 64
    elif attack == "changed_archive_audit":
        row["audit_corroboration_sha256"] = "e" * 64
    elif attack == "changed_archive_key":
        row["key_id"] = "attacker-signing-key"
    elif attack == "changed_archive_task":
        row["target_task_id"] = "task-other"
    elif attack == "changed_owner":
        fixture.db.owned = False
        fixture.db.case.owner = "attacker"
    elif attack == "revoked_flow":
        fixture.db.flow = fixture.db.flow.model_copy(update={"status": "halted"})
    elif attack == "revoked_parent":
        fixture.db.parent.status = "failed"
    elif attack == "missing_grant":
        fixture.db.grants_valid = False
    elif attack == "missing_nonce":
        fixture.db.nonce_present = False
    elif attack == "changed_session_fingerprint":
        fixture.db.case.source.payload["_authority_session_sha256"] = "9" * 64
    elif attack == "expired_roe":
        monkeypatch.setattr(inspector, "guard_sql", AsyncMock(side_effect=RuntimeError("revoked")))
    result = await inspector.inspect_target_finding_evidence(fixture.db, **args)
    assert result["status"] == "UNKNOWN", attack
    assert result["finding_verified"] is False
    assert result["finding_release_eligible"] is False
    assert result["report_release_approved"] is False


@pytest.mark.asyncio
async def test_boolean_and_invalid_ids_do_not_start_sql(archived_case):
    fixture = archived_case
    for field, invalid in (
        ("authorization_version", True),
        ("flow_revision", -1),
        ("audit_sha256", "broken"),
        ("proof_sha256", "x" * 64),
        ("source_task_id", fixture.kwargs["target_task_id"]),
    ):
        args = dict(fixture.kwargs)
        args[field] = invalid
        fixture.db.calls.clear()
        result = await inspector.inspect_target_finding_evidence(fixture.db, **args)
        assert result["status"] == "UNKNOWN"
        assert fixture.db.calls == []
