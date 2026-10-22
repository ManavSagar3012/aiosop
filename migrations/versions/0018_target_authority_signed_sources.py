"""Store bounded, immutable original target-side signed evidence for later verification.

Revision ID: 0018
Revises: 0017

Only canonical signed claims and detached signatures are retained; no cookies,
bearer tokens or HTTP response bodies. An attestation remains candidate-only.
"""

import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("target_claims_json", sa.LargeBinary()),
    ("target_signature_b64url", sa.String(86)),
    ("ownership_audit_json", sa.LargeBinary()),
    ("ownership_audit_signature", sa.String(86)),
    ("access_audit_json", sa.LargeBinary()),
    ("access_audit_signature", sa.String(86)),
)


def upgrade() -> None:
    op.add_column(
        "target_authority_assertions",
        sa.Column("proof_received_at_epoch", sa.BigInteger(), nullable=True),
    )
    for name, column_type in _COLUMNS:
        op.add_column("target_authority_assertions", sa.Column(name, column_type, nullable=True))
    op.create_check_constraint(
        "ck_target_auth_receipt_epoch",
        "target_authority_assertions",
        "proof_received_at_epoch IS NULL OR proof_received_at_epoch > 0",
    )
    op.create_check_constraint(
        "ck_target_auth_original_signed_pair",
        "target_authority_assertions",
        "(target_claims_json IS NULL AND target_signature_b64url IS NULL) "
        "OR (target_claims_json IS NOT NULL AND target_signature_b64url IS NOT NULL "
        "AND proof_received_at_epoch IS NOT NULL "
        "AND octet_length(target_claims_json) BETWEEN 1 AND 4096 "
        "AND target_signature_b64url ~ '^[A-Za-z0-9_-]{86}$')",
    )
    op.create_check_constraint(
        "ck_target_auth_independent_audit_pair",
        "target_authority_assertions",
        "(ownership_audit_json IS NULL "
        "AND ownership_audit_signature IS NULL AND access_audit_json IS NULL "
        "AND access_audit_signature IS NULL) OR "
        "(audit_corroboration_sha256 IS NOT NULL AND ownership_audit_json IS NOT NULL "
        "AND ownership_audit_signature IS NOT NULL AND access_audit_json IS NOT NULL "
        "AND access_audit_signature IS NOT NULL AND octet_length(ownership_audit_json) "
        "BETWEEN 1 AND 4096 AND octet_length(access_audit_json) BETWEEN 1 AND 4096 "
        "AND ownership_audit_signature ~ '^[A-Za-z0-9_-]{86}$' "
        "AND access_audit_signature ~ '^[A-Za-z0-9_-]{86}$')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_target_auth_independent_audit_pair", "target_authority_assertions", type_="check"
    )
    op.drop_constraint(
        "ck_target_auth_original_signed_pair", "target_authority_assertions", type_="check"
    )
    op.drop_constraint("ck_target_auth_receipt_epoch", "target_authority_assertions", type_="check")
    for name, _ in reversed(_COLUMNS):
        op.drop_column("target_authority_assertions", name)
    op.drop_column("target_authority_assertions", "proof_received_at_epoch")
