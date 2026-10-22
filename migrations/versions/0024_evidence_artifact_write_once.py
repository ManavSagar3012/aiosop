"""Harden 0023 evidence artifacts as genuinely write-once PostgreSQL records.

Revision ID: 0024
Revises: 0023

An application-only append convention is not an immutable ledger. This
migration deliberately does NOT assert the artifact is a verified finding or
a trusted signed target observation; 0022 independently governs that proof.
"""

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # This function exists from 0016 and is used by the signed 0022 target
    # authority ledger. Reuse it without weakening its other callsites.
    op.execute(
        "ALTER TABLE evidence_artifacts "
        "ADD CONSTRAINT ck_evidence_artifacts_digest_shapes CHECK ("
        "request_headers_sha256 ~ '^[0-9a-f]{64}$' AND "
        "request_body_sha256 ~ '^[0-9a-f]{64}$' AND "
        "response_headers_sha256 ~ '^[0-9a-f]{64}$' AND "
        "response_body_sha256 ~ '^[0-9a-f]{64}$' AND "
        "merkle_leaf_hash ~ '^[0-9a-f]{64}$')"
    )
    op.execute(
        "CREATE TRIGGER trg_evidence_artifacts_immutable "
        "BEFORE UPDATE OR DELETE ON evidence_artifacts "
        "FOR EACH ROW EXECUTE FUNCTION reject_target_authority_nonce_mutation()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_evidence_artifacts_immutable ON evidence_artifacts")
    op.execute(
        "ALTER TABLE evidence_artifacts " "DROP CONSTRAINT ck_evidence_artifacts_digest_shapes"
    )
