"""Independent user-owned inert knowledge library, outside any Flow.

Revision ID: 0039
Revises: 0038

The library is not an instruction source, target evidence, or agent authority.
Every edit appends a SHA-bound immutable version. A document has one current
revision or a permanent tombstone. It cannot be rebound to another principal.
"""

import sqlalchemy as sa
from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def _postgres() -> sa.engine.Connection:
    conn = op.get_bind()
    if (
        op.get_context().as_sql
        or conn.dialect.name != "postgresql"
        or not conn.in_transaction()
        or conn.scalar(sa.text("SELECT current_setting('server_version_num')::int")) < 140000
    ):
        raise RuntimeError("0039 needs live transactional PostgreSQL >= 14")
    conn.exec_driver_sql("SET LOCAL lock_timeout='5s'")
    conn.exec_driver_sql("SET LOCAL statement_timeout='15s'")
    return conn


def upgrade() -> None:
    conn = _postgres()
    op.create_table(
        "operator_global_library_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("principal_issuer", sa.String(128), nullable=False),
        sa.Column("principal_subject", sa.String(128), nullable=False),
        sa.Column("current_revision", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("id ~ '^lib-[0-9a-f]{32}$'", name="ck_global_library_id"),
        sa.CheckConstraint(
            "length(principal_issuer) BETWEEN 1 AND 128", name="ck_global_library_issuer"
        ),
        sa.CheckConstraint(
            "length(principal_subject) BETWEEN 1 AND 128", name="ck_global_library_subject"
        ),
        sa.CheckConstraint(
            "current_revision BETWEEN 1 AND 2147483646", name="ck_global_library_revision"
        ),
    )
    op.create_table(
        "operator_global_library_versions",
        sa.Column(
            "document_id",
            sa.String(36),
            sa.ForeignKey("operator_global_library_documents.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("revision", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(128), nullable=False),
        sa.Column("doc_type", sa.String(16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "revision BETWEEN 1 AND 2147483646", name="ck_global_library_version_revision"
        ),
        sa.CheckConstraint("doc_type IN ('guide','answer','code')", name="ck_global_library_type"),
        sa.CheckConstraint("length(title) BETWEEN 1 AND 128", name="ck_global_library_title"),
        sa.CheckConstraint("content_bytes BETWEEN 1 AND 8192", name="ck_global_library_bytes"),
        sa.CheckConstraint(
            "octet_length(convert_to(content,'UTF8'))=content_bytes",
            name="ck_global_library_utf8_bytes",
        ),
        sa.CheckConstraint(
            "sha256=encode(sha256(convert_to(content,'UTF8')),'hex')",
            name="ck_global_library_exact_digest",
        ),
    )
    # A document can never point at a missing historical revision. The cycle
    # is intentionally deferred until COMMIT for first-document admission.
    op.create_foreign_key(
        "fk_global_library_current_revision",
        "operator_global_library_documents",
        "operator_global_library_versions",
        ["id", "current_revision"],
        ["document_id", "revision"],
        ondelete="RESTRICT",
        deferrable=True,
        initially="DEFERRED",
    )
    op.create_index(
        "ix_global_library_principal",
        "operator_global_library_documents",
        ["principal_issuer", "principal_subject", "id"],
    )
    conn.exec_driver_sql(
        "CREATE FUNCTION osop_global_library_immutable_version() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN "
        "RAISE EXCEPTION 'original library revisions are immutable' USING ERRCODE='23514'; "
        "END $$"
    )
    conn.exec_driver_sql(
        "CREATE TRIGGER trg_global_library_immutable_version "
        "BEFORE UPDATE OR DELETE ON operator_global_library_versions "
        "FOR EACH ROW EXECUTE FUNCTION osop_global_library_immutable_version()"
    )
    conn.exec_driver_sql(
        "CREATE FUNCTION osop_global_library_guard_document() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN "
        "IF NEW.id IS DISTINCT FROM OLD.id OR "
        "NEW.principal_issuer IS DISTINCT FROM OLD.principal_issuer OR "
        "NEW.principal_subject IS DISTINCT FROM OLD.principal_subject OR "
        "NEW.created_at IS DISTINCT FROM OLD.created_at OR OLD.deleted_at IS NOT NULL OR "
        "NOT ((NEW.deleted_at IS NULL AND NEW.current_revision=OLD.current_revision+1) "
        "OR (NEW.deleted_at IS NOT NULL AND NEW.current_revision=OLD.current_revision)) "
        "THEN RAISE EXCEPTION 'library revision, owner, or tombstone transition denied' "
        "USING ERRCODE='23514'; END IF; RETURN NEW; END $$"
    )
    conn.exec_driver_sql(
        "CREATE TRIGGER trg_global_library_guard_document "
        "BEFORE UPDATE ON operator_global_library_documents "
        "FOR EACH ROW EXECUTE FUNCTION osop_global_library_guard_document()"
    )


def downgrade() -> None:
    conn = _postgres()
    conn.exec_driver_sql(
        "LOCK TABLE operator_global_library_documents, "
        "operator_global_library_versions IN ACCESS EXCLUSIVE MODE"
    )
    if conn.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM operator_global_library_documents)")):
        raise RuntimeError(
            "0039 downgrade denied: global library rows (including tombstones) remain"
        )
    conn.exec_driver_sql(
        "DROP TRIGGER trg_global_library_guard_document ON operator_global_library_documents"
    )
    conn.exec_driver_sql("DROP FUNCTION osop_global_library_guard_document()")
    conn.exec_driver_sql(
        "DROP TRIGGER trg_global_library_immutable_version ON operator_global_library_versions"
    )
    conn.exec_driver_sql("DROP FUNCTION osop_global_library_immutable_version()")
    op.drop_index("ix_global_library_principal", table_name="operator_global_library_documents")
    op.drop_constraint(
        "fk_global_library_current_revision",
        "operator_global_library_documents",
        type_="foreignkey",
    )
    op.drop_table("operator_global_library_versions")
    op.drop_table("operator_global_library_documents")
