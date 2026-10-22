"""Immutable reviewed global-source citation, NOT imported agent instructions.

Revision ID: 0041
Revises: 0040

Only the separately enrolled, current four-authority reviewer writer may insert
these metadata references under the same PostgreSQL locks as the source and
Flow/Task/ROE. This schema never makes user text executable or target evidence.
"""

import sqlalchemy as sa
from alembic import op

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None

_TABLE = "operator_reviewed_global_flow_citations"
_TRIGGER = "trg_reviewed_global_flow_citation_immutable"
_FUNCTION = "osop_reviewed_global_flow_citation_immutable"


def _postgres() -> sa.engine.Connection:
    connection = op.get_bind()
    if (
        op.get_context().as_sql
        or connection.dialect.name != "postgresql"
        or not connection.in_transaction()
        or connection.scalar(sa.text("SELECT current_setting('server_version_num')::int")) < 140000
    ):
        raise RuntimeError("0041 requires online transactional PostgreSQL >=14")
    connection.exec_driver_sql("SET LOCAL lock_timeout='5s'")
    connection.exec_driver_sql("SET LOCAL statement_timeout='15s'")
    return connection


def upgrade() -> None:
    conn = _postgres()
    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(41), primary_key=True),
        sa.Column("principal_issuer", sa.String(128), nullable=False),
        sa.Column("principal_owner_sha256", sa.String(64), nullable=False),
        sa.Column("global_document_id", sa.String(36), nullable=False),
        sa.Column("global_revision", sa.Integer(), nullable=False),
        sa.Column("global_sha256", sa.String(64), nullable=False),
        sa.Column("source_kind", sa.String(16), nullable=False),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("flow_owner", sa.String(64), nullable=False),
        sa.Column("flow_revision", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.String(128), nullable=False),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("reviewed_identity_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["global_document_id", "global_revision"],
            ["operator_global_library_versions.document_id", "operator_global_library_versions.revision"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["flow_id", "engagement_id"],
            ["execution_flows.id", "execution_flows.engagement_id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("id ~ '^citation-[a-f0-9]{32}$'", name="ck_reviewed_citation_id"),
        sa.CheckConstraint("global_revision>=1 AND flow_revision>=0 AND authorization_version>=1", name="ck_reviewed_citation_revisions"),
        sa.CheckConstraint("source_kind IN ('guide','answer','code')", name="ck_reviewed_citation_kind"),
        sa.CheckConstraint(
            "principal_owner_sha256 ~ '^[a-f0-9]{64}$' AND global_sha256 ~ '^[a-f0-9]{64}$' "
            "AND authorization_sha256 ~ '^[a-f0-9]{64}$' AND reviewed_identity_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_reviewed_citation_digests",
        ),
        sa.UniqueConstraint(
            "principal_issuer", "principal_owner_sha256", "global_document_id", "global_revision",
            "engagement_id", "flow_id", "task_id", "authorization_version",
            "reviewed_identity_sha256", name="uq_reviewed_citation_exact_authority",
        ),
    )
    op.create_index("ix_reviewed_citation_flow", _TABLE, ["engagement_id", "flow_id", "flow_owner", "created_at"])
    conn.exec_driver_sql(
        f"CREATE FUNCTION {_FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "RAISE EXCEPTION 'reviewed citation revisions are immutable' USING ERRCODE='23514'; END $$"
    )
    conn.exec_driver_sql(
        f"CREATE TRIGGER {_TRIGGER} BEFORE UPDATE OR DELETE ON {_TABLE} "
        f"FOR EACH ROW EXECUTE FUNCTION {_FUNCTION}()"
    )


def downgrade() -> None:
    conn = _postgres()
    conn.exec_driver_sql(f"LOCK TABLE {_TABLE} IN ACCESS EXCLUSIVE MODE")
    if conn.scalar(sa.text(f"SELECT EXISTS (SELECT 1 FROM {_TABLE})")):
        raise RuntimeError("0041 downgrade denied: immutable reviewed citation history exists")
    conn.exec_driver_sql(f"DROP TRIGGER {_TRIGGER} ON {_TABLE}")
    conn.exec_driver_sql(f"DROP FUNCTION {_FUNCTION}()")
    op.drop_index("ix_reviewed_citation_flow", table_name=_TABLE)
    op.drop_table(_TABLE)
