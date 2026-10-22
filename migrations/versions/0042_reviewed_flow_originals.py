"""Flow-local, immutable reviewed *untrusted* original; never agent instructions.

Revision ID: 0042
Revises: 0041

The original bytes can be stored only beside the 0041 independently reviewed
current-source citation in the same PostgreSQL transaction. This is NOT an
execution approval, prompt ingestion, or independently target-verified finding.
"""

import sqlalchemy as sa
from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None

_TABLE = "operator_reviewed_flow_originals"
_CITATION = "operator_reviewed_global_flow_citations"
_MATCH = "uq_reviewed_citation_original_same_flow_sha"
_IMMUTABLE = "osop_reviewed_flow_original_immutable"
_TRIGGER = "trg_reviewed_flow_original_immutable"


def _postgres() -> sa.engine.Connection:
    connection = op.get_bind()
    if (
        op.get_context().as_sql
        or connection.dialect.name != "postgresql"
        or not connection.in_transaction()
        or connection.scalar(sa.text("SELECT current_setting('server_version_num')::int")) < 140000
    ):
        raise RuntimeError("0042 requires online transactional PostgreSQL >=14")
    connection.exec_driver_sql("SET LOCAL lock_timeout='5s'")
    connection.exec_driver_sql("SET LOCAL statement_timeout='15s'")
    return connection


def upgrade() -> None:
    conn = _postgres()
    op.create_unique_constraint(
        _MATCH,
        _CITATION,
        ["id", "engagement_id", "flow_id", "flow_owner", "global_sha256", "source_kind"],
    )
    op.create_table(
        _TABLE,
        sa.Column("citation_id", sa.String(41), primary_key=True),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("flow_id", sa.String(64), nullable=False),
        sa.Column("flow_owner", sa.String(64), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("source_kind", sa.String(16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_bytes", sa.Integer(), nullable=False),
        sa.Column(
            "approved_for_agent_context",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "verified_target_evidence",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["citation_id", "engagement_id", "flow_id", "flow_owner", "sha256", "source_kind"],
            [f"{_CITATION}.id", f"{_CITATION}.engagement_id", f"{_CITATION}.flow_id",
             f"{_CITATION}.flow_owner", f"{_CITATION}.global_sha256", f"{_CITATION}.source_kind"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("content_bytes BETWEEN 1 AND 8192", name="ck_reviewed_flow_original_bytes"),
        sa.CheckConstraint("octet_length(convert_to(content,'UTF8'))=content_bytes", name="ck_reviewed_flow_original_utf8"),
        sa.CheckConstraint("sha256=encode(sha256(convert_to(content,'UTF8')),'hex')", name="ck_reviewed_flow_original_sha"),
        sa.CheckConstraint(
            "approved_for_agent_context IS FALSE AND verified_target_evidence IS FALSE",
            name="ck_reviewed_flow_original_never_promoted",
        ),
    )
    op.create_index(
        "ix_reviewed_flow_original_owner", _TABLE,
        ["engagement_id", "flow_id", "flow_owner", "created_at"],
    )
    conn.exec_driver_sql(
        f"CREATE FUNCTION {_IMMUTABLE}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "RAISE EXCEPTION 'reviewed original is immutable and inert' USING ERRCODE='23514'; END $$"
    )
    conn.exec_driver_sql(
        f"CREATE TRIGGER {_TRIGGER} BEFORE UPDATE OR DELETE ON {_TABLE} "
        f"FOR EACH ROW EXECUTE FUNCTION {_IMMUTABLE}()"
    )


def downgrade() -> None:
    conn = _postgres()
    conn.exec_driver_sql(f"LOCK TABLE {_TABLE}, {_CITATION} IN ACCESS EXCLUSIVE MODE")
    if conn.scalar(sa.text(f"SELECT EXISTS (SELECT 1 FROM {_TABLE})")):
        raise RuntimeError("0042 downgrade denied: immutable Flow original remains")
    conn.exec_driver_sql(f"DROP TRIGGER {_TRIGGER} ON {_TABLE}")
    conn.exec_driver_sql(f"DROP FUNCTION {_IMMUTABLE}()")
    op.drop_index("ix_reviewed_flow_original_owner", table_name=_TABLE)
    op.drop_table(_TABLE)
    op.drop_constraint(_MATCH, _CITATION, type_="unique")
