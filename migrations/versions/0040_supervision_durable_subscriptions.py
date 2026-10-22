"""Tenant-scoped durable supervision subscriber cursor and fenced lease.

Revision ID: 0040
Revises: 0039

Identity/authority are immutable. A subscriber has one monotone cursor and
lease generation, and a permanent revoked tombstone. Database constraints
protect the shape; the runtime must additionally perform tenant-authenticated
CAS for lease owner/generation/cursor updates in a PostgreSQL transaction.
This table does not authorize execution, revive a revoked subscriber, or
reconcile a provider's UNKNOWN effects.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None

_TABLE = "supervision_durable_subscriptions"
_GUARD = "osop_supervision_durable_subscription_guard"
_TRIGGER = "trg_supervision_durable_subscriptions_guard"


def _postgres() -> sa.engine.Connection:
    """Require an online PostgreSQL transaction, never an offline DDL guess."""
    conn = op.get_bind()
    if (
        op.get_context().as_sql
        or conn.dialect.name != "postgresql"
        or not conn.in_transaction()
        or conn.scalar(sa.text("SELECT current_setting('server_version_num')::int")) < 140000
    ):
        raise RuntimeError("0040 requires live transactional PostgreSQL >=14")
    conn.exec_driver_sql("SET LOCAL lock_timeout='5s'")
    conn.exec_driver_sql("SET LOCAL statement_timeout='15s'")
    return conn


def upgrade() -> None:
    conn = _postgres()
    op.create_table(
        _TABLE,
        sa.Column(
            "engagement_id",
            sa.String(64),
            sa.ForeignKey("session_states.session_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("subscriber_id", sa.String(64), primary_key=True),
        sa.Column("principal_issuer", sa.String(128), nullable=False),
        sa.Column("principal_subject", sa.String(128), nullable=False),
        sa.Column("task_id", sa.String(64), nullable=True),
        sa.Column("authorization_version", sa.Integer(), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column(
            "cursor_sequence", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column("lease_owner", sa.String(128), nullable=True),
        sa.Column("lease_id", sa.String(64), nullable=True),
        sa.Column(
            "lease_generation", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "length(engagement_id)>0 AND length(subscriber_id)>0 AND "
            "length(principal_issuer)>0 AND length(principal_subject)>0",
            name="ck_supervision_subscriber_identity",
        ),
        sa.CheckConstraint(
            "authorization_version>=1 AND "
            "authorization_sha256 ~ '^[a-f0-9]{64}$'",
            name="ck_supervision_subscriber_authorization",
        ),
        sa.CheckConstraint(
            "cursor_sequence>=0 AND lease_generation>=0",
            name="ck_supervision_subscriber_counters",
        ),
        sa.CheckConstraint(
            "(lease_owner IS NULL AND lease_id IS NULL AND lease_until IS NULL) OR "
            "(lease_owner IS NOT NULL AND lease_id IS NOT NULL AND "
            "length(lease_owner)>0 AND length(lease_id)>0 AND lease_until IS NOT NULL)",
            name="ck_supervision_subscriber_lease_triad",
        ),
    )
    op.create_index(
        "ix_supervision_subscriptions_active_lease",
        _TABLE,
        ["engagement_id", "revoked_at", "lease_until"],
    )
    conn.exec_driver_sql(
        f"CREATE FUNCTION {_GUARD}() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN "
        "IF TG_OP='DELETE' THEN "
        "RAISE EXCEPTION 'durable supervision subscriber deletion denied' "
        "USING ERRCODE='23514'; "
        "END IF; "
        "IF NEW.engagement_id IS DISTINCT FROM OLD.engagement_id OR "
        "NEW.subscriber_id IS DISTINCT FROM OLD.subscriber_id OR "
        "NEW.principal_issuer IS DISTINCT FROM OLD.principal_issuer OR "
        "NEW.principal_subject IS DISTINCT FROM OLD.principal_subject OR "
        "NEW.task_id IS DISTINCT FROM OLD.task_id OR "
        "NEW.authorization_version IS DISTINCT FROM OLD.authorization_version OR "
        "NEW.authorization_sha256 IS DISTINCT FROM OLD.authorization_sha256 OR "
        "NEW.created_at IS DISTINCT FROM OLD.created_at OR "
        "OLD.revoked_at IS NOT NULL OR "
        "NEW.cursor_sequence < OLD.cursor_sequence OR "
        "NEW.lease_generation < OLD.lease_generation OR "
        "(NEW.revoked_at IS NOT NULL AND NEW.revoked_at < OLD.created_at) "
        "THEN "
        "RAISE EXCEPTION 'durable supervision identity, authority or fence mutation denied' "
        "USING ERRCODE='23514'; "
        "END IF; "
        "RETURN NEW; END $$"
    )
    conn.exec_driver_sql(
        f"CREATE TRIGGER {_TRIGGER} BEFORE UPDATE OR DELETE ON {_TABLE} "
        f"FOR EACH ROW EXECUTE FUNCTION {_GUARD}()"
    )


def downgrade() -> None:
    conn = _postgres()
    conn.exec_driver_sql(f"LOCK TABLE {_TABLE} IN ACCESS EXCLUSIVE MODE")
    if conn.scalar(sa.text(f"SELECT EXISTS(SELECT 1 FROM {_TABLE})")):
        raise RuntimeError(
            "0040 downgrade denied: durable supervision subscriptions "
            "(including revoked subscribers) remain"
        )
    conn.exec_driver_sql(f"DROP TRIGGER {_TRIGGER} ON {_TABLE}")
    conn.exec_driver_sql(f"DROP FUNCTION {_GUARD}()")
    op.drop_index("ix_supervision_subscriptions_active_lease", table_name=_TABLE)
    op.drop_table(_TABLE)
