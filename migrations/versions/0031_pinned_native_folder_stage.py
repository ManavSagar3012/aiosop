"""Record the approved 0026 folder-assignment SHA at one-time source offer.

Revision ID: 0031
Revises: 0030

This does not permit a worker filesystem side effect by itself; receipt and
independently isolated filesystem staging are separate gated capabilities.
"""

import sqlalchemy as sa
from alembic import op

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "native_mcp_resource_offers",
        sa.Column("folder_staging_sha256", sa.String(64), nullable=True),
    )
    op.create_check_constraint(
        "ck_native_resource_offer_folder_sha",
        "native_mcp_resource_offers",
        "folder_staging_sha256 IS NULL OR folder_staging_sha256 ~ '^[0-9a-f]{64}$'",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_native_resource_offer_folder_sha",
        "native_mcp_resource_offers",
        type_="check",
    )
    op.drop_column("native_mcp_resource_offers", "folder_staging_sha256")
