"""Store Sandbox Server execution profile IDs as strings.

Revision ID: 045
Revises: 044
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "045"
down_revision: str = "044"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("automations") as batch:
        batch.alter_column(
            "execution_profile_id",
            existing_type=sa.Uuid(),
            type_=sa.String(),
            existing_nullable=True,
            postgresql_using="execution_profile_id::text",
        )


def downgrade() -> None:
    with op.batch_alter_table("automations") as batch:
        batch.alter_column(
            "execution_profile_id",
            existing_type=sa.String(),
            type_=sa.Uuid(),
            existing_nullable=True,
            postgresql_using="execution_profile_id::uuid",
        )
