"""Add sandbox execution profile selection.

Revision ID: 044
Revises: 043
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "044"
down_revision: str = "043"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "automations", sa.Column("execution_profile_id", sa.Uuid(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("automations", "execution_profile_id")
