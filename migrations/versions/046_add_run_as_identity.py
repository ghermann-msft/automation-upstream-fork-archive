"""Persist immutable run-as identities for managed execution.

Revision ID: 046
Revises: 045
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "046"
down_revision: str = "045"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("automations") as batch:
        batch.add_column(
            sa.Column("run_as_identity_provider", sa.String(length=64), nullable=True)
        )
        batch.add_column(
            sa.Column("run_as_identity_tenant_id", sa.String(length=255), nullable=True)
        )
        batch.add_column(
            sa.Column(
                "run_as_identity_subject_id", sa.String(length=255), nullable=True
            )
        )
    with op.batch_alter_table("automation_git_sync_org_config") as batch:
        batch.add_column(
            sa.Column(
                "configured_by_identity_provider",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "configured_by_identity_tenant_id",
                sa.String(length=255),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "configured_by_identity_subject_id",
                sa.String(length=255),
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("automation_git_sync_org_config") as batch:
        batch.drop_column("configured_by_identity_subject_id")
        batch.drop_column("configured_by_identity_tenant_id")
        batch.drop_column("configured_by_identity_provider")
    with op.batch_alter_table("automations") as batch:
        batch.drop_column("run_as_identity_subject_id")
        batch.drop_column("run_as_identity_tenant_id")
        batch.drop_column("run_as_identity_provider")
