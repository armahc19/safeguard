"""persist transaction behavioural snapshots

Revision ID: 9ab4c2d7e610
Revises: 4f5e8f8e2c1a
Create Date: 2026-11-15
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "9ab4c2d7e610"
down_revision: str | Sequence[str] | None = "4f5e8f8e2c1a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "transaction_assessments",
        sa.Column(
            "behavior_signals",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("transaction_assessments", "behavior_signals")
