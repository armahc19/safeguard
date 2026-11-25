"""Persist scheduler-generated awareness drafts and simulated delivery state

Revision ID: b2c3d4e5f607
Revises: f1a2b3c4d5e6
Create Date: 2026-11-24
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b2c3d4e5f607"
down_revision: str | Sequence[str] | None = "f1a2b3c4d5e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("awareness_campaigns", sa.Column(
        "generated_by_scheduler", sa.Boolean(), server_default=sa.text("false"), nullable=False,
    ))
    op.add_column("awareness_campaigns", sa.Column(
        "generation_context", postgresql.JSONB(astext_type=sa.Text()),
        server_default=sa.text("'{}'::jsonb"), nullable=False,
    ))
    op.drop_constraint(op.f("ck_awareness_campaigns_awareness_campaign_status_valid"),
                       "awareness_campaigns", type_="check")
    op.create_check_constraint(
        "status_valid", "awareness_campaigns",
        "status IN ('draft', 'approved', 'sent', 'simulated')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_awareness_campaigns_status_valid"),
                       "awareness_campaigns", type_="check")
    op.create_check_constraint(
        "awareness_campaign_status_valid", "awareness_campaigns",
        "status IN ('draft', 'approved', 'sent')",
    )
    op.drop_column("awareness_campaigns", "generation_context")
    op.drop_column("awareness_campaigns", "generated_by_scheduler")
