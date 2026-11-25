"""Allow general scheduled awareness drafts without a signal link

Revision ID: c3d4e5f60718
Revises: b2c3d4e5f607
Create Date: 2026-11-24
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "c3d4e5f60718"
down_revision: str | Sequence[str] | None = "b2c3d4e5f607"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "awareness_campaigns", "source_signal_id",
        existing_type=postgresql.UUID(as_uuid=True), nullable=True,
    )


def downgrade() -> None:
    # Keep generated records intact. Downgrade will fail safely if a general
    # campaign without a signal has already been saved.
    op.alter_column(
        "awareness_campaigns", "source_signal_id",
        existing_type=postgresql.UUID(as_uuid=True), nullable=False,
    )
