"""Track read state for simulated Lite awareness SMS

Revision ID: d4e5f6071829
Revises: c3d4e5f60718
Create Date: 2026-11-24
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "d4e5f6071829"
down_revision: str | Sequence[str] | None = "c3d4e5f60718"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "awareness_scheduled_interactions",
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("awareness_scheduled_interactions", "read_at")
