"""Link each opted-in voice caller to a persistent context case

Revision ID: e5f60718293a
Revises: d4e5f6071829
Create Date: 2026-11-24
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "e5f60718293a"
down_revision: str | Sequence[str] | None = "d4e5f6071829"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user_awareness_preferences",
        sa.Column("voice_case_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_user_awareness_preferences_voice_case_id_fraud_cases",
        "user_awareness_preferences", "fraud_cases", ["voice_case_id"], ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_user_awareness_preferences_voice_case_id_fraud_cases",
        "user_awareness_preferences", type_="foreignkey",
    )
    op.drop_column("user_awareness_preferences", "voice_case_id")
