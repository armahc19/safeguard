"""add scheduled opt-in awareness preferences

Revision ID: d3e5f7a901b2
Revises: c2d4e6f8a901
Create Date: 2026-11-23
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d3e5f7a901b2"
down_revision: str | Sequence[str] | None = "c2d4e6f8a901"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("user_awareness_preferences", sa.Column("schedule_frequency", sa.String(16), server_default="monthly", nullable=False))
    op.add_column("user_awareness_preferences", sa.Column("custom_interval_days", sa.Integer(), nullable=True))
    op.add_column("user_awareness_preferences", sa.Column("delivery_method", sa.String(16), server_default="sms", nullable=False))
    op.add_column("user_awareness_preferences", sa.Column("language", sa.String(32), server_default="english", nullable=False))
    op.add_column("user_awareness_preferences", sa.Column("preferred_time", sa.String(16), server_default="morning", nullable=False))
    op.add_column("user_awareness_preferences", sa.Column("checkup_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.add_column("user_awareness_preferences", sa.Column("fraud_alerts_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    # Preserve the explicit awareness opt-in already recorded by earlier versions.
    op.execute("UPDATE user_awareness_preferences SET fraud_alerts_enabled = proactive_education_enabled")
    op.create_check_constraint("schedule_frequency_valid", "user_awareness_preferences", "schedule_frequency IN ('weekly', 'biweekly', 'monthly', 'custom')")
    op.create_check_constraint("custom_interval_days_valid", "user_awareness_preferences", "custom_interval_days IS NULL OR custom_interval_days BETWEEN 1 AND 365")
    op.create_check_constraint("custom_frequency_consistent", "user_awareness_preferences", "(schedule_frequency = 'custom' AND custom_interval_days IS NOT NULL) OR (schedule_frequency <> 'custom' AND custom_interval_days IS NULL)")
    op.create_check_constraint("delivery_method_valid", "user_awareness_preferences", "delivery_method IN ('sms', 'voice_call', 'both')")
    op.create_check_constraint("preferred_time_valid", "user_awareness_preferences", "preferred_time IN ('morning', 'afternoon', 'evening')")


def downgrade() -> None:
    op.drop_constraint("preferred_time_valid", "user_awareness_preferences", type_="check")
    op.drop_constraint("delivery_method_valid", "user_awareness_preferences", type_="check")
    op.drop_constraint("custom_frequency_consistent", "user_awareness_preferences", type_="check")
    op.drop_constraint("custom_interval_days_valid", "user_awareness_preferences", type_="check")
    op.drop_constraint("schedule_frequency_valid", "user_awareness_preferences", type_="check")
    op.drop_column("user_awareness_preferences", "fraud_alerts_enabled")
    op.drop_column("user_awareness_preferences", "checkup_enabled")
    op.drop_column("user_awareness_preferences", "preferred_time")
    op.drop_column("user_awareness_preferences", "language")
    op.drop_column("user_awareness_preferences", "delivery_method")
    op.drop_column("user_awareness_preferences", "custom_interval_days")
    op.drop_column("user_awareness_preferences", "schedule_frequency")
