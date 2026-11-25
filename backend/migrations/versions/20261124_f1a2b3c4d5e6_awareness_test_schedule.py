"""add development-only one-minute awareness simulation schedule

Revision ID: f1a2b3c4d5e6
Revises: e4f6a8b0c2d4
Create Date: 2026-11-24
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: str | Sequence[str] | None = "e4f6a8b0c2d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("user_awareness_preferences", sa.Column(
        "test_schedule_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False,
    ))
    op.add_column("awareness_scheduler_runs", sa.Column(
        "simulated_count", sa.Integer(), server_default="0", nullable=False,
    ))

    op.drop_constraint(op.f("ck_awareness_scheduled_interactions_status_valid"),
                       "awareness_scheduled_interactions", type_="check")
    op.create_check_constraint(
        "status_valid", "awareness_scheduled_interactions",
        "status IN ('pending', 'sending', 'sent', 'failed', 'responded', 'simulated')",
    )
    op.drop_constraint(op.f("ck_awareness_scheduler_runs_counts_nonnegative"),
                       "awareness_scheduler_runs", type_="check")
    op.create_check_constraint(
        "counts_nonnegative", "awareness_scheduler_runs",
        "due_count >= 0 AND sent_count >= 0 AND simulated_count >= 0 AND failed_count >= 0 AND deferred_count >= 0",
    )
    op.drop_constraint(op.f("ck_awareness_scheduler_runs_trigger_source_valid"),
                       "awareness_scheduler_runs", type_="check")
    op.create_check_constraint(
        "trigger_source_valid", "awareness_scheduler_runs",
        "trigger_source IN ('cron', 'manual', 'in_process')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_awareness_scheduler_runs_trigger_source_valid"),
                       "awareness_scheduler_runs", type_="check")
    op.create_check_constraint(
        "trigger_source_valid", "awareness_scheduler_runs",
        "trigger_source IN ('cron', 'manual', 'in_process')",
    )
    op.drop_constraint(op.f("ck_awareness_scheduler_runs_counts_nonnegative"),
                       "awareness_scheduler_runs", type_="check")
    op.create_check_constraint(
        "counts_nonnegative", "awareness_scheduler_runs",
        "due_count >= 0 AND sent_count >= 0 AND failed_count >= 0 AND deferred_count >= 0",
    )
    op.drop_constraint(op.f("ck_awareness_scheduled_interactions_status_valid"),
                       "awareness_scheduled_interactions", type_="check")
    op.create_check_constraint(
        "status_valid", "awareness_scheduled_interactions",
        "status IN ('pending', 'sending', 'sent', 'failed', 'responded')",
    )
    op.drop_column("awareness_scheduler_runs", "simulated_count")
    op.drop_column("user_awareness_preferences", "test_schedule_enabled")
