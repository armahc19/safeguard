"""persist scheduled awareness conversations and worker runs

Revision ID: e4f6a8b0c2d4
Revises: d3e5f7a901b2
Create Date: 2026-11-23
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e4f6a8b0c2d4"
down_revision: str | Sequence[str] | None = "d3e5f7a901b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("user_awareness_preferences", sa.Column("next_awareness_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("user_awareness_preferences", sa.Column("awareness_context", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False))
    op.execute("""
        UPDATE user_awareness_preferences
        SET next_awareness_at = now() + CASE
            WHEN schedule_frequency = 'weekly' THEN interval '7 days'
            WHEN schedule_frequency = 'biweekly' THEN interval '14 days'
            WHEN schedule_frequency = 'monthly' THEN interval '1 month'
            ELSE custom_interval_days * interval '1 day'
        END
        WHERE proactive_education_enabled = true
    """)

    op.create_table(
        "awareness_scheduled_interactions",
        sa.Column("preference_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivery_channel", sa.String(16), server_default="sms", nullable=False),
        sa.Column("status", sa.String(16), server_default="pending", nullable=False),
        sa.Column("topic", sa.String(160), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("checkup_question", sa.Text(), nullable=True),
        sa.Column("context_snapshot", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("responded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("response", sa.String(16), nullable=True),
        sa.Column("failure_reason", sa.String(256), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("delivery_channel IN ('sms', 'voice_call')", name=op.f("ck_awareness_scheduled_interactions_delivery_channel_valid")),
        sa.CheckConstraint("status IN ('pending', 'sending', 'sent', 'failed', 'responded')", name=op.f("ck_awareness_scheduled_interactions_status_valid")),
        sa.CheckConstraint("response IS NULL OR response IN ('yes', 'unsure', 'no')", name=op.f("ck_awareness_scheduled_interactions_response_valid")),
        sa.CheckConstraint("attempts >= 0", name=op.f("ck_awareness_scheduled_interactions_attempts_nonnegative")),
        sa.ForeignKeyConstraint(["preference_id"], ["user_awareness_preferences.id"], name=op.f("fk_awareness_scheduled_interactions_preference_id_user_awareness_preferences"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_awareness_scheduled_interactions_user_id_users"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["campaign_id"], ["awareness_campaigns.id"], name=op.f("fk_awareness_scheduled_interactions_campaign_id_awareness_campaigns"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_awareness_scheduled_interactions")),
        sa.UniqueConstraint("preference_id", "scheduled_for", name="uq_awareness_scheduled_interaction_slot"),
    )
    op.create_index("ix_awareness_scheduled_interactions_due", "awareness_scheduled_interactions", ["status", "scheduled_for"])
    op.create_index("ix_awareness_scheduled_interactions_user_created", "awareness_scheduled_interactions", ["user_id", "created_at"])

    op.create_table(
        "awareness_scheduler_runs",
        sa.Column("status", sa.String(16), server_default="running", nullable=False),
        sa.Column("trigger_source", sa.String(16), server_default="cron", nullable=False),
        sa.Column("due_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("sent_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("failed_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("deferred_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detail", sa.String(256), nullable=True),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('running', 'succeeded', 'failed', 'already_running')", name=op.f("ck_awareness_scheduler_runs_status_valid")),
        sa.CheckConstraint("trigger_source IN ('cron', 'manual', 'in_process')", name=op.f("ck_awareness_scheduler_runs_trigger_source_valid")),
        sa.CheckConstraint("due_count >= 0 AND sent_count >= 0 AND failed_count >= 0 AND deferred_count >= 0", name=op.f("ck_awareness_scheduler_runs_counts_nonnegative")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_awareness_scheduler_runs")),
    )
    op.create_index("ix_awareness_scheduler_runs_created", "awareness_scheduler_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_awareness_scheduler_runs_created", table_name="awareness_scheduler_runs")
    op.drop_table("awareness_scheduler_runs")
    op.drop_index("ix_awareness_scheduled_interactions_user_created", table_name="awareness_scheduled_interactions")
    op.drop_index("ix_awareness_scheduled_interactions_due", table_name="awareness_scheduled_interactions")
    op.drop_table("awareness_scheduled_interactions")
    op.drop_column("user_awareness_preferences", "awareness_context")
    op.drop_column("user_awareness_preferences", "next_awareness_at")
