"""add opt-in conversational memory and reviewed awareness campaigns

Revision ID: e7f812345678
Revises: d6e7f8123456
Create Date: 2026-11-18
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e7f812345678"
down_revision: str | Sequence[str] | None = "d6e7f8123456"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_awareness_preferences",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("conversation_memory_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("proactive_education_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("channels", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[\"in_app\"]'::jsonb"), nullable=False),
        sa.Column("consent_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_awareness_preferences")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_user_awareness_preferences_user_id_users"), ondelete="CASCADE"),
        sa.UniqueConstraint("user_id", name="uq_user_awareness_preferences_user_id"),
        sa.CheckConstraint("jsonb_typeof(channels) = 'array'", name="awareness_channels_array"),
    )
    op.create_index("ix_user_awareness_preferences_proactive", "user_awareness_preferences", ["proactive_education_enabled"])

    op.create_table(
        "awareness_campaigns",
        sa.Column("source_signal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), server_default="education", nullable=False),
        sa.Column("status", sa.String(length=16), server_default="draft", nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("audience_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_awareness_campaigns")),
        sa.ForeignKeyConstraint(["source_signal_id"], ["cross_institution_signals.id"], name=op.f("fk_awareness_campaigns_source_signal_id_cross_institution_signals"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name=op.f("fk_awareness_campaigns_created_by_users"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], name=op.f("fk_awareness_campaigns_approved_by_users"), ondelete="SET NULL"),
        sa.CheckConstraint("severity IN ('education', 'high_risk')", name="awareness_campaign_severity_valid"),
        sa.CheckConstraint("status IN ('draft', 'approved', 'sent')", name="awareness_campaign_status_valid"),
        sa.CheckConstraint("audience_count >= 0", name="awareness_campaign_audience_nonnegative"),
    )
    op.create_index("ix_awareness_campaigns_status_created", "awareness_campaigns", ["status", "created_at"])

    op.create_table(
        "awareness_deliveries",
        sa.Column("campaign_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.String(length=256), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_awareness_deliveries")),
        sa.ForeignKeyConstraint(["campaign_id"], ["awareness_campaigns.id"], name=op.f("fk_awareness_deliveries_campaign_id_awareness_campaigns"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_awareness_deliveries_user_id_users"), ondelete="CASCADE"),
        sa.UniqueConstraint("campaign_id", "user_id", "channel", name="uq_awareness_delivery_target_channel"),
        sa.CheckConstraint("channel IN ('in_app', 'sms')", name="awareness_delivery_channel_valid"),
        sa.CheckConstraint("status IN ('pending', 'sent', 'failed')", name="awareness_delivery_status_valid"),
    )
    op.create_index("ix_awareness_deliveries_user_created", "awareness_deliveries", ["user_id", "created_at"])
    op.create_index("ix_awareness_deliveries_status_created", "awareness_deliveries", ["status", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_awareness_deliveries_status_created", table_name="awareness_deliveries")
    op.drop_index("ix_awareness_deliveries_user_created", table_name="awareness_deliveries")
    op.drop_table("awareness_deliveries")
    op.drop_index("ix_awareness_campaigns_status_created", table_name="awareness_campaigns")
    op.drop_table("awareness_campaigns")
    op.drop_index("ix_user_awareness_preferences_proactive", table_name="user_awareness_preferences")
    op.drop_table("user_awareness_preferences")
