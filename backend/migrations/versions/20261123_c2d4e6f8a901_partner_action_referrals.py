"""auditable NEXUS partner action referrals

Revision ID: c2d4e6f8a901
Revises: a1b2c3d4e5f6
Create Date: 2026-11-23
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c2d4e6f8a901"
down_revision: str | Sequence[str] | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "partner_action_referrals",
        sa.Column("partner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reviewed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("sent_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("response_recorded_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(24), server_default="draft", nullable=False),
        sa.Column("requested_action", sa.String(40), nullable=False),
        sa.Column("target_label", sa.String(256), nullable=False),
        sa.Column("target_reference", sa.String(256), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("case_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("evidence_snapshot", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column("partner_response", sa.Text(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('draft', 'pending_review', 'approved', 'declined', 'sent', 'responded')", name=op.f("ck_partner_action_referrals_status_valid")),
        sa.CheckConstraint("requested_action IN ('review_account', 'preserve_records', 'assess_restriction', 'assess_recall_recovery', 'other')", name=op.f("ck_partner_action_referrals_action_valid")),
        sa.ForeignKeyConstraint(["partner_id"], ["partners.id"], name=op.f("fk_partner_action_referrals_partner_id_partners"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], name=op.f("fk_partner_action_referrals_created_by_users"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"], name=op.f("fk_partner_action_referrals_reviewed_by_users"), ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["sent_by"], ["users.id"], name=op.f("fk_partner_action_referrals_sent_by_users"), ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["response_recorded_by"], ["users.id"], name=op.f("fk_partner_action_referrals_response_recorded_by_users"), ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["case_id"], ["fraud_cases.id"], name=op.f("fk_partner_action_referrals_case_id_fraud_cases"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_partner_action_referrals")),
    )
    op.create_index("ix_partner_action_referrals_partner_status", "partner_action_referrals", ["partner_id", "status", "created_at"])
    op.create_index("ix_partner_action_referrals_created_by", "partner_action_referrals", ["created_by", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_partner_action_referrals_created_by", table_name="partner_action_referrals")
    op.drop_index("ix_partner_action_referrals_partner_status", table_name="partner_action_referrals")
    op.drop_table("partner_action_referrals")
