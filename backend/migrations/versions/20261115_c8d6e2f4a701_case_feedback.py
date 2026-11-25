"""persist intervention and fraud outcomes

Revision ID: c8d6e2f4a701
Revises: b7c5d1e2f903
Create Date: 2026-11-15
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c8d6e2f4a701"
down_revision: str | Sequence[str] | None = "b7c5d1e2f903"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "case_feedback",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column(
            "outcome",
            sa.Enum(
                "intervention_delivered", "advice_followed", "advice_ignored", "transaction_cancelled",
                "transaction_completed", "report_submitted", "reviewer_decision", "confirmed_fraud",
                "false_positive", "loss_reported", "loss_prevented", "needs_review",
                name="feedback_outcome", native_enum=False, create_constraint=True, length=32,
            ),
            nullable=False,
        ),
        sa.Column("intervention_action", sa.String(length=64), nullable=True),
        sa.Column("followed_recommendation", sa.Boolean(), nullable=True),
        sa.Column("fraud_confirmed", sa.Boolean(), nullable=True),
        sa.Column("amount", sa.Float(), nullable=True),
        sa.Column("currency", sa.String(length=3), nullable=True),
        sa.Column("loss_amount", sa.Float(), nullable=True),
        sa.Column("rating", sa.Integer(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("amount IS NULL OR amount >= 0", name=op.f("ck_case_feedback_amount_nonnegative")),
        sa.CheckConstraint("loss_amount IS NULL OR loss_amount >= 0", name=op.f("ck_case_feedback_loss_amount_nonnegative")),
        sa.CheckConstraint("rating IS NULL OR rating BETWEEN 1 AND 5", name=op.f("ck_case_feedback_rating_range")),
        sa.ForeignKeyConstraint(["case_id"], ["fraud_cases.id"], name=op.f("fk_case_feedback_case_id_fraud_cases"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_case_feedback_user_id_users"), ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_feedback")),
    )
    op.create_index("ix_case_feedback_case_id_created_at", "case_feedback", ["case_id", "created_at"], unique=False)
    op.create_index("ix_case_feedback_outcome_created_at", "case_feedback", ["outcome", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_case_feedback_outcome_created_at", table_name="case_feedback")
    op.drop_index("ix_case_feedback_case_id_created_at", table_name="case_feedback")
    op.drop_table("case_feedback")
