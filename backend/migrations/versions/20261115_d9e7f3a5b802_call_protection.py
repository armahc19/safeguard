"""persist consent-based call assessments

Revision ID: d9e7f3a5b802
Revises: c8d6e2f4a701
Create Date: 2026-11-15
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d9e7f3a5b802"
down_revision: str | Sequence[str] | None = "c8d6e2f4a701"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "call_analyses",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=True),
        sa.Column("caller_phone", sa.String(length=20), nullable=False),
        sa.Column("transcript_hash", sa.String(length=64), nullable=True),
        sa.Column("consented_transcript", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "risk_level",
            sa.Enum("low", "medium", "high", "critical", name="call_risk_level", native_enum=False, create_constraint=True, length=32),
            nullable=False,
        ),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("signals", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 1", name=op.f("ck_call_analyses_risk_score_range")),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name=op.f("ck_call_analyses_confidence_range")),
        sa.ForeignKeyConstraint(["case_id"], ["fraud_cases.id"], name=op.f("fk_call_analyses_case_id_fraud_cases"), ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_call_analyses_user_id_users"), ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_call_analyses")),
    )
    op.create_index("ix_call_analyses_user_id_created_at", "call_analyses", ["user_id", "created_at"], unique=False)
    op.create_index("ix_call_analyses_case_id_created_at", "call_analyses", ["case_id", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_call_analyses_case_id_created_at", table_name="call_analyses")
    op.drop_index("ix_call_analyses_user_id_created_at", table_name="call_analyses")
    op.drop_table("call_analyses")
