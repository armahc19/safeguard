"""shared fraud cases and typed evidence

Revision ID: 4f5e8f8e2c1a
Revises: 68d025f720fe
Create Date: 2026-11-15
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "4f5e8f8e2c1a"
down_revision: str | Sequence[str] | None = "68d025f720fe"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "fraud_cases",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("open", "closed", name="case_status", native_enum=False, create_constraint=True, length=32),
            server_default="open",
            nullable=False,
        ),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_fraud_cases_user_id_users"), ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fraud_cases")),
    )
    op.create_index("ix_fraud_cases_user_id_updated_at", "fraud_cases", ["user_id", "updated_at"], unique=False)

    op.create_table(
        "case_evidence",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column(
            "evidence_type",
            sa.Enum(
                "phone_number", "message", "link", "call", "transaction", "report", "assessment", "identity", "other",
                name="evidence_type", native_enum=False, create_constraint=True, length=32,
            ),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="1.0", nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name=op.f("ck_case_evidence_confidence_range")),
        sa.ForeignKeyConstraint(["case_id"], ["fraud_cases.id"], name=op.f("fk_case_evidence_case_id_fraud_cases"), ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_evidence")),
    )
    op.create_index("ix_case_evidence_case_id_observed_at", "case_evidence", ["case_id", "observed_at"], unique=False)

    for table in ("fraud_reports", "risk_assessments", "shield_analyses", "transaction_assessments"):
        op.add_column(table, sa.Column("case_id", sa.UUID(), nullable=True))
        op.create_foreign_key(
            op.f(f"fk_{table}_case_id_fraud_cases"), table, "fraud_cases", ["case_id"], ["id"], ondelete="SET NULL"
        )

    op.create_index("ix_fraud_reports_case_id", "fraud_reports", ["case_id"], unique=False)
    op.create_index("ix_risk_assessments_case_id_created_at", "risk_assessments", ["case_id", "created_at"], unique=False)
    op.create_index("ix_shield_analyses_case_id_created_at", "shield_analyses", ["case_id", "created_at"], unique=False)
    op.create_index("ix_transaction_assessments_case_id_created_at", "transaction_assessments", ["case_id", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_transaction_assessments_case_id_created_at", table_name="transaction_assessments")
    op.drop_index("ix_shield_analyses_case_id_created_at", table_name="shield_analyses")
    op.drop_index("ix_risk_assessments_case_id_created_at", table_name="risk_assessments")
    op.drop_index("ix_fraud_reports_case_id", table_name="fraud_reports")
    for table in ("transaction_assessments", "shield_analyses", "risk_assessments", "fraud_reports"):
        op.drop_constraint(op.f(f"fk_{table}_case_id_fraud_cases"), table, type_="foreignkey")
        op.drop_column(table, "case_id")
    op.drop_index("ix_case_evidence_case_id_observed_at", table_name="case_evidence")
    op.drop_table("case_evidence")
    op.drop_index("ix_fraud_cases_user_id_updated_at", table_name="fraud_cases")
    op.drop_table("fraud_cases")
