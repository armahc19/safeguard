"""Allow analyzed messages to be stored directly as FIR records.

Revision ID: f81234567890
Revises: e7f812345678
Create Date: 2026-11-21
"""
from collections.abc import Sequence

from alembic import op

revision: str = "f81234567890"
down_revision: str | Sequence[str] | None = "e7f812345678"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        op.f("ck_fir_reports_source_report_exactly_one"), "fir_reports", type_="check"
    )
    op.create_check_constraint(
        "source_report_exactly_one",
        "fir_reports",
        "(community_report_id IS NOT NULL) <> (fraud_report_id IS NOT NULL) "
        "OR (community_report_id IS NULL AND fraud_report_id IS NULL AND source_type = 'message_analysis')",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_fir_reports_source_report_exactly_one"), "fir_reports", type_="check"
    )
    op.create_check_constraint(
        "source_report_exactly_one",
        "fir_reports",
        "(community_report_id IS NOT NULL) <> (fraud_report_id IS NOT NULL)",
    )
