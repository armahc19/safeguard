"""persist fraud-network relationships

Revision ID: b7c5d1e2f903
Revises: 9ab4c2d7e610
Create Date: 2026-11-15
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b7c5d1e2f903"
down_revision: str | Sequence[str] | None = "9ab4c2d7e610"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "network_links",
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_value", sa.String(length=512), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("target_value", sa.String(length=512), nullable=False),
        sa.Column("relation", sa.String(length=64), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="1.0", nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name=op.f("ck_network_links_confidence_range")),
        sa.ForeignKeyConstraint(["case_id"], ["fraud_cases.id"], name=op.f("fk_network_links_case_id_fraud_cases"), ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_links")),
        sa.UniqueConstraint("source_type", "source_value", "target_type", "target_value", "relation", name="uq_network_links_identity"),
    )
    op.create_index("ix_network_links_source", "network_links", ["source_type", "source_value"], unique=False)
    op.create_index("ix_network_links_target", "network_links", ["target_type", "target_value"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_network_links_target", table_name="network_links")
    op.drop_index("ix_network_links_source", table_name="network_links")
    op.drop_table("network_links")
