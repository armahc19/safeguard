"""add admin-managed partner integrations

Revision ID: a3b4c5d6e7f8
Revises: f17a2b3c4d5e
Create Date: 2026-11-17
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a3b4c5d6e7f8"
down_revision: str | Sequence[str] | None = "f17a2b3c4d5e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "partner_integrations",
        sa.Column("partner_id", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("partner_type", sa.String(length=16), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("partner_type IN ('telecom', 'bank', 'momo')", name="ck_partner_integrations_partner_type_valid"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_partner_integrations")),
        sa.UniqueConstraint("partner_id", name=op.f("uq_partner_integrations_partner_id")),
    )
    op.create_index("ix_partner_integrations_active", "partner_integrations", ["is_active"])


def downgrade() -> None:
    op.drop_index("ix_partner_integrations_active", table_name="partner_integrations")
    op.drop_table("partner_integrations")
