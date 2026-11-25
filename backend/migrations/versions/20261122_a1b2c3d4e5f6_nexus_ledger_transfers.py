"""NEXUS ledger: one graph edge per partner transfer (Chainalysis-style money graph).

Revision ID: a1b2c3d4e5f6
Revises: f81234567890
Create Date: 2026-11-22
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a1b2c3d4e5f6"
down_revision: str | Sequence[str] | None = "f81234567890"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "entity_relationships",
        sa.Column("partner_transaction_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        op.f("fk_entity_relationships_partner_transaction_id_partner_transactions"),
        "entity_relationships",
        "partner_transactions",
        ["partner_transaction_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint("uq_entity_relationship_identity", "entity_relationships", type_="unique")
    op.create_index(
        "ix_entity_relationships_partner_transaction_id",
        "entity_relationships",
        ["partner_transaction_id"],
        unique=True,
        postgresql_where=sa.text("partner_transaction_id IS NOT NULL"),
    )
    op.create_index(
        "uq_entity_relationship_identity_non_ledger",
        "entity_relationships",
        ["source_entity_id", "target_entity_id", "relationship_type"],
        unique=True,
        postgresql_where=sa.text("partner_transaction_id IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_entity_relationship_identity_non_ledger", table_name="entity_relationships")
    op.drop_index("ix_entity_relationships_partner_transaction_id", table_name="entity_relationships")
    op.drop_constraint(
        op.f("fk_entity_relationships_partner_transaction_id_partner_transactions"),
        "entity_relationships",
        type_="foreignkey",
    )
    op.drop_column("entity_relationships", "partner_transaction_id")
    op.create_unique_constraint(
        "uq_entity_relationship_identity",
        "entity_relationships",
        ["source_entity_id", "target_entity_id", "relationship_type"],
    )