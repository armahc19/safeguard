"""add liveness attestations and partner intelligence delivery

Revision ID: d6e7f8123456
Revises: c5d6e7f81234
Create Date: 2026-11-18
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d6e7f8123456"
down_revision: str | Sequence[str] | None = "c5d6e7f81234"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("entity_intelligence_profiles", sa.Column(
        "ai_features", postgresql.JSONB(astext_type=sa.Text()),
        server_default=sa.text("'{}'::jsonb"), nullable=False,
    ))
    op.add_column("entity_intelligence_profiles", sa.Column(
        "graph_features", postgresql.JSONB(astext_type=sa.Text()),
        server_default=sa.text("'{}'::jsonb"), nullable=False,
    ))
    op.add_column("entity_intelligence_profiles", sa.Column(
        "fusion_version", sa.String(length=64), server_default="ai-graph-fusion.v1", nullable=False,
    ))

    op.create_table(
        "liveness_challenges",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("phone_reference", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_liveness_challenges")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_liveness_challenges_user_id_users"), ondelete="CASCADE"),
        sa.UniqueConstraint("nonce_hash", name="uq_liveness_challenges_nonce_hash"),
    )
    op.create_index("ix_liveness_challenges_user_created", "liveness_challenges", ["user_id", "created_at"])

    op.create_table(
        "liveness_assessments",
        sa.Column("challenge_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("partner_identity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("provider_name", sa.String(length=120), nullable=False),
        sa.Column("provider_reference", sa.String(length=128), nullable=False),
        sa.Column("liveness_status", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_liveness_assessments")),
        sa.ForeignKeyConstraint(["challenge_id"], ["liveness_challenges.id"], name=op.f("fk_liveness_assessments_challenge_id_liveness_challenges"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["partner_id"], ["partners.id"], name=op.f("fk_liveness_assessments_partner_id_partners"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["partner_identity_id"], ["partner_identities.id"], name=op.f("fk_liveness_assessments_partner_identity_id_partner_identities"), ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["entity_id"], ["community_entities.id"], name=op.f("fk_liveness_assessments_entity_id_community_entities"), ondelete="SET NULL"),
        sa.UniqueConstraint("challenge_id", name="uq_liveness_assessments_challenge_id"),
        sa.UniqueConstraint("partner_id", "provider_reference", name="uq_liveness_partner_provider_reference"),
        sa.CheckConstraint("liveness_status IN ('live', 'spoof', 'inconclusive')", name="liveness_status_valid"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="liveness_confidence_range"),
    )
    op.create_index("ix_liveness_assessments_entity_created", "liveness_assessments", ["entity_id", "created_at"])

    op.create_table(
        "partner_intelligence_deliveries",
        sa.Column("partner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("signal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("delivery_status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_partner_intelligence_deliveries")),
        sa.ForeignKeyConstraint(["partner_id"], ["partners.id"], name=op.f("fk_partner_intelligence_deliveries_partner_id_partners"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["signal_id"], ["cross_institution_signals.id"], name=op.f("fk_partner_intelligence_deliveries_signal_id_cross_institution_signals"), ondelete="CASCADE"),
        sa.UniqueConstraint("partner_id", "signal_id", name="uq_partner_intelligence_delivery_signal"),
        sa.CheckConstraint("delivery_status IN ('pending', 'acknowledged')", name="partner_delivery_status_valid"),
        sa.CheckConstraint("attempts >= 0", name="partner_delivery_attempts_nonnegative"),
    )
    op.create_index("ix_partner_intelligence_deliveries_partner_status", "partner_intelligence_deliveries", ["partner_id", "delivery_status", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_partner_intelligence_deliveries_partner_status", table_name="partner_intelligence_deliveries")
    op.drop_table("partner_intelligence_deliveries")
    op.drop_index("ix_liveness_assessments_entity_created", table_name="liveness_assessments")
    op.drop_table("liveness_assessments")
    op.drop_index("ix_liveness_challenges_user_created", table_name="liveness_challenges")
    op.drop_table("liveness_challenges")
    op.drop_column("entity_intelligence_profiles", "fusion_version")
    op.drop_column("entity_intelligence_profiles", "graph_features")
    op.drop_column("entity_intelligence_profiles", "ai_features")
