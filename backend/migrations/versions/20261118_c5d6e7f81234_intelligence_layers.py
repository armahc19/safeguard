"""persist the first five FIR and partner intelligence layers

Revision ID: c5d6e7f81234
Revises: b4c5d6e7f801
Create Date: 2026-11-18
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c5d6e7f81234"
down_revision: str | Sequence[str] | None = "b4c5d6e7f801"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _risk_enum(name: str) -> sa.Enum:
    return sa.Enum("low", "medium", "high", "critical", name=name,
                   native_enum=False, create_constraint=True, length=32)


def upgrade() -> None:
    op.create_table(
        "identity_resolution_clusters",
        sa.Column("match_type", sa.String(32), nullable=False),
        sa.Column("match_key", sa.String(64), nullable=False),
        sa.Column("resolution_status", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("partner_count", sa.Integer(), nullable=False),
        sa.Column("identity_count", sa.Integer(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_identity_resolution_clusters")),
        sa.UniqueConstraint("match_type", "match_key", name="uq_identity_resolution_cluster_key"),
        sa.CheckConstraint("match_type IN ('national_id', 'phone')", name="identity_match_type_valid"),
        sa.CheckConstraint("resolution_status IN ('resolved', 'candidate')", name="identity_resolution_status_valid"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="identity_cluster_confidence_range"),
        sa.CheckConstraint("partner_count >= 1 AND identity_count >= partner_count", name="identity_cluster_counts_valid"),
    )
    op.create_index("ix_identity_resolution_clusters_status", "identity_resolution_clusters", ["resolution_status"])

    op.create_table(
        "identity_resolution_members",
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("partner_identity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("match_evidence", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_identity_resolution_members")),
        sa.ForeignKeyConstraint(["cluster_id"], ["identity_resolution_clusters.id"], name=op.f("fk_identity_resolution_members_cluster_id_identity_resolution_clusters"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["partner_identity_id"], ["partner_identities.id"], name=op.f("fk_identity_resolution_members_partner_identity_id_partner_identities"), ondelete="CASCADE"),
        sa.UniqueConstraint("cluster_id", "partner_identity_id", name="uq_identity_resolution_member"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="identity_member_confidence_range"),
    )
    op.create_index("ix_identity_resolution_members_identity", "identity_resolution_members", ["partner_identity_id"])

    op.create_table(
        "entity_intelligence_profiles",
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("partner_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("transaction_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("report_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("linked_entity_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("activity_summary", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("risk_score", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("risk_level", _risk_enum("entity_profile_risk_level"), nullable=False, server_default="low"),
        sa.Column("risk_confidence", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("risk_reasons", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_entity_intelligence_profiles")),
        sa.ForeignKeyConstraint(["entity_id"], ["community_entities.id"], name=op.f("fk_entity_intelligence_profiles_entity_id_community_entities"), ondelete="CASCADE"),
        sa.UniqueConstraint("entity_id", name="uq_entity_intelligence_profiles_entity_id"),
        sa.CheckConstraint("partner_count >= 0 AND transaction_count >= 0 AND report_count >= 0 AND linked_entity_count >= 0", name="entity_profile_counts_nonnegative"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="entity_profile_risk_score_range"),
        sa.CheckConstraint("risk_confidence >= 0 AND risk_confidence <= 1", name="entity_profile_risk_confidence_range"),
    )
    op.create_index("ix_entity_intelligence_profiles_risk", "entity_intelligence_profiles", ["risk_level", "risk_score"])

    op.create_table(
        "cross_institution_signals",
        sa.Column("signal_key", sa.String(64), nullable=False),
        sa.Column("signal_type", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), server_default="active", nullable=False),
        sa.Column("risk_level", _risk_enum("cross_institution_risk_level"), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("partner_codes", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("entity_ids", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("reasons", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cross_institution_signals")),
        sa.UniqueConstraint("signal_key", name="uq_cross_institution_signals_signal_key"),
        sa.CheckConstraint("status IN ('active', 'resolved')", name="cross_institution_signal_status_valid"),
        sa.CheckConstraint("score >= 0 AND score <= 1", name="cross_institution_signal_score_range"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="cross_institution_signal_confidence_range"),
    )
    op.create_index("ix_cross_institution_signals_status_created", "cross_institution_signals", ["status", "created_at"])
    op.create_index("ix_cross_institution_signals_type_created", "cross_institution_signals", ["signal_type", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_cross_institution_signals_type_created", table_name="cross_institution_signals")
    op.drop_index("ix_cross_institution_signals_status_created", table_name="cross_institution_signals")
    op.drop_table("cross_institution_signals")
    op.drop_index("ix_entity_intelligence_profiles_risk", table_name="entity_intelligence_profiles")
    op.drop_table("entity_intelligence_profiles")
    op.drop_index("ix_identity_resolution_members_identity", table_name="identity_resolution_members")
    op.drop_table("identity_resolution_members")
    op.drop_index("ix_identity_resolution_clusters_status", table_name="identity_resolution_clusters")
    op.drop_table("identity_resolution_clusters")
