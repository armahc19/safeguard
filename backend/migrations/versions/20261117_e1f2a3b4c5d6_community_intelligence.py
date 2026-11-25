"""add community reports and shared intelligence

Revision ID: e1f2a3b4c5d6
Revises: d9e7f3a5b802
Create Date: 2026-11-17
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e1f2a3b4c5d6"
down_revision: str | Sequence[str] | None = "d9e7f3a5b802"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enum(*values: str, name: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=32)


def upgrade() -> None:
    op.create_table(
        "community_entities",
        sa.Column("entity_type", _enum("phone", "link", "account", "message", name="community_entity_type"), nullable=False),
        sa.Column("normalized_value", sa.String(length=512), nullable=False),
        sa.Column("display_value", sa.String(length=512), nullable=True),
        sa.Column("country_code", sa.String(length=2), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_community_entities")),
        sa.UniqueConstraint("entity_type", "normalized_value", name="uq_community_entities_identity"),
    )
    op.create_index("ix_community_entities_type_value", "community_entities", ["entity_type", "normalized_value"])

    op.create_table(
        "fraud_incidents",
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", _enum("open", "under_review", "confirmed", "rejected", "resolved", name="community_incident_status"), server_default="open", nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("risk_level", _enum("low", "medium", "high", "critical", name="community_incident_risk_level"), server_default="low", nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="community_incident_confidence_range"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fraud_incidents")),
    )
    op.create_index("ix_fraud_incidents_status_updated_at", "fraud_incidents", ["status", "updated_at"])

    op.create_table(
        "community_reports",
        sa.Column("reporter_id", sa.UUID(), nullable=False),
        sa.Column("report_type", sa.String(length=32), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False),
        sa.Column("subject_value", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("evidence_reference", sa.String(length=512), nullable=True),
        sa.Column("status", _enum("submitted", "under_review", "accepted", "rejected", name="community_report_status"), server_default="submitted", nullable=False),
        sa.Column("entity_id", sa.UUID(), nullable=True),
        sa.Column("incident_id", sa.UUID(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["reporter_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["entity_id"], ["community_entities.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["fraud_incidents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_community_reports")),
    )
    op.create_index("ix_community_reports_status_created_at", "community_reports", ["status", "created_at"])
    op.create_index("ix_community_reports_reporter_id_created_at", "community_reports", ["reporter_id", "created_at"])
    op.create_index("ix_community_reports_entity_id", "community_reports", ["entity_id"])

    op.create_table(
        "report_evidence",
        sa.Column("report_id", sa.UUID(), nullable=False),
        sa.Column("evidence_type", sa.String(length=32), nullable=False),
        sa.Column("storage_reference", sa.String(length=512), nullable=False),
        sa.Column("content_hash", sa.String(length=128), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["report_id"], ["community_reports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_evidence")),
    )

    op.create_table(
        "entity_relationships",
        sa.Column("source_entity_id", sa.UUID(), nullable=False),
        sa.Column("target_entity_id", sa.UUID(), nullable=False),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), server_default="1.0", nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="community_relationship_confidence_range"),
        sa.ForeignKeyConstraint(["source_entity_id"], ["community_entities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_entity_id"], ["community_entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_entity_relationships")),
        sa.UniqueConstraint("source_entity_id", "target_entity_id", "relationship_type", name="uq_entity_relationship_identity"),
    )

    op.create_table(
        "intelligence_records",
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("entity_id", sa.UUID(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("status", _enum("draft", "active", "expired", "withdrawn", name="intelligence_status"), server_default="draft", nullable=False),
        sa.Column("confidence", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("risk_level", _enum("low", "medium", "high", "critical", name="intelligence_risk_level"), server_default="low", nullable=False),
        sa.Column("distinct_reporters", sa.Integer(), server_default="0", nullable=False),
        sa.Column("signals", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="intelligence_confidence_range"),
        sa.CheckConstraint("distinct_reporters >= 0", name="intelligence_distinct_reporters_nonnegative"),
        sa.ForeignKeyConstraint(["incident_id"], ["fraud_incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["entity_id"], ["community_entities.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_intelligence_records")),
    )
    op.create_index("ix_intelligence_records_entity_status", "intelligence_records", ["entity_id", "status"])

    op.create_table(
        "report_reviews",
        sa.Column("report_id", sa.UUID(), nullable=False),
        sa.Column("reviewer_id", sa.UUID(), nullable=False),
        sa.Column("decision", _enum("approved", "rejected", "needs_info", name="community_review_decision"), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["report_id"], ["community_reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewer_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_reviews")),
    )
    op.create_index("ix_report_reviews_report_created_at", "report_reviews", ["report_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_report_reviews_report_created_at", table_name="report_reviews")
    op.drop_table("report_reviews")
    op.drop_index("ix_intelligence_records_entity_status", table_name="intelligence_records")
    op.drop_table("intelligence_records")
    op.drop_table("entity_relationships")
    op.drop_table("report_evidence")
    op.drop_index("ix_community_reports_entity_id", table_name="community_reports")
    op.drop_index("ix_community_reports_reporter_id_created_at", table_name="community_reports")
    op.drop_index("ix_community_reports_status_created_at", table_name="community_reports")
    op.drop_table("community_reports")
    op.drop_index("ix_fraud_incidents_status_updated_at", table_name="fraud_incidents")
    op.drop_table("fraud_incidents")
    op.drop_index("ix_community_entities_type_value", table_name="community_entities")
    op.drop_table("community_entities")
