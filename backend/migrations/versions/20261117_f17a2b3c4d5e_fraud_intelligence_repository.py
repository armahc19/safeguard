"""expand community intelligence into the Fraud Intelligence Repository

Revision ID: f17a2b3c4d5e
Revises: e1f2a3b4c5d6
Create Date: 2026-11-17
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f17a2b3c4d5e"
down_revision: str | Sequence[str] | None = "e1f2a3b4c5d6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enum(*values: str, name: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=32)


def upgrade() -> None:
    op.add_column("fraud_cases", sa.Column("assigned_investigator_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_fraud_cases_assigned_investigator_id_users", "fraud_cases", "users",
        ["assigned_investigator_id"], ["id"], ondelete="SET NULL",
    )
    op.add_column("fraud_incidents", sa.Column("incident_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("fraud_incidents", sa.Column("location", sa.String(length=256), nullable=True))
    op.add_column("fraud_incidents", sa.Column(
        "outcome", _enum("unresolved", "confirmed_fraud", "false_report", "funds_recovered", name="fraud_outcome"),
        server_default="unresolved", nullable=False,
    ))
    op.add_column("fraud_incidents", sa.Column("assigned_investigator_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_fraud_incidents_assigned_investigator_id_users", "fraud_incidents", "users",
        ["assigned_investigator_id"], ["id"], ondelete="SET NULL",
    )

    op.drop_constraint("community_entity_type", "community_entities", type_="check")
    op.create_check_constraint(
        "community_entity_type", "community_entities",
        "entity_type IN ('phone', 'link', 'account', 'message', 'person', 'organization', 'wallet', 'email')",
    )

    op.create_table(
        "fir_reports",
        sa.Column("community_report_id", sa.UUID(), nullable=True),
        sa.Column("fraud_report_id", sa.UUID(), nullable=True),
        sa.Column("reporter_id", sa.UUID(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("report_type", sa.String(length=32), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("evidence_reference", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("(community_report_id IS NOT NULL) <> (fraud_report_id IS NOT NULL)", name="source_report_exactly_one"),
        sa.ForeignKeyConstraint(["community_report_id"], ["community_reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["fraud_report_id"], ["fraud_reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reporter_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["fraud_cases.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fir_reports")),
        sa.UniqueConstraint("community_report_id", name="uq_fir_reports_community_report_id"),
        sa.UniqueConstraint("fraud_report_id", name="uq_fir_reports_fraud_report_id"),
    )
    op.create_index("ix_fir_reports_status_created_at", "fir_reports", ["status", "created_at"])
    op.create_index("ix_fir_reports_reporter_created_at", "fir_reports", ["reporter_id", "created_at"])
    op.create_index("ix_fir_reports_case_id", "fir_reports", ["case_id"])
    op.execute("""
        INSERT INTO fir_reports
            (community_report_id, reporter_id, source_type, source, report_type, channel,
             subject, description, category, evidence_reference, status, created_at, updated_at)
        SELECT id, reporter_id, 'community', 'community_api', report_type, channel,
               subject_value, description, category, evidence_reference, status::text, created_at, created_at
        FROM community_reports
    """)
    op.execute("""
        INSERT INTO fir_reports
            (fraud_report_id, reporter_id, case_id, source_type, source, report_type, channel,
             subject, description, evidence_reference, status, created_at, updated_at)
        SELECT r.id, r.user_id, r.case_id, 'number_report', 'reports_api', r.report_type, 'app',
               p.normalized_number, coalesce(r.description, ''), r.evidence_reference, r.status::text,
               r.created_at, r.updated_at
        FROM fraud_reports r JOIN phone_numbers p ON p.id = r.phone_number_id
    """)

    op.execute("""
        INSERT INTO community_entities (entity_type, normalized_value, display_value, country_code)
        SELECT 'phone', p.normalized_number, p.normalized_number, p.country_code
        FROM fraud_reports r JOIN phone_numbers p ON p.id = r.phone_number_id
        ON CONFLICT (entity_type, normalized_value) DO NOTHING
    """)
    op.execute("""
        INSERT INTO fraud_incidents (title, description, status, category, confidence, risk_level, metadata)
        SELECT 'Report involving ' || p.normalized_number, r.description, 'open', NULL, 0, 'low',
               jsonb_build_object('legacy_fraud_report_id', r.id::text)
        FROM fraud_reports r JOIN phone_numbers p ON p.id = r.phone_number_id
    """)

    op.create_table(
        "report_incidents",
        sa.Column("report_id", sa.UUID(), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("confidence", sa.Float(), server_default="1.0", nullable=False),
        sa.Column("link_reason", sa.String(length=64), server_default="report_submission", nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="report_incident_confidence_range"),
        sa.ForeignKeyConstraint(["report_id"], ["fir_reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["fraud_incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_incidents")),
        sa.UniqueConstraint("report_id", "incident_id", name="uq_report_incidents_pair"),
    )
    op.create_index("ix_report_incidents_incident_id", "report_incidents", ["incident_id"])
    op.execute("""
        INSERT INTO report_incidents (report_id, incident_id, confidence, link_reason)
        SELECT fr.id, cr.incident_id, 1.0, 'legacy_report_link'
        FROM community_reports cr JOIN fir_reports fr ON fr.community_report_id = cr.id
        WHERE cr.incident_id IS NOT NULL
        ON CONFLICT (report_id, incident_id) DO NOTHING
    """)
    op.execute("""
        INSERT INTO report_incidents (report_id, incident_id, confidence, link_reason)
        SELECT fr.id, i.id, 1.0, 'legacy_number_report'
        FROM fraud_reports r
        JOIN fir_reports fr ON fr.fraud_report_id = r.id
        JOIN fraud_incidents i ON i.metadata->>'legacy_fraud_report_id' = r.id::text
        ON CONFLICT (report_id, incident_id) DO NOTHING
    """)

    op.create_table(
        "report_entities",
        sa.Column("report_id", sa.UUID(), nullable=False),
        sa.Column("entity_id", sa.UUID(), nullable=False),
        sa.Column("source_text", sa.String(length=512), nullable=True),
        sa.Column("source_kind", sa.String(length=32), server_default="user_report", nullable=False),
        sa.Column("confidence", sa.Float(), server_default="1.0", nullable=False),
        sa.Column("verified", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="report_entity_confidence_range"),
        sa.ForeignKeyConstraint(["report_id"], ["fir_reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["entity_id"], ["community_entities.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_entities")),
        sa.UniqueConstraint("report_id", "entity_id", "source_kind", name="uq_report_entities_source"),
    )
    op.create_index("ix_report_entities_entity_id", "report_entities", ["entity_id"])
    op.execute("""
        INSERT INTO report_entities (report_id, entity_id, source_text, source_kind, confidence)
        SELECT fr.id, cr.entity_id, cr.subject_value, 'user_report', 1.0
        FROM community_reports cr JOIN fir_reports fr ON fr.community_report_id = cr.id
        WHERE cr.entity_id IS NOT NULL
        ON CONFLICT (report_id, entity_id, source_kind) DO NOTHING
    """)
    op.execute("""
        INSERT INTO report_entities (report_id, entity_id, source_text, source_kind, confidence)
        SELECT fr.id, ce.id, p.normalized_number, 'reported_number', 1.0
        FROM fraud_reports r JOIN fir_reports fr ON fr.fraud_report_id = r.id
        JOIN phone_numbers p ON p.id = r.phone_number_id
        JOIN community_entities ce ON ce.entity_type = 'phone' AND ce.normalized_value = p.normalized_number
        ON CONFLICT (report_id, entity_id, source_kind) DO NOTHING
    """)

    op.create_table(
        "incident_entities",
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("entity_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), server_default="1.0", nullable=False),
        sa.Column("verification_status", sa.String(length=32), server_default="unverified", nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="incident_entity_confidence_range"),
        sa.ForeignKeyConstraint(["incident_id"], ["fraud_incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["entity_id"], ["community_entities.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_entities")),
        sa.UniqueConstraint("incident_id", "entity_id", "role", name="uq_incident_entities_role"),
    )
    op.create_index("ix_incident_entities_entity_id", "incident_entities", ["entity_id"])
    op.execute("""
        INSERT INTO incident_entities (incident_id, entity_id, role, confidence, verification_status)
        SELECT ri.incident_id, re.entity_id, 'related', re.confidence, 'unverified'
        FROM report_incidents ri JOIN report_entities re ON re.report_id = ri.report_id
        ON CONFLICT (incident_id, entity_id, role) DO NOTHING
    """)

    op.create_table(
        "incident_findings",
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("report_id", sa.UUID(), nullable=True),
        sa.Column("finding_type", sa.String(length=32), nullable=False),
        sa.Column("taxonomy_id", sa.String(length=128), nullable=True),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("finding_type IN ('pattern', 'behaviour', 'other')", name="finding_type_allowed"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="finding_confidence_range"),
        sa.ForeignKeyConstraint(["incident_id"], ["fraud_incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["report_id"], ["fir_reports.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_findings")),
    )
    op.create_index("ix_incident_findings_incident_type", "incident_findings", ["incident_id", "finding_type"])

    op.create_table(
        "fir_risk_assessments",
        sa.Column("report_id", sa.UUID(), nullable=True),
        sa.Column("incident_id", sa.UUID(), nullable=True),
        sa.Column("risk_level", _enum("low", "medium", "high", "critical", name="fir_risk_level"), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("reasons", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("model_version", sa.String(length=64), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("report_id IS NOT NULL OR incident_id IS NOT NULL", name="risk_assessment_subject_required"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="fir_risk_score_range"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="fir_risk_confidence_range"),
        sa.ForeignKeyConstraint(["report_id"], ["fir_reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["incident_id"], ["fraud_incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fir_risk_assessments")),
    )
    op.create_index("ix_fir_risk_assessments_report_created", "fir_risk_assessments", ["report_id", "created_at"])
    op.create_index("ix_fir_risk_assessments_incident_created", "fir_risk_assessments", ["incident_id", "created_at"])

    op.create_table(
        "investigation_activities",
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("actor_id", sa.UUID(), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["fraud_incidents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_investigation_activities")),
    )
    op.create_index("ix_investigation_activities_incident_created", "investigation_activities", ["incident_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_investigation_activities_incident_created", table_name="investigation_activities")
    op.drop_table("investigation_activities")
    op.drop_index("ix_fir_risk_assessments_incident_created", table_name="fir_risk_assessments")
    op.drop_index("ix_fir_risk_assessments_report_created", table_name="fir_risk_assessments")
    op.drop_table("fir_risk_assessments")
    op.drop_index("ix_incident_findings_incident_type", table_name="incident_findings")
    op.drop_table("incident_findings")
    op.drop_index("ix_incident_entities_entity_id", table_name="incident_entities")
    op.drop_table("incident_entities")
    op.drop_index("ix_report_entities_entity_id", table_name="report_entities")
    op.drop_table("report_entities")
    op.drop_index("ix_report_incidents_incident_id", table_name="report_incidents")
    op.drop_table("report_incidents")
    op.drop_index("ix_fir_reports_case_id", table_name="fir_reports")
    op.drop_index("ix_fir_reports_reporter_created_at", table_name="fir_reports")
    op.drop_index("ix_fir_reports_status_created_at", table_name="fir_reports")
    op.drop_table("fir_reports")
    op.drop_constraint("fk_fraud_incidents_assigned_investigator_id_users", "fraud_incidents", type_="foreignkey")
    op.drop_column("fraud_incidents", "assigned_investigator_id")
    op.drop_column("fraud_incidents", "outcome")
    op.drop_column("fraud_incidents", "location")
    op.drop_column("fraud_incidents", "incident_at")
    op.drop_constraint("fk_fraud_cases_assigned_investigator_id_users", "fraud_cases", type_="foreignkey")
    op.drop_column("fraud_cases", "assigned_investigator_id")
    op.drop_constraint("community_entity_type", "community_entities", type_="check")
    op.create_check_constraint(
        "community_entity_type", "community_entities",
        "entity_type IN ('phone', 'link', 'account', 'message')",
    )
