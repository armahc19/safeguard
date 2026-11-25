"""expand partner registry into the Partner Data Repository

Revision ID: b4c5d6e7f801
Revises: a3b4c5d6e7f8
Create Date: 2026-11-17
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b4c5d6e7f801"
down_revision: str | Sequence[str] | None = "a3b4c5d6e7f8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Preserve admin-created partner credentials while making this the repository's partners table.
    op.drop_index("ix_partner_integrations_active", table_name="partner_integrations")
    op.drop_constraint("uq_partner_integrations_partner_id", "partner_integrations", type_="unique")
    op.rename_table("partner_integrations", "partners")
    op.alter_column("partners", "partner_id", new_column_name="partner_code")
    op.alter_column("partners", "display_name", new_column_name="partner_name")
    op.alter_column("partners", "created_at", new_column_name="registration_datetime")
    op.drop_constraint(
        op.f("ck_partner_integrations_ck_partner_integrations_partner_3c60"),
        "partners", type_="check",
    )
    op.alter_column("partners", "is_active", new_column_name="partner_status")
    op.alter_column(
        "partners", "partner_status", existing_type=sa.Boolean(), type_=sa.String(length=16),
        postgresql_using="CASE WHEN partner_status THEN 'active' ELSE 'inactive' END", server_default="active",
    )
    op.create_unique_constraint("uq_partners_partner_code", "partners", ["partner_code"])
    op.create_check_constraint("partner_type_valid", "partners", "partner_type IN ('telecom', 'bank', 'momo')")
    op.create_check_constraint("partner_status_valid", "partners", "partner_status IN ('active', 'inactive')")
    op.create_index("ix_partners_partner_status", "partners", ["partner_status"])

    op.create_table(
        "partner_submissions",
        sa.Column("partner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("submission_reference", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=16), server_default="1", nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("raw_payload_encrypted", sa.Text(), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("processing_status", sa.String(length=16), server_default="accepted", nullable=False),
        sa.Column("record_counts", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("normalized_payload", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["partner_id"], ["partners.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_partner_submissions")),
        sa.UniqueConstraint("partner_id", "submission_reference", name="uq_partner_submissions_partner_reference"),
    )
    op.create_index("ix_partner_submissions_received_at", "partner_submissions", ["received_at"])

    op.create_table(
        "partner_identities",
        sa.Column("partner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity_reference", sa.String(length=128), nullable=False),
        sa.Column("national_id_reference", sa.String(length=256)),
        sa.Column("phone_number_reference", sa.String(length=64)),
        sa.Column("verified_ownership", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("verification_status", sa.String(length=16), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("verification_status IN ('verified', 'pending', 'unverified')", name="verification_status_valid"),
        sa.CheckConstraint("NOT verified_ownership OR verification_status = 'verified'", name="ownership_status_consistent"),
        sa.ForeignKeyConstraint(["partner_id"], ["partners.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["submission_id"], ["partner_submissions.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_partner_identities")),
        sa.UniqueConstraint("partner_id", "identity_reference", name="uq_partner_identities_partner_reference"),
    )
    op.create_index("ix_partner_identities_national_id_reference", "partner_identities", ["national_id_reference"])
    op.create_index("ix_partner_identities_phone_reference", "partner_identities", ["phone_number_reference"])

    op.create_table(
        "partner_accounts",
        sa.Column("identity_id", postgresql.UUID(as_uuid=True)),
        sa.Column("partner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity_reference", sa.String(length=128)),
        sa.Column("account_identifier", sa.String(length=128), nullable=False),
        sa.Column("account_type", sa.String(length=64), nullable=False),
        sa.Column("service_provider", sa.String(length=120), nullable=False),
        sa.Column("account_status", sa.String(length=16), nullable=False),
        sa.Column("ownership_reference", sa.String(length=128)),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("account_status IN ('active', 'suspended', 'closed')", name="account_status_valid"),
        sa.ForeignKeyConstraint(["identity_id"], ["partner_identities.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["partner_id"], ["partners.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["submission_id"], ["partner_submissions.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_partner_accounts")),
        sa.UniqueConstraint("partner_id", "account_identifier", name="uq_partner_accounts_partner_identifier"),
    )
    op.create_index("ix_partner_accounts_identity_id", "partner_accounts", ["identity_id"])

    op.create_table(
        "partner_transactions",
        sa.Column("partner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("submission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("transaction_reference", sa.String(length=128), nullable=False),
        sa.Column("sender_account_id", postgresql.UUID(as_uuid=True)),
        sa.Column("receiver_account_id", postgresql.UUID(as_uuid=True)),
        sa.Column("sender_partner_id", postgresql.UUID(as_uuid=True)),
        sa.Column("receiver_partner_id", postgresql.UUID(as_uuid=True)),
        sa.Column("sender_partner_code", sa.String(length=64), nullable=False),
        sa.Column("receiver_partner_code", sa.String(length=64), nullable=False),
        sa.Column("sender_account_reference", sa.String(length=128), nullable=False),
        sa.Column("receiver_account_reference", sa.String(length=128), nullable=False),
        sa.Column("amount", sa.Numeric(20, 4), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("balance", sa.Numeric(20, 4)),
        sa.Column("transaction_datetime", sa.DateTime(timezone=True), nullable=False),
        sa.Column("transaction_status", sa.String(length=16), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("amount > 0", name="amount_positive"),
        sa.CheckConstraint("balance IS NULL OR balance >= 0", name="balance_nonnegative"),
        sa.CheckConstraint("transaction_status IN ('successful', 'pending', 'failed')", name="transaction_status_valid"),
        sa.ForeignKeyConstraint(["partner_id"], ["partners.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["submission_id"], ["partner_submissions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["sender_account_id"], ["partner_accounts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["receiver_account_id"], ["partner_accounts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["sender_partner_id"], ["partners.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["receiver_partner_id"], ["partners.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_partner_transactions")),
        sa.UniqueConstraint("partner_id", "transaction_reference", name="uq_partner_transactions_partner_reference"),
    )
    op.create_index("ix_partner_transactions_timestamp", "partner_transactions", ["transaction_datetime"])
    op.create_index("ix_partner_transactions_sender_account_id", "partner_transactions", ["sender_account_id"])
    op.create_index("ix_partner_transactions_receiver_account_id", "partner_transactions", ["receiver_account_id"])


def downgrade() -> None:
    op.drop_table("partner_transactions")
    op.drop_table("partner_accounts")
    op.drop_table("partner_identities")
    op.drop_table("partner_submissions")
    op.drop_index("ix_partners_partner_status", table_name="partners")
    op.drop_constraint(op.f("ck_partners_partner_type_valid"), "partners", type_="check")
    op.drop_constraint(op.f("ck_partners_partner_status_valid"), "partners", type_="check")
    op.drop_constraint("uq_partners_partner_code", "partners", type_="unique")
    op.alter_column(
        "partners", "partner_status", existing_type=sa.String(length=16), type_=sa.Boolean(),
        postgresql_using="partner_status = 'active'", server_default=sa.true(),
    )
    op.alter_column("partners", "partner_status", new_column_name="is_active")
    op.alter_column("partners", "registration_datetime", new_column_name="created_at")
    op.alter_column("partners", "partner_name", new_column_name="display_name")
    op.alter_column("partners", "partner_code", new_column_name="partner_id")
    op.rename_table("partners", "partner_integrations")
    op.create_check_constraint(
        "partner_type_valid", "partner_integrations", "partner_type IN ('telecom', 'bank', 'momo')"
    )
    op.create_unique_constraint("uq_partner_integrations_partner_id", "partner_integrations", ["partner_id"])
    op.create_index("ix_partner_integrations_active", "partner_integrations", ["is_active"])
