"""SQLAlchemy 2.0 models for the phone-fraud reporting / risk platform (PostgreSQL)."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    MetaData,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _enum(py_enum: type[enum.Enum], name: str) -> Enum:
    # VARCHAR + CHECK constraint instead of a native PG enum: far easier to evolve in migrations.
    return Enum(
        py_enum,
        name=name,
        native_enum=False,
        create_constraint=True,
        values_callable=lambda e: [m.value for m in e],
        length=32,
    )


# ---------------------------------------------------------------- enums (defined in app/enums.py)
from app.enums import (
    AccountStatus,
    CaseStatus,
    CommunityEntityType,
    CommunityIncidentStatus,
    CommunityReportStatus,
    EvidenceType,
    FeedbackOutcome,
    FraudOutcome,
    IntelligenceStatus,
    ReportStatus,
    ReviewDecision,
    RiskLevel,
    UserRole,
)


# ---------------------------------------------------------------- mixins
class UUIDPK:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )


class CreatedAt:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Timestamps(CreatedAt):
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


# ---------------------------------------------------------------- models
class FraudCase(UUIDPK, Timestamps, Base):
    """User-owned investigation context joining reports and assessments."""

    __tablename__ = "fraud_cases"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    assigned_investigator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    status: Mapped[CaseStatus] = mapped_column(
        _enum(CaseStatus, "case_status"), default=CaseStatus.OPEN,
        server_default=CaseStatus.OPEN.value, nullable=False,
    )
    case_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="cases", foreign_keys=[user_id])
    evidence: Mapped[list[CaseEvidence]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CaseEvidence.observed_at"
    )
    reports: Mapped[list[FraudReport]] = relationship(back_populates="case")
    risk_assessments: Mapped[list[RiskAssessment]] = relationship(back_populates="case")
    shield_analyses: Mapped[list[ShieldAnalysis]] = relationship(back_populates="case")
    transaction_assessments: Mapped[list[TransactionAssessment]] = relationship(back_populates="case")

    __table_args__ = (Index("ix_fraud_cases_user_id_updated_at", "user_id", "updated_at"),)


class CaseEvidence(UUIDPK, CreatedAt, Base):
    """Typed, auditable evidence attached to a case.

    ``value`` is for a safe reference or normalised identifier, not secrets or
    raw message bodies. Sensitive source data belongs in protected storage.
    """

    __tablename__ = "case_evidence"

    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("fraud_cases.id", ondelete="CASCADE"), nullable=False)
    evidence_type: Mapped[EvidenceType] = mapped_column(_enum(EvidenceType, "evidence_type"), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    value: Mapped[str | None] = mapped_column(String(512))
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0, server_default="1.0")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    case: Mapped[FraudCase] = relationship(back_populates="evidence")

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        Index("ix_case_evidence_case_id_observed_at", "case_id", "observed_at"),
    )


class NetworkLink(UUIDPK, Timestamps, Base):
    """Privacy-preserving relationship between fraud-intelligence nodes."""

    __tablename__ = "network_links"

    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_value: Mapped[str] = mapped_column(String(512), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_value: Mapped[str] = mapped_column(String(512), nullable=False)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("fraud_cases.id", ondelete="SET NULL"))
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0, server_default="1.0")
    link_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    case: Mapped[FraudCase | None] = relationship()

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        UniqueConstraint(
            "source_type", "source_value", "target_type", "target_value", "relation",
            name="uq_network_links_identity",
        ),
        Index("ix_network_links_source", "source_type", "source_value"),
        Index("ix_network_links_target", "target_type", "target_value"),
    )


class CaseFeedback(UUIDPK, CreatedAt, Base):
    """Outcome signal used to evaluate interventions and improve intelligence."""

    __tablename__ = "case_feedback"

    case_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("fraud_cases.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    outcome: Mapped[FeedbackOutcome] = mapped_column(_enum(FeedbackOutcome, "feedback_outcome"), nullable=False)
    intervention_action: Mapped[str | None] = mapped_column(String(64))
    followed_recommendation: Mapped[bool | None]
    fraud_confirmed: Mapped[bool | None]
    amount: Mapped[float | None] = mapped_column(Float)
    currency: Mapped[str | None] = mapped_column(String(3))
    loss_amount: Mapped[float | None] = mapped_column(Float)
    rating: Mapped[int | None] = mapped_column()
    notes: Mapped[str | None] = mapped_column(Text)
    feedback_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        CheckConstraint("amount IS NULL OR amount >= 0", name="amount_nonnegative"),
        CheckConstraint("loss_amount IS NULL OR loss_amount >= 0", name="loss_amount_nonnegative"),
        CheckConstraint("rating IS NULL OR rating BETWEEN 1 AND 5", name="rating_range"),
        Index("ix_case_feedback_case_id_created_at", "case_id", "created_at"),
        Index("ix_case_feedback_outcome_created_at", "outcome", "created_at"),
    )


class User(UUIDPK, Timestamps, Base):
    __tablename__ = "users"

    phone: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # E.164
    account_status: Mapped[AccountStatus] = mapped_column(
        _enum(AccountStatus, "account_status"), default=AccountStatus.ACTIVE,
        server_default=AccountStatus.ACTIVE.value, nullable=False,
    )

    role: Mapped[UserRole] = mapped_column(
        _enum(UserRole, "user_role"), default=UserRole.USER, server_default=UserRole.USER.value, nullable=False,
    )

    devices: Mapped[list[Device]] = relationship(back_populates="user", cascade="all, delete-orphan")
    fraud_reports: Mapped[list[FraudReport]] = relationship(
        back_populates="user", foreign_keys="FraudReport.user_id"
    )
    risk_assessments: Mapped[list[RiskAssessment]] = relationship(back_populates="user")
    shield_analyses: Mapped[list[ShieldAnalysis]] = relationship(back_populates="user")
    transaction_assessments: Mapped[list[TransactionAssessment]] = relationship(back_populates="user")
    cases: Mapped[list[FraudCase]] = relationship(
        back_populates="user", cascade="all, delete-orphan", foreign_keys="FraudCase.user_id"
    )


class Partner(UUIDPK, Base):
    """Partner registry plus integration credentials for authenticated data intake."""

    __tablename__ = "partners"

    partner_code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    partner_name: Mapped[str] = mapped_column(String(120), nullable=False)
    partner_type: Mapped[str] = mapped_column(String(16), nullable=False)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    partner_status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", server_default="active")
    registration_datetime: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    __table_args__ = (
        CheckConstraint("partner_type IN ('telecom', 'bank', 'momo')", name="partner_type_valid"),
        CheckConstraint("partner_status IN ('active', 'inactive')", name="partner_status_valid"),
        Index("ix_partners_partner_status", "partner_status"),
    )


class PartnerSubmission(UUIDPK, Timestamps, Base):
    """Encrypted original partner request retained alongside normalized records."""

    __tablename__ = "partner_submissions"

    partner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partners.id", ondelete="RESTRICT"), nullable=False)
    submission_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1", server_default="1")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    raw_payload_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    processing_status: Mapped[str] = mapped_column(String(16), nullable=False, default="accepted", server_default="accepted")
    record_counts: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    normalized_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("partner_id", "submission_reference", name="uq_partner_submissions_partner_reference"),
        Index("ix_partner_submissions_received_at", "received_at"),
    )


class PartnerIdentity(UUIDPK, Timestamps, Base):
    """Partner-scoped identity and protected identity references."""

    __tablename__ = "partner_identities"

    partner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partners.id", ondelete="RESTRICT"), nullable=False)
    submission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partner_submissions.id", ondelete="RESTRICT"), nullable=False)
    identity_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    national_id_reference: Mapped[str | None] = mapped_column(String(256))
    phone_number_reference: Mapped[str | None] = mapped_column(String(64))
    verified_ownership: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    verification_status: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        UniqueConstraint("partner_id", "identity_reference", name="uq_partner_identities_partner_reference"),
        CheckConstraint("verification_status IN ('verified', 'pending', 'unverified')", name="verification_status_valid"),
        CheckConstraint("NOT verified_ownership OR verification_status = 'verified'", name="ownership_status_consistent"),
        Index("ix_partner_identities_national_id_reference", "national_id_reference"),
        Index("ix_partner_identities_phone_reference", "phone_number_reference"),
    )


class PartnerAccount(UUIDPK, Timestamps, Base):
    """Partner account record with optional resolved link to a partner identity."""

    __tablename__ = "partner_accounts"

    identity_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("partner_identities.id", ondelete="SET NULL"))
    partner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partners.id", ondelete="RESTRICT"), nullable=False)
    submission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partner_submissions.id", ondelete="RESTRICT"), nullable=False)
    identity_reference: Mapped[str | None] = mapped_column(String(128))
    account_identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    account_type: Mapped[str] = mapped_column(String(64), nullable=False)
    service_provider: Mapped[str] = mapped_column(String(120), nullable=False)
    account_status: Mapped[str] = mapped_column(String(16), nullable=False)
    ownership_reference: Mapped[str | None] = mapped_column(String(128))

    __table_args__ = (
        UniqueConstraint("partner_id", "account_identifier", name="uq_partner_accounts_partner_identifier"),
        CheckConstraint("account_status IN ('active', 'suspended', 'closed')", name="account_status_valid"),
        Index("ix_partner_accounts_identity_id", "identity_id"),
    )


class PartnerTransaction(UUIDPK, Timestamps, Base):
    """Partner transaction; unresolved account references are retained until resolved."""

    __tablename__ = "partner_transactions"

    partner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partners.id", ondelete="RESTRICT"), nullable=False)
    submission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partner_submissions.id", ondelete="RESTRICT"), nullable=False)
    transaction_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    sender_account_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("partner_accounts.id", ondelete="SET NULL"))
    receiver_account_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("partner_accounts.id", ondelete="SET NULL"))
    sender_partner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("partners.id", ondelete="SET NULL"))
    receiver_partner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("partners.id", ondelete="SET NULL"))
    sender_partner_code: Mapped[str] = mapped_column(String(64), nullable=False)
    receiver_partner_code: Mapped[str] = mapped_column(String(64), nullable=False)
    sender_account_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    receiver_account_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(20, 4), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    balance: Mapped[Decimal | None] = mapped_column(Numeric(20, 4))
    transaction_datetime: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    transaction_status: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        UniqueConstraint("partner_id", "transaction_reference", name="uq_partner_transactions_partner_reference"),
        CheckConstraint("amount > 0", name="amount_positive"),
        CheckConstraint("balance IS NULL OR balance >= 0", name="balance_nonnegative"),
        CheckConstraint("transaction_status IN ('successful', 'pending', 'failed')", name="transaction_status_valid"),
        Index("ix_partner_transactions_timestamp", "transaction_datetime"),
        Index("ix_partner_transactions_sender_account_id", "sender_account_id"),
        Index("ix_partner_transactions_receiver_account_id", "receiver_account_id"),
    )


class IdentityResolutionCluster(UUIDPK, Timestamps, Base):
    """A confidence-scored identity grouping derived from protected partner references."""

    __tablename__ = "identity_resolution_clusters"

    match_type: Mapped[str] = mapped_column(String(32), nullable=False)
    match_key: Mapped[str] = mapped_column(String(64), nullable=False)
    resolution_status: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    partner_count: Mapped[int] = mapped_column(nullable=False)
    identity_count: Mapped[int] = mapped_column(nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("match_type", "match_key", name="uq_identity_resolution_cluster_key"),
        CheckConstraint("match_type IN ('national_id', 'phone')", name="identity_match_type_valid"),
        CheckConstraint("resolution_status IN ('resolved', 'candidate')", name="identity_resolution_status_valid"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="identity_cluster_confidence_range"),
        CheckConstraint("partner_count >= 1 AND identity_count >= partner_count", name="identity_cluster_counts_valid"),
        Index("ix_identity_resolution_clusters_status", "resolution_status"),
    )


class IdentityResolutionMember(UUIDPK, CreatedAt, Base):
    """Partner identity membership and evidence for a resolved/candidate identity group."""

    __tablename__ = "identity_resolution_members"

    cluster_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identity_resolution_clusters.id", ondelete="CASCADE"), nullable=False
    )
    partner_identity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("partner_identities.id", ondelete="CASCADE"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    match_evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("cluster_id", "partner_identity_id", name="uq_identity_resolution_member"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="identity_member_confidence_range"),
        Index("ix_identity_resolution_members_identity", "partner_identity_id"),
    )


class EntityIntelligenceProfile(UUIDPK, Timestamps, Base):
    """Derived activity, linkage, FIR evidence, and risk snapshot for a graph entity."""

    __tablename__ = "entity_intelligence_profiles"

    entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("community_entities.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    partner_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    transaction_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    report_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    linked_entity_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    activity_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    ai_features: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    graph_features: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    fusion_version: Mapped[str] = mapped_column(String(64), nullable=False, default="ai-graph-fusion.v1", server_default="ai-graph-fusion.v1")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, server_default="0.0")
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "entity_profile_risk_level"), nullable=False, default=RiskLevel.LOW, server_default=RiskLevel.LOW.value)
    risk_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, server_default="0.0")
    risk_reasons: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint("partner_count >= 0 AND transaction_count >= 0 AND report_count >= 0 AND linked_entity_count >= 0", name="entity_profile_counts_nonnegative"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="entity_profile_risk_score_range"),
        CheckConstraint("risk_confidence >= 0 AND risk_confidence <= 1", name="entity_profile_risk_confidence_range"),
        Index("ix_entity_intelligence_profiles_risk", "risk_level", "risk_score"),
    )


class CrossInstitutionSignal(UUIDPK, Timestamps, Base):
    """Auditable cross-partner signal derived from linked identities and transaction graph."""

    __tablename__ = "cross_institution_signals"

    signal_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active", server_default="active")
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "cross_institution_risk_level"), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    partner_codes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    entity_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    reasons: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint("status IN ('active', 'resolved')", name="cross_institution_signal_status_valid"),
        CheckConstraint("score >= 0 AND score <= 1", name="cross_institution_signal_score_range"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="cross_institution_signal_confidence_range"),
        Index("ix_cross_institution_signals_status_created", "status", "created_at"),
        Index("ix_cross_institution_signals_type_created", "signal_type", "created_at"),
    )


class UserAwarenessPreference(UUIDPK, Timestamps, Base):
    """Explicit opt-ins for context memory and proactive education messages."""

    __tablename__ = "user_awareness_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    conversation_memory_enabled: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    voice_case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("fraud_cases.id", ondelete="SET NULL"), nullable=True,
    )
    proactive_education_enabled: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    channels: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[\"in_app\"]'::jsonb"))
    consent_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    schedule_frequency: Mapped[str] = mapped_column(String(16), nullable=False, default="monthly", server_default="monthly")
    custom_interval_days: Mapped[int | None] = mapped_column()
    delivery_method: Mapped[str] = mapped_column(String(16), nullable=False, default="sms", server_default="sms")
    language: Mapped[str] = mapped_column(String(32), nullable=False, default="english", server_default="english")
    preferred_time: Mapped[str] = mapped_column(String(16), nullable=False, default="morning", server_default="morning")
    checkup_enabled: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    fraud_alerts_enabled: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    test_schedule_enabled: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    next_awareness_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    awareness_context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        CheckConstraint("jsonb_typeof(channels) = 'array'", name="awareness_channels_array"),
        CheckConstraint("schedule_frequency IN ('weekly', 'biweekly', 'monthly', 'custom')", name="schedule_frequency_valid"),
        CheckConstraint("custom_interval_days IS NULL OR custom_interval_days BETWEEN 1 AND 365", name="custom_interval_days_valid"),
        CheckConstraint("(schedule_frequency = 'custom' AND custom_interval_days IS NOT NULL) OR (schedule_frequency <> 'custom' AND custom_interval_days IS NULL)", name="custom_frequency_consistent"),
        CheckConstraint("delivery_method IN ('sms', 'voice_call', 'both')", name="delivery_method_valid"),
        CheckConstraint("preferred_time IN ('morning', 'afternoon', 'evening')", name="preferred_time_valid"),
        Index("ix_user_awareness_preferences_proactive", "proactive_education_enabled"),
    )


class AwarenessCampaign(UUIDPK, Timestamps, Base):
    """Reviewer-authored signal campaigns or general scheduled education."""

    __tablename__ = "awareness_campaigns"

    source_signal_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cross_institution_signals.id", ondelete="RESTRICT"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="education", server_default="education")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="draft", server_default="draft")
    generated_by_scheduler: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    generation_context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    audience_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")

    __table_args__ = (
        CheckConstraint("severity IN ('education', 'high_risk')", name="awareness_campaign_severity_valid"),
        CheckConstraint("status IN ('draft', 'approved', 'sent', 'simulated')", name="awareness_campaign_status_valid"),
        CheckConstraint("audience_count >= 0", name="awareness_campaign_audience_nonnegative"),
        Index("ix_awareness_campaigns_status_created", "status", "created_at"),
    )


class AwarenessDelivery(UUIDPK, CreatedAt, Base):
    """Per-user inbox/SMS delivery with auditable outcome and deduplication."""

    __tablename__ = "awareness_deliveries"

    campaign_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("awareness_campaigns.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", server_default="pending")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(String(256))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("campaign_id", "user_id", "channel", name="uq_awareness_delivery_target_channel"),
        CheckConstraint("channel IN ('in_app', 'sms')", name="awareness_delivery_channel_valid"),
        CheckConstraint("status IN ('pending', 'sent', 'failed')", name="awareness_delivery_status_valid"),
        Index("ix_awareness_deliveries_user_created", "user_id", "created_at"),
        Index("ix_awareness_deliveries_status_created", "status", "created_at"),
    )


class AwarenessScheduledInteraction(UUIDPK, Timestamps, Base):
    """A due subscriber's review-gated SMS and optional USSD check-up interaction."""

    __tablename__ = "awareness_scheduled_interactions"

    preference_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_awareness_preferences.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("awareness_campaigns.id", ondelete="SET NULL"))
    scheduled_for: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivery_channel: Mapped[str] = mapped_column(String(16), nullable=False, default="sms", server_default="sms")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", server_default="pending")
    topic: Mapped[str] = mapped_column(String(160), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    checkup_question: Mapped[str | None] = mapped_column(Text)
    context_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    response: Mapped[str | None] = mapped_column(String(16))
    failure_reason: Mapped[str | None] = mapped_column(String(256))
    attempts: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")

    __table_args__ = (
        UniqueConstraint("preference_id", "scheduled_for", name="uq_awareness_scheduled_interaction_slot"),
        CheckConstraint("delivery_channel IN ('sms', 'voice_call')", name="delivery_channel_valid"),
        CheckConstraint("status IN ('pending', 'sending', 'sent', 'failed', 'responded', 'simulated')", name="status_valid"),
        CheckConstraint("response IS NULL OR response IN ('yes', 'unsure', 'no')", name="response_valid"),
        CheckConstraint("attempts >= 0", name="attempts_nonnegative"),
        Index("ix_awareness_scheduled_interactions_due", "status", "scheduled_for"),
        Index("ix_awareness_scheduled_interactions_user_created", "user_id", "created_at"),
    )


class AwarenessSchedulerRun(UUIDPK, CreatedAt, Base):
    """Heartbeat and outcome counters for the recurring awareness draft worker."""

    __tablename__ = "awareness_scheduler_runs"

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running", server_default="running")
    trigger_source: Mapped[str] = mapped_column(String(16), nullable=False, default="cron", server_default="cron")
    due_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    sent_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    simulated_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    failed_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    deferred_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    detail: Mapped[str | None] = mapped_column(String(256))

    __table_args__ = (
        CheckConstraint("status IN ('running', 'succeeded', 'failed', 'already_running')", name="status_valid"),
        CheckConstraint("trigger_source IN ('cron', 'manual', 'in_process')", name="trigger_source_valid"),
        CheckConstraint("due_count >= 0 AND sent_count >= 0 AND simulated_count >= 0 AND failed_count >= 0 AND deferred_count >= 0", name="counts_nonnegative"),
        Index("ix_awareness_scheduler_runs_created", "created_at"),
    )


class LivenessChallenge(UUIDPK, CreatedAt, Base):
    """Single-use challenge for a trusted external liveness verifier."""

    __tablename__ = "liveness_challenges"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    phone_reference: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_liveness_challenges_user_created", "user_id", "created_at"),)


class LivenessAssessment(UUIDPK, CreatedAt, Base):
    """Provider-attested liveness result; biometric media is never stored here."""

    __tablename__ = "liveness_assessments"

    challenge_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("liveness_challenges.id", ondelete="RESTRICT"), unique=True, nullable=False
    )
    partner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partners.id", ondelete="RESTRICT"), nullable=False)
    partner_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("partner_identities.id", ondelete="SET NULL")
    )
    entity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("community_entities.id", ondelete="SET NULL")
    )
    provider_name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    liveness_status: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(64))
    reason_code: Mapped[str | None] = mapped_column(String(64))
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("partner_id", "provider_reference", name="uq_liveness_partner_provider_reference"),
        CheckConstraint("liveness_status IN ('live', 'spoof', 'inconclusive')", name="liveness_status_valid"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="liveness_confidence_range"),
        Index("ix_liveness_assessments_entity_created", "entity_id", "created_at"),
    )


class PartnerIntelligenceDelivery(UUIDPK, CreatedAt, Base):
    """Durable, partner-scoped outbox entry for real-time intelligence sharing."""

    __tablename__ = "partner_intelligence_deliveries"

    partner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partners.id", ondelete="CASCADE"), nullable=False)
    signal_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cross_institution_signals.id", ondelete="CASCADE"), nullable=False
    )
    delivery_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    last_delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("partner_id", "signal_id", name="uq_partner_intelligence_delivery_signal"),
        CheckConstraint("delivery_status IN ('pending', 'acknowledged')", name="partner_delivery_status_valid"),
        CheckConstraint("attempts >= 0", name="partner_delivery_attempts_nonnegative"),
        Index("ix_partner_intelligence_deliveries_partner_status", "partner_id", "delivery_status", "created_at"),
    )


class PartnerActionReferral(UUIDPK, Timestamps, Base):
    """Auditable investigator referral prepared for a partner's independent review."""

    __tablename__ = "partner_action_referrals"

    partner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("partners.id", ondelete="RESTRICT"), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    sent_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    response_recorded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="draft", server_default="draft")
    requested_action: Mapped[str] = mapped_column(String(40), nullable=False)
    target_label: Mapped[str] = mapped_column(String(256), nullable=False)
    target_reference: Mapped[str] = mapped_column(String(256), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("fraud_cases.id", ondelete="SET NULL"))
    evidence_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    review_note: Mapped[str | None] = mapped_column(Text)
    partner_response: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("status IN ('draft', 'pending_review', 'approved', 'declined', 'sent', 'responded')", name="status_valid"),
        CheckConstraint("requested_action IN ('review_account', 'preserve_records', 'assess_restriction', 'assess_recall_recovery', 'other')", name="action_valid"),
        Index("ix_partner_action_referrals_partner_status", "partner_id", "status", "created_at"),
        Index("ix_partner_action_referrals_created_by", "created_by", "created_at"),
    )


class Device(UUIDPK, Timestamps, Base):
    __tablename__ = "devices"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_type: Mapped[str] = mapped_column(String(32), nullable=False)  # phone / tablet / web
    platform: Mapped[str] = mapped_column(String(32), nullable=False)  # android / ios / web

    user: Mapped[User] = relationship(back_populates="devices")
    fraud_reports: Mapped[list[FraudReport]] = relationship(back_populates="device")


class PhoneNumber(UUIDPK, CreatedAt, Base):
    __tablename__ = "phone_numbers"

    normalized_number: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # E.164
    country_code: Mapped[str] = mapped_column(String(2), nullable=False)  # ISO 3166-1 alpha-2

    fraud_reports: Mapped[list[FraudReport]] = relationship(back_populates="phone_number")
    threat_indicators: Mapped[list[ThreatIndicator]] = relationship(
        back_populates="phone_number", cascade="all, delete-orphan"
    )


class ScamCategory(UUIDPK, Base):
    __tablename__ = "scam_categories"

    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)

    threat_indicators: Mapped[list[ThreatIndicator]] = relationship(back_populates="category")


class FraudReport(UUIDPK, Timestamps, Base):
    __tablename__ = "fraud_reports"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    phone_number_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("phone_numbers.id", ondelete="RESTRICT"), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("fraud_cases.id", ondelete="SET NULL"))
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)  # call / sms / whatsapp ...
    description: Mapped[str | None] = mapped_column(Text)
    evidence_reference: Mapped[str | None] = mapped_column(String(512))  # object-storage key, never the file itself
    status: Mapped[ReportStatus] = mapped_column(
        _enum(ReportStatus, "report_status"), default=ReportStatus.PENDING,
        server_default=ReportStatus.PENDING.value, nullable=False,
    )

    user: Mapped[User] = relationship(back_populates="fraud_reports", foreign_keys=[user_id])
    device: Mapped[Device | None] = relationship(back_populates="fraud_reports")
    phone_number: Mapped[PhoneNumber] = relationship(back_populates="fraud_reports")
    verification: Mapped[VerificationRecord | None] = relationship(
        back_populates="report", uselist=False, cascade="all, delete-orphan"
    )
    case: Mapped[FraudCase | None] = relationship(back_populates="reports")

    __table_args__ = (
        Index("ix_fraud_reports_phone_number_id_status", "phone_number_id", "status"),
        Index("ix_fraud_reports_user_id_created_at", "user_id", "created_at"),
        Index("ix_fraud_reports_status_created_at", "status", "created_at"),
    )


class CommunityReport(UUIDPK, CreatedAt, Base):
    """Original community submission; never replaced by derived intelligence."""

    __tablename__ = "community_reports"

    reporter_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_value: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str | None] = mapped_column(String(64))
    evidence_reference: Mapped[str | None] = mapped_column(String(512))
    status: Mapped[CommunityReportStatus] = mapped_column(
        _enum(CommunityReportStatus, "community_report_status"),
        default=CommunityReportStatus.SUBMITTED,
        server_default=CommunityReportStatus.SUBMITTED.value,
        nullable=False,
    )
    entity_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("community_entities.id", ondelete="SET NULL"))
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("fraud_incidents.id", ondelete="SET NULL"))
    report_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    reporter: Mapped[User] = relationship(foreign_keys=[reporter_id])
    entity: Mapped[CommunityEntity | None] = relationship(back_populates="reports", foreign_keys=[entity_id])
    incident: Mapped[FraudIncident | None] = relationship(back_populates="legacy_reports", foreign_keys=[incident_id])
    evidence: Mapped[list[ReportEvidence]] = relationship(back_populates="report", cascade="all, delete-orphan")
    reviews: Mapped[list[ReportReview]] = relationship(back_populates="report", cascade="all, delete-orphan")
    fir_record: Mapped[FIRReportRecord | None] = relationship(
        back_populates="community_report", uselist=False
    )

    __table_args__ = (
        Index("ix_community_reports_status_created_at", "status", "created_at"),
        Index("ix_community_reports_reporter_id_created_at", "reporter_id", "created_at"),
        Index("ix_community_reports_entity_id", "entity_id"),
    )


class ReportEvidence(UUIDPK, CreatedAt, Base):
    __tablename__ = "report_evidence"

    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("community_reports.id", ondelete="CASCADE"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    storage_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    content_hash: Mapped[str | None] = mapped_column(String(128))
    evidence_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    report: Mapped[CommunityReport] = relationship(back_populates="evidence")


class FIRReportRecord(UUIDPK, Timestamps, Base):
    """Canonical FIR index row for either supported source report pipeline."""

    __tablename__ = "fir_reports"

    community_report_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("community_reports.id", ondelete="CASCADE"), unique=True
    )
    fraud_report_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("fraud_reports.id", ondelete="CASCADE"), unique=True
    )
    reporter_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("fraud_cases.id", ondelete="SET NULL"))
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str | None] = mapped_column(String(64))
    evidence_reference: Mapped[str | None] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(32), nullable=False)

    community_report: Mapped[CommunityReport | None] = relationship(back_populates="fir_record")
    incident_links: Mapped[list[FIRReportIncident]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "(community_report_id IS NOT NULL) <> (fraud_report_id IS NOT NULL) "
            "OR (community_report_id IS NULL AND fraud_report_id IS NULL AND source_type = 'message_analysis')",
            name="source_report_exactly_one",
        ),
        Index("ix_fir_reports_status_created_at", "status", "created_at"),
        Index("ix_fir_reports_reporter_created_at", "reporter_id", "created_at"),
        Index("ix_fir_reports_case_id", "case_id"),
    )


class FIRReportIncident(UUIDPK, CreatedAt, Base):
    """Many-to-many link: one report may describe multiple incidents."""

    __tablename__ = "report_incidents"

    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fir_reports.id", ondelete="CASCADE"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fraud_incidents.id", ondelete="CASCADE"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0, server_default="1.0")
    link_reason: Mapped[str] = mapped_column(String(64), nullable=False, default="report_submission", server_default="report_submission")
    details: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    report: Mapped[FIRReportRecord] = relationship(back_populates="incident_links")
    incident: Mapped[FraudIncident] = relationship(back_populates="report_links")

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="report_incident_confidence_range"),
        UniqueConstraint("report_id", "incident_id", name="uq_report_incidents_pair"),
        Index("ix_report_incidents_incident_id", "incident_id"),
    )


class CommunityEntity(UUIDPK, Timestamps, Base):
    __tablename__ = "community_entities"

    entity_type: Mapped[CommunityEntityType] = mapped_column(_enum(CommunityEntityType, "community_entity_type"), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(512), nullable=False)
    display_value: Mapped[str | None] = mapped_column(String(512))
    country_code: Mapped[str | None] = mapped_column(String(2))
    entity_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    reports: Mapped[list[CommunityReport]] = relationship(back_populates="entity", foreign_keys="CommunityReport.entity_id")
    source_relationships: Mapped[list[EntityRelationship]] = relationship(
        back_populates="source_entity", foreign_keys="EntityRelationship.source_entity_id", cascade="all, delete-orphan"
    )
    target_relationships: Mapped[list[EntityRelationship]] = relationship(
        back_populates="target_entity", foreign_keys="EntityRelationship.target_entity_id", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("entity_type", "normalized_value", name="uq_community_entities_identity"),
        Index("ix_community_entities_type_value", "entity_type", "normalized_value"),
    )


class ReportEntity(UUIDPK, CreatedAt, Base):
    """Extracted entity with provenance attached to the report it came from."""

    __tablename__ = "report_entities"

    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fir_reports.id", ondelete="CASCADE"), nullable=False
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("community_entities.id", ondelete="RESTRICT"), nullable=False
    )
    source_text: Mapped[str | None] = mapped_column(String(512))
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="user_report", server_default="user_report")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0, server_default="1.0")
    verified: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")

    entity: Mapped[CommunityEntity] = relationship()

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="report_entity_confidence_range"),
        UniqueConstraint("report_id", "entity_id", "source_kind", name="uq_report_entities_source"),
        Index("ix_report_entities_entity_id", "entity_id"),
    )


class IncidentEntity(UUIDPK, CreatedAt, Base):
    """Role of a normalized entity in an incident, such as victim or suspect."""

    __tablename__ = "incident_entities"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fraud_incidents.id", ondelete="CASCADE"), nullable=False
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("community_entities.id", ondelete="RESTRICT"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0, server_default="1.0")
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified", server_default="unverified")
    details: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    entity: Mapped[CommunityEntity] = relationship()

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="incident_entity_confidence_range"),
        UniqueConstraint("incident_id", "entity_id", "role", name="uq_incident_entities_role"),
        Index("ix_incident_entities_entity_id", "entity_id"),
    )


class EntityRelationship(UUIDPK, CreatedAt, Base):
    __tablename__ = "entity_relationships"

    source_entity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("community_entities.id", ondelete="CASCADE"), nullable=False)
    target_entity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("community_entities.id", ondelete="CASCADE"), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0, server_default="1.0")
    partner_transaction_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("partner_transactions.id", ondelete="CASCADE"), nullable=True,
    )
    relationship_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    source_entity: Mapped[CommunityEntity] = relationship(back_populates="source_relationships", foreign_keys=[source_entity_id])
    target_entity: Mapped[CommunityEntity] = relationship(back_populates="target_relationships", foreign_keys=[target_entity_id])

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="community_relationship_confidence_range"),
        Index(
            "ix_entity_relationships_partner_transaction_id",
            "partner_transaction_id",
            unique=True,
            postgresql_where=text("partner_transaction_id IS NOT NULL"),
        ),
        Index(
            "uq_entity_relationship_identity_non_ledger",
            "source_entity_id",
            "target_entity_id",
            "relationship_type",
            unique=True,
            postgresql_where=text("partner_transaction_id IS NULL"),
        ),
    )


class FraudIncident(UUIDPK, Timestamps, Base):
    __tablename__ = "fraud_incidents"

    title: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[CommunityIncidentStatus] = mapped_column(
        _enum(CommunityIncidentStatus, "community_incident_status"),
        default=CommunityIncidentStatus.OPEN, server_default=CommunityIncidentStatus.OPEN.value, nullable=False,
    )
    category: Mapped[str | None] = mapped_column(String(64))
    incident_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    location: Mapped[str | None] = mapped_column(String(256))
    outcome: Mapped[FraudOutcome] = mapped_column(
        _enum(FraudOutcome, "fraud_outcome"), default=FraudOutcome.UNRESOLVED,
        server_default=FraudOutcome.UNRESOLVED.value, nullable=False,
    )
    assigned_investigator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, server_default="0.0")
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "community_incident_risk_level"), default=RiskLevel.LOW, server_default=RiskLevel.LOW.value, nullable=False)
    incident_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    legacy_reports: Mapped[list[CommunityReport]] = relationship(
        back_populates="incident", foreign_keys="CommunityReport.incident_id"
    )
    report_links: Mapped[list[FIRReportIncident]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    intelligence_records: Mapped[list[IntelligenceRecord]] = relationship(back_populates="incident", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="community_incident_confidence_range"),
        Index("ix_fraud_incidents_status_updated_at", "status", "updated_at"),
    )


class IntelligenceRecord(UUIDPK, Timestamps, Base):
    __tablename__ = "intelligence_records"

    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("fraud_incidents.id", ondelete="CASCADE"), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("community_entities.id", ondelete="RESTRICT"), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[IntelligenceStatus] = mapped_column(
        _enum(IntelligenceStatus, "intelligence_status"), default=IntelligenceStatus.DRAFT,
        server_default=IntelligenceStatus.DRAFT.value, nullable=False,
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, server_default="0.0")
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "intelligence_risk_level"), default=RiskLevel.LOW, server_default=RiskLevel.LOW.value, nullable=False)
    distinct_reporters: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    signals: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    incident: Mapped[FraudIncident] = relationship(back_populates="intelligence_records")
    entity: Mapped[CommunityEntity] = relationship()

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="intelligence_confidence_range"),
        CheckConstraint("distinct_reporters >= 0", name="intelligence_distinct_reporters_nonnegative"),
        Index("ix_intelligence_records_entity_status", "entity_id", "status"),
    )


class IncidentFinding(UUIDPK, Timestamps, Base):
    """Versioned pattern, behaviour, or other derived finding for an incident."""

    __tablename__ = "incident_findings"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fraud_incidents.id", ondelete="CASCADE"), nullable=False
    )
    report_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("fir_reports.id", ondelete="SET NULL")
    )
    finding_type: Mapped[str] = mapped_column(String(32), nullable=False)
    taxonomy_id: Mapped[str | None] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(64))
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        CheckConstraint("finding_type IN ('pattern', 'behaviour', 'other')", name="finding_type_allowed"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="finding_confidence_range"),
        Index("ix_incident_findings_incident_type", "incident_id", "finding_type"),
    )


class FIRRiskAssessment(UUIDPK, CreatedAt, Base):
    """Immutable point-in-time risk snapshot associated with FIR report/event."""

    __tablename__ = "fir_risk_assessments"

    report_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("fir_reports.id", ondelete="CASCADE")
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("fraud_incidents.id", ondelete="CASCADE")
    )
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "fir_risk_level"), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    reasons: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        CheckConstraint("report_id IS NOT NULL OR incident_id IS NOT NULL", name="risk_assessment_subject_required"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="fir_risk_score_range"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="fir_risk_confidence_range"),
        Index("ix_fir_risk_assessments_report_created", "report_id", "created_at"),
        Index("ix_fir_risk_assessments_incident_created", "incident_id", "created_at"),
    )


class InvestigationActivity(UUIDPK, CreatedAt, Base):
    """Append-only investigator action, finding, or decision in the FIR."""

    __tablename__ = "investigation_activities"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fraud_incidents.id", ondelete="CASCADE"), nullable=False
    )
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (Index("ix_investigation_activities_incident_created", "incident_id", "created_at"),)


class ReportReview(UUIDPK, CreatedAt, Base):
    __tablename__ = "report_reviews"

    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("community_reports.id", ondelete="CASCADE"), nullable=False)
    reviewer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    decision: Mapped[ReviewDecision] = mapped_column(_enum(ReviewDecision, "community_review_decision"), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)

    report: Mapped[CommunityReport] = relationship(back_populates="reviews")
    reviewer: Mapped[User] = relationship(foreign_keys=[reviewer_id])

    __table_args__ = (Index("ix_report_reviews_report_created_at", "report_id", "created_at"),)


class ThreatIndicator(UUIDPK, Timestamps, Base):
    __tablename__ = "threat_indicators"

    phone_number_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("phone_numbers.id", ondelete="CASCADE"), nullable=False
    )
    category_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scam_categories.id", ondelete="SET NULL"))
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)  # report_volume / pattern / blocklist ...
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "indicator_risk_level"), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    phone_number: Mapped[PhoneNumber] = relationship(back_populates="threat_indicators")
    category: Mapped[ScamCategory | None] = relationship(back_populates="threat_indicators")
    risk_assessments: Mapped[list[RiskAssessment]] = relationship(back_populates="threat_indicator")

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        UniqueConstraint("phone_number_id", "indicator_type", "category_id", name="uq_threat_indicators_identity",
                         postgresql_nulls_not_distinct=True),
        # phone_number_id lookups are served by the leading column of the unique constraint above
        Index("ix_threat_indicators_category_id", "category_id"),
    )


class VerificationRecord(UUIDPK, CreatedAt, Base):
    __tablename__ = "verification_records"

    report_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fraud_reports.id", ondelete="CASCADE"), unique=True, nullable=False  # 1:0..1
    )
    decision: Mapped[ReviewDecision] = mapped_column(_enum(ReviewDecision, "review_decision"), nullable=False)
    reviewer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    report: Mapped[FraudReport] = relationship(back_populates="verification")
    reviewer: Mapped[User] = relationship(foreign_keys=[reviewer_id])


class RiskAssessment(UUIDPK, CreatedAt, Base):
    """A point-in-time risk check a user requested for a phone number."""

    __tablename__ = "risk_assessments"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("fraud_cases.id", ondelete="SET NULL"))
    phone_number_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("phone_numbers.id", ondelete="RESTRICT"), nullable=False)
    threat_indicator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("threat_indicators.id", ondelete="SET NULL")
    )
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "assessment_risk_level"), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    signals: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    user: Mapped[User] = relationship(back_populates="risk_assessments")
    phone_number: Mapped[PhoneNumber] = relationship()
    threat_indicator: Mapped[ThreatIndicator | None] = relationship(back_populates="risk_assessments")
    case: Mapped[FraudCase | None] = relationship(back_populates="risk_assessments")

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="risk_score_range"),
        Index("ix_risk_assessments_user_id_created_at", "user_id", "created_at"),
        Index("ix_risk_assessments_phone_number_id", "phone_number_id"),
        Index("ix_risk_assessments_threat_indicator_id", "threat_indicator_id"),
        Index("ix_risk_assessments_case_id_created_at", "case_id", "created_at"),
    )


class ShieldAnalysis(UUIDPK, CreatedAt, Base):
    """Derived SMS analysis; raw message content is intentionally not retained."""

    __tablename__ = "shield_analyses"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("fraud_cases.id", ondelete="SET NULL"))
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "shield_risk_level"), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    ai_label: Mapped[str] = mapped_column(String(64), nullable=False)
    ai_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    indicators: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    rules: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    user: Mapped[User] = relationship(back_populates="shield_analyses")
    case: Mapped[FraudCase | None] = relationship(back_populates="shield_analyses")

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="shield_risk_score_range"),
        CheckConstraint("ai_confidence >= 0 AND ai_confidence <= 1", name="shield_ai_confidence_range"),
        Index("ix_shield_analyses_user_id_created_at", "user_id", "created_at"),
        Index("ix_shield_analyses_case_id_created_at", "case_id", "created_at"),
    )


class CallAnalysis(UUIDPK, CreatedAt, Base):
    """Consent-based call assessment; audio and raw transcripts are never stored."""

    __tablename__ = "call_analyses"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("fraud_cases.id", ondelete="SET NULL"))
    caller_phone: Mapped[str] = mapped_column(String(20), nullable=False)
    transcript_hash: Mapped[str | None] = mapped_column(String(64))
    consented_transcript: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "call_risk_level"), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    signals: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="risk_score_range"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        Index("ix_call_analyses_user_id_created_at", "user_id", "created_at"),
        Index("ix_call_analyses_case_id_created_at", "case_id", "created_at"),
    )


class TransactionAssessment(UUIDPK, CreatedAt, Base):
    """Point-in-time transfer decision with derived questionnaire signals."""

    __tablename__ = "transaction_assessments"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("fraud_cases.id", ondelete="SET NULL"))
    recipient_phone: Mapped[str] = mapped_column(String(20), nullable=False)
    amount: Mapped[float | None] = mapped_column(Float)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "transaction_risk_level"), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    questionnaire_score: Mapped[float] = mapped_column(Float, nullable=False)
    recommendation: Mapped[str] = mapped_column(String(64), nullable=False)
    questionnaire: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    behavior_signals: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    reasons: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))

    user: Mapped[User] = relationship(back_populates="transaction_assessments")
    case: Mapped[FraudCase | None] = relationship(back_populates="transaction_assessments")

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="transaction_risk_score_range"),
        CheckConstraint("questionnaire_score >= 0 AND questionnaire_score <= 1", name="questionnaire_score_range"),
        Index("ix_transaction_assessments_user_id_created_at", "user_id", "created_at"),
        Index("ix_transaction_assessments_recipient_phone", "recipient_phone"),
        Index("ix_transaction_assessments_case_id_created_at", "case_id", "created_at"),
    )
