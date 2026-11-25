"""SQLAlchemy 2.0 models for the phone-fraud reporting / risk platform (PostgreSQL)."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    MetaData,
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


# ---------------------------------------------------------------- enums
class AccountStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class ReportStatus(str, enum.Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    VERIFIED = "verified"
    REJECTED = "rejected"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewDecision(str, enum.Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_INFO = "needs_info"


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
class User(UUIDPK, Timestamps, Base):
    __tablename__ = "users"

    phone: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # E.164
    account_status: Mapped[AccountStatus] = mapped_column(
        _enum(AccountStatus, "account_status"), default=AccountStatus.ACTIVE,
        server_default=AccountStatus.ACTIVE.value, nullable=False,
    )

    devices: Mapped[list[Device]] = relationship(back_populates="user", cascade="all, delete-orphan")
    fraud_reports: Mapped[list[FraudReport]] = relationship(
        back_populates="user", foreign_keys="FraudReport.user_id"
    )
    risk_assessments: Mapped[list[RiskAssessment]] = relationship(back_populates="user")


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
    device_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    phone_number_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("phone_numbers.id", ondelete="RESTRICT"), nullable=False)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)  # call / sms / whatsapp ...
    description: Mapped[Optional[str]] = mapped_column(Text)
    evidence_reference: Mapped[Optional[str]] = mapped_column(String(512))  # object-storage key, never the file itself
    status: Mapped[ReportStatus] = mapped_column(
        _enum(ReportStatus, "report_status"), default=ReportStatus.PENDING,
        server_default=ReportStatus.PENDING.value, nullable=False,
    )

    user: Mapped[User] = relationship(back_populates="fraud_reports", foreign_keys=[user_id])
    device: Mapped[Optional[Device]] = relationship(back_populates="fraud_reports")
    phone_number: Mapped[PhoneNumber] = relationship(back_populates="fraud_reports")
    verification: Mapped[Optional[VerificationRecord]] = relationship(
        back_populates="report", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_fraud_reports_phone_number_id_status", "phone_number_id", "status"),
        Index("ix_fraud_reports_user_id_created_at", "user_id", "created_at"),
        Index("ix_fraud_reports_status_created_at", "status", "created_at"),
    )


class ThreatIndicator(UUIDPK, Timestamps, Base):
    __tablename__ = "threat_indicators"

    phone_number_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("phone_numbers.id", ondelete="CASCADE"), nullable=False
    )
    category_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scam_categories.id", ondelete="SET NULL"))
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)  # report_volume / pattern / blocklist ...
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "indicator_risk_level"), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    phone_number: Mapped[PhoneNumber] = relationship(back_populates="threat_indicators")
    category: Mapped[Optional[ScamCategory]] = relationship(back_populates="threat_indicators")
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
    phone_number_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("phone_numbers.id", ondelete="RESTRICT"), nullable=False)
    threat_indicator_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("threat_indicators.id", ondelete="SET NULL")
    )
    risk_level: Mapped[RiskLevel] = mapped_column(_enum(RiskLevel, "assessment_risk_level"), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    signals: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    user: Mapped[User] = relationship(back_populates="risk_assessments")
    phone_number: Mapped[PhoneNumber] = relationship()
    threat_indicator: Mapped[Optional[ThreatIndicator]] = relationship(back_populates="risk_assessments")

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="risk_score_range"),
        Index("ix_risk_assessments_user_id_created_at", "user_id", "created_at"),
        Index("ix_risk_assessments_phone_number_id", "phone_number_id"),
        Index("ix_risk_assessments_threat_indicator_id", "threat_indicator_id"),
    )
