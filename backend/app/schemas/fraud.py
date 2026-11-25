import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.enums import (
    CommunityEntityType,
    CommunityIncidentStatus,
    CommunityReportStatus,
    CommunicationChannel,
    IntelligenceStatus,
    ReportStatus,
    ReportType,
    ReviewDecision,
    RiskLevel,
    ThreatIndicatorType,
)
from app.schemas.intervention import InterventionPlan


def _blank_to_none(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    return v or None


# ---------------------------------------------------------------- reports
class ReportCreate(BaseModel):
    number: str = Field(min_length=7, max_length=20, description="The number being reported")
    report_type: ReportType
    description: str | None = Field(default=None, max_length=2000)
    # object-storage key of an uploaded screenshot/recording, never a URL
    evidence_reference: str | None = Field(default=None, max_length=512, pattern=r"^[A-Za-z0-9._/\-]+$")
    device_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None
    channel: CommunicationChannel = CommunicationChannel.APP

    _clean_description = field_validator("description")(_blank_to_none)

    @field_validator("evidence_reference")
    @classmethod
    def _safe_key(cls, v: str | None) -> str | None:
        if v is not None and (v.startswith("/") or ".." in v.split("/")):
            raise ValueError("evidence_reference must be a relative storage key")
        return v


class ReportOut(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID | None = None
    phone: str
    report_type: ReportType
    description: str | None
    evidence_reference: str | None
    status: ReportStatus
    created_at: datetime
    decision: ReviewDecision | None = None
    reviewed_at: datetime | None = None


class ReviewRequest(BaseModel):
    decision: ReviewDecision
    # only with `approved`: records the scam type on the number's threat indicators
    category_id: uuid.UUID | None = None


# ---------------------------------------------------------------- community intelligence
class CommunityReportCreate(BaseModel):
    subject: str = Field(min_length=7, max_length=512, description="Phone number or other reported indicator")
    report_type: ReportType
    channel: CommunicationChannel = CommunicationChannel.APP
    description: str = Field(min_length=10, max_length=4000)
    category: str | None = Field(default=None, max_length=64)
    evidence_reference: str | None = Field(default=None, max_length=512, pattern=r"^[A-Za-z0-9._/\-]+$")
    case_id: uuid.UUID | None = None

    _clean_description = field_validator("description")(_blank_to_none)
    _clean_category = field_validator("category")(_blank_to_none)

    @field_validator("evidence_reference")
    @classmethod
    def _safe_evidence_key(cls, v: str | None) -> str | None:
        if v is not None and (v.startswith("/") or ".." in v.split("/")):
            raise ValueError("evidence_reference must be a relative storage key")
        return v


class CommunityReportOut(BaseModel):
    id: uuid.UUID
    subject: str
    report_type: ReportType
    channel: CommunicationChannel
    description: str
    category: str | None
    status: CommunityReportStatus
    entity_id: uuid.UUID | None
    incident_id: uuid.UUID | None
    created_at: datetime


class CommunityReviewRequest(BaseModel):
    decision: ReviewDecision
    notes: str | None = Field(default=None, max_length=2000)


class IntelligenceOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    entity_id: uuid.UUID
    entity_type: CommunityEntityType
    entity_value: str
    summary: str
    status: IntelligenceStatus
    confidence: float
    risk_level: RiskLevel
    distinct_reporters: int
    signals: dict
    published_at: datetime | None


class IncidentOut(BaseModel):
    id: uuid.UUID
    title: str
    category: str | None
    status: CommunityIncidentStatus
    confidence: float
    risk_level: RiskLevel
    report_count: int
    distinct_reporters: int
    intelligence: list[IntelligenceOut]
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------- lookup
class MessageIndicatorsIn(BaseModel):
    """Normalized output from the message/call analysis layer."""

    suspicious_keyword_score: float = Field(default=0.0, ge=0, le=1)
    malicious_link_score: float = Field(default=0.0, ge=0, le=1)
    impersonation_score: float = Field(default=0.0, ge=0, le=1)
    urgency_score: float = Field(default=0.0, ge=0, le=1)
    indicator_count: int = Field(default=0, ge=0, le=100)


class TransactionContextIn(BaseModel):
    """Normalized output from transaction-behavior analysis."""

    new_recipient: bool = False
    amount_anomaly_score: float = Field(default=0.0, ge=0, le=1)
    velocity_anomaly_score: float = Field(default=0.0, ge=0, le=1)
    recipient_mismatch_score: float = Field(default=0.0, ge=0, le=1)
    high_value: bool = False


class LookupRequest(BaseModel):
    number: str = Field(min_length=7, max_length=20)
    case_id: uuid.UUID | None = None
    channel: CommunicationChannel = CommunicationChannel.APP
    message_indicators: MessageIndicatorsIn | None = None
    transaction_context: TransactionContextIn | None = None


class LookupOut(BaseModel):
    case_id: uuid.UUID | None = None
    phone: str
    known: bool
    risk_level: RiskLevel
    risk_score: float
    # distinct reporters, never who they are
    verified_reports: int
    pending_reports: int
    categories: list[str]
    last_reported_at: datetime | None
    override: Literal["blocklist", "allowlist"] | None
    advice: str
    short_message: str  # <= 160 chars, for USSD / SMS screens
    assessment_components: dict[str, float] = Field(default_factory=dict)
    risk_reasons: list[str] = Field(default_factory=list)
    risk_confidence: float = 0.0
    risk_evidence: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    recommended_action: str = "proceed_with_caution"
    network_score: float = 0.0
    related_patterns: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    intervention: InterventionPlan | None = None
    graph_exposure_sentence: str | None = None
    graph_exposure_pct: float | None = None


# ---------------------------------------------------------------- threats
class ThreatOut(BaseModel):
    id: uuid.UUID
    phone: str
    indicator_type: ThreatIndicatorType
    risk_level: RiskLevel
    confidence: float
    category_id: uuid.UUID | None
    last_seen: datetime
    created_at: datetime
    updated_at: datetime


class ThreatCreate(BaseModel):
    number: str = Field(min_length=7, max_length=20)
    indicator_type: Literal[ThreatIndicatorType.BLOCKLIST, ThreatIndicatorType.ALLOWLIST]
    risk_level: RiskLevel = RiskLevel.HIGH  # blocklist: high or critical. Ignored for allowlist (always low).
    confidence: float = Field(default=1.0, ge=0, le=1)
    category_id: uuid.UUID | None = None


class ThreatUpdate(BaseModel):
    risk_level: RiskLevel | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)


# ---------------------------------------------------------------- categories
class CategoryCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64)

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = " ".join(v.split())
        if len(v) < 2:
            raise ValueError("name is too short")
        return v


class CategoryOut(BaseModel):
    id: uuid.UUID
    name: str


# ---------------------------------------------------------------- gateway (USSD / SMS)
class GatewayLookup(BaseModel):
    msisdn: str = Field(min_length=7, max_length=20, description="Caller's number, supplied by the operator")
    number: str = Field(min_length=7, max_length=20)
    case_id: uuid.UUID | None = None


class GatewayReport(BaseModel):
    msisdn: str = Field(min_length=7, max_length=20)
    number: str | None = Field(default=None, min_length=7, max_length=20)
    report_type: ReportType = ReportType.OTHER
    description: str | None = Field(default=None, max_length=500)
    case_id: uuid.UUID | None = None

    _clean_description = field_validator("description")(_blank_to_none)

    @field_validator("number")
    @classmethod
    def _clean_number(cls, value: str | None) -> str | None:
        return _blank_to_none(value)

    @model_validator(mode="after")
    def _requires_report_content(self):
        if self.number is None and self.description is None:
            raise ValueError("Provide a scam report message or the phone number being reported.")
        return self


class GatewayReportOut(BaseModel):
    report_id: uuid.UUID
    case_id: uuid.UUID | None = None
    message: str


class GatewayReportHistoryOut(BaseModel):
    title: str
    status: str
    created_at: datetime
