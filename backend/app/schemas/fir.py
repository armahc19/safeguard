"""Fraud Intelligence Repository API contracts."""
import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.enums import (
    CommunityEntityType,
    CommunityIncidentStatus,
    FraudOutcome,
    RiskLevel,
)


class FIRReportItem(BaseModel):
    id: uuid.UUID
    reporter_reference: uuid.UUID
    report_type: str
    source: str
    channel: str
    subject: str
    description: str
    category: str | None
    evidence_reference: str | None
    status: str
    incident_ids: list[uuid.UUID]
    created_at: datetime


class FIRReportPage(BaseModel):
    items: list[FIRReportItem]
    total: int
    limit: int
    offset: int


class FIRIncidentCreate(BaseModel):
    report_id: uuid.UUID
    title: str = Field(min_length=3, max_length=160)
    description: str | None = None
    category: str | None = Field(default=None, max_length=64)
    incident_at: datetime | None = None
    location: str | None = Field(default=None, max_length=256)
    link_confidence: float = Field(default=1.0, ge=0, le=1)
    link_reason: str = Field(default="investigator_review", max_length=64)


class FIRIncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=160)
    description: str | None = None
    category: str | None = Field(default=None, max_length=64)
    incident_at: datetime | None = None
    location: str | None = Field(default=None, max_length=256)
    status: CommunityIncidentStatus | None = None
    outcome: FraudOutcome | None = None
    assigned_investigator_id: uuid.UUID | None = None


class FIRIncidentLinkCreate(BaseModel):
    confidence: float = Field(default=1.0, ge=0, le=1)
    reason: str = Field(default="investigator_review", max_length=64)


class FIREntityCreate(BaseModel):
    entity_type: CommunityEntityType
    value: str = Field(min_length=1, max_length=512)
    role: str = Field(pattern="^(victim|suspect|related)$")
    confidence: float = Field(default=1.0, ge=0, le=1)
    verification_status: str = Field(default="unverified", max_length=32)
    details: dict = Field(default_factory=dict)


class FIRExtractedEntityCreate(BaseModel):
    entity_type: CommunityEntityType
    value: str = Field(min_length=1, max_length=512)
    source_text: str | None = Field(default=None, max_length=512)
    source_kind: str = Field(default="automated_extraction", max_length=32)
    confidence: float = Field(default=1.0, ge=0, le=1)
    verified: bool = False


class FIRCaseAssignment(BaseModel):
    investigator_id: uuid.UUID


class FIRRelationshipCreate(BaseModel):
    source_entity_id: uuid.UUID
    target_entity_id: uuid.UUID
    relationship_type: str = Field(min_length=2, max_length=64)
    confidence: float = Field(default=1.0, ge=0, le=1)
    metadata: dict = Field(default_factory=dict)


class FIRFindingCreate(BaseModel):
    finding_type: str = Field(pattern="^(pattern|behaviour|other)$")
    taxonomy_id: str | None = Field(default=None, max_length=128)
    title: str = Field(min_length=1, max_length=160)
    description: str | None = None
    confidence: float = Field(ge=0, le=1)
    source: str = Field(default="reviewer", max_length=64)
    model_version: str | None = Field(default=None, max_length=64)
    report_id: uuid.UUID | None = None
    evidence: dict = Field(default_factory=dict)


class FIRRiskAssessmentCreate(BaseModel):
    report_id: uuid.UUID | None = None
    risk_level: RiskLevel
    risk_score: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    reasons: list[str] = Field(default_factory=list, max_length=50)
    source: str = Field(max_length=64)
    model_version: str | None = Field(default=None, max_length=64)


class FIRActivityCreate(BaseModel):
    action_type: str = Field(min_length=2, max_length=64)
    summary: str = Field(min_length=1, max_length=4000)
    details: dict = Field(default_factory=dict)


class FIRAbridgedEntity(BaseModel):
    id: uuid.UUID
    entity_type: CommunityEntityType
    value: str
    role: str | None = None
    confidence: float
    verification_status: str | None = None
    source_text: str | None = None
    source_kind: str | None = None
    verified: bool | None = None
    details: dict = Field(default_factory=dict)


class FIREvidenceItem(BaseModel):
    id: uuid.UUID
    evidence_type: str
    storage_reference: str
    content_hash: str | None
    metadata: dict = Field(default_factory=dict)
    created_at: datetime


class FIRFindingItem(BaseModel):
    id: uuid.UUID
    finding_type: str
    taxonomy_id: str | None
    title: str
    description: str | None
    confidence: float
    source: str
    model_version: str | None
    evidence: dict
    created_at: datetime


class FIRRiskItem(BaseModel):
    id: uuid.UUID
    report_id: uuid.UUID | None
    incident_id: uuid.UUID | None
    risk_level: RiskLevel
    risk_score: float
    confidence: float
    reasons: list[str]
    source: str
    model_version: str | None
    created_at: datetime


class FIRReviewItem(BaseModel):
    id: uuid.UUID
    reviewer_reference: uuid.UUID
    decision: str
    notes: str | None
    created_at: datetime


class FIRActivityItem(BaseModel):
    id: uuid.UUID
    actor_reference: uuid.UUID
    action_type: str
    summary: str
    details: dict
    created_at: datetime


class FIRReportDetail(FIRReportItem):
    case_id: uuid.UUID | None = None
    case: dict | None = None
    evidence: list[FIREvidenceItem]
    extracted_entities: list[FIRAbridgedEntity]
    incidents: list[dict]
    reviews: list[FIRReviewItem]
    risk_assessments: list[FIRRiskItem]
    findings: list[FIRFindingItem]


class FIRIncidentItem(BaseModel):
    id: uuid.UUID
    title: str
    description: str | None
    category: str | None
    incident_at: datetime | None
    location: str | None
    status: CommunityIncidentStatus
    outcome: FraudOutcome
    risk_level: RiskLevel
    confidence: float
    assigned_investigator_id: uuid.UUID | None
    report_ids: list[uuid.UUID]
    case_ids: list[uuid.UUID]
    created_at: datetime
    updated_at: datetime


class FIRIncidentDetail(FIRIncidentItem):
    entities: list[FIRAbridgedEntity]
    relationships: list[dict]
    findings: list[FIRFindingItem]
    risk_assessments: list[FIRRiskItem]
    intelligence: list[dict]
    investigation_activity: list[FIRActivityItem]
