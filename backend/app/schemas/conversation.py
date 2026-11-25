import uuid
from typing import Any

from pydantic import BaseModel, Field

from app.enums import CommunicationChannel, ConversationStage, RiskLevel
from app.schemas.communication import CommunicationContext
from app.schemas.intervention import InterventionPlan


class ConversationTurnRequest(BaseModel):
    message: str = Field(min_length=1, max_length=5000)
    case_id: uuid.UUID | None = None
    channel: CommunicationChannel = CommunicationChannel.APP
    phone_number: str | None = Field(default=None, min_length=7, max_length=20)


class ConversationNotes(BaseModel):
    channel: str = ""
    claimed_identity: str = ""
    story: str = ""
    requests_made: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    user_actions_taken: list[str] = Field(default_factory=list)
    stage: ConversationStage = ConversationStage.UNCLEAR
    risk: RiskLevel = RiskLevel.LOW
    confidence: str = "low"


class SharedCaseContext(BaseModel):
    case_id: uuid.UUID
    turn_count: int = 0
    channels_seen: list[str] = Field(default_factory=list)
    known_facts: list[str] = Field(default_factory=list)
    requested_actions: list[str] = Field(default_factory=list)
    user_actions_taken: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    notes: ConversationNotes = Field(default_factory=ConversationNotes)


class SimilarCase(BaseModel):
    case_id: str
    summary: str
    retrieval_score: float
    verification_status: str = ""
    fraud_pattern_ids: list[str] = Field(default_factory=list)
    behaviour_tactic_ids: list[str] = Field(default_factory=list)


class ConversationIntelligence(BaseModel):
    context_summary: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, list[str]] = Field(default_factory=dict)
    similar_cases: list[SimilarCase] = Field(default_factory=list)
    detected_patterns: list[dict[str, Any]] = Field(default_factory=list)
    behaviour_indicators: list[dict[str, Any]] = Field(default_factory=list)
    risk_level: RiskLevel
    risk_score: float
    confidence: float
    risk_evidence: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    recommended_action: str


class ConversationTurnOut(BaseModel):
    case_id: uuid.UUID
    context: SharedCaseContext
    communication: CommunicationContext
    notes: ConversationNotes
    intelligence: ConversationIntelligence
    intervention: InterventionPlan
    privacy_notice: str
    fir_report_id: uuid.UUID | None = None
    extracted_identifiers: list[dict[str, Any]] = Field(default_factory=list)
