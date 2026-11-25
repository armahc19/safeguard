import uuid

from pydantic import BaseModel, Field

from app.enums import CommunicationChannel, RiskLevel
from app.schemas.identity import IdentityAnalyzeOut
from app.schemas.intervention import InterventionPlan
from app.schemas.patterns import PatternMatchOut


class ShieldAnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    case_id: uuid.UUID | None = None
    channel: CommunicationChannel = CommunicationChannel.APP
    phone_number: str | None = Field(default=None, min_length=7, max_length=20)


class ShieldRuleOut(BaseModel):
    code: str
    label: str
    score: float
    explanation: str
    evidence: list[str]


class ShieldAIOut(BaseModel):
    label: str
    confidence: float
    explanation: str


class ShieldAnalyzeOut(BaseModel):
    assessment_id: uuid.UUID
    case_id: uuid.UUID | None = None
    normalized_text: str
    risk_level: RiskLevel
    risk_score: float
    indicators: dict[str, float | int]
    rules: list[ShieldRuleOut]
    ai: ShieldAIOut
    explanation: str
    risk_confidence: float = 0.0
    risk_evidence: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    recommended_action: str = "proceed_with_caution"
    patterns: list[PatternMatchOut] = Field(default_factory=list)
    pattern_model_version: str = ""
    campaign_fingerprint: str = ""
    identity: IdentityAnalyzeOut | None = None
    intervention: InterventionPlan | None = None


class GatewayShieldRequest(BaseModel):
    msisdn: str = Field(min_length=7, max_length=20)
    text: str = Field(min_length=1, max_length=5000)
    case_id: uuid.UUID | None = None


class GatewayShieldOut(BaseModel):
    analysis_id: uuid.UUID
    case_id: uuid.UUID | None = None
    risk_level: RiskLevel
    risk_score: float
    classification: str
    short_message: str = Field(max_length=160)
    explanation: str
    risk_confidence: float = 0.0
    recommended_action: str = "proceed_with_caution"
    identity: IdentityAnalyzeOut | None = None
    intervention: InterventionPlan | None = None
