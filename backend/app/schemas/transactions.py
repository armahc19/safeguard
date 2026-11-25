import uuid
from typing import Literal

from pydantic import BaseModel, Field

from app.enums import CommunicationChannel, RiskLevel
from app.schemas.intervention import InterventionPlan


class SocialEngineeringAnswers(BaseModel):
    """Answers collected immediately before a user confirms a transfer."""

    recipient_claims_to_be_institution: bool = False
    asked_for_pin_or_otp: bool = False
    pressured_to_act: bool = False
    asked_to_keep_transaction_secret: bool = False
    unexpected_prize_refund_or_investment: bool = False
    asked_to_install_app_or_give_remote_access: bool = False
    user_knows_recipient_personally: bool = True


class TransactionAssessRequest(BaseModel):
    recipient_number: str = Field(min_length=7, max_length=20)
    case_id: uuid.UUID | None = None
    channel: CommunicationChannel = CommunicationChannel.APP
    amount: float | None = Field(default=None, gt=0)
    currency: str = Field(default="GHS", min_length=3, max_length=3, pattern=r"^[A-Za-z]{3}$")
    new_recipient: bool = False
    amount_anomaly_score: float = Field(default=0.0, ge=0, le=1)
    velocity_anomaly_score: float = Field(default=0.0, ge=0, le=1)
    recipient_mismatch_score: float = Field(default=0.0, ge=0, le=1)
    high_value: bool = False
    questionnaire: SocialEngineeringAnswers = Field(default_factory=SocialEngineeringAnswers)


class TransactionRecommendation(BaseModel):
    action: Literal["proceed_with_caution", "verify_recipient", "stop_and_contact_bank"]
    title: str
    message: str


class TransactionAssessOut(BaseModel):
    assessment_id: uuid.UUID
    case_id: uuid.UUID | None = None
    recipient_phone: str
    recipient_known: bool
    phone_risk_level: RiskLevel
    risk_level: RiskLevel
    risk_score: float
    questionnaire_score: float
    recommendation: TransactionRecommendation
    reasons: list[str]
    recipient_report_summary: dict[str, int | list[str]]
    risk_confidence: float = 0.0
    risk_evidence: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    recommended_action: str = "proceed_with_caution"
    behavior_signals: dict[str, object] = Field(default_factory=dict)
    intervention: InterventionPlan | None = None


class GatewayTransactionAssessRequest(TransactionAssessRequest):
    msisdn: str = Field(min_length=7, max_length=20)


class GatewayTransactionAssessOut(BaseModel):
    assessment_id: uuid.UUID
    case_id: uuid.UUID | None = None
    risk_level: RiskLevel
    risk_score: float
    action: str
    short_message: str = Field(max_length=160)
    reasons: list[str]
    behavior_signals: dict[str, object] = Field(default_factory=dict)
    intervention: InterventionPlan | None = None
