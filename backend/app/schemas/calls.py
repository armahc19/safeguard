import uuid

from pydantic import BaseModel, Field, model_validator

from app.enums import CommunicationChannel, RiskLevel
from app.schemas.identity import IdentityAnalyzeOut
from app.schemas.intervention import InterventionPlan
from app.schemas.patterns import PatternMatchOut


class CallAnalyzeRequest(BaseModel):
    caller_number: str = Field(min_length=7, max_length=20)
    case_id: uuid.UUID | None = None
    user_activated_protection: bool = False
    consented_transcript: bool = False
    transcript: str | None = Field(default=None, max_length=10000)
    claimed_identity: str | None = Field(default=None, max_length=160)
    call_duration_seconds: int | None = Field(default=None, ge=0, le=86400)
    channel: CommunicationChannel = CommunicationChannel.CALL

    @model_validator(mode="after")
    def _require_activation_and_consent(self) -> "CallAnalyzeRequest":
        if not self.user_activated_protection:
            raise ValueError("call protection must be activated by the user")
        if self.transcript and not self.consented_transcript:
            raise ValueError("transcript analysis requires explicit consent")
        return self


class CallAnalyzeOut(BaseModel):
    analysis_id: uuid.UUID
    case_id: uuid.UUID | None
    caller_phone: str
    risk_level: RiskLevel
    risk_score: float
    confidence: float
    transcript_recorded: bool = False
    transcript_hash: str | None = None
    indicators: dict[str, float | int] = Field(default_factory=dict)
    patterns: list[PatternMatchOut] = Field(default_factory=list)
    identity: IdentityAnalyzeOut | None = None
    intervention: InterventionPlan
    explanation: str
    privacy_notice: str
