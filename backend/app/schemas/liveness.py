"""Schemas for one-time liveness challenges and trusted-provider results."""
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.schemas.partners import PartnerReference


class LivenessChallengeOut(BaseModel):
    challenge_id: UUID
    challenge_nonce: str
    expires_at: datetime


class LivenessAssessmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    challenge_id: UUID
    challenge_nonce: Annotated[str, StringConstraints(min_length=24, max_length=128)]
    identity_reference: PartnerReference
    provider_name: Annotated[str, StringConstraints(min_length=2, max_length=120)]
    provider_reference: PartnerReference
    liveness_status: Literal["live", "spoof", "inconclusive"]
    confidence: float = Field(ge=0, le=1)
    model_version: Annotated[str, StringConstraints(min_length=1, max_length=64)] | None = None
    reason_code: Annotated[str, StringConstraints(min_length=1, max_length=64)] | None = None
    assessed_at: datetime

    @field_validator("assessed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Assessment time must include a timezone.")
        return value


class LivenessAssessmentOut(BaseModel):
    assessment_id: UUID
    liveness_status: str
    confidence: float
    assessed_at: datetime


class PartnerAlertOut(BaseModel):
    delivery_id: UUID
    payload: dict
    created_at: datetime


class PartnerAlertListOut(BaseModel):
    items: list[PartnerAlertOut]
    limit: int
