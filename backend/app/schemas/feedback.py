import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.enums import FeedbackOutcome


class FeedbackCreate(BaseModel):
    outcome: FeedbackOutcome
    intervention_action: str | None = Field(default=None, max_length=64)
    followed_recommendation: bool | None = None
    fraud_confirmed: bool | None = None
    amount: float | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3, pattern=r"^[A-Za-z]{3}$")
    loss_amount: float | None = Field(default=None, ge=0)
    rating: int | None = Field(default=None, ge=1, le=5)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("notes")
    @classmethod
    def _clean_notes(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class FeedbackOut(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    outcome: FeedbackOutcome
    intervention_action: str | None
    followed_recommendation: bool | None
    fraud_confirmed: bool | None
    amount: float | None
    currency: str | None
    loss_amount: float | None
    rating: int | None
    notes: str | None
    created_at: datetime
