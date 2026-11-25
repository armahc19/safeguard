"""Consent, inbox and reviewer-controlled awareness campaign contracts."""
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


class AwarenessPreferencesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conversation_memory_enabled: bool = False
    proactive_education_enabled: bool = False
    channels: list[Literal["in_app", "sms"]] = Field(default_factory=lambda: ["in_app"], max_length=2)


class AwarenessPreferencesOut(AwarenessPreferencesIn):
    consent_updated_at: datetime | None = None
    schedule_frequency: Literal["weekly", "biweekly", "monthly", "custom"] = "monthly"
    custom_interval_days: int | None = None
    delivery_method: Literal["sms", "voice_call", "both"] = "sms"
    language: str = "english"
    preferred_time: Literal["morning", "afternoon", "evening"] = "morning"
    checkup_enabled: bool = False
    fraud_alerts_enabled: bool = False
    next_awareness_at: datetime | None = None
    test_schedule_enabled: bool = False
    test_schedule_available: bool = False


class GatewayAwarenessSubscriptionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    msisdn: str = Field(min_length=7, max_length=20)
    subscription_active: bool
    schedule_frequency: Literal["weekly", "biweekly", "monthly", "custom"]
    custom_interval_days: int | None = Field(default=None, ge=1, le=365)
    delivery_method: Literal["sms", "voice_call", "both"]
    language: str = Field(min_length=2, max_length=32, pattern=r"^[A-Za-z][A-Za-z -]*$")
    preferred_time: Literal["morning", "afternoon", "evening"]
    checkup_enabled: bool
    fraud_alerts_enabled: bool
    test_schedule_enabled: bool = False

    @model_validator(mode="after")
    def validate_interval(self):
        if self.schedule_frequency == "custom" and self.custom_interval_days is None:
            raise ValueError("Custom frequency requires an interval between 1 and 365 days.")
        if self.schedule_frequency != "custom" and self.custom_interval_days is not None:
            raise ValueError("Custom interval is only used with custom frequency.")
        return self


class GatewayAwarenessCheckupResponseIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    msisdn: str = Field(min_length=7, max_length=20)
    interaction_id: UUID
    answer: Literal["yes", "unsure", "no"]


class GatewayVoiceMemoryIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    msisdn: str = Field(min_length=7, max_length=20)
    enabled: bool


class GatewayVoiceHistoryTurn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    role: Literal["user", "assistant"]
    text: str = Field(min_length=1, max_length=1000)


class GatewayVoiceTurnIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    msisdn: str = Field(min_length=7, max_length=20)
    message: str = Field(min_length=1, max_length=3000)
    history: list[GatewayVoiceHistoryTurn] = Field(default_factory=list, max_length=10)


class AwarenessDeliveryOut(BaseModel):
    id: UUID
    campaign_title: str
    message: str
    severity: str
    channel: str
    sent_at: datetime | None
    read_at: datetime | None


class AwarenessInboxOut(BaseModel):
    items: list[AwarenessDeliveryOut]


class AwarenessCampaignCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    source_signal_id: UUID
    title: Annotated[str, StringConstraints(min_length=4, max_length=160)]
    message: Annotated[str, StringConstraints(min_length=20, max_length=1000)]
    severity: Literal["education", "high_risk"] = "education"


class AwarenessCampaignOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_signal_id: UUID | None = None
    title: str
    message: str
    severity: str
    status: str
    generated_by_scheduler: bool = False
    generation_context: dict = Field(default_factory=dict)
    audience_count: int
    created_at: datetime
    approved_at: datetime | None = None
    sent_at: datetime | None = None


class AwarenessCampaignSuggestOut(BaseModel):
    title: str
    message: str
    suggested_severity: Literal["education", "high_risk"]
    signal_type: str
    risk_level: str
    score: float
    partner_codes: list[str]
    partner_summary: str


class AwarenessAudiencePreviewOut(BaseModel):
    signal_id: UUID
    signal_linked_users: int
    opted_in_users: int
    eligible_users: int
    suppressed_by_frequency_limit: int
    suppressed_by_unsupported_preference: int = 0
    estimated_deliveries: int
    channels: dict[str, int]
    used_report_fallback: bool


class AwarenessAdminDeliveryOut(BaseModel):
    id: UUID
    campaign_title: str
    severity: str
    channel: str
    status: str
    delivered_at: datetime | None
    read_at: datetime | None
    created_at: datetime


class AwarenessOutreachStatsOut(BaseModel):
    interventions_delivered_30d: int
    awareness_read_30d: int
    sms_sent_30d: int
    read_rate: float


class AwarenessCampaignSendOut(BaseModel):
    campaign_id: UUID
    status: str
    eligible_users: int
    deliveries_created: int
    sms_sent: int
    simulated_count: int = 0
    sms_failed: int
    suppressed_by_frequency_limit: int
    suppressed_by_unsupported_preference: int = 0
