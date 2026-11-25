from typing import Literal

from pydantic import BaseModel, Field

from app.enums import CommunicationChannel, RiskLevel


class InterventionPlan(BaseModel):
    action: Literal[
        "inform", "ask_for_more_information", "verify_independently",
        "warn_and_pause", "stop_and_escalate", "report_and_escalate",
    ]
    risk_level: RiskLevel
    title: str
    message: str
    short_message: str = Field(max_length=160)
    steps: list[str] = Field(default_factory=list)
    channel: CommunicationChannel
    requires_confirmation: bool = False
    escalation: str | None = None
    reason: str
