from pydantic import BaseModel, Field

from app.enums import CommunicationChannel, CommunicationIntent, ConversationStage


class CommunicationInterpretRequest(BaseModel):
    channel: CommunicationChannel = CommunicationChannel.APP
    text: str | None = Field(default=None, max_length=5000)
    phone_number: str | None = Field(default=None, min_length=7, max_length=20)


class CommunicationContext(BaseModel):
    contract_version: str = "communication.v1"
    channel: CommunicationChannel
    normalized_text: str | None = None
    normalized_phone: str | None = None
    language: str = "unknown"
    intent: CommunicationIntent = CommunicationIntent.UNKNOWN
    stage: ConversationStage = ConversationStage.UNCLEAR
    requested_action: str | None = None
    privacy_notes: list[str] = Field(default_factory=list)
    consent_required: bool = False
    raw_text_storage: str = "derived_signals_only"
