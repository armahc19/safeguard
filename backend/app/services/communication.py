"""Channel-independent input normalisation and conservative intent detection."""
from __future__ import annotations

import re
import unicodedata

from app.core.phone import normalize_phone
from app.enums import CommunicationChannel, CommunicationIntent, ConversationStage
from app.schemas.communication import CommunicationContext

_WORD_RE = re.compile(r"[a-z0-9']+")
_GREETING_RE = re.compile(r"\b(hi|hello|hey|good morning|good afternoon|akwaaba)\b")
_REPORT_RE = re.compile(r"\b(report|scam|fraud|cheated|cheat|defrauded|stole)\b")
_CHECK_NUMBER_RE = re.compile(r"\b(check|look up|lookup|who called|safe number|number)\b")
_MESSAGE_RE = re.compile(r"\b(analy[sz]e|check|suspicious|message|sms|text|link)\b")
_TRANSACTION_RE = re.compile(r"\b(send money|transfer|recipient|pay|payment|momo|transaction)\b")
_ADVICE_RE = re.compile(r"\b(advice|what should i do|help me|protect|safety)\b")
_URGENT_RE = re.compile(r"\b(urgent|immediately|now|quickly|last warning|send)\b")
_CREDENTIAL_RE = re.compile(r"\b(pin|otp|password|passcode|verification code)\b")
_LOSS_RE = re.compile(r"\b(sent money|lost money|was defrauded|already paid|already shared)\b")
_TWI_WORDS = {"mepa", "boa", "yɛ", "sika", "ko", "fa", "kyerɛ", "adwuma"}


def _normalise_text(text: str | None) -> str | None:
    if text is None:
        return None
    value = unicodedata.normalize("NFKC", text).replace("\u200b", "").replace("\ufeff", "")
    return re.sub(r"\s+", " ", value).strip().lower() or None


def _language(text: str | None) -> str:
    if not text:
        return "unknown"
    tokens = set(_WORD_RE.findall(text))
    if tokens & _TWI_WORDS:
        return "twi_or_mixed"
    return "en"


def _intent(text: str | None) -> tuple[CommunicationIntent, str | None]:
    if not text:
        return CommunicationIntent.UNKNOWN, None
    if _GREETING_RE.search(text) and len(text.split()) <= 5:
        return CommunicationIntent.GREETING, None
    if _REPORT_RE.search(text):
        return CommunicationIntent.REPORT_SCAM, "report suspected fraud"
    if _TRANSACTION_RE.search(text):
        return CommunicationIntent.TRANSACTION_CHECK, "check a transfer or recipient"
    if _MESSAGE_RE.search(text):
        return CommunicationIntent.ANALYZE_MESSAGE, "analyse a message or link"
    if _CHECK_NUMBER_RE.search(text):
        return CommunicationIntent.CHECK_NUMBER, "check a phone number"
    if _ADVICE_RE.search(text):
        return CommunicationIntent.SAFETY_ADVICE, "provide safety guidance"
    return CommunicationIntent.UNKNOWN, None


def _stage(text: str | None) -> ConversationStage:
    if not text:
        return ConversationStage.UNCLEAR
    if _LOSS_RE.search(text):
        return ConversationStage.LOSS
    if _CREDENTIAL_RE.search(text) or _URGENT_RE.search(text):
        return ConversationStage.MANIPULATION
    if _TRANSACTION_RE.search(text):
        return ConversationStage.ACTION
    if _REPORT_RE.search(text):
        return ConversationStage.CONVERSATION
    return ConversationStage.CONTACT


class CommunicationIntelligence:
    """Single channel-independent communication interpretation service."""

    version = "communication.v1"

    def interpret(
        self,
        *,
        channel: CommunicationChannel = CommunicationChannel.APP,
        text: str | None = None,
        phone_number: str | None = None,
        default_calling_code: str = "233",
    ) -> CommunicationContext:
        normalized_text = _normalise_text(text)
        normalized_phone = normalize_phone(phone_number, default_calling_code) if phone_number else None
        intent, requested_action = _intent(normalized_text)
        consent_required = channel == CommunicationChannel.CALL and bool(normalized_text)
        privacy_notes = []
        if channel == CommunicationChannel.CALL:
            privacy_notes.append("call content requires explicit user consent")
        if normalized_text and _CREDENTIAL_RE.search(normalized_text):
            privacy_notes.append("never retain PINs, OTPs or passwords")
        if normalized_text:
            privacy_notes.append("store derived signals only; do not retain raw channel text")
        return CommunicationContext(
            contract_version=self.version,
            channel=channel, normalized_text=normalized_text, normalized_phone=normalized_phone,
            language=_language(normalized_text), intent=intent, stage=_stage(normalized_text),
            requested_action=requested_action, privacy_notes=list(dict.fromkeys(privacy_notes)),
            consent_required=consent_required, raw_text_storage="derived_signals_only",
        )


communication_intelligence = CommunicationIntelligence()


def interpret(
    *,
    channel: CommunicationChannel = CommunicationChannel.APP,
    text: str | None = None,
    phone_number: str | None = None,
    default_calling_code: str = "233",
) -> CommunicationContext:
    """Backward-compatible facade for the canonical service."""
    return communication_intelligence.interpret(
        channel=channel, text=text, phone_number=phone_number,
        default_calling_code=default_calling_code,
    )
