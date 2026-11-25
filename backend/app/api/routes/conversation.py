import re
from uuid import UUID

from fastapi import APIRouter

from app.api.deps import CurrentUser, DbDep, RedisDep, SettingsDep
from app.schemas.conversation import (
    ConversationTurnOut,
    ConversationTurnRequest,
    SharedCaseContext,
)
from app.services.conversation_intelligence import analyze_turn, get_context

router = APIRouter(prefix="/conversation", tags=["conversation-intelligence"])


def _message_advice(message: str, result) -> tuple[str, str]:
    """Explain observed message signals and give concise, context-aware advice."""
    text = message.lower()
    level = result.intelligence.risk_level.value.upper()
    patterns = result.intelligence.detected_patterns
    pattern_names = [str(item.get("name", "")) for item in patterns]
    pattern_categories = {str(item.get("category", "")).lower() for item in patterns}
    impersonation = (
        "impersonation" in pattern_categories
        or any("impersonation" in name.lower() for name in pattern_names)
        or bool(re.search(r"\b(pretend|pretending|posing as|impersonat)\b", text))
    )
    credential_request = bool(re.search(r"\b(pin|otp|password|passcode|verification code|one[- ]?time code)\b", text))
    advance_fee_prize = (
        ("reward_bait" in pattern_categories
         or any(re.search(r"\b(prize|reward|winnings?)\b", name.lower()) for name in pattern_names)
         or bool(re.search(r"\b(prize|reward|winnings?)\b", text)))
        and bool(re.search(r"\b(processing fee|upfront fee|pay.{0,30}fee|fee.{0,30}before)\b", text))
    )
    provider = next((name for name, token in (
        ("MTN", "mtn"), ("Telecel", "telecel"), ("AirtelTigo", "airteltigo"), ("Vodafone", "vodafone"),
    ) if token in text), None)
    stopped = bool(re.search(r"\b(ended|hung up|disconnected)\b.{0,40}\b(call|caller)\b|\bended the call\b", text))
    shared_secret = bool(re.search(r"\b(shared|gave|told|provided)\b.{0,35}\b(pin|otp|password|passcode|code)\b", text))

    if level in {"HIGH", "CRITICAL"}:
        if impersonation and credential_request:
            claimed_source = f"{provider} support" if provider else "customer support"
            explanation = f"This looks like a {level.lower()}-risk impersonation attempt: the caller claims to be {claimed_source} and asks for your PIN or security code. Legitimate support should not ask you to disclose it."
        elif advance_fee_prize:
            explanation = f"This looks like a {level.lower()}-risk advance-fee scam: it promises a prize but asks you to pay a processing fee first."
        elif credential_request:
            explanation = f"This looks like a {level.lower()}-risk attempt to obtain account credentials because it asks for your PIN or security code."
        elif pattern_names:
            explanation = f"This looks like a {level.lower()}-risk scam because it matches {pattern_names[0].lower()}."
        else:
            explanation = f"This message has warning signs consistent with a {level.lower()}-risk scam."

        if shared_secret:
            advice = "Contact your provider through its official channel now to secure your account."
        elif stopped:
            advice = "You did the right thing ending the call. Do not call back; contact the provider officially if you shared anything or notice unusual activity."
        elif advance_fee_prize:
            advice = "Good instinct to pause. Do not pay the fee or share account details; verify the prize with the organizer through an official channel."
        elif credential_request:
            advice = "Do not share the PIN or code. Stop responding and verify through the provider's official app or contact channel."
        else:
            advice = result.intervention.message
        reply = f"{explanation} {advice}"
        short = f"{provider + ' support' if provider else 'A caller'} asked for your PIN/code. Do not share it; verify through official support."
        if stopped:
            short = "Ending the call was right. Do not share your PIN; contact official support if you shared details."
        elif advance_fee_prize:
            short = "Prize requires an upfront fee? Don't pay. Verify directly with the official organizer."
        return reply, short[:160]

    if level == "MEDIUM":
        if pattern_names:
            explanation = f"I found a warning sign consistent with {pattern_names[0].lower()}."
        elif credential_request:
            explanation = "The message mentions a PIN or security code, so verify what it is asking before acting."
        else:
            explanation = "I found some warning signs, but not enough to confirm this is a scam."
        reply = f"{explanation} {result.intervention.message}"
        return reply, reply[:160]

    if pattern_names:
        explanation = f"I found no strong risk signal, though the message resembles {pattern_names[0].lower()}."
    else:
        explanation = "I found no strong scam signals in this message."
    reply = f"{explanation} {result.intervention.message}"
    return reply, reply[:160]


@router.post("/turn", response_model=ConversationTurnOut)
async def conversation_turn(
    body: ConversationTurnRequest, user: CurrentUser, db: DbDep, redis: RedisDep, settings: SettingsDep,
) -> ConversationTurnOut:
    """Analyze one conversational turn through the canonical backend pipeline."""
    return await analyze_turn(db=db, redis=redis, user=user, settings=settings, request=body)


@router.post("/adapter-turn")
async def conversation_adapter_turn(
    body: ConversationTurnRequest, user: CurrentUser, db: DbDep, redis: RedisDep, settings: SettingsDep,
) -> dict:
    """Compatibility adapter for browser SMS/chat clients.

    This endpoint replaces the separate Gradio relay process. It runs inside
    the main FastAPI app and delegates all interpretation, risk, and
    intervention decisions to the canonical conversation service.
    """
    result = await analyze_turn(
        db=db, redis=redis, user=user, settings=settings, request=body,
        persist_message_to_fir=True,
    )
    level = result.intelligence.risk_level.value
    reply, short_reply = _message_advice(body.message, result)
    return {
        "reply": reply,
        "short_reply": short_reply,
        "case_id": str(result.case_id),
        "fir_report_id": str(result.fir_report_id) if result.fir_report_id else None,
        "extracted_identifiers": result.extracted_identifiers,
        "context": result.context.model_dump(mode="json"),
        "notes": result.notes.model_dump(mode="json"),
        "intelligence": result.intelligence.model_dump(mode="json"),
        "intervention": result.intervention.model_dump(mode="json"),
        "risk_level": level,
        "communication": result.communication.model_dump(mode="json"),
        "privacy_notice": result.privacy_notice,
    }


@router.get("/{case_id}/context", response_model=SharedCaseContext)
async def conversation_context(
    case_id: UUID, user: CurrentUser, db: DbDep, redis: RedisDep,
) -> SharedCaseContext:
    """Return the shared context that can be continued by another channel."""
    return await get_context(db=db, redis=redis, user=user, case_id=case_id)
