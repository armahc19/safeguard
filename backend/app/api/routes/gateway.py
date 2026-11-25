"""Endpoints for the USSD and SMS gateways (SafeGuard Lite / feature phones).

Auth is the gateway's HMAC signature, not a user token. The caller's MSISDN comes from the operator network,
so we trust it only because the request is signed, and create the user on first contact.
"""
import asyncio
import re
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Query, Request, status
from sqlalchemy import delete, select

from app.api.deps import DbDep, FraudServiceDep, GatewayDep, RedisDep, SettingsDep
from app.core.exceptions import (NotFoundError, PermissionDenied,
                                 ServiceUnavailableError, ValidationFailed)
from app.core.phone import normalize_phone
from app.enums import AccountStatus, CommunicationChannel, EvidenceType
from app.models import (AwarenessScheduledInteraction, CaseEvidence, CommunityReport,
                        FraudCase, FraudReport, ShieldAnalysis, UserAwarenessPreference)
from app.schemas.cases import EvidenceCreate
from app.schemas.fraud import (
    CommunityReportCreate,
    GatewayLookup,
    GatewayReport,
    GatewayReportHistoryOut,
    GatewayReportOut,
    LookupOut,
    ReportCreate,
)
from app.schemas.awareness import (GatewayAwarenessCheckupResponseIn,
                                  GatewayAwarenessSubscriptionIn, GatewayVoiceMemoryIn,
                                  GatewayVoiceTurnIn)
from app.schemas.conversation import ConversationTurnRequest
from app.schemas.shield import GatewayShieldOut, GatewayShieldRequest
from app.schemas.transactions import (
    GatewayTransactionAssessOut,
    GatewayTransactionAssessRequest,
)
from app.services.case_service import CaseService
from app.services.awareness import preferences_payload, update_gateway_awareness_subscription
from app.services.conversation_intelligence import analyze_turn
from app.services.community_intelligence import CommunityIntelligenceService
from app.services.feedback import FeedbackService
from app.services.fraud_intelligence_orchestrator import fraud_intelligence_orchestrator
from app.services.network_intelligence import NetworkService
from app.services.transaction_intelligence import assess_transaction
from app.services.users import get_or_create_user

router = APIRouter(prefix="/gateway", tags=["gateway"])


def _voice_phone_candidates(text: str, default_calling_code: str) -> list[str]:
    candidates = re.findall(r"(?<!\d)(?:\+?233|0)(?:[\s().-]*\d){9}(?!\d)", text)
    normalized: list[str] = []
    for candidate in candidates:
        try:
            value = normalize_phone(candidate, default_calling_code)
        except ValidationFailed:
            continue
        if value not in normalized:
            normalized.append(value)
    return normalized


def _voice_help_intent(message: str, history: list, default_calling_code: str) -> str | None:
    """Recover the active SafeGuard-help task across short voice turns."""
    turns = [str(item.text) for item in history if item.role == "user"] + [message]
    for text in reversed(turns):
        value = text.casefold()
        if re.search(r"\b(report|send)\b.{0,30}\b(suspicious\s+)?sms\b|\bsuspicious\s+text\b", value):
            return "suspicious_sms"
        if re.search(r"\b(report|file|make)\b.{0,30}\b(scam|fraud)\s+report\b|\breport\s+(a\s+)?scam\b", value):
            return "report_scam"
        if re.search(r"\b(my\s+)?(past\s+)?reports\b|\bcheck\s+(my\s+)?reports\b", value):
            return "my_reports"
        if re.search(r"\b(safety\s+advice|fraud\s+advice|scam\s+advice|how\s+do\s+i\s+stay\s+safe)\b", value):
            return "safety_advice"
        if re.search(r"\b(check|look\s+up|search)\b.{0,24}\b(number|phone)\b|\bwho\s+is\s+calling\b", value):
            return "check_number"
        if _voice_phone_candidates(text, default_calling_code) and re.search(r"\b(check|look\s+up|search)\b", value):
            return "check_number"
        if _voice_phone_candidates(text, default_calling_code) and any(
            re.search(r"\b(check|look\s+up|search)\b.{0,24}\b(number|phone)\b", prior, re.I)
            for prior in turns[:turns.index(text)]
        ):
            return "check_number"
    return None


def _voice_help_followup(intent: str, message: str, history: list,
                         default_calling_code: str) -> str | None:
    """Ask for the next required detail, or signal that the task can run."""
    if intent == "check_number":
        if not _voice_phone_candidates(message, default_calling_code):
            if re.search(r"(?<!\d)(?:\+?233|0)(?:[\s().-]*\d){6,8}(?!\d)", message):
                return "That number looks incomplete. Please say the full Ghana number: 10 digits starting with 0, or 12 digits starting with 233."
            return "Sure. What Ghana phone number would you like me to check? Please say all 10 digits."
        return None
    if intent == "report_scam":
        if len(message.strip()) < 10 or re.fullmatch(r"\s*(report|a scam|report a scam|scam)\s*", message, re.I):
            return "Tell me what happened, including any number involved and how money or information was requested. I’ll submit it for review."
        return None
    if intent == "suspicious_sms":
        if len(message.strip()) < 8 or re.fullmatch(r"\s*(report|suspicious sms|report suspicious sms|sms)\s*", message, re.I):
            return "Please read or paste the suspicious text message. I’ll check it for warning signs."
        return None
    return None


def _voice_momo_intent(message: str, history: list) -> str | None:
    turns = [str(item.text) for item in history if item.role == "user"] + [message]
    for text in reversed(turns):
        value = text.casefold()
        if re.search(r"\b(check|see|view|what(?:'s| is))\b.{0,40}\b(balance|balances)\b|\b(my|wallet) balance\b", value):
            return "balance"
        if re.search(r"\b(received|incoming|came in|come in)\b.{0,40}\b(money|payment|transfer)\b|\b(check|show)\b.{0,30}\breceived\b", value):
            return "received"
        if re.search(r"\b(send|transfer|pay)\b.{0,35}\b(money|cedis|gh[₵c]|someone|friend|number)\b|\bi want to send\b", value):
            return "send"
    return None


def _voice_momo_amount(turns: list[str]) -> str | None:
    for text in reversed(turns):
        value = re.sub(r"(?<!\d)(?:\+?233|0)(?:[\s().-]*\d){9}(?!\d)", " ", text)
        match = re.search(r"(?:gh\s*[₵c]|ghs|cedis?)\s*(\d{1,5}(?:\.\d{1,2})?)|"
                          r"\b(\d{1,5}(?:\.\d{1,2})?)\s*(?:cedis?|ghs)\b", value, re.I)
        if match:
            return next(group for group in match.groups() if group)
        if re.fullmatch(r"\s*\d{1,5}(?:\.\d{1,2})?\s*", value):
            return value.strip()
    return None


@router.post("/voice/transcribe")
async def transcribe_gateway_voice(
    request: Request, gateway: GatewayDep, db: DbDep, settings: SettingsDep,
    msisdn: str = Query(min_length=7, max_length=20),
) -> dict[str, str]:
    """Transcribe a short microphone clip in memory; audio is not persisted."""
    await _caller(db, settings, msisdn)
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    audio = await request.body()
    if not audio or len(audio) > 950_000:
        raise ValidationFailed("Record a short voice message and try again.", code="voice_audio_size_invalid")
    from app.services.awareness_gradio import create_gradio_client, transcribe_voice_audio
    api_key = settings.groq_api_key.get_secret_value() if settings.groq_api_key else None
    client = create_gradio_client(api_key)

    try:
        transcript = await asyncio.to_thread(transcribe_voice_audio, audio, content_type, llm=client)
    except ValueError as exc:
        raise ValidationFailed(str(exc), code="voice_audio_format_unsupported") from exc
    except Exception as exc:
        raise ServiceUnavailableError("Speech recognition is temporarily unavailable.",
                                      code="voice_transcription_failed") from exc
    if transcript is None:
        raise ServiceUnavailableError(
            "Speech recognition is not configured. Add GROQ_API_KEY to the backend environment or type your message.",
            code="voice_transcription_unconfigured",
        )
    if not transcript:
        raise ValidationFailed("I couldn't hear any words. Please try again or type your message.",
                               code="voice_transcript_empty")
    return {"transcript": transcript}


@router.get("/voice/memory")
async def get_voice_memory_preference(
    gateway: GatewayDep, db: DbDep, settings: SettingsDep,
    msisdn: str = Query(min_length=7, max_length=20),
) -> dict[str, bool]:
    user = await _caller(db, settings, msisdn)
    preference = await db.scalar(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id == user.id,
    ))
    return {"enabled": bool(preference and preference.conversation_memory_enabled)}


@router.put("/voice/memory")
async def set_voice_memory_preference(
    body: GatewayVoiceMemoryIn, gateway: GatewayDep, db: DbDep,
    redis: RedisDep, settings: SettingsDep,
) -> dict[str, bool | str]:
    user = await _caller(db, settings, body.msisdn)
    preference = await db.scalar(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id == user.id,
    ))
    if preference is None:
        preference = UserAwarenessPreference(user_id=user.id)
        db.add(preference)
    preference.conversation_memory_enabled = body.enabled
    preference.consent_updated_at = datetime.now(UTC)
    if not body.enabled:
        case_ids = (await db.scalars(select(FraudCase.id).where(
            FraudCase.user_id == user.id,
        ))).all()
        if case_ids:
            await db.execute(delete(CaseEvidence).where(
                CaseEvidence.case_id.in_(case_ids),
                CaseEvidence.source == "conversation_context",
            ))
            await redis.delete(*[
                f"safeguard:conversation-context:{user.id}:{case_id}"
                for case_id in case_ids
            ])
        preference.voice_case_id = None
    await db.commit()
    return {"enabled": body.enabled,
            "message": "Voice context memory enabled." if body.enabled
            else "Voice context memory disabled and saved context cleared."}


@router.post("/voice/turn")
async def gateway_voice_turn(
    body: GatewayVoiceTurnIn, gateway: GatewayDep, db: DbDep,
    redis: RedisDep, settings: SettingsDep, fraud: FraudServiceDep,
) -> dict:
    """Analyze one speech-to-text turn, reusing opted-in caller context."""
    user = await _caller(db, settings, body.msisdn)
    preference = await db.scalar(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id == user.id,
    ))
    memory_enabled = bool(preference and preference.conversation_memory_enabled)
    case_id = None
    if memory_enabled and preference is not None:
        case = None
        if preference.voice_case_id is not None:
            case = await db.scalar(select(FraudCase).where(
                FraudCase.id == preference.voice_case_id,
                FraudCase.user_id == user.id,
            ))
        if case is None:
            case = await CaseService(db).get_or_create(
                user, None, title="SafeGuard Voice conversation context",
            )
            preference.voice_case_id = case.id
        case_id = case.id

    result = await analyze_turn(
        db=db, redis=redis, user=user, settings=settings,
        request=ConversationTurnRequest(
            message=body.message, case_id=case_id, channel=CommunicationChannel.CALL,
        ),
        persist_message_to_fir=False,
        persist_case=memory_enabled,
    )
    momo_intent = _voice_momo_intent(body.message, body.history)
    if momo_intent:
        from app.services.momo_sandbox import momo_sandbox
        if settings.environment not in {"development", "test"}:
            return {"reply": "MoMo sandbox tasks are available only in the development demo.",
                    "intent": momo_intent, "simulated": True,
                    "memory_enabled": memory_enabled, "privacy_notice": result.privacy_notice}
        if momo_intent == "balance":
            balance = await momo_sandbox.balance(user.phone)
            return {"reply": f"Your simulated sandbox balance is GH₵{balance['balance']}. This is test data, not your real wallet balance.",
                    "intent": momo_intent, "simulated": True,
                    "memory_enabled": memory_enabled, "privacy_notice": result.privacy_notice}
        if momo_intent == "received":
            received = await momo_sandbox.received(user.phone)
            items = received["items"]
            if not items:
                reply = "There are no simulated incoming payments in this sandbox wallet."
            else:
                latest = items[0]
                reply = (f"The latest simulated payment received was GH₵{latest['amount']} from "
                         f"{latest['sender'][-4:]}, status {latest['status']}. This is sandbox test data.")
            return {"reply": reply, "intent": momo_intent, "simulated": True,
                    "transactions": items, "memory_enabled": memory_enabled,
                    "privacy_notice": result.privacy_notice}

        recent_users = [item.text for item in body.history if item.role == "user"] + [body.message]
        affirmative = bool(re.fullmatch(r"\s*(yes|yes confirm|confirm|go ahead|do it)\s*[.!]?\s*", body.message, re.I))
        negative = bool(re.fullmatch(r"\s*(no|cancel|stop)\s*[.!]?\s*", body.message, re.I))
        awaiting_confirmation = any(item.role == "assistant" and "confirm" in item.text.casefold()
                                    for item in body.history)
        if negative and awaiting_confirmation:
            await momo_sandbox.cancel_transfer(user.phone)
            return {"reply": "Okay, I cancelled the simulated transfer. No sandbox money was moved.",
                    "intent": momo_intent, "simulated": True,
                    "memory_enabled": memory_enabled, "privacy_notice": result.privacy_notice}
        if affirmative and awaiting_confirmation:
            try:
                transfer = await momo_sandbox.confirm_transfer(user.phone)
            except ValueError as exc:
                return {"reply": f"I couldn’t complete the simulated transfer: {exc}",
                        "intent": momo_intent, "simulated": True,
                        "memory_enabled": memory_enabled, "privacy_notice": result.privacy_notice}
            return {"reply": (f"Simulated transfer complete: GH₵{transfer['amount']} to a number ending "
                               f"{transfer['recipient'][-4:]}. Reference {transfer['reference']}. "
                               "This was sandbox-only; no real money moved."),
                    "intent": momo_intent, "simulated": True, "transfer": transfer,
                    "memory_enabled": memory_enabled, "privacy_notice": result.privacy_notice}
        recipients = list(dict.fromkeys(
            number for text in recent_users for number in _voice_phone_candidates(text, settings.default_calling_code)
            if number != user.phone
        ))
        if not recipients:
            reply = "Who would you like to send simulated money to? Please say their full Ghana mobile number."
        elif len(recipients) > 1:
            reply = "I heard more than one recipient number. Please provide just one Ghana number for the simulated transfer."
        else:
            amount = _voice_momo_amount(recent_users)
            if amount is None:
                reply = "How much would you like to send in Ghana cedis? You can say an amount such as 50 cedis."
            else:
                try:
                    staged = await momo_sandbox.stage_transfer(user.phone, recipients[0], amount)
                    reply = (f"This is only a simulation. You asked to send GH₵{staged['amount']} to a number ending "
                             f"{staged['recipient'][-4:]}. Say ‘yes, confirm’ to simulate it, or ‘cancel’. "
                             "Never say your MoMo PIN aloud.")
                except ValueError as exc:
                    reply = f"I can’t prepare that simulated transfer: {exc}"
        return {"reply": reply, "intent": momo_intent, "simulated": True,
                "memory_enabled": memory_enabled, "privacy_notice": result.privacy_notice}

    help_intent = _voice_help_intent(body.message, body.history, settings.default_calling_code)
    if help_intent:
        followup = _voice_help_followup(
            help_intent, body.message, body.history, settings.default_calling_code,
        )
        if followup:
            return {"reply": followup, "intent": help_intent,
                    "memory_enabled": memory_enabled, "case_id": str(result.case_id) if memory_enabled else None,
                    "privacy_notice": result.privacy_notice}
        if help_intent == "check_number":
            number = _voice_phone_candidates(body.message, settings.default_calling_code)[0]
            lookup = await fraud.lookup(user, number, case_id=case_id, channel=CommunicationChannel.CALL)
            if lookup.verified_reports or lookup.pending_reports:
                reply = (f"SafeGuard has {lookup.verified_reports} reviewed and {lookup.pending_reports} pending "
                         f"report(s) for that number. Reports are not proof of guilt. {lookup.advice}")
            else:
                reply = ("SafeGuard has no recorded reports for that number. That does not guarantee it is safe. "
                         "Verify who you are dealing with before sharing money or information.")
            return {"reply": reply, "intent": help_intent, "risk_level": lookup.risk_level.value,
                    "memory_enabled": memory_enabled, "case_id": str(result.case_id) if memory_enabled else None,
                    "privacy_notice": result.privacy_notice}
        if help_intent == "report_scam":
            from app.enums import ReportType
            number_candidates = _voice_phone_candidates(body.message, settings.default_calling_code)
            submitted = await gateway_report(
                GatewayReport(msisdn=body.msisdn, number=number_candidates[0] if len(number_candidates) == 1 else None,
                              report_type=ReportType.OTHER, description=body.message),
                gateway, db, settings, fraud,
            )
            return {"reply": f"Your report was received for review. Reference {str(submitted.report_id)[:8]}.",
                    "intent": help_intent, "memory_enabled": memory_enabled,
                    "case_id": str(result.case_id) if memory_enabled else None,
                    "privacy_notice": result.privacy_notice}
        if help_intent == "suspicious_sms":
            analysis = await gateway_shield(
                GatewayShieldRequest(msisdn=body.msisdn, text=body.message),
                gateway, db, settings,
            )
            return {"reply": f"This message is rated {analysis.risk_level.value}. {analysis.explanation} "
                              f"{analysis.intervention.message}",
                    "intent": help_intent, "risk_level": analysis.risk_level.value,
                    "memory_enabled": memory_enabled, "case_id": str(result.case_id) if memory_enabled else None,
                    "privacy_notice": result.privacy_notice}
        if help_intent == "safety_advice":
            return {"reply": "Never share your MoMo PIN or OTP. Pause if someone pressures you to send money. "
                              "Verify requests through your provider’s official channel.",
                    "intent": help_intent, "memory_enabled": memory_enabled,
                    "case_id": str(result.case_id) if memory_enabled else None,
                    "privacy_notice": result.privacy_notice}
        if help_intent == "my_reports":
            reports = await gateway_report_history(body.msisdn, gateway, db, settings)
            summary = ("You have no reports on this account." if not reports else
                       "Your recent reports: " + "; ".join(
                           f"{item.title}, {item.status.replace('_', ' ')}" for item in reports[:5]
                       ))
            return {"reply": summary, "intent": help_intent,
                    "memory_enabled": memory_enabled, "case_id": str(result.case_id) if memory_enabled else None,
                    "privacy_notice": result.privacy_notice}

    from app.services.awareness_gradio import create_gradio_client, generate_voice_reply
    api_key = settings.groq_api_key.get_secret_value() if settings.groq_api_key else None
    client = create_gradio_client(api_key, timeout=20.0)

    recent_user_text = " ".join(
        [item.text for item in body.history if item.role == "user"] + [body.message]
    )
    payment_context = bool(
        re.search(r"\b(send|sending|transfer|transferring|pay|paying|recipient|beneficiar(?:y|ies))\b",
                  recent_user_text, re.IGNORECASE)
        or any("transfer" in action.lower() or "recipient" in action.lower()
               for action in result.context.requested_actions)
    )
    phone_candidates = _voice_phone_candidates(body.message, settings.default_calling_code)
    recipient_lookup = None
    if payment_context and len(phone_candidates) == 1:
        candidate = phone_candidates[0]
        if candidate == user.phone:
            recipient_lookup = {"status": "not_checked", "reason": "matches_calling_number"}
        else:
            try:
                lookup = await fraud.lookup(
                    user, candidate, case_id=case_id, channel=CommunicationChannel.CALL,
                )
                recipient_lookup = {
                    "status": "checked", "phone_last_four": lookup.phone[-4:],
                    "risk_level": lookup.risk_level.value,
                    "known": lookup.known,
                    "reviewed_reports": lookup.verified_reports,
                    "unverified_reports": lookup.pending_reports,
                    "categories": lookup.categories,
                    "risk_reasons": lookup.risk_reasons[:5],
                    "recommended_action": lookup.recommended_action,
                    "provenance": lookup.provenance,
                }
            except Exception:
                recipient_lookup = {"status": "unavailable"}

    assessment = {
        "risk_level": result.intelligence.risk_level.value,
        "confidence": result.intelligence.confidence,
        "risk_evidence": result.intelligence.risk_evidence,
        "unknowns": result.intelligence.unknowns,
        "recommended_action": result.intelligence.recommended_action,
        "intent": result.communication.intent.value,
        "stage": result.communication.stage.value,
    }
    reply = await asyncio.to_thread(
        generate_voice_reply,
        message=body.message,
        assessment=assessment,
        guidance=result.intervention.message,
        context=result.context.model_dump(mode="json") if memory_enabled else None,
        history=[item.model_dump() for item in body.history],
        recipient_lookup=recipient_lookup,
        llm=client,
    )
    return {
        "reply": reply,
        "risk_level": result.intelligence.risk_level.value,
        "case_id": str(result.case_id) if memory_enabled else None,
        "memory_enabled": memory_enabled,
        "context": result.context.model_dump(mode="json") if memory_enabled else None,
        "privacy_notice": ("A short structured context is saved for future calls. Audio and raw transcripts are not stored."
                           if memory_enabled else
                           "This turn is analyzed for an immediate response; conversation memory is off."),
    }


def _require_ussd(gateway: str) -> None:
    if gateway != "ussd":
        raise PermissionDenied("Awareness subscriptions are managed through the USSD channel.",
                               code="ussd_channel_required")


@router.get("/awareness/preferences")
async def get_gateway_awareness_preferences(gateway: GatewayDep, db: DbDep, settings: SettingsDep,
                                             msisdn: str = Query(min_length=7, max_length=20)) -> dict:
    _require_ussd(gateway)
    user = await _caller(db, settings, msisdn)
    row = await db.scalar(select(UserAwarenessPreference).where(UserAwarenessPreference.user_id == user.id))
    test_available = settings.environment in {"development", "test"}
    latest_test = None
    if test_available:
        latest_test = await db.scalar(select(AwarenessScheduledInteraction).where(
            AwarenessScheduledInteraction.user_id == user.id,
            AwarenessScheduledInteraction.status == "simulated",
            AwarenessScheduledInteraction.read_at.is_(None),
        ).order_by(AwarenessScheduledInteraction.created_at.desc()).limit(1))
    return {**preferences_payload(row), "subscription_active": bool(row and row.proactive_education_enabled),
            "test_schedule_available": test_available,
            "latest_test_interaction": ({"message": latest_test.message,
                                         "topic": latest_test.topic,
                                         "created_at": latest_test.created_at,
                                         "checkup_available": bool(latest_test.checkup_question and not latest_test.responded_at)}
                                        if latest_test else None)}


@router.get("/awareness/messages")
async def get_gateway_awareness_messages(
    gateway: GatewayDep, db: DbDep, settings: SettingsDep,
    msisdn: str = Query(min_length=7, max_length=20),
) -> dict:
    """Return unread simulated SMS for the signed-in Lite gateway number."""
    _require_ussd(gateway)
    user = await _caller(db, settings, msisdn)
    rows = (await db.scalars(select(AwarenessScheduledInteraction).where(
        AwarenessScheduledInteraction.user_id == user.id,
        AwarenessScheduledInteraction.status.in_(("simulated", "responded")),
        AwarenessScheduledInteraction.context_snapshot["test_schedule"].as_boolean().is_(True),
        AwarenessScheduledInteraction.read_at.is_(None),
    ).order_by(AwarenessScheduledInteraction.created_at.desc()).limit(50))).all()
    return {"items": [{"id": item.id, "topic": item.topic, "message": item.message,
                       "sent_at": item.delivered_at or item.created_at}
                      for item in rows]}


@router.post("/awareness/messages/{interaction_id}/read")
async def mark_gateway_awareness_message_read(
    interaction_id: UUID, gateway: GatewayDep, db: DbDep, settings: SettingsDep,
    msisdn: str = Query(min_length=7, max_length=20),
) -> dict[str, str]:
    """Mark a Lite simulated SMS read; keep the row as delivery history."""
    _require_ussd(gateway)
    user = await _caller(db, settings, msisdn)
    item = await db.scalar(select(AwarenessScheduledInteraction).where(
        AwarenessScheduledInteraction.id == interaction_id,
        AwarenessScheduledInteraction.user_id == user.id,
        AwarenessScheduledInteraction.status.in_(("simulated", "responded")),
        AwarenessScheduledInteraction.context_snapshot["test_schedule"].as_boolean().is_(True),
    ).with_for_update())
    if item is None:
        raise NotFoundError("Awareness message not found.", code="awareness_message_not_found")
    item.read_at = item.read_at or datetime.now(UTC)
    await db.commit()
    return {"status": "read"}


@router.put("/awareness/preferences")
async def put_gateway_awareness_preferences(body: GatewayAwarenessSubscriptionIn, gateway: GatewayDep,
                                             db: DbDep, settings: SettingsDep) -> dict:
    _require_ussd(gateway)
    if body.test_schedule_enabled:
        if settings.environment not in {"development", "test"}:
            raise ValidationFailed("The one-minute test schedule is only available in development.",
                                   code="awareness_test_schedule_unavailable")
        if body.delivery_method == "voice_call" or body.language.lower() != "english":
            raise ValidationFailed("The one-minute test schedule requires English SMS delivery.",
                                   code="awareness_test_schedule_requires_sms")
    user = await _caller(db, settings, body.msisdn)
    result = await update_gateway_awareness_subscription(db, user, body)
    result["test_schedule_available"] = settings.environment in {"development", "test"}
    if not body.subscription_active:
        result["message"] = "You are unsubscribed from Continuous Awareness."
    elif body.test_schedule_enabled:
        result["message"] = ("One-minute test enabled. The Gradio awareness agent will prepare a draft for admin approval; "
                              "after approval, the simulated SMS appears here in SafeGuard Lite. No carrier SMS is sent.")
    else:
        result["message"] = ("Preferences saved. Your next SMS reminder is scheduled; delivery requires the SafeGuard "
                              "scheduler and SMS provider to be running. Dial SafeGuard and choose option 6 to answer a "
                              "check-up. Voice calls are not connected.")
    result["voice_delivery_available"] = False
    return result


@router.get("/awareness/checkup")
async def get_gateway_awareness_checkup(
    gateway: GatewayDep, db: DbDep, settings: SettingsDep,
    msisdn: str = Query(min_length=7, max_length=20),
) -> dict:
    _require_ussd(gateway)
    user = await _caller(db, settings, msisdn)
    pref = await db.scalar(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id == user.id,
        UserAwarenessPreference.proactive_education_enabled.is_(True),
        UserAwarenessPreference.checkup_enabled.is_(True),
    ))
    if pref is None:
        return {"available": False, "message": "No check-up is waiting."}
    item = await db.scalar(select(AwarenessScheduledInteraction).where(
        AwarenessScheduledInteraction.user_id == user.id,
        AwarenessScheduledInteraction.status.in_(("sent", "simulated")),
        AwarenessScheduledInteraction.checkup_question.is_not(None),
        AwarenessScheduledInteraction.responded_at.is_(None),
    ).order_by(AwarenessScheduledInteraction.created_at.desc()).limit(1))
    if item is None:
        return {"available": False, "message": "No check-up is waiting."}
    return {"available": True, "interaction_id": item.id,
            "question": item.checkup_question,
            "simulated": item.status == "simulated",
            "choices": [{"value": "yes", "label": "I know what to do"},
                        {"value": "unsure", "label": "I'm not sure"},
                        {"value": "no", "label": "I would share it"}]}


@router.post("/awareness/checkup/respond")
async def respond_gateway_awareness_checkup(
    body: GatewayAwarenessCheckupResponseIn, gateway: GatewayDep,
    db: DbDep, settings: SettingsDep,
) -> dict:
    _require_ussd(gateway)
    user = await _caller(db, settings, body.msisdn)
    pref = await db.scalar(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id == user.id,
        UserAwarenessPreference.proactive_education_enabled.is_(True),
        UserAwarenessPreference.checkup_enabled.is_(True),
    ))
    item = await db.scalar(select(AwarenessScheduledInteraction).where(
        AwarenessScheduledInteraction.id == body.interaction_id,
        AwarenessScheduledInteraction.user_id == user.id,
        AwarenessScheduledInteraction.status.in_(("sent", "simulated")),
        AwarenessScheduledInteraction.responded_at.is_(None),
    ).with_for_update())
    if pref is None or item is None or item.checkup_question is None:
        from app.core.exceptions import ConflictError
        raise ConflictError("This check-up is no longer available.", code="awareness_checkup_unavailable")
    now = datetime.now(UTC)
    item.response = body.answer
    item.responded_at = now
    item.status = "responded"
    context = dict(pref.awareness_context or {})
    context.update({"last_topic": item.topic, "last_response": body.answer,
                    "last_interaction_at": now.isoformat(),
                    "turn_count": int(context.get("turn_count", 0)) + 1})
    topics = list(context.get("recent_topics", []))[-4:]
    if item.topic not in topics:
        topics.append(item.topic)
    context["recent_topics"] = topics[-5:]
    pref.awareness_context = context
    await db.commit()
    feedback = {
        "yes": "Correct. Never share your PIN or OTP; contact your provider through its official channel.",
        "unsure": "Remember: never share a PIN or OTP. Hang up and verify through your provider's official channel.",
        "no": "A caller should never receive your PIN or OTP. Hang up and contact your provider through its official channel.",
    }[body.answer]
    return {"saved": True, "message": feedback}


async def _caller(db, settings, msisdn: str):
    user = await get_or_create_user(db, normalize_phone(msisdn, settings.default_calling_code))
    if user.account_status != AccountStatus.ACTIVE:
        raise PermissionDenied("This account is not active.", code="account_inactive")
    return user


def _report_history_title(description: str | None, report_type: str) -> str:
    """Create a short list title without returning the submitted description."""
    text = re.sub(r"\s+", " ", (description or "").strip().lower())
    kind = report_type.replace("_", " ").title()
    if not text:
        return f"{kind} scam report"
    if re.search(r"\b(momo|mobile money|mobilemoney)\b", text):
        if re.search(r"\b(stole|stolen|theft|lost|loss|took)\b", text):
            return "Mobile money theft report"
        return "Mobile money scam report"
    if re.search(r"\b(phish|link|otp|pin|password|verify|verification)\b", text):
        return "Phishing or account access report"
    if re.search(r"\b(impersonat|pretend|posing as|fake agent)\b", text):
        return "Impersonation scam report"
    if re.search(r"\b(wrong transfer|refund|mistakenly sent|sent by mistake)\b", text):
        return "Suspicious transfer report"
    if re.search(r"\b(stole|stolen|theft|lost|loss)\b", text):
        return "Money theft report"
    return f"{kind} scam report"


@router.post("/lookup", response_model=LookupOut)
async def gateway_lookup(body: GatewayLookup, gateway: GatewayDep, db: DbDep, settings: SettingsDep,
                         fraud: FraudServiceDep) -> LookupOut:
    """Use `short_message` in the response as the USSD / SMS text."""
    user = await _caller(db, settings, body.msisdn)
    channel = CommunicationChannel.SMS if gateway == "sms" else CommunicationChannel.USSD
    return await fraud.lookup(user, body.number, case_id=body.case_id, channel=channel)


@router.post("/reports", response_model=GatewayReportOut, status_code=status.HTTP_201_CREATED)
async def gateway_report(body: GatewayReport, gateway: GatewayDep, db: DbDep, settings: SettingsDep,
                         fraud: FraudServiceDep) -> GatewayReportOut:
    user = await _caller(db, settings, body.msisdn)
    channel = CommunicationChannel.SMS if gateway == "sms" else CommunicationChannel.USSD
    if body.number:
        report = await fraud.submit_report(
            user, ReportCreate(number=body.number, report_type=body.report_type, description=body.description,
                               case_id=body.case_id, channel=channel)
        )
        report_id, case_id = report.id, report.case_id
    else:
        message = body.description or ""
        if len(message) < 10:
            from app.core.exceptions import ValidationFailed

            raise ValidationFailed("Please provide at least 10 characters describing the scam.")
        case = await CaseService(db).get_or_create(user, body.case_id, title="Community scam report")
        report = await CommunityIntelligenceService(
            db, settings.default_calling_code, settings
        ).submit(
            user,
            CommunityReportCreate(
                subject=message[:512], report_type=body.report_type, channel=channel,
                description=message, case_id=case.id,
            ),
        )
        report_id, case_id = report.id, case.id
    return GatewayReportOut(
        report_id=report_id, case_id=case_id,
        message="SafeGuard: thank you, your report details were received for review.",
    )


@router.get("/reports", response_model=list[GatewayReportHistoryOut])
async def gateway_report_history(
    msisdn: str, gateway: GatewayDep, db: DbDep, settings: SettingsDep,
) -> list[GatewayReportHistoryOut]:
    """Return all legacy and message-based reports submitted by this gateway phone."""
    user = await _caller(db, settings, msisdn)
    legacy_reports = await db.scalars(
        select(FraudReport).where(FraudReport.user_id == user.id)
    )
    community_reports = await db.scalars(
        select(CommunityReport).where(CommunityReport.reporter_id == user.id)
    )
    items: list[GatewayReportHistoryOut] = []
    for report in legacy_reports:
        title = _report_history_title(report.description, report.report_type)
        items.append(GatewayReportHistoryOut(
            title=title, status=report.status.value,
            created_at=report.created_at,
        ))
    for report in community_reports:
        title = _report_history_title(report.description, report.report_type)
        items.append(GatewayReportHistoryOut(
            title=title, status=report.status.value,
            created_at=report.created_at,
        ))
    return sorted(items, key=lambda item: item.created_at, reverse=True)


@router.post("/shield", response_model=GatewayShieldOut)
async def gateway_shield(body: GatewayShieldRequest, gateway: GatewayDep, db: DbDep, settings: SettingsDep) -> GatewayShieldOut:
    """Analyze an SMS for feature-phone channels. The caller is identified by the signed gateway MSISDN."""
    user = await _caller(db, settings, body.msisdn)
    channel = CommunicationChannel.SMS if gateway == "sms" else CommunicationChannel.USSD
    result = fraud_intelligence_orchestrator.analyze_message(
        channel=channel, text=body.text, phone_number=body.msisdn,
        default_calling_code=settings.default_calling_code,
    )
    communication, assessment, patterns = result.communication, result.shield, result.patterns
    identity, decision, intervention = result.identity, result.decision, result.intervention
    case = await CaseService(db).get_or_create(user, body.case_id, title="SMS safety analysis")
    record = ShieldAnalysis(
        user_id=user.id, case_id=case.id, risk_level=decision.result.level, risk_score=decision.result.score,
        ai_label=assessment.ai.label, ai_confidence=assessment.ai.confidence,
        indicators={"suspicious_keyword_score": assessment.indicators.suspicious_keyword_score,
                    "malicious_link_score": assessment.indicators.malicious_link_score,
                    "impersonation_score": assessment.indicators.impersonation_score,
                    "urgency_score": assessment.indicators.urgency_score,
                    "indicator_count": assessment.indicators.indicator_count},
        rules=[{"code": r.code, "label": r.label, "score": r.score, "evidence": list(r.evidence)}
               for r in assessment.rules],
        explanation=assessment.explanation,
    )
    db.add(record)
    await db.flush()
    network_service = NetworkService(db, settings.default_calling_code)
    await network_service.record_patterns(body.msisdn, patterns, case.id)
    await network_service.record_identity(body.msisdn, identity, case.id)
    await CaseService(db).add_internal_evidence(
        case,
        EvidenceCreate(evidence_type=EvidenceType.MESSAGE, source="gateway_shield",
                       value=None, confidence=decision.confidence,
                       details={"ai_label": assessment.ai.label,
                                "communication": communication.model_dump(mode="json"),
                                "patterns": [{"id": match.pattern_id, "probability": match.probability,
                                              "selected": match.selected} for match in patterns.matches],
                                "pattern_model_version": patterns.model_version,
                                "campaign_fingerprint": patterns.campaign_fingerprint,
                                "identity": identity.signals(),
                                "intervention": intervention.model_dump(mode="json"),
                                **decision.signals()}),
    )
    await FeedbackService(db).record_delivery(
        case_id=case.id, user=user, action=intervention.action, channel=channel.value,
    )
    await db.commit()
    short = f"SafeGuard {decision.result.level.value.upper()}: {assessment.ai.label}. Avoid links, PINs and codes."
    return GatewayShieldOut(analysis_id=record.id, case_id=case.id, risk_level=decision.result.level,
                            risk_score=decision.result.score, classification=assessment.ai.label,
                            short_message=short[:160], explanation=assessment.explanation,
                            risk_confidence=decision.confidence, recommended_action=decision.recommended_action,
                            identity=identity.signals(), intervention=intervention)


@router.post("/transaction-assess", response_model=GatewayTransactionAssessOut)
async def gateway_transaction_assess(body: GatewayTransactionAssessRequest, gateway: GatewayDep,
                                     db: DbDep, settings: SettingsDep, fraud: FraudServiceDep) -> GatewayTransactionAssessOut:
    user = await _caller(db, settings, body.msisdn)
    channel = CommunicationChannel.USSD if gateway == "ussd" else CommunicationChannel.SMS
    _lookup, _questionnaire, final, reasons, assessment_id, case_id, _decision, behaviour, intervention = await assess_transaction(
        user, body.model_copy(update={"channel": channel}), fraud
    )
    short = intervention.short_message
    return GatewayTransactionAssessOut(assessment_id=assessment_id, case_id=case_id, risk_level=final.level,
                                       risk_score=final.score, action=intervention.action,
                                       short_message=short[:160], reasons=list(reasons),
                                       behavior_signals=behaviour.signals, intervention=intervention)
