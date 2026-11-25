from app.enums import CommunicationChannel, CommunicationIntent, ConversationStage
from app.services.communication import communication_intelligence, interpret


def test_interpret_normalises_sms_and_detects_social_engineering():
    context = interpret(
        channel=CommunicationChannel.SMS,
        text="  URGENT! Share your OTP now.  ",
        phone_number="024 123 4567",
    )

    assert context.normalized_text == "urgent! share your otp now."
    assert context.normalized_phone == "+233241234567"
    assert context.intent == CommunicationIntent.UNKNOWN
    assert context.stage == ConversationStage.MANIPULATION
    assert "never retain PINs, OTPs or passwords" in context.privacy_notes
    assert context.contract_version == "communication.v1"
    assert context.raw_text_storage == "derived_signals_only"


def test_interpret_routes_common_user_intents():
    assert interpret(text="Please report this scam").intent == CommunicationIntent.REPORT_SCAM
    assert interpret(text="Can I send money to this recipient?").intent == CommunicationIntent.TRANSACTION_CHECK
    assert interpret(text="Hi there").intent == CommunicationIntent.GREETING


def test_interpret_detects_mixed_language_hint_and_call_privacy():
    context = interpret(channel=CommunicationChannel.CALL, text="Mepa, someone called me")

    assert context.language == "twi_or_mixed"
    assert "call content requires explicit user consent" in context.privacy_notes
    assert context.consent_required is True


def test_function_facade_and_shared_service_return_same_context():
    via_function = interpret(text="Please report this scam")
    via_service = communication_intelligence.interpret(text="Please report this scam")

    assert via_function == via_service
