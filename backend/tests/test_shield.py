import pytest

from app.enums import RiskLevel
from app.services.shield import analyze_sms, preprocess_sms


def test_preprocess_normalizes_unicode_spacing_and_extracts_urls():
    message = preprocess_sms("  PAY\u200b NOW: https://EXAMPLE.com/login  ")
    assert message.normalized == "pay now: https://example.com/login"
    assert message.urls == ("https://example.com/login",)


def test_shield_explains_high_risk_sms():
    result = analyze_sms(
        "URGENT! Your bank account will close. Share your OTP now and verify at http://bit.ly/login"
    )

    assert result.risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert result.ai.label in ("account_takeover", "phishing")
    assert {rule.code for rule in result.rules} >= {"credential_request", "impersonation", "urgency", "suspicious_link"}
    assert "AI classification" in result.explanation
    assert result.indicators.malicious_link_score > 0


def test_shield_does_not_overstate_plain_message():
    result = analyze_sms("Your meeting is scheduled for tomorrow at 10am.")

    assert result.ai.label == "benign"
    assert result.risk.level == RiskLevel.LOW
    assert result.rules == ()


def test_shield_detects_wrong_transfer_recovery_scam():
    result = analyze_sms(
        "I mistakenly sent GHS 500 to your MoMo. Please send it back to this number."
    )

    assert "wrong_transfer_recovery" in {rule.code for rule in result.rules}
    assert result.risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_shield_detects_reversal_code_request():
    result = analyze_sms(
        "MTN sent you a reversal code. Read the code to me so I can reverse the money."
    )

    assert "reversal_code_request" in {rule.code for rule in result.rules}
    assert result.risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_shield_does_not_flag_legitimate_pin_warning_as_credential_theft():
    result = analyze_sms(
        "MTN will never ask for your MoMo PIN or OTP. Do not share either with anyone."
    )

    assert "credential_request" not in {rule.code for rule in result.rules}


@pytest.mark.parametrize("message", [
    "MTN MoMo: Your transaction of GHS 200 to Ama Mensah was successful. Balance GHS 312.40.",
    "Maame, me send GHS 100 give you for chop money. Check your MoMo.",
    "MTN will never ask for your MoMo PIN or OTP. Report fraud on 419.",
])
def test_shield_keeps_ordinary_momo_messages_low_risk(message):
    result = analyze_sms(message)

    assert result.risk.level == RiskLevel.LOW
    assert "impersonation" not in {rule.code for rule in result.rules}


def test_reversal_code_rule_requires_reversal_context():
    result = analyze_sms(
        "Your bank sent OTP 482916 for transfer. Do not share this code with anyone."
    )

    assert "reversal_code_request" not in {rule.code for rule in result.rules}


@pytest.mark.parametrize("message, rule", [
    (
        "Congratulations! You won GHS 5,000. Pay GHS 200 processing fee to claim.",
        "advance_fee_or_opportunity",
    ),
    (
        "My WhatsApp code came to your phone by mistake. Please forward it quickly.",
        "messaging_account_takeover",
    ),
    (
        "This is your cousin. I lost my phone and need GHS 800 urgently for an accident.",
        "emergency_impersonation_payment",
    ),
    (
        "Your SIM will be deactivated. Reply with your Ghana Card number and PIN.",
        "sim_swap_account_takeover",
    ),
])
def test_shield_escalates_category_specific_social_engineering(message, rule):
    result = analyze_sms(message)

    assert rule in {item.code for item in result.rules}
    assert result.risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


@pytest.mark.parametrize("message, rule", [
    (
        "We are recruiting part-time workers. Earn GHS 500 daily liking posts on WhatsApp to start immediately.",
        "fake_job_or_task",
    ),
    (
        "This is a cash-in notification. You have received GHS 500. Reference: Cash In.",
        "fake_deposit_alert",
    ),
    (
        "Fast Loans: your loan is approved. Pay GHS 100 insurance to receive it today.",
        "advance_fee_or_opportunity",
    ),
    (
        "A WhatsApp code came to your phone by mistake. Please read it to me.",
        "messaging_account_takeover",
    ),
])
def test_ghana_specific_fraud_categories_escalate(message, rule):
    result = analyze_sms(message)

    assert rule in {item.code for item in result.rules}
    assert result.risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


@pytest.mark.parametrize("message", [
    "Dear customer, your statement is ready. Sign in using your bank's official app.",
    "MTN will never ask for your MoMo PIN or OTP. Report fraud on 419.",
    "Chale, this number asked for my OTP. I no give am.",
    "Bro, send me the GHS 50 waakye and transport money on my MTN MoMo.",
])
def test_genuine_advisories_and_personal_messages_stay_low(message):
    result = analyze_sms(message)

    assert result.risk.level == RiskLevel.LOW


def test_empty_sms_is_rejected():
    with pytest.raises(ValueError):
        analyze_sms("   ")
