"""Recipient and transaction safety assessment."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.enums import EvidenceType, RiskLevel
from app.models import TransactionAssessment
from app.schemas.cases import EvidenceCreate
from app.schemas.fraud import TransactionContextIn
from app.schemas.transactions import (
    SocialEngineeringAnswers,
    TransactionAssessRequest,
    TransactionRecommendation,
)
from app.services.behavioural_intelligence import assess_transaction_behaviour
from app.services.case_service import CaseService
from app.services.communication import interpret
from app.services.feedback import FeedbackService
from app.services.intervention import intervention_engine
from app.services.risk_engine import assess as assess_risk
from app.services.scoring import (
    PhoneReputation,
    RiskResult,
    TransactionContext,
    level_for,
)

if TYPE_CHECKING:
    from app.services.fraud_service import FraudService


QUESTION_WEIGHTS = {
    "recipient_claims_to_be_institution": 0.22,
    "asked_for_pin_or_otp": 0.32,
    "pressured_to_act": 0.18,
    "asked_to_keep_transaction_secret": 0.16,
    "unexpected_prize_refund_or_investment": 0.20,
    "asked_to_install_app_or_give_remote_access": 0.28,
    "not_known_personally": 0.12,
}


@dataclass(frozen=True)
class QuestionnaireResult:
    score: float
    reasons: tuple[str, ...]


def assess_social_engineering(answers: SocialEngineeringAnswers) -> QuestionnaireResult:
    values = {
        key: float(getattr(answers, key))
        for key in QUESTION_WEIGHTS
        if key != "not_known_personally"
    }
    values["not_known_personally"] = float(not answers.user_knows_recipient_personally)
    score = round(min(1.0, sum(QUESTION_WEIGHTS[key] * value for key, value in values.items())), 4)
    reasons = []
    if answers.asked_for_pin_or_otp:
        reasons.append("recipient asked for a PIN or one-time code")
    if answers.asked_to_install_app_or_give_remote_access:
        reasons.append("recipient requested app installation or remote access")
    if answers.recipient_claims_to_be_institution:
        reasons.append("recipient claims to represent an institution")
    if answers.pressured_to_act:
        reasons.append("you were pressured to act quickly")
    if answers.asked_to_keep_transaction_secret:
        reasons.append("you were asked to keep the transaction secret")
    if answers.unexpected_prize_refund_or_investment:
        reasons.append("the transfer relates to an unexpected prize, refund or investment")
    if not answers.user_knows_recipient_personally:
        reasons.append("you do not know the recipient personally")
    return QuestionnaireResult(score=score, reasons=tuple(reasons))


def combine_transaction_risk(phone: RiskResult, questionnaire: QuestionnaireResult) -> RiskResult:
    """Legacy pure helper retained for compatibility, not used by API flows.

    Production transaction assessments use ``risk_engine.assess`` directly;
    this helper does not own a final product decision.
    """
    if questionnaire.score == 0:
        return phone
    phone_weight = -math.log1p(-min(phone.score, 0.999999))
    score = round(1 - math.exp(-(phone_weight + questionnaire.score)), 4)
    confidence = round(min(1.0, max(phone.confidence, questionnaire.score)), 4)
    return RiskResult(score=score, level=level_for(score), confidence=confidence)


def recommendation_for(level: RiskLevel, questionnaire_score: float) -> TransactionRecommendation:
    if level in (RiskLevel.HIGH, RiskLevel.CRITICAL) or questionnaire_score >= 0.55:
        return TransactionRecommendation(
            action="stop_and_contact_bank",
            title="Stop before sending",
            message="Do not transfer money. Contact your bank or mobile-money provider using an official channel.",
        )
    if level == RiskLevel.MEDIUM or questionnaire_score >= 0.25:
        return TransactionRecommendation(
            action="verify_recipient",
            title="Verify the recipient",
            message="Pause and verify the recipient independently before confirming this transaction.",
        )
    return TransactionRecommendation(
        action="proceed_with_caution",
        title="Proceed carefully",
        message="Check the recipient and amount. Never share your PIN or one-time code.",
    )


async def assess_transaction(user, body: TransactionAssessRequest, fraud: FraudService):
    questionnaire = assess_social_engineering(body.questionnaire)
    behaviour_text = " ".join(
        label for enabled, label in (
            (body.questionnaire.recipient_claims_to_be_institution, "recipient claims to be an institution"),
            (body.questionnaire.asked_for_pin_or_otp, "asked for PIN or OTP"),
            (body.questionnaire.pressured_to_act, "pressured to act quickly"),
            (body.questionnaire.asked_to_keep_transaction_secret, "asked to keep transaction secret"),
            (body.questionnaire.unexpected_prize_refund_or_investment, "unexpected prize refund or investment"),
            (body.questionnaire.asked_to_install_app_or_give_remote_access, "asked for remote access"),
            (not body.questionnaire.user_knows_recipient_personally, "recipient is not personally known"),
        ) if enabled
    )
    communication = interpret(channel=body.channel, phone_number=body.recipient_number,
                              default_calling_code=fraud.settings.default_calling_code)
    case = await CaseService(fraud.db).get_or_create(user, body.case_id, title="Transaction safety assessment")
    behaviour = await assess_transaction_behaviour(
        fraud.db, user, recipient_phone=communication.normalized_phone or body.recipient_number,
        amount=body.amount, currency=body.currency.upper(),
        explicit_new_recipient=body.new_recipient,
        explicit_amount_anomaly=body.amount_anomaly_score,
        explicit_velocity_anomaly=body.velocity_anomaly_score,
        explicit_recipient_mismatch=body.recipient_mismatch_score,
        explicit_high_value=body.high_value, settings=fraud.settings,
        text=behaviour_text,
    )
    transaction_context = TransactionContextIn(
        new_recipient=behaviour.new_recipient,
        amount_anomaly_score=behaviour.amount_anomaly_score,
        velocity_anomaly_score=behaviour.velocity_anomaly_score,
        recipient_mismatch_score=behaviour.recipient_mismatch_score,
        high_value=behaviour.high_value,
    )
    lookup = await fraud.lookup(
        user,
        body.recipient_number,
        transaction=transaction_context,
        case_id=case.id,
        channel=body.channel,
    )
    decision = assess_risk(
        PhoneReputation(
            verified_reporters=lookup.verified_reports,
            pending_reporters=lookup.pending_reports,
            blocklist_levels=(lookup.risk_level,) if lookup.override == "blocklist" else (),
            allowlisted=lookup.override == "allowlist",
        ),
        transaction=TransactionContext(
            new_recipient=behaviour.new_recipient,
            amount_anomaly_score=behaviour.amount_anomaly_score,
            velocity_anomaly_score=behaviour.velocity_anomaly_score,
            recipient_mismatch_score=behaviour.recipient_mismatch_score,
            high_value=behaviour.high_value,
        ),
        additional_hazard=questionnaire.score + min(
            0.2, max(behaviour.model_scores.values(), default=0.0) * 0.15,
        ),
        identity_score=0.65 if body.questionnaire.recipient_claims_to_be_institution else None,
        additional_provenance=("behavioural_intelligence", "behaviour_model", "identity_questionnaire"),
        additional_reasons=tuple(lookup.risk_reasons) + questionnaire.reasons + behaviour.reasons + tuple(
            f"behaviour model signal: {label}" for label in sorted(behaviour.model_scores)
        ) + (
            ("recipient identity claim is unverified",)
            if body.questionnaire.recipient_claims_to_be_institution else ()
        ),
        additional_contradictions=(
            ("claimed institution requests a secret or pressured action",)
            if body.questionnaire.recipient_claims_to_be_institution and (
                body.questionnaire.asked_for_pin_or_otp or body.questionnaire.pressured_to_act
            ) else ()
        ),
    )
    intervention = intervention_engine.plan(
        decision, channel=body.channel, stage=communication.stage,
        potential_harm=questionnaire.score >= 0.55,
    )
    final = decision.result
    reasons = list(decision.reasons)
    if behaviour.new_recipient:
        reasons.append("recipient is new")
    reasons = tuple(dict.fromkeys(reasons))
    recommendation = recommendation_for(final.level, questionnaire.score)
    record = TransactionAssessment(
        user_id=user.id, case_id=case.id,
        recipient_phone=lookup.phone,
        amount=body.amount,
        currency=body.currency.upper(),
        risk_level=final.level,
        risk_score=final.score,
        questionnaire_score=questionnaire.score,
        recommendation=recommendation.action,
        questionnaire=body.questionnaire.model_dump(),
        behavior_signals=behaviour.signals,
        reasons=list(reasons),
    )
    fraud.db.add(record)
    await fraud.db.flush()
    await CaseService(fraud.db).add_internal_evidence(
        case,
        EvidenceCreate(
            evidence_type=EvidenceType.TRANSACTION,
            source="transaction_intelligence",
            value=lookup.phone,
            confidence=decision.confidence,
            details={"questionnaire_score": questionnaire.score,
                     "behaviour": behaviour.signals,
                     "communication": communication.model_dump(mode="json"),
                     "intervention": intervention.model_dump(mode="json"), **decision.signals()},
        ),
    )
    await FeedbackService(fraud.db).record_delivery(
        case_id=case.id, user=user, action=intervention.action, channel=body.channel.value,
    )
    await fraud.db.commit()
    return lookup, questionnaire, final, reasons, record.id, case.id, decision, behaviour, intervention
