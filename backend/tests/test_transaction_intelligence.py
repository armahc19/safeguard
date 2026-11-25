from app.enums import RiskLevel
from app.schemas.transactions import SocialEngineeringAnswers
from app.services.behavioural_intelligence import BehaviourAssessment
from app.services.scoring import RiskResult
from app.services.transaction_intelligence import (
    assess_social_engineering,
    combine_transaction_risk,
    recommendation_for,
)


def test_social_engineering_questionnaire_is_explainable():
    result = assess_social_engineering(SocialEngineeringAnswers(
        recipient_claims_to_be_institution=True,
        asked_for_pin_or_otp=True,
        pressured_to_act=True,
        user_knows_recipient_personally=False,
    ))

    assert result.score >= 0.5
    assert "recipient asked for a PIN or one-time code" in result.reasons
    assert "you were pressured to act quickly" in result.reasons


def test_questionnaire_raises_recipient_risk():
    result = combine_transaction_risk(
        RiskResult(0.0, RiskLevel.LOW, 0.0),
        assess_social_engineering(SocialEngineeringAnswers(asked_for_pin_or_otp=True)),
    )
    assert result.score > 0 and result.level == RiskLevel.MEDIUM


def test_recommendations_are_actionable():
    assert recommendation_for(RiskLevel.CRITICAL, 0).action == "stop_and_contact_bank"
    assert recommendation_for(RiskLevel.LOW, 0.3).action == "verify_recipient"
    assert recommendation_for(RiskLevel.LOW, 0).action == "proceed_with_caution"


def test_behavioural_snapshot_is_explicit_and_non_identity_based():
    assessment = BehaviourAssessment(
        recipient_seen=False, recent_assessments=0, amount_baseline=None,
        amount_anomaly_score=0.0, velocity_anomaly_score=0.0,
        recipient_mismatch_score=0.0, new_recipient=True, high_value=False,
        reasons=("recipient is new based on assessment history",),
    )

    assert assessment.signals["source"] == "transaction_assessment_history"
    assert assessment.signals["new_recipient"] is True
