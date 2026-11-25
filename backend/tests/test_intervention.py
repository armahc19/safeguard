from app.enums import CommunicationChannel, ConversationStage, RiskLevel
from app.services import scoring
from app.services.intervention import intervention_engine, plan_intervention
from app.services.risk_engine import RiskDecision


def decision(level, score, confidence=0.8, unknowns=()):
    return RiskDecision(
        result=scoring.RiskResult(score, level, confidence),
        override=None, unknowns=tuple(unknowns),
    )


def test_high_risk_intervention_stops_and_escalates():
    plan = plan_intervention(decision(RiskLevel.HIGH, 0.7), channel=CommunicationChannel.APP)

    assert plan.action == "stop_and_escalate"
    assert plan.requires_confirmation is True
    assert plan.escalation == "bank_or_mobile_money_provider"


def test_low_confidence_intervention_asks_for_context():
    plan = plan_intervention(
        decision(RiskLevel.LOW, 0.0, confidence=0.0, unknowns=("message content was not provided",)),
        channel=CommunicationChannel.APP,
    )

    assert plan.action == "ask_for_more_information"


def test_gateway_intervention_is_short_and_handles_loss():
    plan = plan_intervention(
        decision(RiskLevel.MEDIUM, 0.4),
        channel=CommunicationChannel.USSD,
        stage=ConversationStage.LOSS,
    )

    assert plan.action == "report_and_escalate"
    assert len(plan.short_message) <= 160
    assert plan.message == plan.short_message


def test_compatibility_facade_and_central_engine_match():
    risk = decision(RiskLevel.HIGH, 0.7)
    from_facade = plan_intervention(risk, channel=CommunicationChannel.SMS)
    from_engine = intervention_engine.plan(risk, channel=CommunicationChannel.SMS)

    assert from_facade == from_engine
    assert intervention_engine.version == "intervention.v1"
