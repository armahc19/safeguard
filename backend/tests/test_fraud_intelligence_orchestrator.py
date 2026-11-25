from app.enums import CommunicationChannel, RiskLevel
from app.services.fraud_intelligence_orchestrator import (
    FraudIntelligenceOrchestrator,
)
from app.services.scoring import PhoneReputation


def test_orchestrator_returns_one_shared_message_result():
    result = FraudIntelligenceOrchestrator().analyze_message(
        text="MTN support says send your PIN now to unblock your account",
        channel=CommunicationChannel.SMS,
        phone_number="0241234567",
    )

    assert result.communication.channel == CommunicationChannel.SMS
    assert result.shield.ai.label in {"account_takeover", "suspicious"}
    assert result.patterns.selected
    assert result.identity.claimed_identity == "MTN Mobile Money"
    assert result.decision.result.level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert result.intervention.action in {"stop_and_escalate", "report_and_escalate"}
    assert "model_classification" in result.decision.provenance


def test_orchestrator_accepts_shared_number_reputation():
    result = FraudIntelligenceOrchestrator().analyze_message(
        text="Please verify the recipient before paying.",
        phone_reputation=PhoneReputation(verified_reporters=3),
    )

    assert result.decision.result.score > 0
    assert "phone_reports" in result.decision.provenance
