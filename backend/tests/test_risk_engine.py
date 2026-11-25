from app.enums import RiskLevel
from app.services import scoring
from app.services.risk_engine import assess, reassess_external_result


def test_engine_reports_unknowns_when_context_is_missing():
    decision = assess(scoring.PhoneReputation())

    assert decision.result.level == RiskLevel.LOW
    assert "message content was not provided" in decision.unknowns
    assert "transaction context was not provided" in decision.unknowns
    assert decision.recommended_action == "ask_for_more_information"
    assert "phone_reports" in decision.provenance


def test_engine_combines_message_evidence_and_recommends_stopping():
    decision = assess(
        scoring.PhoneReputation(),
        message=scoring.MessageIndicators(
            suspicious_keyword_score=0.9,
            malicious_link_score=0.9,
            impersonation_score=0.9,
            urgency_score=0.8,
            indicator_count=4,
        ),
        model_label="phishing",
        model_confidence=0.9,
        rules=("credential_request", "suspicious_link", "impersonation"),
    )

    assert decision.result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert decision.recommended_action == "stop_and_contact_bank"
    assert "model classification: phishing" in decision.evidence
    assert "message_indicators" in decision.provenance


def test_engine_exposes_contradictions_and_respects_blocklist():
    decision = assess(
        scoring.PhoneReputation(
            blocklist_levels=(RiskLevel.HIGH,),
            allowlisted=True,
        ),
        message=scoring.MessageIndicators(indicator_count=1),
        model_label="benign",
    )

    assert decision.override == "blocklist"
    assert decision.result.level == RiskLevel.HIGH
    assert decision.contradictions
    assert "allowlist conflicts with content or transaction warning signs" in decision.contradictions


def test_external_assessment_is_recalculated_by_engine():
    decision = reassess_external_result(
        score=0.8,
        reported_level=RiskLevel.LOW,
        confidence=0.9,
        reasons=("upstream evidence",),
    )

    assert decision.result.level == RiskLevel.HIGH
    assert 0.5 <= decision.result.score <= 1.0
    assert "external_assessment_input" in decision.provenance
    assert decision.contradictions
