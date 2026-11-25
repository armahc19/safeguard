"""The single composition point for SafeGuard fraud intelligence.

Individual intelligence services remain small and testable. This module owns
the order in which they are applied and produces one shared result for every
message-like channel (conversation, SMS, USSD and an opted-in call transcript).
Routes may persist or format the result, but they must not re-compose the
intelligence pipeline themselves.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.enums import CommunicationChannel
from app.schemas.communication import CommunicationContext
from app.schemas.intervention import InterventionPlan
from app.services import scoring
from app.services.communication import communication_intelligence
from app.services.identity_intelligence import IdentityAnalysis, assess_identity
from app.services.intervention import intervention_engine
from app.services.model_runtime import ModelPrediction, unified_model_runtime
from app.services.pattern_intelligence import PatternAnalysis, analyze_patterns
from app.services.risk_engine import RiskDecision
from app.services.risk_engine import assess as assess_risk
from app.services.shield import ShieldAssessment, analyze_sms


@dataclass(frozen=True)
class FraudIntelligenceResult:
    """Shared output consumed by API, conversation and channel adapters."""

    communication: CommunicationContext
    shield: ShieldAssessment
    patterns: PatternAnalysis
    behaviour: ModelPrediction
    identity: IdentityAnalysis
    decision: RiskDecision
    intervention: InterventionPlan


class FraudIntelligenceOrchestrator:
    """Coordinate communication, classifiers, risk and intervention once."""

    version = "fraud-intelligence.v1"

    def analyze_message(
        self,
        *,
        text: str,
        channel: CommunicationChannel = CommunicationChannel.APP,
        phone_number: str | None = None,
        default_calling_code: str = "233",
        phone_reputation: scoring.PhoneReputation | None = None,
        additional_hazard: float = 0.0,
        additional_reasons: tuple[str, ...] = (),
        additional_provenance: tuple[str, ...] = (),
        additional_contradictions: tuple[str, ...] = (),
    ) -> FraudIntelligenceResult:
        """Run the canonical communication-to-intervention pipeline."""
        communication = communication_intelligence.interpret(
            channel=channel,
            text=text,
            phone_number=phone_number,
            default_calling_code=default_calling_code,
        )
        normalized = communication.normalized_text or text
        shield = analyze_sms(normalized)
        patterns = analyze_patterns(normalized, shield)
        behaviour = unified_model_runtime.behaviour_classifier.predict(normalized)
        identity = assess_identity(normalized, phone_number=phone_number)
        behaviour_hazard = min(0.2, max(behaviour.scores.values(), default=0.0) * 0.15)
        behaviour_reasons = tuple(
            f"behaviour model signal: {label}"
            for label in sorted(behaviour.scores)
        )
        indicators = scoring.MessageIndicators(
            suspicious_keyword_score=shield.indicators.suspicious_keyword_score,
            malicious_link_score=shield.indicators.malicious_link_score,
            impersonation_score=shield.indicators.impersonation_score,
            urgency_score=shield.indicators.urgency_score,
            indicator_count=shield.indicators.indicator_count,
        )
        decision = assess_risk(
            phone_reputation or scoring.PhoneReputation(),
            message=indicators,
            model_label=shield.ai.label,
            model_confidence=shield.ai.confidence,
            rules=tuple(rule.code for rule in shield.rules),
            additional_hazard=additional_hazard + patterns.hazard + behaviour_hazard,
            additional_reasons=patterns.reasons + identity.reasons + behaviour_reasons + additional_reasons,
            additional_provenance=identity.provenance + ("behaviour_model",) + additional_provenance,
            additional_contradictions=identity.contradictions + additional_contradictions,
            identity_score=identity.identity_score if identity.claimed_identity else None,
        )
        intervention = intervention_engine.plan(
            decision, channel=channel, stage=communication.stage,
        )
        return FraudIntelligenceResult(
            communication=communication,
            shield=shield,
            patterns=patterns,
            behaviour=behaviour,
            identity=identity,
            decision=decision,
            intervention=intervention,
        )


fraud_intelligence_orchestrator = FraudIntelligenceOrchestrator()


def analyze_message(**kwargs) -> FraudIntelligenceResult:
    """Compatibility facade for callers that prefer a function API."""
    return fraud_intelligence_orchestrator.analyze_message(**kwargs)
