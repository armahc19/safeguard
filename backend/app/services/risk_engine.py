"""Unified, explainable risk assessment orchestration.

``scoring`` owns the bounded mathematical formula. This module owns the
decision contract: what evidence was used, what is missing, what conflicts,
where the evidence came from, and what SafeGuard should recommend next.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from app.enums import RiskLevel
from app.services import scoring


@dataclass(frozen=True)
class RiskDecision:
    result: scoring.RiskResult
    override: str | None
    components: dict[str, float] = field(default_factory=dict)
    reasons: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    recommended_action: str = "proceed_with_caution"

    @property
    def confidence(self) -> float:
        return self.result.confidence

    def signals(self) -> dict[str, object]:
        return {
            "risk_level": self.result.level.value,
            "risk_score": self.result.score,
            "confidence": self.confidence,
            "override": self.override,
            "components": self.components,
            "reasons": list(self.reasons),
            "evidence": list(self.evidence),
            "contradictions": list(self.contradictions),
            "unknowns": list(self.unknowns),
            "provenance": list(self.provenance),
            "recommended_action": self.recommended_action,
        }


def _bounded(value: float) -> float:
    try:
        return min(1.0, max(0.0, float(value))) if math.isfinite(float(value)) else 0.0
    except (TypeError, ValueError):
        return 0.0


def _combine_hazard(base: scoring.RiskResult, hazard: float) -> scoring.RiskResult:
    hazard = _bounded(hazard)
    if not hazard:
        return base
    base_weight = -math.log1p(-min(base.score, 0.999999))
    score = round(1 - math.exp(-(base_weight + hazard)), 4)
    confidence = round(min(1.0, base.confidence + min(0.4, hazard * 0.35)), 4)
    return scoring.RiskResult(score=score, level=scoring.level_for(score), confidence=confidence)


def _action(level: RiskLevel, confidence: float, unknowns: tuple[str, ...]) -> str:
    if level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        return "stop_and_contact_bank"
    if level == RiskLevel.MEDIUM:
        return "verify_recipient"
    if unknowns and confidence < 0.35:
        return "ask_for_more_information"
    return "proceed_with_caution"


def assess(
    phone: scoring.PhoneReputation,
    *,
    message: scoring.MessageIndicators | None = None,
    transaction: scoring.TransactionContext | None = None,
    additional_hazard: float = 0.0,
    additional_reasons: tuple[str, ...] = (),
    additional_provenance: tuple[str, ...] = (),
    additional_contradictions: tuple[str, ...] = (),
    model_label: str | None = None,
    model_confidence: float | None = None,
    identity_score: float | None = None,
    network_score: float | None = None,
    rules: tuple[str, ...] = (),
) -> RiskDecision:
    """Produce the shared risk decision used by every protection surface."""
    baseline = scoring.assess_risk(phone, message=message, transaction=transaction)
    result = baseline.result
    components = dict(baseline.components)
    reasons = list(baseline.reasons)
    evidence: list[str] = []
    provenance: list[str] = ["phone_reports"]
    contradictions: list[str] = []
    unknowns: list[str] = []

    if message is not None:
        provenance.append("message_indicators")
        evidence.extend(rule for rule in rules if rule)
        if message.indicator_count:
            evidence.append(f"{message.indicator_count} message indicator(s)")
        # A claimed mistaken transfer plus a return request, or a request for
        # a reversal code, is materially riskier than generic payment language.
        # These hazards are deliberately attached to named, explainable rules
        # rather than broad keywords such as “MoMo” or “send”.
        special_hazards = {
            "wrong_transfer_recovery": 0.60,
            "fake_transaction_alert": 0.50,
            "reversal_code_request": 0.70,
            "advance_fee_or_opportunity": 0.60,
            "messaging_account_takeover": 0.50,
            "emergency_impersonation_payment": 0.60,
            "sim_swap_account_takeover": 0.65,
            "social_engineering_payment": 0.50,
            "fake_deposit_alert": 0.62,
            "fake_job_or_task": 0.58,
            "romance_or_customs_payment": 0.58,
            "money_mule_recruitment": 0.55,
            "otp_social_engineering": 0.68,
            "malicious_attachment_or_code": 0.58,
            "local_language_account_takeover": 0.62,
            "account_blocking_impersonation": 0.62,
            "compromised_wallet": 0.72,
            "remote_access_financial": 0.58,
            "investment_bait": 0.55,
            "government_data_harvest": 0.58,
            "reported_account_loss": 0.78,
            "repeat_payment_after_transfer": 0.55,
        }
        for rule in rules:
            hazard = special_hazards.get(rule)
            if hazard is not None:
                additional_hazard += hazard
                reasons.append(f"high-risk MoMo recovery signal: {rule}")
        if {"credential_request", "impersonation"}.issubset(rules):
            additional_hazard += 0.42
            reasons.append("credential request is paired with provider impersonation")
        if {"credential_request", "urgency"}.issubset(rules):
            additional_hazard += 0.30
            reasons.append("credential request is paired with urgency")
        if "payment_request" in rules and any(
            rule in rules for rule in (
                "urgency", "suspicious_link", "wrong_transfer_recovery",
                "reversal_code_request", "fake_transaction_alert",
            )
        ):
            additional_hazard += 0.35
            reasons.append("payment request is paired with urgency or recovery evidence")
        if {"payment_request", "impersonation"}.issubset(rules):
            additional_hazard += 0.25
            reasons.append("payment request is paired with an identity claim")
        if "suspicious_link" in rules and any(rule in rules for rule in ("payment_request", "urgency")):
            additional_hazard += 0.25
            reasons.append("suspicious link is paired with a payment or urgency cue")
    else:
        unknowns.append("message content was not provided")

    if transaction is not None:
        provenance.append("transaction_context")
        evidence.append("transaction context supplied")
    else:
        unknowns.append("transaction context was not provided")

    if identity_score is None:
        unknowns.append("identity verification is not available")
    else:
        provenance.append("identity_intelligence")
        components["identity_intelligence"] = _bounded(identity_score)
        additional_hazard += _bounded(identity_score) * 0.35

    if network_score is None:
        unknowns.append("fraud network context is not available")
    else:
        provenance.append("fraud_network_intelligence")
        components["fraud_network_intelligence"] = _bounded(network_score)
        additional_hazard += _bounded(network_score) * 0.35

    if model_label is not None:
        provenance.append("model_classification")
        evidence.append(f"model classification: {model_label}")
        if model_confidence is not None:
            components["model_confidence"] = _bounded(model_confidence)
    elif message is not None:
        unknowns.append("model classification was not provided")

    if additional_hazard:
        components["additional_evidence"] = round(_bounded(additional_hazard), 4)
        result = _combine_hazard(result, additional_hazard)
    reasons.extend(additional_reasons)
    provenance.extend(additional_provenance)
    contradictions.extend(additional_contradictions)

    if phone.allowlisted and (message is not None or transaction is not None) and result.level != RiskLevel.LOW:
        contradictions.append("allowlist conflicts with content or transaction warning signs")
    if model_label == "benign" and message is not None and message.indicator_count:
        contradictions.append("model labelled the input benign despite rule indicators")
    if phone.verified_reporters == 0 and message is not None and message.indicator_count:
        contradictions.append("content is suspicious even though the number has no verified reports")

    reasons = list(dict.fromkeys(reasons))
    evidence = list(dict.fromkeys(evidence))
    provenance = list(dict.fromkeys(provenance))
    unknowns = list(dict.fromkeys(unknowns))
    contradictions = list(dict.fromkeys(contradictions))
    if contradictions:
        components["contradictions"] = min(1.0, len(contradictions) * 0.1)
    if override := baseline.override:
        result = baseline.result
        components["final_score"] = result.score
    else:
        components["final_score"] = result.score
    return RiskDecision(
        result=result, override=override, components=components, reasons=tuple(reasons),
        evidence=tuple(evidence), contradictions=tuple(contradictions), unknowns=tuple(unknowns),
        provenance=tuple(provenance), recommended_action=_action(result.level, result.confidence, tuple(unknowns)),
    )


def reassess_external_result(
    *,
    score: float,
    reported_level: RiskLevel,
    confidence: float,
    reasons: tuple[str, ...] = (),
    unknowns: tuple[str, ...] = (),
) -> RiskDecision:
    """Re-enter the canonical engine for an upstream assessment.

    This compatibility boundary is used when an older client already has a
    score. The client-provided level is treated as evidence only; the engine
    recalculates the final level from the bounded score and records any
    disagreement.
    """
    score = _bounded(score)
    hazard = -math.log1p(-min(score, 0.999999)) if score else 0.0
    contradictions = () if reported_level == scoring.level_for(score) else (
        "upstream risk level disagreed with the canonical score-derived level",
    )
    decision = assess(
        scoring.PhoneReputation(),
        additional_hazard=hazard,
        additional_reasons=reasons,
        additional_provenance=("external_assessment_input",),
        additional_contradictions=contradictions,
    )
    # Confidence is bounded upstream evidence, but the risk level/score above
    # remain exclusively owned by this engine.
    components = dict(decision.components)
    components["external_confidence"] = _bounded(confidence)
    return RiskDecision(
        result=decision.result, override=decision.override, components=components,
        reasons=decision.reasons, evidence=decision.evidence,
        contradictions=decision.contradictions, unknowns=decision.unknowns + tuple(unknowns),
        provenance=decision.provenance, recommended_action=decision.recommended_action,
    )
