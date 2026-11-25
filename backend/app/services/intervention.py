"""Turn explainable risk decisions into safe, channel-specific actions."""
from app.enums import CommunicationChannel, ConversationStage, RiskLevel
from app.schemas.intervention import InterventionPlan
from app.services.risk_engine import RiskDecision


class InterventionEngine:
    """Single owner of SafeGuard's protective actions and channel wording."""

    version = "intervention.v1"

    def plan(
        self,
        decision: RiskDecision,
        *,
        channel: CommunicationChannel = CommunicationChannel.APP,
        stage: ConversationStage = ConversationStage.UNCLEAR,
        potential_harm: bool = False,
    ) -> InterventionPlan:
        level = decision.result.level
        if stage == ConversationStage.LOSS:
            action = "report_and_escalate"
            title = "Secure your account and report it"
            message = "If money or credentials were already shared, contact your bank or mobile-money provider through an official channel now."
            steps = ["Stop further contact", "Secure the account through official support", "Report the incident"]
            escalation = "bank_or_mobile_money_provider"
            requires_confirmation = False
            reason = "the case indicates that a harmful action may already have happened"
        elif level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            action = "stop_and_escalate"
            title = "Stop before you respond"
            message = "Do not send money or share your PIN, OTP, password, or codes. Contact your bank or provider using an official channel."
            steps = ["Stop the call or close the message", "Do not open links or approve a transfer", "Verify through official support"]
            escalation = "bank_or_mobile_money_provider"
            requires_confirmation = True
            reason = "the combined evidence indicates a high likelihood of harm"
        elif level == RiskLevel.MEDIUM or potential_harm:
            action = "verify_independently"
            title = "Pause and verify independently"
            message = "Pause before acting. Confirm the person, number, and request through a trusted official channel."
            steps = ["Do not use the contact details in the message", "Check the official app or statement", "Confirm the recipient separately"]
            escalation = None
            requires_confirmation = True
            reason = "there are meaningful warning signs, but more independent verification is needed"
        elif decision.unknowns and decision.confidence < 0.35:
            action = "ask_for_more_information"
            title = "Tell us a little more"
            message = "I do not have enough context to judge this safely. What did the person ask you to do?"
            steps = ["Do not share a PIN or OTP while checking"]
            escalation = None
            requires_confirmation = False
            reason = "important context is missing and confidence is low"
        else:
            action = "inform"
            title = "Stay careful"
            message = "No strong warning sign was found. Still verify unexpected requests and never share your PIN or one-time code."
            steps = ["Use official contact details", "Keep PINs and one-time codes private"]
            escalation = None
            requires_confirmation = False
            reason = "no high-confidence intervention trigger was found"

        short = _short_message(action, level)
        if channel in (CommunicationChannel.USSD, CommunicationChannel.SMS):
            message = short
            steps = steps[:2]
        return InterventionPlan(
            action=action, risk_level=level, title=title, message=message,
            short_message=short, steps=steps, channel=channel,
            requires_confirmation=requires_confirmation, escalation=escalation, reason=reason,
        )


intervention_engine = InterventionEngine()


def plan_intervention(
    decision: RiskDecision,
    *,
    channel: CommunicationChannel = CommunicationChannel.APP,
    stage: ConversationStage = ConversationStage.UNCLEAR,
    potential_harm: bool = False,
) -> InterventionPlan:
    """Compatibility facade delegating to the central intervention engine."""
    return intervention_engine.plan(
        decision, channel=channel, stage=stage, potential_harm=potential_harm,
    )


def _short_message(action: str, level: RiskLevel) -> str:
    if action == "report_and_escalate":
        return "SafeGuard: stop contact. Secure your account and call your bank/provider through an official channel."
    if action == "stop_and_escalate":
        return f"SafeGuard {level.value.upper()}: STOP. Do not pay or share PIN/OTP. Contact your bank/provider officially."
    if action == "verify_independently":
        return "SafeGuard: pause. Verify the person, number and request through an official channel before acting."
    if action == "ask_for_more_information":
        return "SafeGuard: tell us what the caller or message asked you to do. Do not share a PIN or OTP."
    return "SafeGuard: no strong warning found. Stay careful and never share your PIN or one-time code."


def plan_from_decision(decision: RiskDecision, *, channel: CommunicationChannel, stage: ConversationStage = ConversationStage.UNCLEAR, potential_harm: bool = False) -> InterventionPlan:
    return intervention_engine.plan(decision, channel=channel, stage=stage, potential_harm=potential_harm)
