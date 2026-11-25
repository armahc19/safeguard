"""Risk scoring for phone numbers. Pure functions: no database, easy to test and tune.

Automatic score from reports, counting DISTINCT reporters (ten reports from one person count once):

    score = 1 - exp(-(VERIFIED_WEIGHT * verified_reporters + PENDING_WEIGHT * pending_reporters))

    verified: 1 -> 0.45 (medium)   2 -> 0.70 (high)   3 -> 0.83 (critical)
    pending : 1 -> 0.14 (low)      3 -> 0.36 (medium) 6 -> 0.59 (high)

Manual blocklist / allowlist indicators then override the automatic result (see `combine`).
"""
import math
from dataclasses import dataclass, field

from app.enums import RiskLevel

VERIFIED_WEIGHT = 0.6
PENDING_WEIGHT = 0.15

# lower bound of each level; the order here is also the severity order
LEVEL_FLOORS: dict[RiskLevel, float] = {
    RiskLevel.LOW: 0.0,
    RiskLevel.MEDIUM: 0.25,
    RiskLevel.HIGH: 0.5,
    RiskLevel.CRITICAL: 0.75,
}
_ORDER = list(LEVEL_FLOORS)


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: RiskLevel
    confidence: float


@dataclass(frozen=True)
class MessageIndicators:
    """Signals extracted from an SMS, chat message, URL or call transcript.

    All scores are probabilities/evidence strengths in the inclusive range 0..1.
    Keeping the extractor separate from this module lets a rules engine or an ML
    model produce the signals without coupling it to the risk calculation.
    """

    suspicious_keyword_score: float = 0.0
    malicious_link_score: float = 0.0
    impersonation_score: float = 0.0
    urgency_score: float = 0.0
    indicator_count: int = 0


@dataclass(frozen=True)
class TransactionContext:
    """Contextual signals for a payment or transfer risk check."""

    new_recipient: bool = False
    amount_anomaly_score: float = 0.0
    velocity_anomaly_score: float = 0.0
    recipient_mismatch_score: float = 0.0
    high_value: bool = False


@dataclass(frozen=True)
class PhoneReputation:
    """The phone-level evidence used by the assessment engine."""

    verified_reporters: int = 0
    pending_reporters: int = 0
    blocklist_levels: tuple[RiskLevel, ...] = ()
    allowlisted: bool = False


@dataclass(frozen=True)
class AssessmentResult:
    """Full risk decision, including explainable component contributions."""

    result: RiskResult
    override: str | None
    components: dict[str, float] = field(default_factory=dict)
    reasons: tuple[str, ...] = ()


# Additional evidence is expressed as hazard weight and combined with the phone
# reputation using the same saturating curve as the report score. This prevents
# the sum from exceeding 1 while ensuring independent signals reinforce one
# another rather than replacing existing report evidence.
MESSAGE_WEIGHTS = {
    "suspicious_keywords": 0.35,
    "malicious_link": 0.55,
    "impersonation": 0.45,
    "urgency": 0.20,
    "indicator_count": 0.05,
}
TRANSACTION_WEIGHTS = {
    "new_recipient": 0.20,
    "amount_anomaly": 0.35,
    "velocity_anomaly": 0.30,
    "recipient_mismatch": 0.35,
    "high_value": 0.10,
}


def level_for(score: float) -> RiskLevel:
    level = RiskLevel.LOW
    for candidate, floor in LEVEL_FLOORS.items():
        if score >= floor:
            level = candidate
    return level


def max_level(levels: list[RiskLevel]) -> RiskLevel:
    return max(levels, key=_ORDER.index)


def score_reports(verified_reporters: int, pending_reporters: int) -> RiskResult:
    weight = VERIFIED_WEIGHT * max(verified_reporters, 0) + PENDING_WEIGHT * max(pending_reporters, 0)
    score = round(1 - math.exp(-weight), 4)
    confidence = round(min(1.0, 0.2 * verified_reporters + 0.05 * pending_reporters), 4)
    return RiskResult(score=score, level=level_for(score), confidence=confidence)


def _bounded(value: float, *, default: float = 0.0) -> float:
    """Return a safe finite score in the inclusive range 0..1."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return default
    return value if math.isfinite(value) and 0.0 <= value <= 1.0 else default


def assess_risk(
    phone: PhoneReputation,
    *,
    message: MessageIndicators | None = None,
    transaction: TransactionContext | None = None,
) -> AssessmentResult:
    """Assess a number using phone reputation, content and transaction context.

    The phone report score remains the baseline. Message and transaction signals
    add hazard weight, so a single weak signal cannot make a number critical but
    several strong, independent signals can. Manual blocklists and allowlists
    retain their existing precedence rules.
    """
    phone_result = score_reports(phone.verified_reporters, phone.pending_reporters)
    result, override = combine(phone_result, list(phone.blocklist_levels), phone.allowlisted)
    components = {"phone_reputation": phone_result.score}
    reasons: list[str] = []

    # Manual decisions are authoritative. Still report the evidence components
    # for auditability, but do not let content/context weaken an override.
    if override == "blocklist":
        reasons.append("number is on the blocklist")
    elif override == "allowlist":
        reasons.append("number is on the allowlist")

    extra_weight = 0.0
    if message is not None:
        message_values = {
            "suspicious_keywords": _bounded(message.suspicious_keyword_score),
            "malicious_link": _bounded(message.malicious_link_score),
            "impersonation": _bounded(message.impersonation_score),
            "urgency": _bounded(message.urgency_score),
            "indicator_count": _bounded(min(max(message.indicator_count, 0), 4) / 4),
        }
        message_weight = sum(MESSAGE_WEIGHTS[k] * v for k, v in message_values.items())
        components["message_indicators"] = round(message_weight, 4)
        extra_weight += message_weight
        if message_values["malicious_link"] >= 0.7:
            reasons.append("message contains a high-risk link")
        if message_values["impersonation"] >= 0.7:
            reasons.append("message resembles impersonation")
        if message_values["suspicious_keywords"] >= 0.7:
            reasons.append("message contains suspicious scam language")

    if transaction is not None:
        transaction_values = {
            "new_recipient": float(transaction.new_recipient),
            "amount_anomaly": _bounded(transaction.amount_anomaly_score),
            "velocity_anomaly": _bounded(transaction.velocity_anomaly_score),
            "recipient_mismatch": _bounded(transaction.recipient_mismatch_score),
            "high_value": float(transaction.high_value),
        }
        transaction_weight = sum(TRANSACTION_WEIGHTS[k] * v for k, v in transaction_values.items())
        components["transaction_context"] = round(transaction_weight, 4)
        extra_weight += transaction_weight
        if transaction.new_recipient:
            reasons.append("recipient is new")
        if transaction_values["amount_anomaly"] >= 0.7:
            reasons.append("transaction amount is unusual")
        if transaction_values["velocity_anomaly"] >= 0.7:
            reasons.append("transaction velocity is unusual")
        if transaction_values["recipient_mismatch"] >= 0.7:
            reasons.append("recipient does not match expected transaction context")

    if override is None and extra_weight:
        score = round(1 - math.exp(-( -math.log1p(-phone_result.score) + extra_weight)), 4)
        confidence = round(min(1.0, phone_result.confidence + min(0.4, extra_weight * 0.35)), 4)
        result = RiskResult(score=score, level=level_for(score), confidence=confidence)
    elif override is not None:
        components["final_score"] = result.score

    components["final_score"] = result.score
    return AssessmentResult(result=result, override=override, components=components, reasons=tuple(reasons))


def combine(auto: RiskResult, blocklist_levels: list[RiskLevel], allowlisted: bool) -> tuple[RiskResult, str | None]:
    """Apply manual overrides. Blocklist beats allowlist: when in doubt, warn the user.

    Returns (result, override) where override is "blocklist", "allowlist" or None.
    """
    if blocklist_levels:
        level = max_level(blocklist_levels)
        score = max(auto.score, LEVEL_FLOORS[level])
        return RiskResult(score=score, level=level_for(score), confidence=1.0), "blocklist"
    if allowlisted:
        return RiskResult(score=0.0, level=RiskLevel.LOW, confidence=1.0), "allowlist"
    return auto, None


# ---------------------------------------------------------------- user-facing text
_ADVICE = {
    RiskLevel.LOW: "No strong warning signs, but never share PINs or one-time codes with anyone.",
    RiskLevel.MEDIUM: "Be careful. Do not send money or share PINs or one-time codes with this number.",
    RiskLevel.HIGH: "Likely a scam number. Do not send money or share any personal or account details.",
    RiskLevel.CRITICAL: "Very likely a scam. Hang up or ignore it, and do not send money or share any details.",
}


def advice_for(level: RiskLevel) -> str:
    return _ADVICE[level]


def short_message(number: str, level: RiskLevel, *, known: bool, verified: int, pending: int,
                  override: str | None) -> str:
    """One-liner for USSD / SMS screens (<= 160 chars, GSM-7 safe)."""
    if override == "allowlist":
        msg = f"SafeGuard: {number} is a known trusted number."
    elif level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        msg = f"SafeGuard DANGER: {number} is a likely scam number. Do not pay or share your PIN or codes."
    elif level == RiskLevel.MEDIUM:
        msg = f"SafeGuard CAUTION: {number} has been reported for scams. Do not share PINs or codes."
    elif not known or (verified == 0 and pending == 0):
        msg = f"SafeGuard: no reports for {number}. Still, never share your PIN or codes."
    else:
        msg = f"SafeGuard: {number} has {pending + verified} report(s) not yet confirmed. Stay careful."
    return msg[:160]
