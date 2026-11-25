"""Explainable behavioural signals for transaction safety checks.

These are assessment-history signals, not claims about a user's identity or
intent. They are bounded and are always combined with other evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models import TransactionAssessment, User
from app.services.model_runtime import ModelPrediction, unified_model_runtime


def _bounded(value: float) -> float:
    return round(min(1.0, max(0.0, value)), 4)


@dataclass(frozen=True)
class BehaviourAssessment:
    recipient_seen: bool
    recent_assessments: int
    amount_baseline: float | None
    amount_anomaly_score: float
    velocity_anomaly_score: float
    recipient_mismatch_score: float
    new_recipient: bool
    high_value: bool
    reasons: tuple[str, ...]
    model_version: str = "not_run"
    model_scores: dict[str, float] = field(default_factory=dict)

    @property
    def signals(self) -> dict[str, float | int | bool | None]:
        return {
            "recipient_seen": self.recipient_seen,
            "recent_assessments": self.recent_assessments,
            "amount_baseline": self.amount_baseline,
            "amount_anomaly_score": self.amount_anomaly_score,
            "velocity_anomaly_score": self.velocity_anomaly_score,
            "recipient_mismatch_score": self.recipient_mismatch_score,
            "new_recipient": self.new_recipient,
            "high_value": self.high_value,
            "reasons": list(self.reasons),
            "model_version": self.model_version,
            "model_scores": self.model_scores,
            "source": "transaction_assessment_history",
        }


def classify_behaviour(text: str | None) -> ModelPrediction:
    """Run the shared behavioural joblib model without making a verdict."""
    return unified_model_runtime.behaviour_classifier.predict(text or "")


async def assess_transaction_behaviour(
    db: AsyncSession,
    user: User,
    *,
    recipient_phone: str,
    amount: float | None,
    currency: str,
    explicit_new_recipient: bool,
    explicit_amount_anomaly: float,
    explicit_velocity_anomaly: float,
    explicit_recipient_mismatch: float,
    explicit_high_value: bool,
    settings: Settings,
    text: str | None = None,
) -> BehaviourAssessment:
    now = datetime.now(UTC)
    lookback = now - timedelta(days=settings.behaviour_lookback_days)
    rows = (await db.scalars(
        select(TransactionAssessment)
        .where(TransactionAssessment.user_id == user.id, TransactionAssessment.created_at >= lookback)
        .order_by(TransactionAssessment.created_at.desc())
        .limit(200)
    )).all()
    same_recipient = [row for row in rows if row.recipient_phone == recipient_phone]
    same_currency_amounts = [
        float(row.amount) for row in rows
        if row.amount is not None and row.currency == currency
    ]
    baseline = round(sum(same_currency_amounts) / len(same_currency_amounts), 2) if same_currency_amounts else None
    recipient_seen = bool(same_recipient)
    new_recipient = explicit_new_recipient or not recipient_seen

    amount_score = _bounded(explicit_amount_anomaly)
    high_value = explicit_high_value
    if amount is not None and baseline and baseline > 0:
        ratio = amount / baseline
        amount_score = max(amount_score, _bounded((ratio - 1.0) / 2.0))
        high_value = high_value or ratio >= 3.0

    velocity_count = sum(1 for row in rows if row.created_at and row.created_at >= now - timedelta(
        hours=settings.behaviour_velocity_window_hours
    ))
    velocity_score = max(
        _bounded(explicit_velocity_anomaly),
        _bounded(velocity_count / max(settings.behaviour_velocity_alert_count, 1)),
    )
    mismatch_score = _bounded(explicit_recipient_mismatch)
    model_prediction = classify_behaviour(text)

    reasons: list[str] = []
    if new_recipient:
        reasons.append("recipient is new based on assessment history")
    if amount_score >= 0.7:
        reasons.append("amount is unusual compared with recent assessment history")
    if velocity_score >= 0.7:
        reasons.append("assessment activity is unusually frequent")
    if high_value:
        reasons.append("amount is high compared with the user's recent baseline")
    if mismatch_score >= 0.7:
        reasons.append("recipient context does not match the supplied history")

    return BehaviourAssessment(
        recipient_seen=recipient_seen,
        recent_assessments=len(rows),
        amount_baseline=baseline,
        amount_anomaly_score=amount_score,
        velocity_anomaly_score=velocity_score,
        recipient_mismatch_score=mismatch_score,
        new_recipient=new_recipient,
        high_value=high_value,
        reasons=tuple(dict.fromkeys(reasons)),
        model_version=model_prediction.version,
        model_scores=model_prediction.scores,
    )
