"""Feedback and outcome recording for the protection loop."""
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.enums import EvidenceType, FeedbackOutcome, UserRole
from app.models import CaseEvidence, CaseFeedback, FraudCase, RiskAssessment, User
from app.schemas.feedback import FeedbackCreate, FeedbackOut


class FeedbackService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(self, user: User, case_id: UUID, data: FeedbackCreate) -> FeedbackOut:
        await self._owned_case(user, case_id)
        feedback = self._build(case_id, user.id, data)
        await self._attach_decision_snapshot(feedback, case_id)
        self.db.add(feedback)
        await self.db.flush()
        await self._record_loop_evidence(feedback)
        return self._to_out(feedback)

    async def list(self, user: User, case_id: UUID) -> list[FeedbackOut]:
        await self._owned_case(user, case_id)
        rows = (await self.db.scalars(
            select(CaseFeedback).where(CaseFeedback.case_id == case_id).order_by(CaseFeedback.created_at)
        )).all()
        return [self._to_out(row) for row in rows]

    async def record_system(
        self, *, case_id: UUID, actor: User, outcome: FeedbackOutcome, notes: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> CaseFeedback | None:
        if actor.role not in {UserRole.REVIEWER, UserRole.ADMIN}:
            return None
        feedback = CaseFeedback(
            case_id=case_id, user_id=actor.id, outcome=outcome, notes=notes,
            feedback_metadata=metadata or {},
        )
        await self._attach_decision_snapshot(feedback, case_id)
        self.db.add(feedback)
        await self.db.flush()
        await self._record_loop_evidence(feedback)
        return feedback

    async def record_delivery(self, *, case_id: UUID, user: User, action: str, channel: str) -> CaseFeedback:
        feedback = CaseFeedback(
            case_id=case_id, user_id=user.id, outcome=FeedbackOutcome.INTERVENTION_DELIVERED,
            intervention_action=action, feedback_metadata={"channel": channel},
        )
        await self._attach_decision_snapshot(feedback, case_id)
        self.db.add(feedback)
        await self.db.flush()
        return feedback

    async def risk_signals(self, case_id: UUID) -> tuple[float, tuple[str, ...], tuple[str, ...]]:
        """Return bounded outcome evidence for a later assessment in this case."""
        rows = (await self.db.scalars(
            select(CaseFeedback).where(CaseFeedback.case_id == case_id)
            .order_by(CaseFeedback.created_at.desc()).limit(20)
        )).all()
        hazard = 0.0
        reasons: list[str] = []
        provenance: list[str] = []
        for row in rows:
            if row.outcome == FeedbackOutcome.CONFIRMED_FRAUD or row.fraud_confirmed is True:
                hazard = max(hazard, 0.45)
                reasons.append("prior case feedback confirmed fraud")
            elif row.outcome in {FeedbackOutcome.LOSS_REPORTED, FeedbackOutcome.LOSS_PREVENTED}:
                hazard = max(hazard, 0.35)
                reasons.append("prior case feedback records fraud-related harm or prevention")
            elif row.outcome == FeedbackOutcome.FALSE_POSITIVE:
                reasons.append("prior case feedback marked an earlier assessment as a false positive")
            if row.outcome != FeedbackOutcome.INTERVENTION_DELIVERED:
                provenance.append("case_feedback")
        return hazard, tuple(dict.fromkeys(reasons)), tuple(dict.fromkeys(provenance))

    async def _attach_decision_snapshot(self, feedback: CaseFeedback, case_id: UUID) -> None:
        latest = (await self.db.scalars(
            select(RiskAssessment).where(RiskAssessment.case_id == case_id)
            .order_by(RiskAssessment.created_at.desc()).limit(1)
        )).first()
        metadata = dict(feedback.feedback_metadata or {})
        if latest is not None:
            signals = latest.signals or {}
            metadata.update({
                "risk_assessment_id": str(latest.id),
                "risk_level_at_delivery": latest.risk_level.value,
                "risk_score_at_delivery": latest.risk_score,
                "risk_provenance_at_delivery": signals.get("provenance", []),
                "intervention_contract": "intervention.v1",
            })
        else:
            evidence = (await self.db.scalars(
                select(CaseEvidence).where(CaseEvidence.case_id == case_id)
                .order_by(CaseEvidence.observed_at.desc()).limit(1)
            )).first()
            if evidence is not None:
                details = evidence.details or {}
                decision = details.get("decision") or details.get("signals") or details
                metadata.update({
                    "evidence_source_at_delivery": evidence.source,
                    "risk_level_at_delivery": decision.get("risk_level"),
                    "risk_score_at_delivery": decision.get("risk_score"),
                    "risk_provenance_at_delivery": decision.get("provenance", []),
                    "intervention_contract": "intervention.v1",
                })
        feedback.feedback_metadata = metadata

    async def _record_loop_evidence(self, feedback: CaseFeedback) -> None:
        details = {
            "outcome": feedback.outcome.value,
            "fraud_confirmed": feedback.fraud_confirmed,
            "followed_recommendation": feedback.followed_recommendation,
            "intervention_action": feedback.intervention_action,
            "risk_snapshot": feedback.feedback_metadata,
        }
        self.db.add(CaseEvidence(
            case_id=feedback.case_id,
            evidence_type=EvidenceType.ASSESSMENT,
            source="feedback_loop",
            confidence=1.0 if feedback.fraud_confirmed is True else 0.7,
            details=details,
        ))

    async def _owned_case(self, user: User, case_id: UUID) -> FraudCase:
        case = await self.db.scalar(select(FraudCase).where(FraudCase.id == case_id, FraudCase.user_id == user.id))
        if case is None:
            raise NotFoundError("Case not found.")
        return case

    @staticmethod
    def _build(case_id: UUID, user_id: UUID, data: FeedbackCreate) -> CaseFeedback:
        return CaseFeedback(
            case_id=case_id, user_id=user_id, outcome=data.outcome,
            intervention_action=data.intervention_action,
            followed_recommendation=data.followed_recommendation,
            fraud_confirmed=data.fraud_confirmed, amount=data.amount,
            currency=data.currency.upper() if data.currency else None,
            loss_amount=data.loss_amount, rating=data.rating, notes=data.notes,
            feedback_metadata={},
        )

    @staticmethod
    def _to_out(row: CaseFeedback) -> FeedbackOut:
        return FeedbackOut(
            id=row.id, case_id=row.case_id, outcome=row.outcome,
            intervention_action=row.intervention_action,
            followed_recommendation=row.followed_recommendation,
            fraud_confirmed=row.fraud_confirmed, amount=row.amount,
            currency=row.currency, loss_amount=row.loss_amount,
            rating=row.rating, notes=row.notes, created_at=row.created_at,
        )
