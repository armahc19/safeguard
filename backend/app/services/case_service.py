"""Shared case and evidence lifecycle for all protection channels."""
from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ValidationFailed
from app.enums import CaseStatus
from app.models import CaseEvidence, FraudCase, User
from app.schemas.cases import (
    CaseCreate,
    CaseDetailOut,
    CaseOut,
    EvidenceCreate,
    EvidenceOut,
)


class CaseService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create(self, user: User, data: CaseCreate) -> CaseOut:
        case = FraudCase(user_id=user.id, title=data.title.strip(), summary=data.summary)
        self.db.add(case)
        await self.db.flush()
        return self._to_case(case, 0)

    async def get(self, user: User, case_id: UUID) -> CaseDetailOut:
        case = await self._owned_case(user, case_id)
        evidence = (await self.db.scalars(
            select(CaseEvidence).where(CaseEvidence.case_id == case.id).order_by(CaseEvidence.observed_at)
        )).all()
        return self._to_detail(case, evidence)

    async def list(self, user: User, *, limit: int, offset: int) -> list[CaseOut]:
        rows = (await self.db.execute(
            select(FraudCase, func.count(CaseEvidence.id))
            .outerjoin(CaseEvidence, CaseEvidence.case_id == FraudCase.id)
            .where(FraudCase.user_id == user.id)
            .group_by(FraudCase.id)
            .order_by(FraudCase.updated_at.desc())
            .limit(limit).offset(offset)
        )).all()
        return [self._to_case(case, count) for case, count in rows]

    async def add_evidence(self, user: User, case_id: UUID, data: EvidenceCreate) -> EvidenceOut:
        case = await self._owned_case(user, case_id)
        evidence = await self.add_internal_evidence(case, data)
        return self._to_evidence(evidence)

    async def close(self, user: User, case_id: UUID) -> CaseOut:
        case = await self._owned_case(user, case_id)
        case.status = CaseStatus.CLOSED
        case.closed_at = datetime.now(UTC)
        await self.db.flush()
        # Refresh server-generated `updated_at` before building the response.
        # Accessing an expired attribute here would initiate implicit async I/O.
        await self.db.refresh(case)
        return self._to_case(case, 0)

    async def get_or_create(self, user: User, case_id: UUID | None, *, title: str) -> FraudCase:
        if case_id is not None:
            return await self._owned_case(user, case_id)
        case = FraudCase(user_id=user.id, title=title[:160])
        self.db.add(case)
        await self.db.flush()
        return case

    async def add_internal_evidence(self, case: FraudCase, data: EvidenceCreate) -> CaseEvidence:
        if case.status == CaseStatus.CLOSED:
            raise ValidationFailed("Closed cases cannot receive new evidence.", code="case_closed")
        evidence = CaseEvidence(
            case_id=case.id, evidence_type=data.evidence_type, source=data.source,
            value=data.value, confidence=data.confidence,
            observed_at=data.observed_at or datetime.now(UTC), details=data.details,
        )
        self.db.add(evidence)
        await self.db.flush()
        return evidence

    async def _owned_case(self, user: User, case_id: UUID) -> FraudCase:
        case = await self.db.scalar(select(FraudCase).where(FraudCase.id == case_id, FraudCase.user_id == user.id))
        if case is None:
            raise NotFoundError("Case not found.")
        return case

    @staticmethod
    def _to_evidence(evidence: CaseEvidence) -> EvidenceOut:
        return EvidenceOut(
            id=evidence.id, case_id=evidence.case_id, evidence_type=evidence.evidence_type,
            source=evidence.source, value=evidence.value, confidence=evidence.confidence,
            observed_at=evidence.observed_at, created_at=evidence.created_at, details=evidence.details,
        )

    @classmethod
    def _to_case(cls, case: FraudCase, count: int) -> CaseOut:
        return CaseOut(
            id=case.id, title=case.title, summary=case.summary, status=case.status,
            created_at=case.created_at, updated_at=case.updated_at, closed_at=case.closed_at,
            evidence_count=count,
        )

    @classmethod
    def _to_detail(cls, case: FraudCase, evidence: list[CaseEvidence]) -> CaseDetailOut:
        return CaseDetailOut(
            **cls._to_case(case, len(evidence)).model_dump(),
            evidence=[cls._to_evidence(item) for item in evidence],
        )
