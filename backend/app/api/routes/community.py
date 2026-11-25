from uuid import UUID

from fastapi import APIRouter, status

from app.api.deps import CurrentUser, DbDep, PageDep, ReviewerUser, SettingsDep
from app.schemas.common import Page
from app.schemas.fraud import (
    CommunityReportCreate,
    CommunityReportOut,
    CommunityReviewRequest,
    IntelligenceOut,
)
from app.services.community_intelligence import CommunityIntelligenceService

router = APIRouter(prefix="/community", tags=["community-intelligence"])


def _service(db: DbDep, settings: SettingsDep) -> CommunityIntelligenceService:
    return CommunityIntelligenceService(db, settings.default_calling_code, settings)


@router.post("/reports", response_model=CommunityReportOut, status_code=status.HTTP_201_CREATED)
async def submit_community_report(body: CommunityReportCreate, user: CurrentUser, db: DbDep, settings: SettingsDep):
    return await _service(db, settings).submit(user, body)


@router.get("/reports/mine", response_model=Page[CommunityReportOut])
async def my_community_reports(user: CurrentUser, db: DbDep, settings: SettingsDep, page: PageDep):
    service = _service(db, settings)
    # Keep the public implementation small; report ownership is enforced by the query.
    from sqlalchemy import func, select

    from app.models import CommunityReport
    total = await db.scalar(select(func.count()).select_from(CommunityReport).where(CommunityReport.reporter_id == user.id))
    rows = (await db.execute(select(CommunityReport).where(CommunityReport.reporter_id == user.id).order_by(CommunityReport.created_at.desc()).limit(page.limit).offset(page.offset))).scalars().all()
    return Page(items=[service._report_out(row) for row in rows], total=total or 0, limit=page.limit, offset=page.offset)


@router.get("/reports/queue", response_model=Page[CommunityReportOut])
async def community_review_queue(reviewer: ReviewerUser, db: DbDep, settings: SettingsDep, page: PageDep):
    return await _service(db, settings).list_reports(reviewer, page.limit, page.offset)


@router.post("/reports/{report_id}/review", response_model=CommunityReportOut)
async def review_community_report(report_id: UUID, body: CommunityReviewRequest, reviewer: ReviewerUser, db: DbDep, settings: SettingsDep):
    return await _service(db, settings).review(reviewer, report_id, body.decision, body.notes)


@router.get("/intelligence/{subject}", response_model=IntelligenceOut)
async def get_community_intelligence(subject: str, user: CurrentUser, db: DbDep, settings: SettingsDep):
    return await _service(db, settings).get_intelligence(subject)
