from uuid import UUID

from fastapi import APIRouter, Query, status

from app.api.deps import CurrentUser, FraudServiceDep, PageDep, ReviewerUser
from app.enums import ReportStatus
from app.schemas.common import Page
from app.schemas.fraud import ReportCreate, ReportOut, ReviewRequest

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
async def submit_report(body: ReportCreate, user: CurrentUser, fraud: FraudServiceDep) -> ReportOut:
    """Report a scam number. Starts as `pending` until a reviewer verifies it."""
    return await fraud.submit_report(user, body)


@router.get("/mine", response_model=Page[ReportOut])
async def my_reports(user: CurrentUser, fraud: FraudServiceDep, page: PageDep) -> Page[ReportOut]:
    return await fraud.list_reports(user_id=user.id, limit=page.limit, offset=page.offset)


@router.get("", response_model=Page[ReportOut])
async def review_queue(
    reviewer: ReviewerUser,
    fraud: FraudServiceDep,
    page: PageDep,
    status_filter: ReportStatus | None = Query(ReportStatus.PENDING, alias="status"),  # noqa: B008
    number: str | None = Query(None, max_length=20),
) -> Page[ReportOut]:
    """Reviewer queue, oldest first. Defaults to pending reports."""
    return await fraud.list_reports(status=status_filter, number=number, oldest_first=True,
                                    limit=page.limit, offset=page.offset)


@router.get("/{report_id}", response_model=ReportOut)
async def get_report(report_id: UUID, user: CurrentUser, fraud: FraudServiceDep) -> ReportOut:
    return await fraud.get_report(user, report_id)


@router.post("/{report_id}/review", response_model=ReportOut)
async def review_report(report_id: UUID, body: ReviewRequest, reviewer: ReviewerUser,
                        fraud: FraudServiceDep) -> ReportOut:
    """Approve, reject, or ask for more info. Approved/rejected decisions are final."""
    return await fraud.review_report(reviewer, report_id, body.decision, body.category_id)
