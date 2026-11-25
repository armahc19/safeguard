from uuid import UUID

from fastapi import APIRouter, Query, Response, status

from app.api.deps import AdminUser, CurrentUser, FraudServiceDep, PageDep, ReviewerUser
from app.enums import RiskLevel, ThreatIndicatorType
from app.schemas.common import Page
from app.schemas.fraud import (
    CategoryCreate,
    CategoryOut,
    ThreatCreate,
    ThreatOut,
    ThreatUpdate,
)

router = APIRouter(prefix="/threats", tags=["threats"])
categories_router = APIRouter(prefix="/scam-categories", tags=["threats"])


@router.get("", response_model=Page[ThreatOut])
async def list_threats(
    reviewer: ReviewerUser,
    fraud: FraudServiceDep,
    page: PageDep,
    risk_level: RiskLevel | None = None,
    category_id: UUID | None = None,
    indicator_type: ThreatIndicatorType | None = None,
    number: str | None = Query(None, max_length=20),
) -> Page[ThreatOut]:
    return await fraud.list_threats(risk_level=risk_level, category_id=category_id, indicator_type=indicator_type,
                                    number=number, limit=page.limit, offset=page.offset)


@router.get("/{threat_id}", response_model=ThreatOut)
async def get_threat(threat_id: UUID, reviewer: ReviewerUser, fraud: FraudServiceDep) -> ThreatOut:
    return await fraud.get_threat(threat_id)


@router.post("", response_model=ThreatOut, status_code=status.HTTP_201_CREATED)
async def create_threat(body: ThreatCreate, reviewer: ReviewerUser, fraud: FraudServiceDep) -> ThreatOut:
    """Manually blocklist a number (reviewer+) or allowlist a trusted one (admin only)."""
    return await fraud.create_threat(reviewer, body)


@router.patch("/{threat_id}", response_model=ThreatOut)
async def update_threat(threat_id: UUID, body: ThreatUpdate, reviewer: ReviewerUser,
                        fraud: FraudServiceDep) -> ThreatOut:
    """Only manual (blocklist/allowlist) entries are editable; automatic ones follow the reports."""
    return await fraud.update_threat(reviewer, threat_id, body)


@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_threat(threat_id: UUID, reviewer: ReviewerUser, fraud: FraudServiceDep) -> Response:
    await fraud.delete_threat(reviewer, threat_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@categories_router.get("", response_model=list[CategoryOut])
async def list_categories(user: CurrentUser, fraud: FraudServiceDep) -> list[CategoryOut]:
    return await fraud.list_categories()


@categories_router.post("", response_model=CategoryOut, status_code=status.HTTP_201_CREATED)
async def create_category(body: CategoryCreate, admin: AdminUser, fraud: FraudServiceDep) -> CategoryOut:
    return await fraud.create_category(body.name)
