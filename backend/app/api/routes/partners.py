"""Authenticated partner data intake into the Partner Data Repository."""
from typing import Annotated
from uuid import UUID

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select

from app.api.deps import AdminUser, DbDep, SettingsDep
from app.core import security
from app.core.exceptions import AuthenticationError, NotFoundError, PermissionDenied
from app.core.partner_secrets import decrypt_partner_secret
from app.models import Partner, PartnerIntelligenceDelivery
from app.schemas.liveness import (
    LivenessAssessmentIn,
    LivenessAssessmentOut,
    PartnerAlertListOut,
)
from app.schemas.partners import (
    PartnerAccountSubmissionIn,
    PartnerCreate,
    PartnerCreated,
    PartnerDataSubmissionIn,
    PartnerIdentitySubmissionIn,
    PartnerSubmissionOut,
    PartnerTransactionSubmissionIn,
)
from app.services.liveness_verification import record_partner_assessment
from app.services.partner_integration import (
    PartnerContext,
    ingest_partner_submission,
    register_partner,
)

router = APIRouter(prefix="/partners", tags=["partner integrations"])


async def require_partner(request: Request, db: DbDep, settings: SettingsDep) -> PartnerContext:
    partner_code = request.headers.get("X-Partner-Id", "")
    partner = await db.scalar(select(Partner).where(Partner.partner_code == partner_code))
    if partner is None:
        raise AuthenticationError("Invalid partner credentials.", code="invalid_partner_signature")
    if partner.partner_status != "active":
        raise PermissionDenied("This partner integration is inactive.", code="partner_inactive")
    try:
        partner_secret = decrypt_partner_secret(
            partner.encrypted_secret, settings.secret_key.get_secret_value()
        )
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise AuthenticationError("Invalid partner credentials.", code="invalid_partner_signature") from exc
    if not security.verify_gateway_request(
        partner_secret,
        request.headers.get("X-Timestamp", ""),
        await request.body(),
        request.headers.get("X-Signature", ""),
        tolerance_seconds=settings.gateway_timestamp_tolerance_seconds,
    ):
        raise AuthenticationError("Invalid partner credentials.", code="invalid_partner_signature")
    return PartnerContext(
        partner_id=partner.id,
        partner_code=partner.partner_code,
        partner_name=partner.partner_name,
        partner_type=partner.partner_type,
    )


PartnerDep = Annotated[PartnerContext, Depends(require_partner)]


@router.post("", response_model=PartnerCreated, status_code=status.HTTP_201_CREATED)
async def register_partner_endpoint(
    body: PartnerCreate, admin: AdminUser, db: DbDep, settings: SettingsDep
) -> PartnerCreated:
    """Register a partner integration. This endpoint is restricted to SafeGuard admins."""
    return await register_partner(db, admin.id, body, settings)


@router.post("/identity", response_model=PartnerSubmissionOut)
async def submit_identity_data(
    body: PartnerIdentitySubmissionIn, request: Request, partner: PartnerDep,
    db: DbDep, settings: SettingsDep,
) -> PartnerSubmissionOut:
    batch = PartnerDataSubmissionIn.model_validate(body.model_dump())
    return await ingest_partner_submission(db, partner, batch, await request.body(), settings)


@router.post("/account", response_model=PartnerSubmissionOut)
async def submit_account_data(
    body: PartnerAccountSubmissionIn, request: Request, partner: PartnerDep,
    db: DbDep, settings: SettingsDep,
) -> PartnerSubmissionOut:
    batch = PartnerDataSubmissionIn.model_validate(body.model_dump())
    return await ingest_partner_submission(db, partner, batch, await request.body(), settings)


@router.post("/transactions", response_model=PartnerSubmissionOut)
async def submit_transaction_data(
    body: PartnerTransactionSubmissionIn, request: Request, partner: PartnerDep,
    db: DbDep, settings: SettingsDep,
) -> PartnerSubmissionOut:
    batch = PartnerDataSubmissionIn.model_validate(body.model_dump())
    return await ingest_partner_submission(db, partner, batch, await request.body(), settings)


@router.post("/data", response_model=PartnerSubmissionOut)
async def receive_partner_data(
    body: PartnerDataSubmissionIn,
    request: Request,
    partner: PartnerDep,
    db: DbDep,
    settings: SettingsDep,
) -> PartnerSubmissionOut:
    """Store the encrypted original submission and upsert normalized partner records."""
    return await ingest_partner_submission(
        db, partner, body, await request.body(), settings
    )


@router.post("/liveness", response_model=LivenessAssessmentOut)
async def submit_liveness_assessment(
    body: LivenessAssessmentIn, partner: PartnerDep, db: DbDep, settings: SettingsDep,
) -> LivenessAssessmentOut:
    """Accept a signed liveness verdict from a trusted partner/verifier."""
    return await record_partner_assessment(db, partner.partner_id, partner.partner_code, body, settings)


@router.get("/intelligence/alerts", response_model=PartnerAlertListOut)
async def get_intelligence_alerts(
    partner: PartnerDep, db: DbDep,
    limit: int = Query(50, ge=1, le=200),
) -> PartnerAlertListOut:
    """Poll this partner's durable, privacy-minimized intelligence delivery feed."""
    rows = (await db.scalars(select(PartnerIntelligenceDelivery).where(
        PartnerIntelligenceDelivery.partner_id == partner.partner_id,
        PartnerIntelligenceDelivery.delivery_status == "pending",
    ).order_by(PartnerIntelligenceDelivery.created_at).limit(limit))).all()
    from datetime import UTC, datetime
    now = datetime.now(UTC)
    for row in rows:
        row.attempts += 1
        row.last_delivered_at = now
    await db.commit()
    return PartnerAlertListOut(items=[{"delivery_id": row.id, "payload": row.payload,
                                      "created_at": row.created_at} for row in rows], limit=limit)


@router.post("/intelligence/alerts/{delivery_id}/acknowledge")
async def acknowledge_intelligence_alert(
    delivery_id: UUID, partner: PartnerDep, db: DbDep,
) -> dict[str, str]:
    """Acknowledge delivery so subsequent feed polls do not return the same alert."""
    from datetime import UTC, datetime

    delivery = await db.scalar(select(PartnerIntelligenceDelivery).where(
        PartnerIntelligenceDelivery.id == delivery_id,
        PartnerIntelligenceDelivery.partner_id == partner.partner_id,
    ))
    if delivery is None:
        raise NotFoundError("Intelligence alert delivery not found.", code="alert_delivery_not_found")
    delivery.delivery_status = "acknowledged"
    delivery.acknowledged_at = datetime.now(UTC)
    await db.commit()
    return {"status": "acknowledged"}
