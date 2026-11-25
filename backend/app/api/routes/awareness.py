"""User consent, conversation memory controls and personal awareness inbox."""
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.deps import CurrentUser, DbDep, RedisDep
from app.core.exceptions import NotFoundError
from app.models import AwarenessCampaign, AwarenessDelivery, UserAwarenessPreference
from app.schemas.awareness import (
    AwarenessInboxOut,
    AwarenessPreferencesIn,
    AwarenessPreferencesOut,
)
from app.services.awareness import preferences_payload, update_preferences

router = APIRouter(prefix="/awareness", tags=["continuous-awareness"])


@router.get("/preferences", response_model=AwarenessPreferencesOut)
async def get_awareness_preferences(user: CurrentUser, db: DbDep) -> dict:
    row = await db.scalar(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id == user.id))
    return preferences_payload(row)


@router.put("/preferences", response_model=AwarenessPreferencesOut)
async def put_awareness_preferences(body: AwarenessPreferencesIn, user: CurrentUser,
                                    db: DbDep, redis: RedisDep) -> dict:
    return await update_preferences(db, redis, user, body)


@router.get("/inbox", response_model=AwarenessInboxOut)
async def awareness_inbox(user: CurrentUser, db: DbDep,
                          limit: int = Query(50, ge=1, le=100)) -> dict:
    rows = (await db.execute(select(AwarenessDelivery, AwarenessCampaign).join(
        AwarenessCampaign, AwarenessCampaign.id == AwarenessDelivery.campaign_id
    ).where(AwarenessDelivery.user_id == user.id,
            AwarenessDelivery.channel == "in_app",
            AwarenessDelivery.status == "sent")
      .order_by(AwarenessDelivery.created_at.desc()).limit(limit))).all()
    return {"items": [{"id": delivery.id, "campaign_title": campaign.title,
        "message": delivery.message, "severity": campaign.severity,
        "channel": delivery.channel, "sent_at": delivery.delivered_at,
        "read_at": delivery.read_at} for delivery, campaign in rows]}


@router.post("/inbox/{delivery_id}/read")
async def mark_awareness_read(delivery_id: UUID, user: CurrentUser, db: DbDep) -> dict[str, str]:
    delivery = await db.scalar(select(AwarenessDelivery).where(
        AwarenessDelivery.id == delivery_id, AwarenessDelivery.user_id == user.id,
        AwarenessDelivery.channel == "in_app"))
    if delivery is None:
        raise NotFoundError("Awareness message not found.", code="awareness_delivery_not_found")
    from datetime import UTC, datetime
    delivery.read_at = datetime.now(UTC)
    await db.commit()
    return {"status": "read"}
