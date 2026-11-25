import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select

from app.api.deps import AdminUser, DbDep, ReviewerUser, SettingsDep, get_sms_sender
from app.core.config import Settings
from app.core.exceptions import NotFoundError
from app.models import (AwarenessCampaign, AwarenessDelivery, AwarenessScheduledInteraction,
                        AwarenessSchedulerRun, CrossInstitutionSignal, Partner,
                        UserAwarenessPreference)
from app.schemas.admin import AdminDashboardOut, PartnerStatusUpdate
from app.schemas.awareness import (
    AwarenessAdminDeliveryOut,
    AwarenessAudiencePreviewOut,
    AwarenessCampaignCreate,
    AwarenessCampaignOut,
    AwarenessCampaignSendOut,
    AwarenessCampaignSuggestOut,
    AwarenessOutreachStatsOut,
)
from app.schemas.partners import PartnerCreate, PartnerCreated, PartnerOut
from app.services.admin_intelligence import (
    get_admin_monitoring,
    get_intelligence_overview,
    seed_intelligence_demo,
)
from app.services.admin_service import get_dashboard
from app.services.awareness import (
    awareness_outreach_stats,
    create_campaign,
    list_recent_deliveries,
    preview_audience,
    send_campaign,
    suggest_campaign_copy,
)
from app.services.awareness_scheduler import run_due_awareness
from app.services.partner_integration import register_partner
from app.services.sms import SMSSender

router = APIRouter(prefix="/admin", tags=["administration"])


@router.get("/awareness/operations")
async def awareness_operations(reviewer: ReviewerUser, db: DbDep, settings: SettingsDep) -> dict:
    """Read-only operational overview for opt-ins, campaign review, and delivery adapters."""
    active_filter = UserAwarenessPreference.proactive_education_enabled.is_(True)
    active_count = int(await db.scalar(select(func.count()).select_from(UserAwarenessPreference).where(active_filter)) or 0)
    checkup_count = int(await db.scalar(select(func.count()).select_from(UserAwarenessPreference).where(
        active_filter, UserAwarenessPreference.checkup_enabled.is_(True))) or 0)
    alert_count = int(await db.scalar(select(func.count()).select_from(UserAwarenessPreference).where(
        active_filter, UserAwarenessPreference.fraud_alerts_enabled.is_(True))) or 0)
    test_schedule_count = int(await db.scalar(select(func.count()).select_from(UserAwarenessPreference).where(
        active_filter, UserAwarenessPreference.test_schedule_enabled.is_(True))) or 0)
    frequency_rows = (await db.execute(select(UserAwarenessPreference.schedule_frequency,
        func.count()).where(active_filter).group_by(UserAwarenessPreference.schedule_frequency))).all()
    method_rows = (await db.execute(select(UserAwarenessPreference.delivery_method,
        func.count()).where(active_filter).group_by(UserAwarenessPreference.delivery_method))).all()
    draft_count = int(await db.scalar(select(func.count()).select_from(AwarenessCampaign).where(
        AwarenessCampaign.status == "draft")) or 0)

    since = datetime.now(UTC) - timedelta(hours=24)
    delivery_rows = (await db.execute(select(AwarenessDelivery.status, AwarenessDelivery.channel,
        func.count()).where(AwarenessDelivery.created_at >= since).group_by(
            AwarenessDelivery.status, AwarenessDelivery.channel))).all()
    last_delivery = await db.scalar(select(func.max(AwarenessDelivery.delivered_at)).where(
        AwarenessDelivery.delivered_at.is_not(None)))
    now = datetime.now(UTC)
    latest_run = await db.scalar(select(AwarenessSchedulerRun).order_by(
        AwarenessSchedulerRun.created_at.desc()).limit(1))
    due_count = int(await db.scalar(select(func.count()).select_from(UserAwarenessPreference).where(
        active_filter, UserAwarenessPreference.next_awareness_at.is_not(None),
        UserAwarenessPreference.next_awareness_at <= now)) or 0)
    pending_checkups = int(await db.scalar(select(func.count()).select_from(
        AwarenessScheduledInteraction).where(
            AwarenessScheduledInteraction.status.in_(("sent", "simulated")),
            AwarenessScheduledInteraction.checkup_question.is_not(None),
            AwarenessScheduledInteraction.responded_at.is_(None))) or 0)
    recent_deliveries: dict[str, dict[str, int]] = {}
    for delivery_status, channel, count in delivery_rows:
        recent_deliveries.setdefault(channel, {})[delivery_status] = int(count)

    scheduler_status = "starting" if settings.awareness_scheduler_enabled else "disabled"
    if settings.awareness_scheduler_enabled:
        if latest_run and latest_run.trigger_source == "manual" and latest_run.status == "succeeded":
            scheduler_status = "manual_run"
        elif latest_run and latest_run.status == "running":
            scheduler_status = "running"
        elif latest_run and latest_run.status == "succeeded":
            scheduler_status = ("healthy" if latest_run.finished_at and
                            (now - latest_run.finished_at).total_seconds() <= settings.effective_awareness_scheduler_interval_seconds * 3
                                else "stale")
        elif latest_run and latest_run.status == "failed":
            scheduler_status = "failed"
    return {
        "scheduler": {"status": scheduler_status,
                      "enabled": settings.awareness_scheduler_enabled,
                      "interval_seconds": settings.effective_awareness_scheduler_interval_seconds,
                      "last_run_at": latest_run.finished_at if latest_run else None,
                      "next_run_at": None,
                      "due_subscribers": due_count,
                      "pending_checkups": pending_checkups,
                      "test_schedules": test_schedule_count,
                      "last_run": {"status": latest_run.status, "due_count": latest_run.due_count,
                                   "sent_count": latest_run.sent_count, "failed_count": latest_run.failed_count,
                                   "deferred_count": latest_run.deferred_count,
                                   "detail": latest_run.detail} if latest_run else None,
                      "detail": _awareness_scheduler_detail(latest_run, settings)},
        "subscriptions": {"active": active_count, "checkups_enabled": checkup_count,
                           "fraud_alerts_enabled": alert_count,
                           "frequency": {key: int(value) for key, value in frequency_rows},
                           "delivery_method": {key: int(value) for key, value in method_rows}},
        "campaigns": {"awaiting_review": draft_count},
        "deliveries_24h": recent_deliveries,
        "last_delivery_at": last_delivery,
        "channels": {"sms": {"mode": "http_provider" if settings.sms_provider == "http" else "console_only",
                               "operational": settings.sms_provider == "http"},
                     "voice_call": {"mode": "not_connected", "operational": False}},
    }


def _awareness_scheduler_detail(latest_run: AwarenessSchedulerRun | None, settings: Settings) -> str:
    if not settings.awareness_scheduler_enabled:
        return "The in-process worker is disabled by configuration."
    cadence = settings.effective_awareness_scheduler_interval_seconds
    if latest_run is None:
        return f"The in-process worker is enabled and will check due subscribers every {cadence} seconds."
    if latest_run.trigger_source == "manual":
        return f"Manual dispatch completed; the in-process worker checks due subscribers every {cadence} seconds."
    if latest_run.trigger_source == "cron":
        return f"Optional cron fallback ran; the in-process worker checks every {cadence} seconds."
    return latest_run.detail or f"The in-process worker checks due subscribers every {cadence} seconds."


@router.post("/awareness/scheduler/run-now")
async def run_awareness_scheduler_now(
    reviewer: ReviewerUser,
    db: DbDep,
    settings: SettingsDep,
    sms: Annotated[SMSSender, Depends(get_sms_sender)],
) -> dict:
    """Ask the same recurring worker to generate or update a due subscriber draft."""
    return await run_due_awareness(db, sms, trigger_source="manual",
                                   sms_operational=settings.sms_provider == "http",
                                   allow_test_schedule=settings.environment in {"development", "test"},
                                   groq_api_key=(settings.groq_api_key.get_secret_value()
                                                 if settings.groq_api_key else None))


@router.get("/intelligence")
async def intelligence_overview(admin: AdminUser, db: DbDep) -> dict:
    """Summarize FIR/PDR outputs from all nine intelligence layers for the admin console."""
    return await get_intelligence_overview(db)


@router.post("/intelligence/demo-data")
async def populate_intelligence_demo_data(admin: AdminUser, db: DbDep,
                                          settings: SettingsDep) -> dict:
    """Seed clearly labeled local demo reports and partner transactions."""
    return await seed_intelligence_demo(db, admin, settings)


@router.get("/awareness/outreach-stats", response_model=AwarenessOutreachStatsOut)
async def awareness_stats(reviewer: ReviewerUser, db: DbDep) -> dict:
    return await awareness_outreach_stats(db)


@router.get("/awareness/deliveries", response_model=list[AwarenessAdminDeliveryOut])
async def list_awareness_deliveries(
    reviewer: ReviewerUser, db: DbDep, limit: int = Query(50, ge=1, le=200),
) -> list[dict]:
    return await list_recent_deliveries(db, limit=limit)


@router.get("/awareness/signals/{signal_id}/suggest", response_model=AwarenessCampaignSuggestOut)
async def suggest_awareness_campaign(signal_id: uuid.UUID, reviewer: ReviewerUser,
                                     db: DbDep) -> dict:
    signal = await db.get(CrossInstitutionSignal, signal_id)
    if signal is None or signal.status != "active":
        raise NotFoundError("Active intelligence signal not found.", code="awareness_signal_not_found")
    return suggest_campaign_copy(signal)


@router.get("/awareness/signals/{signal_id}/audience-preview",
            response_model=AwarenessAudiencePreviewOut)
async def awareness_audience_preview(signal_id: uuid.UUID, reviewer: ReviewerUser,
                                     db: DbDep) -> dict:
    return await preview_audience(db, signal_id)


@router.get("/awareness/campaigns", response_model=list[AwarenessCampaignOut])
async def list_awareness_campaigns(reviewer: ReviewerUser, db: DbDep) -> list[AwarenessCampaign]:
    return (await db.scalars(select(AwarenessCampaign).order_by(
        AwarenessCampaign.created_at.desc()).limit(100))).all()


@router.post("/awareness/campaigns", response_model=AwarenessCampaignOut)
async def draft_awareness_campaign(body: AwarenessCampaignCreate,
                                   reviewer: ReviewerUser, db: DbDep) -> AwarenessCampaign:
    """Draft campaign copy tied to an active network signal; sending requires a separate review action."""
    return await create_campaign(db, reviewer, body)


@router.post("/awareness/campaigns/{campaign_id}/approve-and-send",
             response_model=AwarenessCampaignSendOut)
async def approve_and_send_awareness_campaign(
    campaign_id: uuid.UUID, reviewer: ReviewerUser, db: DbDep,
    settings: SettingsDep,
    sms: Annotated[SMSSender, Depends(get_sms_sender)],
) -> dict:
    """Approve a manual audience campaign or release a scheduler-targeted draft."""
    return await send_campaign(db, reviewer, campaign_id, sms,
                               sms_operational=settings.sms_provider == "http",
                               allow_test_schedule=settings.environment in {"development", "test"})


@router.get("/dashboard", response_model=AdminDashboardOut)
async def dashboard(admin: AdminUser, db: DbDep) -> AdminDashboardOut:
    """Live operational metrics for administrators."""
    return await get_dashboard(db)


@router.get("/monitoring")
async def admin_monitoring(admin: AdminUser, db: DbDep) -> dict:
    """Monitoring band: risk distribution, active signals, and highest-risk entities."""
    return await get_admin_monitoring(db)


@router.get("/partners", response_model=list[PartnerOut])
async def list_partners(admin: AdminUser, db: DbDep) -> list[PartnerOut]:
    """List registered integration partners without disclosing their signing secrets."""
    rows = (await db.scalars(select(Partner).order_by(Partner.partner_name))).all()
    return [PartnerOut(id=row.id, partner_code=row.partner_code, partner_name=row.partner_name,
                       partner_type=row.partner_type, partner_status=row.partner_status,
                       registration_datetime=row.registration_datetime) for row in rows]


@router.post("/partners", response_model=PartnerCreated, status_code=status.HTTP_201_CREATED)
async def create_partner(body: PartnerCreate, admin: AdminUser, db: DbDep,
                         settings: SettingsDep) -> PartnerCreated:
    """Register a partner. Its generated HMAC secret is disclosed only in this response."""
    return await register_partner(db, admin.id, body, settings)


@router.patch("/partners/{partner_id}/status", response_model=PartnerOut)
async def update_partner_status(partner_id: uuid.UUID, body: PartnerStatusUpdate,
                                admin: AdminUser, db: DbDep) -> PartnerOut:
    partner = await db.get(Partner, partner_id)
    if partner is None:
        raise NotFoundError("Partner not found.", code="partner_not_found")
    partner.partner_status = body.partner_status
    await db.commit()
    await db.refresh(partner)
    return PartnerOut(id=partner.id, partner_code=partner.partner_code, partner_name=partner.partner_name,
                      partner_type=partner.partner_type, partner_status=partner.partner_status,
                      registration_datetime=partner.registration_datetime)
