"""Consent-aware conversation memory, inbox and reviewed awareness delivery."""
from datetime import UTC, datetime, timedelta
from calendar import monthrange
from zoneinfo import ZoneInfo
from uuid import UUID

import httpx
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ConflictError, NotFoundError, ValidationFailed
from app.models import (
    AwarenessCampaign,
    AwarenessDelivery,
    AwarenessScheduledInteraction,
    CaseEvidence,
    CrossInstitutionSignal,
    EntityRelationship,
    FIRReportRecord,
    FraudCase,
    ReportEntity,
    User,
    UserAwarenessPreference,
)
from app.schemas.awareness import AwarenessCampaignCreate, AwarenessPreferencesIn, GatewayAwarenessSubscriptionIn
from app.services.sms import SMSSender

_SIGNAL_COPY_TEMPLATES: dict[str, dict[str, str]] = {
    "mule_network_candidate": {
        "title": "Protect your wallet from mule accounts",
        "message": (
            "SafeGuard alert: Criminals use “mule” wallets to move stolen money. "
            "Never receive funds for strangers or share your MoMo PIN or OTP. "
            "If someone asks you to “hold” money, report the number in SafeGuard."
        ),
    },
    "real_time_entity_risk": {
        "title": "High-risk number activity near you",
        "message": (
            "SafeGuard alert: We detected suspicious activity linked to numbers like one you reported. "
            "Do not send money or codes to callers claiming to be support. "
            "Use your provider’s official short code to verify."
        ),
    },
}
_DEFAULT_COPY = {
    "title": "Stay safe from mobile money scams",
    "message": (
        "SafeGuard alert: Scammers may pose as bank or MoMo support and ask for your OTP. "
        "Never share codes by SMS or phone. Hang up and verify through official channels."
    ),
}


def preferences_payload(row: UserAwarenessPreference | None) -> dict:
    if row is None:
        return {"conversation_memory_enabled": False, "proactive_education_enabled": False,
                "channels": ["in_app"], "consent_updated_at": None,
                "schedule_frequency": "monthly", "custom_interval_days": None,
                "delivery_method": "sms", "language": "english", "preferred_time": "morning",
                "checkup_enabled": False, "fraud_alerts_enabled": False, "next_awareness_at": None,
                "test_schedule_enabled": False}
    return {"conversation_memory_enabled": row.conversation_memory_enabled,
            "proactive_education_enabled": row.proactive_education_enabled,
            "channels": row.channels, "consent_updated_at": row.consent_updated_at,
            "schedule_frequency": row.schedule_frequency, "custom_interval_days": row.custom_interval_days,
            "delivery_method": row.delivery_method, "language": row.language,
            "preferred_time": row.preferred_time, "checkup_enabled": row.checkup_enabled,
            "fraud_alerts_enabled": row.fraud_alerts_enabled,
            "next_awareness_at": row.next_awareness_at,
            "test_schedule_enabled": row.test_schedule_enabled}


_ACCRA = ZoneInfo("Africa/Accra")
_PREFERRED_HOUR = {"morning": 9, "afternoon": 14, "evening": 18}


def next_awareness_time(anchor: datetime, frequency: str, custom_days: int | None,
                        preferred_time: str, *, after: datetime | None = None,
                        test_schedule_enabled: bool = False) -> datetime:
    """Compute a future local send-window time, skipping missed periods instead of bursting."""
    if test_schedule_enabled:
        threshold = (after or anchor).astimezone(UTC)
        anchor_utc = anchor.astimezone(UTC)
        return max(anchor_utc + timedelta(minutes=1), threshold + timedelta(minutes=1))
    local = anchor.astimezone(_ACCRA)
    threshold = (after or anchor).astimezone(_ACCRA)
    hour = _PREFERRED_HOUR.get(preferred_time, 9)
    for _ in range(400):
        if frequency == "weekly":
            date = local.date() + timedelta(days=7)
        elif frequency == "biweekly":
            date = local.date() + timedelta(days=14)
        elif frequency == "monthly":
            month_index = local.year * 12 + (local.month - 1) + 1
            year, month_zero = divmod(month_index, 12)
            month = month_zero + 1
            date = local.date().replace(year=year, month=month,
                day=min(local.day, monthrange(year, month)[1]))
        else:
            date = local.date() + timedelta(days=max(1, int(custom_days or 30)))
        candidate = datetime(date.year, date.month, date.day, hour, 0, tzinfo=_ACCRA)
        if candidate > threshold:
            return candidate.astimezone(UTC)
        local = candidate
    raise ValueError("Could not compute the next awareness delivery time.")


async def update_gateway_awareness_subscription(db: AsyncSession, user: User,
                                                data: GatewayAwarenessSubscriptionIn) -> dict:
    row = await db.scalar(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id == user.id))
    now = datetime.now(UTC)
    if row is None:
        row = UserAwarenessPreference(user_id=user.id)
        db.add(row)
    row.proactive_education_enabled = data.subscription_active
    row.schedule_frequency = data.schedule_frequency
    row.custom_interval_days = data.custom_interval_days
    row.delivery_method = data.delivery_method
    row.language = data.language
    row.preferred_time = data.preferred_time
    row.checkup_enabled = data.checkup_enabled if data.subscription_active else False
    row.fraud_alerts_enabled = data.fraud_alerts_enabled if data.subscription_active else False
    row.test_schedule_enabled = bool(data.subscription_active and data.test_schedule_enabled)
    # Only SMS has an operational bulk-delivery adapter today. Never send SMS
    # to someone who selected voice-only; voice consent remains recorded separately.
    row.channels = ["sms"] if data.subscription_active and data.delivery_method in {"sms", "both"} else []
    row.consent_updated_at = now
    row.next_awareness_at = (next_awareness_time(now, data.schedule_frequency, data.custom_interval_days,
                                data.preferred_time,
                                test_schedule_enabled=row.test_schedule_enabled) if data.subscription_active else None)
    await db.commit()
    await db.refresh(row)
    return {**preferences_payload(row), "subscription_active": row.proactive_education_enabled}


async def update_preferences(db: AsyncSession, redis, user: User,
                             data: AwarenessPreferencesIn) -> dict:
    if data.proactive_education_enabled and not data.channels:
        raise ValidationFailed("Select at least one channel for proactive education.",
                               code="awareness_channel_required")
    row = await db.scalar(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id == user.id))
    memory_was_enabled = bool(row and row.conversation_memory_enabled)
    now = datetime.now(UTC)
    if row is None:
        row = UserAwarenessPreference(user_id=user.id)
        db.add(row)
    row.conversation_memory_enabled = data.conversation_memory_enabled
    row.proactive_education_enabled = data.proactive_education_enabled
    row.test_schedule_enabled = False
    row.fraud_alerts_enabled = data.proactive_education_enabled
    row.channels = list(dict.fromkeys(data.channels))
    row.consent_updated_at = now
    row.next_awareness_at = (next_awareness_time(now, row.schedule_frequency, row.custom_interval_days,
                                row.preferred_time,
                                test_schedule_enabled=False) if data.proactive_education_enabled else None)

    if not data.conversation_memory_enabled or not memory_was_enabled:
        case_ids = (await db.scalars(select(FraudCase.id).where(FraudCase.user_id == user.id))).all()
        if case_ids:
            await db.execute(delete(CaseEvidence).where(
                CaseEvidence.case_id.in_(case_ids), CaseEvidence.source == "conversation_context"))
            keys = [f"safeguard:conversation-context:{user.id}:{case_id}" for case_id in case_ids]
            if keys:
                await redis.delete(*keys)
    if not data.conversation_memory_enabled:
        row.voice_case_id = None
    await db.commit()
    await db.refresh(row)
    return preferences_payload(row)


def suggest_campaign_copy(signal: CrossInstitutionSignal) -> dict:
    template = _SIGNAL_COPY_TEMPLATES.get(signal.signal_type, _DEFAULT_COPY)
    severity = "high_risk" if signal.risk_level.value in {"high", "critical"} and signal.score >= 0.6 else "education"
    partners = ", ".join(signal.partner_codes or []) or "multiple providers"
    reasons = " ".join(signal.reasons or [])[:180]
    message = template["message"]
    if reasons:
        message = f"{message} Pattern: {reasons}."
    return {
        "title": template["title"],
        "message": message[:1000],
        "suggested_severity": severity,
        "signal_type": signal.signal_type,
        "risk_level": signal.risk_level.value,
        "score": signal.score,
        "partner_codes": list(signal.partner_codes or []),
        "partner_summary": partners,
    }


async def resolve_audience_user_ids(db: AsyncSession, signal: CrossInstitutionSignal) -> set[UUID]:
    entity_ids = [UUID(value) for value in signal.entity_ids if _is_uuid(value)]
    target_ids: set[UUID] = set()
    if entity_ids:
        affected_ids = set(entity_ids)
        frontier = set(entity_ids)
        for _ in range(3):
            edges = (await db.execute(select(EntityRelationship.source_entity_id,
                EntityRelationship.target_entity_id).where(
                    EntityRelationship.relationship_type.in_((
                        "owns", "associated_phone", "same_phone_reference",
                        "resolved_as", "candidate_match",
                    )), or_(
                    EntityRelationship.source_entity_id.in_(frontier),
                    EntityRelationship.target_entity_id.in_(frontier),
                )))).all()
            next_frontier = set()
            for source_id, target_id in edges:
                if source_id in frontier:
                    next_frontier.add(target_id)
                if target_id in frontier:
                    next_frontier.add(source_id)
            frontier = next_frontier - affected_ids
            if not frontier:
                break
            affected_ids.update(frontier)
        target_ids = set((await db.scalars(select(FIRReportRecord.reporter_id).join(
            ReportEntity, ReportEntity.report_id == FIRReportRecord.id
        ).where(ReportEntity.entity_id.in_(affected_ids), FIRReportRecord.reporter_id.is_not(None)))).all())
    if target_ids:
        return target_ids
    # Education fallback: recent reporters when graph seed has no entity linkage yet.
    window_start = datetime.now(UTC) - timedelta(days=90)
    return set((await db.scalars(select(FIRReportRecord.reporter_id).where(
        FIRReportRecord.created_at >= window_start,
        FIRReportRecord.reporter_id.is_not(None),
    ).distinct())).all())


async def preview_audience(db: AsyncSession, signal_id: UUID) -> dict:
    signal = await db.get(CrossInstitutionSignal, signal_id)
    if signal is None or signal.status != "active":
        raise NotFoundError("Active intelligence signal not found.", code="awareness_signal_not_found")
    target_ids = await resolve_audience_user_ids(db, signal)
    preference_rows = (await db.scalars(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id.in_(target_ids),
        UserAwarenessPreference.proactive_education_enabled.is_(True),
        UserAwarenessPreference.fraud_alerts_enabled.is_(True),
    ))).all() if target_ids else []
    opted_in = {row.user_id for row in preference_rows}
    deliverable_preferences = {row.user_id for row in preference_rows
        if row.language.lower() == "english" and row.delivery_method in {"sms", "both"}}
    unsupported_preferences = opted_in - deliverable_preferences
    frequency_start = datetime.now(UTC) - timedelta(days=7)
    suppressed_ids: set[UUID] = set()
    if deliverable_preferences:
        recent_rows = (await db.execute(select(AwarenessDelivery.user_id,
            func.count(func.distinct(AwarenessDelivery.campaign_id))).where(
                AwarenessDelivery.user_id.in_(deliverable_preferences), AwarenessDelivery.created_at >= frequency_start,
                AwarenessDelivery.status.in_(("pending", "sent")),
            ).group_by(AwarenessDelivery.user_id))).all()
        suppressed_ids = {user_id for user_id, count in recent_rows if count >= 3}
    eligible = deliverable_preferences - suppressed_ids
    channel_counts = {"in_app": 0, "sms": 0}
    for row in preference_rows:
        if row.user_id not in eligible:
            continue
        for channel in row.channels:
            if channel in channel_counts:
                channel_counts[channel] += 1
    return {
        "signal_id": signal.id,
        "signal_linked_users": len(target_ids),
        "opted_in_users": len(opted_in),
        "eligible_users": len(eligible),
        "suppressed_by_frequency_limit": len(suppressed_ids),
        "suppressed_by_unsupported_preference": len(unsupported_preferences),
        "estimated_deliveries": sum(channel_counts.values()),
        "channels": channel_counts,
        "used_report_fallback": not bool(signal.entity_ids),
    }


def _sms_body(message: str) -> str:
    text = " ".join(message.split())
    if len(text) <= 160:
        return text
    return text[:157] + "…"


async def list_recent_deliveries(db: AsyncSession, limit: int = 50) -> list[dict]:
    rows = (await db.execute(select(AwarenessDelivery, AwarenessCampaign).join(
        AwarenessCampaign, AwarenessCampaign.id == AwarenessDelivery.campaign_id,
    ).order_by(AwarenessDelivery.created_at.desc()).limit(limit))).all()
    return [{
        "id": delivery.id,
        "campaign_title": campaign.title,
        "severity": campaign.severity,
        "channel": delivery.channel,
        "status": delivery.status,
        "delivered_at": delivery.delivered_at,
        "read_at": delivery.read_at,
        "created_at": delivery.created_at,
    } for delivery, campaign in rows]


async def awareness_outreach_stats(db: AsyncSession) -> dict:
    since = datetime.now(UTC) - timedelta(days=30)
    sent = int(await db.scalar(select(func.count()).select_from(AwarenessDelivery).where(
        AwarenessDelivery.status == "sent",
        AwarenessDelivery.created_at >= since,
    )) or 0)
    read = int(await db.scalar(select(func.count()).select_from(AwarenessDelivery).where(
        AwarenessDelivery.status == "sent",
        AwarenessDelivery.read_at.is_not(None),
        AwarenessDelivery.created_at >= since,
    )) or 0)
    sms_sent = int(await db.scalar(select(func.count()).select_from(AwarenessDelivery).where(
        AwarenessDelivery.status == "sent",
        AwarenessDelivery.channel == "sms",
        AwarenessDelivery.created_at >= since,
    )) or 0)
    return {
        "interventions_delivered_30d": sent,
        "awareness_read_30d": read,
        "sms_sent_30d": sms_sent,
        "read_rate": round(read / sent, 4) if sent else 0.0,
    }


async def create_campaign(db: AsyncSession, reviewer: User,
                          data: AwarenessCampaignCreate) -> AwarenessCampaign:
    signal = await db.get(CrossInstitutionSignal, data.source_signal_id)
    if signal is None or signal.status != "active":
        raise NotFoundError("Active intelligence signal not found.", code="awareness_signal_not_found")
    if data.severity == "high_risk" and (signal.risk_level.value not in {"high", "critical"}
                                           or signal.score < 0.6):
        raise ValidationFailed("High-risk alerts require a high or critical signal with a score of at least 0.6.",
                               code="awareness_signal_below_threshold")
    campaign = AwarenessCampaign(
        source_signal_id=signal.id, title=data.title, message=data.message,
        severity=data.severity, created_by=reviewer.id,
    )
    db.add(campaign)
    await db.commit()
    await db.refresh(campaign)
    return campaign


async def send_campaign(db: AsyncSession, reviewer: User, campaign_id: UUID,
                        sms: SMSSender, *, sms_operational: bool = True,
                        allow_test_schedule: bool = False) -> dict:
    campaign = await db.get(AwarenessCampaign, campaign_id)
    if campaign is None:
        raise NotFoundError("Awareness campaign not found.", code="awareness_campaign_not_found")
    if campaign.status != "draft":
        raise ConflictError("Only draft campaigns can be approved and sent.", code="awareness_campaign_not_draft")
    if campaign.generated_by_scheduler:
        return await _approve_scheduled_campaign(
            db, reviewer, campaign, sms,
            sms_operational=sms_operational,
            allow_test_schedule=allow_test_schedule,
        )
    signal = (await db.get(CrossInstitutionSignal, campaign.source_signal_id)
              if campaign.source_signal_id is not None else None)
    if signal is None or signal.status != "active":
        raise ValidationFailed("The source intelligence signal is no longer active.",
                               code="awareness_signal_inactive")
    if campaign.severity == "high_risk" and (signal.risk_level.value not in {"high", "critical"}
                                               or signal.score < 0.6):
        raise ValidationFailed("The source signal no longer meets the high-risk threshold.",
                               code="awareness_signal_below_threshold")
    if campaign.severity == "high_risk" and campaign.created_by == reviewer.id:
        raise ValidationFailed("A different reviewer must approve and send a high-risk alert.",
                               code="awareness_second_reviewer_required")
    target_ids = await resolve_audience_user_ids(db, signal)
    if not target_ids:
        raise ValidationFailed("No users are linked to reports about this signal.",
                               code="awareness_audience_empty")

    opted_preference_rows = (await db.scalars(select(UserAwarenessPreference).where(
        UserAwarenessPreference.user_id.in_(target_ids),
        UserAwarenessPreference.proactive_education_enabled.is_(True),
        UserAwarenessPreference.fraud_alerts_enabled.is_(True),
    ))).all()
    prefs_by_user = {row.user_id: row for row in opted_preference_rows
        if row.language.lower() == "english" and row.delivery_method in {"sms", "both"}}
    eligible = set(prefs_by_user)
    unsupported_preferences = len(opted_preference_rows) - len(prefs_by_user)
    if not opted_preference_rows:
        raise ValidationFailed("No report-linked users have opted in to fraud alerts.",
                               code="awareness_no_opted_in_users")
    if not eligible:
        raise ValidationFailed("No opted-in subscribers currently have an available language and delivery channel.",
                               code="awareness_no_supported_delivery")

    frequency_start = datetime.now(UTC) - timedelta(days=7)
    recent_rows = (await db.execute(select(AwarenessDelivery.user_id,
        func.count(func.distinct(AwarenessDelivery.campaign_id))).where(
            AwarenessDelivery.user_id.in_(eligible), AwarenessDelivery.created_at >= frequency_start,
            AwarenessDelivery.status.in_(("pending", "sent")),
        ).group_by(AwarenessDelivery.user_id))).all()
    recent_campaigns = dict(recent_rows)
    suppressed = {user_id for user_id in eligible if recent_campaigns.get(user_id, 0) >= 3}
    eligible -= suppressed

    users = {user.id: user for user in (await db.scalars(select(User).where(User.id.in_(eligible)))).all()}
    now = datetime.now(UTC)
    new_deliveries: list[AwarenessDelivery] = []
    for user_id in eligible:
        pref = prefs_by_user[user_id]
        for channel in pref.channels:
            delivery = AwarenessDelivery(campaign_id=campaign.id, user_id=user_id,
                channel=channel, status="pending", message=campaign.message)
            db.add(delivery)
            new_deliveries.append(delivery)
    campaign.status = "approved"
    campaign.approved_by = reviewer.id
    campaign.approved_at = now
    campaign.audience_count = len(eligible)
    await db.flush()

    sms_sent = 0
    sms_failed = 0
    for delivery in new_deliveries:
        if delivery.channel == "in_app":
            delivery.status = "sent"
            delivery.delivered_at = now
        elif delivery.channel == "sms":
            user = users.get(delivery.user_id)
            if user is None:
                delivery.status = "failed"
                delivery.failure_reason = "User account no longer exists."
                sms_failed += 1
                continue
            try:
                await sms.send(user.phone, _sms_body(delivery.message))
                delivery.status = "sent"
                delivery.delivered_at = datetime.now(UTC)
                sms_sent += 1
            except httpx.HTTPError:
                delivery.status = "failed"
                delivery.failure_reason = "SMS provider delivery failed."
                sms_failed += 1
    campaign.status = "sent"
    campaign.sent_at = datetime.now(UTC)
    await db.commit()
    return {"campaign_id": campaign.id, "status": campaign.status,
            "eligible_users": len(eligible), "deliveries_created": len(new_deliveries),
            "sms_sent": sms_sent, "simulated_count": 0, "sms_failed": sms_failed,
            "suppressed_by_frequency_limit": len(suppressed),
            "suppressed_by_unsupported_preference": unsupported_preferences}


async def _approve_scheduled_campaign(
    db: AsyncSession, reviewer: User, campaign: AwarenessCampaign, sms: SMSSender, *,
    sms_operational: bool, allow_test_schedule: bool,
) -> dict:
    signal = (await db.get(CrossInstitutionSignal, campaign.source_signal_id)
              if campaign.source_signal_id is not None else None)
    if campaign.source_signal_id is not None and (signal is None or signal.status != "active"):
        raise ValidationFailed("The source intelligence signal is no longer active.",
                               code="awareness_signal_inactive")
    targets = (await db.scalars(select(AwarenessScheduledInteraction).where(
        AwarenessScheduledInteraction.campaign_id == campaign.id,
        AwarenessScheduledInteraction.status == "pending",
    ).with_for_update())).all()
    if not targets:
        raise ValidationFailed("This scheduled draft has no subscribers waiting for approval.",
                               code="awareness_scheduled_audience_empty")
    valid_targets: list[tuple[AwarenessScheduledInteraction, User, UserAwarenessPreference, bool]] = []
    for item in targets:
        user = await db.get(User, item.user_id)
        pref = await db.get(UserAwarenessPreference, item.preference_id)
        if user is None or pref is None or not pref.proactive_education_enabled:
            item.status = "failed"
            item.failure_reason = "Subscriber no longer has an active awareness opt-in."
            continue
        is_simulated = bool(
            allow_test_schedule and pref.test_schedule_enabled
            and (item.context_snapshot or {}).get("test_schedule")
        )
        if not is_simulated and (
            pref.delivery_method == "voice_call" or pref.language.lower() != "english"
            or "sms" not in (pref.channels or [])
        ):
            item.status = "failed"
            item.failure_reason = "Subscriber no longer has a supported SMS preference."
            continue
        valid_targets.append((item, user, pref, is_simulated))

    if any(not is_simulated for _, _, _, is_simulated in valid_targets) and not sms_operational:
        raise ValidationFailed("Configure an HTTP SMS provider before approving this live subscriber message.",
                               code="awareness_sms_provider_unavailable")

    now = datetime.now(UTC)
    campaign.approved_by = reviewer.id
    campaign.approved_at = now
    sms_sent = sms_failed = simulated_count = 0
    for item, user, pref, is_simulated in valid_targets:
        item.message = campaign.message
        item.topic = campaign.title
        if is_simulated:
            item.status = "simulated"
            simulated_count += 1
        else:
            try:
                await sms.send(user.phone, _sms_body(campaign.message))
                item.status = "sent"
                item.delivered_at = datetime.now(UTC)
                db.add(AwarenessDelivery(
                    campaign_id=campaign.id,
                    user_id=user.id,
                    channel="sms",
                    status="sent",
                    message=campaign.message,
                    delivered_at=item.delivered_at,
                ))
                sms_sent += 1
            except Exception as exc:
                item.status = "failed"
                item.failure_reason = str(exc)[:256]
                sms_failed += 1
        pref.next_awareness_at = next_awareness_time(
            item.scheduled_for, pref.schedule_frequency, pref.custom_interval_days,
            pref.preferred_time, after=now, test_schedule_enabled=is_simulated,
        )

    campaign.audience_count = sms_sent + simulated_count
    if simulated_count and not sms_sent:
        campaign.status = "simulated"
        campaign.sent_at = None
    else:
        campaign.status = "sent"
        campaign.sent_at = now
    await db.commit()
    return {
        "campaign_id": campaign.id,
        "status": campaign.status,
        "eligible_users": sms_sent + simulated_count,
        "deliveries_created": sms_sent + simulated_count,
        "sms_sent": sms_sent,
        "simulated_count": simulated_count,
        "sms_failed": sms_failed,
        "suppressed_by_frequency_limit": 0,
        "suppressed_by_unsupported_preference": len(targets) - len(valid_targets),
    }


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except (ValueError, TypeError):
        return False


