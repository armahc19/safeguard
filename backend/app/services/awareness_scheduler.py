"""Cron/manual worker for opted-in Continuous Awareness SMS and USSD check-ups."""
import asyncio
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import UserRole
from app.models import (
    AwarenessCampaign,
    AwarenessScheduledInteraction,
    AwarenessSchedulerRun,
    User,
    UserAwarenessPreference,
)
from app.services.sms import SMSSender

_CHECKUP = "A caller says a MoMo transfer was reversed and asks for your PIN. What should you do?"


async def run_due_awareness(db: AsyncSession, _sms: SMSSender, *, limit: int = 100,
                           trigger_source: str = "in_process", sms_operational: bool = True,
                           allow_test_schedule: bool = False,
                           groq_api_key: str | None = None) -> dict:
    """Ask the shared Gradio agent for an admin-review draft for due subscribers.

    This worker never sends a message. The reviewer approval endpoint later
    delivers normal subscribers or writes simulated SMS interactions for the
    development-only one-minute test subscribers.
    """
    now = datetime.now(UTC)
    run = AwarenessSchedulerRun(status="running", trigger_source=trigger_source)
    db.add(run)
    deferred = 0
    try:
        has_pending_interaction = select(AwarenessScheduledInteraction.id).where(
            AwarenessScheduledInteraction.preference_id == UserAwarenessPreference.id,
            AwarenessScheduledInteraction.status == "pending",
        ).exists()
        rows = (await db.execute(
            select(UserAwarenessPreference, User)
            .join(User, User.id == UserAwarenessPreference.user_id)
            .where(
                UserAwarenessPreference.proactive_education_enabled.is_(True),
                UserAwarenessPreference.next_awareness_at.is_not(None),
                UserAwarenessPreference.next_awareness_at <= now,
                UserAwarenessPreference.delivery_method.in_(("sms", "both", "voice_call")),
                ~has_pending_interaction,
            )
            .order_by(UserAwarenessPreference.next_awareness_at)
            .limit(limit)
            .with_for_update(skip_locked=True, of=UserAwarenessPreference)
        )).all()
        run.due_count = len(rows)
        eligible: list[tuple[UserAwarenessPreference, User, bool]] = []
        for pref, user in rows:
            test_target = bool(pref.test_schedule_enabled and allow_test_schedule)
            if (pref.delivery_method == "voice_call" or "sms" not in (pref.channels or [])
                    or pref.language.lower() != "english" or (not sms_operational and not test_target)):
                deferred += 1
                continue
            eligible.append((pref, user, test_target))

        campaign = None
        if eligible:
            campaign = await db.scalar(select(AwarenessCampaign).where(
                AwarenessCampaign.generated_by_scheduler.is_(True),
                AwarenessCampaign.status == "draft",
            ).order_by(AwarenessCampaign.created_at.asc()).limit(1).with_for_update())
            if campaign is None:
                reviewer = await db.scalar(select(User).where(
                    User.role.in_((UserRole.ADMIN, UserRole.REVIEWER)),
                ).order_by(User.created_at.asc()).limit(1))
                if reviewer is None:
                    deferred += len(eligible)
                    eligible = []
                    run.detail = "No reviewer/admin account exists to own the generated draft."
                else:
                    recent_campaigns = (await db.scalars(select(AwarenessCampaign).where(
                        AwarenessCampaign.generated_by_scheduler.is_(True),
                    ).order_by(AwarenessCampaign.created_at.desc()).limit(12))).all()
                    recent_topics = [
                        str((item.generation_context or {}).get("topic"))
                        for item in recent_campaigns
                        if (item.generation_context or {}).get("topic")
                    ]
                    recent_messages = [item.message for item in recent_campaigns]
                    from app.services.awareness_gradio import generate_random_awareness_copy

                    generated = await asyncio.to_thread(
                        generate_random_awareness_copy,
                        recent_topics=recent_topics,
                        recent_messages=recent_messages,
                        api_key=groq_api_key,
                    )
                    generation_context = {
                        "topic": generated["topic"],
                        "copy_source": generated["copy_source"],
                        "generated_by": "gradio_awareness_agent",
                        "predictive": False,
                        "advice_type": "scam_avoidance_defence",
                        "description": "Randomly rotated general mobile-money safety education; not based on FIR trend prediction.",
                    }
                    campaign = AwarenessCampaign(
                        source_signal_id=None,
                        title=generated["title"],
                        message=generated["message"],
                        severity="education",
                        status="draft",
                        created_by=reviewer.id,
                        generated_by_scheduler=True,
                        generation_context=generation_context,
                    )
                    db.add(campaign)
                    await db.flush()

            if campaign is not None and eligible:
                for pref, user, test_target in eligible:
                    due_at = pref.next_awareness_at or now
                    db.add(AwarenessScheduledInteraction(
                        preference_id=pref.id,
                        user_id=user.id,
                        campaign_id=campaign.id,
                        scheduled_for=due_at,
                        status="pending",
                        topic=campaign.title,
                        message="Awaiting admin review and approval.",
                        checkup_question=_CHECKUP if pref.checkup_enabled else None,
                        context_snapshot={
                            "test_schedule": test_target,
                            "awareness_context": dict(pref.awareness_context or {}),
                        },
                    ))
                existing_targets = int(await db.scalar(select(func.count()).select_from(
                    AwarenessScheduledInteraction).where(
                        AwarenessScheduledInteraction.campaign_id == campaign.id,
                        AwarenessScheduledInteraction.status == "pending",
                    )) or 0)
                campaign.audience_count = existing_targets

        # The due slot remains pending until a reviewer approves. A pending
        # interaction excludes the subscriber from later draft batches.
        await db.commit()
        run.status = "succeeded"
        run.deferred_count = deferred
        run.finished_at = datetime.now(UTC)
        if campaign is not None:
            run.detail = f"Gradio awareness agent draft {campaign.id} awaits admin approval for {campaign.audience_count} subscriber(s)."
        elif eligible:
            run.detail = "Due subscribers could not be attached to an agent draft."
        elif deferred and not run.detail:
            run.detail = "Some due subscribers were deferred because their SMS channel or language is unsupported."
        await db.commit()
        return _run_payload(run)
    except Exception as exc:
        await db.rollback()
        db.add(run)
        run.status = "failed"
        run.deferred_count = deferred
        run.finished_at = datetime.now(UTC)
        run.detail = str(exc)[:256]
        await db.commit()
        raise


def _run_payload(run: AwarenessSchedulerRun) -> dict:
    return {"id": str(run.id), "status": run.status, "due_count": run.due_count,
            "sent_count": run.sent_count, "simulated_count": run.simulated_count,
            "failed_count": run.failed_count,
            "deferred_count": run.deferred_count, "finished_at": run.finished_at,
            "detail": run.detail}


async def main() -> None:
    from app.core.config import get_settings
    from app.db.session import create_engine, create_session_factory
    from app.services.sms import create_sms_sender

    settings = get_settings()
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    async with factory() as db:
        result = await run_due_awareness(db, create_sms_sender(settings),
                                         trigger_source="cron",
                                         sms_operational=settings.sms_provider == "http",
                                         allow_test_schedule=settings.environment in {"development", "test"},
                                         groq_api_key=(settings.groq_api_key.get_secret_value()
                                                       if settings.groq_api_key else None))
        print(result)
    await engine.dispose()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
