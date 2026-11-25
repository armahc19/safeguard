from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import CaseStatus, FeedbackOutcome, ReportStatus, RiskLevel, ThreatIndicatorType
from app.models import (
    CaseFeedback,
    CrossInstitutionSignal,
    FIRReportRecord,
    FraudCase,
    FraudReport,
    Partner,
    PhoneNumber,
    RiskAssessment,
    ThreatIndicator,
)
from app.schemas.admin import AdminDashboardOut, DashboardReport


async def get_dashboard(db: AsyncSession) -> AdminDashboardOut:
    now = datetime.now(UTC)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    month_ago = now - timedelta(days=30)

    reports_today = await db.scalar(
        select(func.count()).select_from(FraudReport).where(FraudReport.created_at >= today)
    )
    pending_review = await db.scalar(
        select(func.count()).select_from(FraudReport).where(
            FraudReport.status.in_((ReportStatus.PENDING, ReportStatus.UNDER_REVIEW))
        )
    )
    numbers_protected = await db.scalar(select(func.count()).select_from(PhoneNumber))
    high_risk_blocked = await db.scalar(
        select(func.count()).select_from(ThreatIndicator).where(
            ThreatIndicator.indicator_type == ThreatIndicatorType.BLOCKLIST.value,
            ThreatIndicator.risk_level.in_((RiskLevel.HIGH, RiskLevel.CRITICAL)),
        )
    )
    fraud_reports = await db.scalar(select(func.count()).select_from(FIRReportRecord))
    active_investigations = await db.scalar(select(func.count()).select_from(FraudCase).where(
        FraudCase.status == CaseStatus.OPEN,
    ))
    suspicious_signals = await db.scalar(select(func.count()).select_from(CrossInstitutionSignal).where(
        CrossInstitutionSignal.status == "active",
    ))
    connected_partners = await db.scalar(select(func.count()).select_from(Partner).where(
        Partner.partner_status == "active",
    ))

    grouped = await db.execute(
        select(RiskAssessment.risk_level, func.count())
        .where(RiskAssessment.created_at >= month_ago)
        .group_by(RiskAssessment.risk_level)
    )
    distribution = {level: 0 for level in RiskLevel}
    for level, count in grouped.all():
        distribution[level] = count

    recent = await db.execute(
        select(FraudReport, PhoneNumber.normalized_number)
        .join(PhoneNumber, PhoneNumber.id == FraudReport.phone_number_id)
        .order_by(FraudReport.created_at.desc())
        .limit(10)
    )
    recent_reports = [
        DashboardReport(
            id=report.id,
            phone=phone,
            report_type=report.report_type,
            status=report.status,
            created_at=report.created_at,
        )
        for report, phone in recent.all()
    ]
    feedback_rows = await db.execute(
        select(CaseFeedback.outcome, func.count())
        .where(CaseFeedback.created_at >= month_ago)
        .group_by(CaseFeedback.outcome)
    )
    feedback_summary = {outcome.value: count for outcome, count in feedback_rows.all()}
    feedback_effectiveness = {
        "interventions_delivered": feedback_summary.get(FeedbackOutcome.INTERVENTION_DELIVERED.value, 0),
        "advice_followed": feedback_summary.get(FeedbackOutcome.ADVICE_FOLLOWED.value, 0),
        "loss_prevented": feedback_summary.get(FeedbackOutcome.LOSS_PREVENTED.value, 0),
        "confirmed_fraud": feedback_summary.get(FeedbackOutcome.CONFIRMED_FRAUD.value, 0),
        "false_positive": feedback_summary.get(FeedbackOutcome.FALSE_POSITIVE.value, 0),
    }
    from app.services.awareness import awareness_outreach_stats
    outreach = await awareness_outreach_stats(db)
    feedback_effectiveness["interventions_delivered"] += outreach["interventions_delivered_30d"]
    feedback_effectiveness["advice_followed"] += outreach["awareness_read_30d"]
    feedback_effectiveness["awareness_sms_sent_30d"] = outreach["sms_sent_30d"]
    feedback_effectiveness["awareness_read_rate"] = outreach["read_rate"]
    delivered = feedback_effectiveness["interventions_delivered"]
    followed = feedback_effectiveness["advice_followed"]
    feedback_effectiveness["follow_rate"] = round(followed / delivered, 4) if delivered else 0.0
    return AdminDashboardOut(
        fraud_reports=fraud_reports or 0,
        active_investigations=active_investigations or 0,
        suspicious_signals=suspicious_signals or 0,
        connected_partners=connected_partners or 0,
        reports_today=reports_today or 0,
        pending_review=pending_review or 0,
        numbers_protected=numbers_protected or 0,
        high_risk_blocked=high_risk_blocked or 0,
        risk_distribution=distribution,
        recent_reports=recent_reports,
        feedback_summary=feedback_summary,
        feedback_effectiveness=feedback_effectiveness,
    )
