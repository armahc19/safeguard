"""Admin dashboard summary and repeatable, clearly marked FIR/PDR demo data."""
import hashlib
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

from sqlalchemy import case, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import PermissionDenied
from app.core.partner_secrets import protect_partner_reference
from app.enums import CommunicationChannel, CommunityEntityType, ReportType, RiskLevel, UserRole
from app.models import (
    CommunityEntity,
    CommunityReport,
    CrossInstitutionSignal,
    EntityIntelligenceProfile,
    EntityRelationship,
    FIRReportRecord,
    FIRRiskAssessment,
    FraudIncident,
    IdentityResolutionCluster,
    LivenessAssessment,
    LivenessChallenge,
    Partner,
    PartnerAccount,
    PartnerIdentity,
    PartnerIntelligenceDelivery,
    PartnerTransaction,
    User,
)
from app.schemas.fraud import CommunityReportCreate
from app.schemas.liveness import LivenessAssessmentIn
from app.schemas.partners import PartnerCreate, PartnerDataSubmissionIn
from app.services.community_intelligence import CommunityIntelligenceService
from app.services.liveness_verification import record_partner_assessment
from app.services.admin_service import get_dashboard
from app.services.partner_integration import (
    PartnerContext,
    ingest_partner_submission,
    register_partner,
)


_MOBILE_MONEY_CONTEXT = re.compile(
    r"(?<![a-z0-9])(momo|mobile[\s_-]+money|mobile[\s_-]+wallet|wallet|ussd|"
    r"mobile[\s_-]+banking|mtn|telecel|airteltigo)(?![a-z0-9])|(?:gh[₵¢s]|₵)\s*[\d,]+",
    re.IGNORECASE,
)
_TACTIC_LABELS = {
    "credential_theft": "PIN / OTP theft",
    "account_takeover": "SIM swap / account takeover",
    "impersonation": "Impersonation / fake support",
    "phishing": "Phishing links",
    "advance_fee": "Fake fees / prize scams",
    "reversal": "Fake reversal / refund",
    "mule_routing": "Mule-account routing",
    "transfer_deception": "Deceptive money transfers",
    "social_engineering": "Other social engineering",
    "unclassified": "Unclassified mobile-money report",
}
_EXPLICIT_TACTIC_CATEGORIES = {
    "credential_theft": "credential_theft", "otp_theft": "credential_theft",
    "pin_theft": "credential_theft", "account_takeover": "account_takeover",
    "sim_swap": "account_takeover", "sim_swap_fraud": "account_takeover",
    "impersonation": "impersonation", "fake_support": "impersonation",
    "phishing": "phishing", "malicious_link": "phishing",
    "advance_fee": "advance_fee", "fake_prize": "advance_fee",
    "lottery_scam": "advance_fee", "reversal_scam": "reversal",
    "refund_scam": "reversal", "money_mule": "mule_routing",
    "mule_account": "mule_routing", "social_engineering": "social_engineering",
    "transfer_deception": "transfer_deception",
}


def _classify_mobile_money_tactic(report: FIRReportRecord) -> tuple[str, str] | None:
    text = f"{report.subject or ''} {report.description or ''}"
    if not _MOBILE_MONEY_CONTEXT.search(f"{report.category or ''} {text}"):
        return None
    category = re.sub(r"[^a-z0-9]+", "_", (report.category or "").casefold()).strip("_")
    explicit = _EXPLICIT_TACTIC_CATEGORIES.get(category)
    if explicit:
        return explicit, "fir_category"

    content = text.casefold()
    rules = (
        ("account_takeover", r"sim\s*swap|sim\s*replacement|number\s*port|account\s*takeover"),
        ("credential_theft", r"\botp\b|\bpin\b|verification\s+code|security\s+code|one.?time\s+password"),
        ("impersonation", r"impersonat|pretend(?:ed|ing)?\s+(?:to\s+be|as)|posing\s+as|fake\s+(?:support|officer|agent)|claimed\s+to\s+be"),
        ("phishing", r"phish|malicious\s+link|click\s+(?:this|the)\s+link|fake\s+website"),
        ("advance_fee", r"advance\s+fee|processing\s+fee|release\s+fee|prize|lottery|fake\s+loan|pay\s+(?:a\s+)?fee"),
        ("reversal", r"reversal|refund|reverse\s+(?:the\s+)?transfer|sent\s+(?:the\s+)?money\s+by\s+mistake|fake\s+payment\s+alert"),
        ("mule_routing", r"money\s+mule|mule\s+account|cash\s*out|forward(?:ed|ing)?\s+(?:the\s+)?money|layer(?:ed|ing)\s+funds"),
        ("transfer_deception", r"unauthori[sz]ed\s+transfer|tricked\s+me\s+into\s+(?:sending|transferring)|deceptive\s+transfer"),
        ("social_engineering", r"deceiv|scam|trick|pressur|urgent|coerc|fraud"),
    )
    for tactic, pattern in rules:
        if re.search(pattern, content):
            return tactic, "text_suggestion"
    return "unclassified", "text_suggestion"


def _mobile_money_tactic_summary(reports: list[FIRReportRecord], now: datetime) -> dict:
    periods = ("30d", "90d", "all")
    counts: dict[str, dict] = {}
    mobile_reports = rejected = synthetic_total = 0
    cutoffs = {"30d": now - timedelta(days=30), "90d": now - timedelta(days=90)}
    for report in reports:
        classification = _classify_mobile_money_tactic(report)
        if classification is None:
            continue
        status = str(report.status or "").casefold()
        if status == "rejected":
            rejected += 1
            continue
        mobile_reports += 1
        synthetic = ((report.category or "").casefold().startswith("synthetic_")
                     or "synthetic training scenario" in (report.description or "").casefold()
                     or (report.evidence_reference or "").casefold().startswith(("synthetic/", "demo/")))
        synthetic_total += int(synthetic)
        tactic, method = classification
        item = counts.setdefault(tactic, {
            "key": tactic, "label": _TACTIC_LABELS[tactic],
            "first_seen_at": None, "last_seen_at": None, "newly_reported_30d": False,
            "periods": {
                period: {"reports": 0, "reviewed_reports": 0, "suggested_reports": 0,
                         "explicit_category_reports": 0, "synthetic_reports": 0}
                for period in periods
            },
        })
        created_at = report.created_at
        if created_at is not None and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        if created_at is not None:
            first_seen = item["first_seen_at"]
            last_seen = item["last_seen_at"]
            item["first_seen_at"] = min(first_seen, created_at) if first_seen else created_at
            item["last_seen_at"] = max(last_seen, created_at) if last_seen else created_at
            item["newly_reported_30d"] = item["first_seen_at"] >= cutoffs["30d"]
        report_periods = ["all"]
        if created_at is not None:
            if created_at >= cutoffs["90d"]:
                report_periods.append("90d")
            if created_at >= cutoffs["30d"]:
                report_periods.append("30d")
        reviewed = status in {"accepted", "approved", "verified"}
        for period in report_periods:
            tally = item["periods"][period]
            tally["reports"] += 1
            tally["reviewed_reports"] += int(reviewed)
            tally["suggested_reports"] += int(method == "text_suggestion")
            tally["explicit_category_reports"] += int(method == "fir_category")
            tally["synthetic_reports"] += int(synthetic)

    return {
        "taxonomy_version": "mobile-money-tactics.v1",
        "count_basis": "non-rejected FIR reports; one primary tactic per report",
        "mobile_money_reports": mobile_reports,
        "rejected_reports_excluded": rejected,
        "synthetic_reports": synthetic_total,
        "techniques": sorted(counts.values(), key=lambda item: (
            -item["periods"]["all"]["reports"], item["label"])),
    }


async def get_admin_monitoring(db: AsyncSession) -> dict:
    """Operational monitoring slice: dashboard risk mix + top entities and active signals."""
    dashboard = await get_dashboard(db)
    intelligence = await get_intelligence_overview(db)
    risk_distribution = {
        (level.value if hasattr(level, "value") else str(level)): count
        for level, count in dashboard.risk_distribution.items()
    }
    return {
        "updated_at": datetime.now(UTC).isoformat(),
        "metrics": {
            "fraud_reports": dashboard.fraud_reports,
            "active_investigations": dashboard.active_investigations,
            "suspicious_signals": dashboard.suspicious_signals,
            "connected_partners": dashboard.connected_partners,
            "pending_review": dashboard.pending_review,
        },
        "risk_distribution": risk_distribution,
        "feedback_effectiveness": dashboard.feedback_effectiveness,
        "recent_signals": intelligence.get("recent_signals") or [],
        "top_entities": intelligence.get("top_entities") or [],
    }


async def get_intelligence_overview(db: AsyncSession) -> dict:
    async def count(model) -> int:
        return int(await db.scalar(select(func.count()).select_from(model)) or 0)

    profiles = (await db.execute(select(EntityIntelligenceProfile.risk_level,
        func.count(EntityIntelligenceProfile.id)).group_by(EntityIntelligenceProfile.risk_level))).all()
    risk_distribution = {str(level.value if hasattr(level, "value") else level): amount
                         for level, amount in profiles}
    cluster_rows = (await db.execute(select(IdentityResolutionCluster.resolution_status,
        func.count(IdentityResolutionCluster.id)).group_by(IdentityResolutionCluster.resolution_status))).all()
    clusters = {status: amount for status, amount in cluster_rows}
    signal_rows = (await db.execute(select(CrossInstitutionSignal.signal_type,
        func.count(CrossInstitutionSignal.id)).where(CrossInstitutionSignal.status == "active")
        .group_by(CrossInstitutionSignal.signal_type))).all()
    signals_by_type = {signal_type: amount for signal_type, amount in signal_rows}
    detection_count = sum(signals_by_type.get(signal_type, 0)
                          for signal_type in ("mule_network_candidate", "real_time_entity_risk"))
    liveness_rows = (await db.execute(select(LivenessAssessment.liveness_status,
        func.count(LivenessAssessment.id)).group_by(LivenessAssessment.liveness_status))).all()
    liveness = {status: amount for status, amount in liveness_rows}
    delivery_rows = (await db.execute(select(PartnerIntelligenceDelivery.delivery_status,
        func.count(PartnerIntelligenceDelivery.id)).group_by(PartnerIntelligenceDelivery.delivery_status))).all()
    deliveries = {status: amount for status, amount in delivery_rows}

    now = datetime.now(UTC)
    first_day = (now - timedelta(days=13)).replace(hour=0, minute=0, second=0, microsecond=0)
    risk_rows = (await db.execute(select(
        func.date(FIRRiskAssessment.created_at).label("day"),
        FIRRiskAssessment.risk_level, func.count(FIRRiskAssessment.id),
    ).where(FIRRiskAssessment.created_at >= first_day)
      .group_by("day", FIRRiskAssessment.risk_level).order_by("day"))).all()
    risk_by_day: dict[str, dict[str, int]] = {}
    for offset in range(14):
        day = (first_day + timedelta(days=offset)).date().isoformat()
        risk_by_day[day] = {level: 0 for level in ("low", "medium", "high", "critical")}
    for day, level, amount in risk_rows:
        day_key = day.isoformat() if hasattr(day, "isoformat") else str(day)
        level_key = level.value if hasattr(level, "value") else str(level).lower()
        if level_key in risk_by_day[day_key]:
            risk_by_day[day_key][level_key] = amount

    report_rows = (await db.execute(select(
        func.date(FIRReportRecord.created_at).label("day"),
        func.count(FIRReportRecord.id),
    ).where(FIRReportRecord.created_at >= first_day)
      .group_by("day").order_by("day"))).all()
    reports_by_day = {day: 0 for day in risk_by_day}
    for day, amount in report_rows:
        day_key = day.isoformat() if hasattr(day, "isoformat") else str(day)
        reports_by_day[day_key] = amount
    report_status_rows = (await db.execute(select(
        FIRReportRecord.status, func.count(FIRReportRecord.id)
    ).group_by(FIRReportRecord.status))).all()
    fir_tactic_reports = (await db.scalars(select(FIRReportRecord))).all()
    mobile_money_tactics = _mobile_money_tactic_summary(fir_tactic_reports, now)

    signal_trend_rows = (await db.execute(select(
        func.date(CrossInstitutionSignal.created_at).label("day"),
        func.count(CrossInstitutionSignal.id),
        func.sum(case((CrossInstitutionSignal.risk_level.in_((RiskLevel.HIGH, RiskLevel.CRITICAL)), 1), else_=0)),
    ).where(CrossInstitutionSignal.created_at >= first_day)
      .group_by("day").order_by("day"))).all()
    signals_by_day = {day: {"total": 0, "high_risk": 0} for day in risk_by_day}
    for day, total, high_risk in signal_trend_rows:
        day_key = day.isoformat() if hasattr(day, "isoformat") else str(day)
        signals_by_day[day_key] = {"total": total or 0, "high_risk": high_risk or 0}

    active_signal_rows = (await db.execute(select(
        CrossInstitutionSignal.risk_level, func.count(CrossInstitutionSignal.id)
    ).where(CrossInstitutionSignal.status == "active")
      .group_by(CrossInstitutionSignal.risk_level))).all()
    active_signals_by_risk = {
        (level.value if hasattr(level, "value") else str(level).lower()): amount
        for level, amount in active_signal_rows
    }
    node_rows = (await db.execute(select(
        CommunityEntity.entity_type, func.count(CommunityEntity.id)
    ).group_by(CommunityEntity.entity_type))).all()
    nodes_by_type = {kind.value: amount for kind, amount in node_rows}
    edge_rows = (await db.execute(select(
        EntityRelationship.relationship_type, func.count(EntityRelationship.id)
    ).group_by(EntityRelationship.relationship_type).order_by(
        func.count(EntityRelationship.id).desc()))).all()
    edges_by_type = {kind: amount for kind, amount in edge_rows}
    transaction_status_rows = (await db.execute(select(
        PartnerTransaction.transaction_status, func.count(PartnerTransaction.id)
    ).group_by(PartnerTransaction.transaction_status))).all()
    transactions_by_status = {status: amount for status, amount in transaction_status_rows}
    transaction_currency_rows = (await db.execute(select(
        PartnerTransaction.currency, func.count(PartnerTransaction.id),
        func.sum(PartnerTransaction.amount),
    ).where(PartnerTransaction.transaction_status == "successful")
      .group_by(PartnerTransaction.currency))).all()

    top_profiles = (await db.execute(select(EntityIntelligenceProfile, CommunityEntity)
        .join(CommunityEntity, CommunityEntity.id == EntityIntelligenceProfile.entity_id)
        .order_by(EntityIntelligenceProfile.risk_score.desc(), EntityIntelligenceProfile.computed_at.desc())
        .limit(8))).all()
    recent_signals = (await db.scalars(select(CrossInstitutionSignal)
        .where(CrossInstitutionSignal.status == "active")
        .order_by(CrossInstitutionSignal.last_seen_at.desc()).limit(10))).all()

    return {
        "fir": {"reports": await count(FIRReportRecord), "community_reports": await count(CommunityReport)},
        "pdr": {"partners": await count(Partner), "identities": await count(PartnerIdentity),
                "accounts": await count(PartnerAccount), "transactions": await count(PartnerTransaction)},
        "identity": {"clusters": sum(clusters.values()), "resolved": clusters.get("resolved", 0),
                      "candidates": clusters.get("candidate", 0)},
        "entities": {"profiles": await count(EntityIntelligenceProfile),
                     "risk_distribution": risk_distribution},
        "graph": {"nodes": await count(CommunityEntity), "edges": await count(EntityRelationship)},
        "fraud_risk": {"high_or_critical": risk_distribution.get("high", 0) + risk_distribution.get("critical", 0),
                       "risk_distribution": risk_distribution},
        "cross_institution": {"active_signals": sum(signals_by_type.values()), "by_type": signals_by_type},
        "dashboard": {
            "fraud_signals": {
                "active": sum(active_signals_by_risk.values()),
                "active_by_risk": active_signals_by_risk,
                "by_type": signals_by_type,
                "trend_14d": [{"date": day, **signals_by_day[day]} for day in risk_by_day],
            },
            "risk_trends": [{"date": day, **risk_by_day[day]} for day in risk_by_day],
            "reports": {
                "total": await count(FIRReportRecord),
                "last_14_days": sum(reports_by_day.values()),
                "by_status": {status: amount for status, amount in report_status_rows},
                "trend_14d": [{"date": day, "count": reports_by_day[day]} for day in risk_by_day],
            },
            "mobile_money_tactics": mobile_money_tactics,
            "network": {
                "nodes": sum(nodes_by_type.values()), "nodes_by_type": nodes_by_type,
                "relationships": sum(edges_by_type.values()), "relationships_by_type": edges_by_type,
                "partner_transactions": await count(PartnerTransaction),
                "transactions_by_status": transactions_by_status,
                "successful_volume_by_currency": [
                    {"currency": currency, "count": amount, "total_amount": float(total_amount or 0)}
                    for currency, amount, total_amount in transaction_currency_rows
                ],
            },
        },
        "ai_graph": {"profiles": await count(EntityIntelligenceProfile), "fusion_version": "ai-graph-fusion.v1"},
        "liveness": {"assessments": await count(LivenessAssessment), "by_status": liveness},
        "real_time_detection": {"active_signals": detection_count, "by_type": signals_by_type},
        "sharing": {"pending": deliveries.get("pending", 0), "acknowledged": deliveries.get("acknowledged", 0)},
        "top_entities": [{"id": str(profile.entity_id), "type": entity.entity_type.value,
            "display_value": entity.display_value or entity.entity_type.value,
            "risk_score": profile.risk_score, "risk_level": profile.risk_level.value,
            "risk_confidence": profile.risk_confidence, "risk_reasons": profile.risk_reasons,
            "ai_features": profile.ai_features, "graph_features": profile.graph_features}
            for profile, entity in top_profiles],
        "recent_signals": [{"id": str(signal.id), "signal_type": signal.signal_type,
            "risk_level": signal.risk_level.value, "score": signal.score,
            "confidence": signal.confidence, "partner_codes": signal.partner_codes,
            "entity_ids": list(signal.entity_ids or []),
            "reasons": signal.reasons, "created_at": signal.created_at.isoformat()}
            for signal in recent_signals],
    }


async def _ensure_partner(db: AsyncSession, admin_id: UUID, settings: Settings,
                          code: str, name: str, kind: str) -> PartnerContext:
    partner = await db.scalar(select(Partner).where(Partner.partner_code == code))
    if partner is None:
        result = await register_partner(db, admin_id,
            PartnerCreate(partner_code=code, partner_name=name, partner_type=kind), settings)
        partner = await db.get(Partner, result.id)
    elif partner.partner_status != "active":
        partner.partner_status = "active"
        await db.commit()
        await db.refresh(partner)
    return PartnerContext(partner_id=partner.id, partner_code=partner.partner_code,
        partner_name=partner.partner_name, partner_type=partner.partner_type)


_DEMO_TREND_SCORES = {
    RiskLevel.LOW: 0.22,
    RiskLevel.MEDIUM: 0.48,
    RiskLevel.HIGH: 0.74,
    RiskLevel.CRITICAL: 0.91,
}
_DEMO_CHART_SUBJECT = "+233550000777"


async def _seed_admin_trend_charts(
    db: AsyncSession,
    now: datetime,
    partner_codes: list[str],
) -> dict[str, int]:
    """Backfill 14-day FIR risk and report counts so admin trend cards are visible in dev/test."""
    await db.execute(delete(FIRRiskAssessment).where(FIRRiskAssessment.source == "demo_trend_seed"))

    reports = (await db.scalars(
        select(FIRReportRecord)
        .where(or_(
            FIRReportRecord.subject == _DEMO_CHART_SUBJECT,
            FIRReportRecord.subject.ilike("%550000777%"),
            FIRReportRecord.evidence_reference.like("demo/evidence%"),
        ))
        .order_by(FIRReportRecord.created_at)
        .limit(20)
    )).all()
    if not reports:
        reports = (await db.scalars(
            select(FIRReportRecord).order_by(FIRReportRecord.created_at.desc()).limit(14)
        )).all()

    incidents = (await db.scalars(
        select(FraudIncident).order_by(FraudIncident.created_at.desc()).limit(8)
    )).all()

    level_cycle = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    risk_rows = 0
    for day_offset in range(14):
        day_base = (now - timedelta(days=13 - day_offset)).replace(
            hour=9, minute=0, second=0, microsecond=0,
        )
        for slot in range(2):
            level = level_cycle[(day_offset + slot) % 4]
            created = day_base + timedelta(hours=slot * 4)
            if reports:
                report = reports[(day_offset + slot) % len(reports)]
                db.add(FIRRiskAssessment(
                    report_id=report.id,
                    risk_level=level,
                    risk_score=_DEMO_TREND_SCORES[level],
                    confidence=0.8,
                    reasons=["demo trend chart sample"],
                    source="demo_trend_seed",
                    created_at=created,
                ))
            elif incidents:
                incident = incidents[(day_offset + slot) % len(incidents)]
                db.add(FIRRiskAssessment(
                    incident_id=incident.id,
                    risk_level=level,
                    risk_score=_DEMO_TREND_SCORES[level],
                    confidence=0.8,
                    reasons=["demo trend chart sample"],
                    source="demo_trend_seed",
                    created_at=created,
                ))
            else:
                continue
            risk_rows += 1

    for index, report in enumerate(reports):
        report.created_at = (now - timedelta(days=min(index, 13), hours=index % 6)).replace(
            minute=15, second=0, microsecond=0,
        )

    signals_added = 0
    active_count = int(await db.scalar(
        select(func.count()).select_from(CrossInstitutionSignal).where(
            CrossInstitutionSignal.status == "active",
        ),
    ) or 0)
    if active_count < 2 and partner_codes:
        signal_key = f"demo-trend-mule-{now.strftime('%Y%m%d')}"
        existing = await db.scalar(
            select(CrossInstitutionSignal.id).where(CrossInstitutionSignal.signal_key == signal_key),
        )
        if existing is None:
            seen = now - timedelta(days=2)
            phone_entity = await db.scalar(select(CommunityEntity).where(
                CommunityEntity.entity_type == CommunityEntityType.PHONE,
                CommunityEntity.normalized_value == _DEMO_CHART_SUBJECT,
            ))
            entity_ids = [str(phone_entity.id)] if phone_entity else []
            db.add(CrossInstitutionSignal(
                signal_key=signal_key,
                signal_type="mule_network_candidate",
                status="active",
                risk_level=RiskLevel.HIGH,
                score=0.82,
                confidence=0.77,
                partner_codes=partner_codes,
                entity_ids=entity_ids,
                reasons=["demo trend chart sample", "cross-provider mule pattern"],
                evidence={"demo": True},
                first_seen_at=seen,
                last_seen_at=now,
                created_at=seen,
            ))
            signals_added = 1

    return {
        "trend_risk_rows": risk_rows,
        "trend_reports_spread": len(reports),
        "trend_signals_added": signals_added,
    }


async def _seed_submission(db: AsyncSession, context: PartnerContext,
                           body: PartnerDataSubmissionIn, settings: Settings) -> None:
    # Stable JSON and minute-bucketed reference make repeat clicks idempotent.
    raw = json.dumps(body.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    await ingest_partner_submission(db, context, body, raw, settings)


async def seed_intelligence_demo(db: AsyncSession, admin: User, settings: Settings) -> dict:
    """Populate development data that exercises reports, identity, graph and sharing."""
    if settings.environment not in {"development", "test"}:
        raise PermissionDenied("Demo data can only be seeded in development or test environments.",
                               code="demo_seed_environment_forbidden")

    now = datetime.now(UTC).replace(second=0, microsecond=0)
    bucket = now.strftime("%Y%m%d%H%M")
    mtn = await _ensure_partner(db, admin.id, settings, "demo_mtn_momo", "Demo MTN MoMo", "momo")
    bank = await _ensure_partner(db, admin.id, settings, "demo_bank", "Demo Community Bank", "bank")

    mtn_identities = [{
        "identity_reference": "demo-cross-provider-person",
        "national_id_reference": "GHA-DEMO-SHARED-001",
        "phone_number": "+233550000777", "verified_ownership": True,
        "verification_status": "verified",
    }]
    mtn_accounts = [{"identity_reference": "demo-cross-provider-person",
        "account_identifier": "demo-mtn-mule-wallet", "account_type": "momo",
        "service_provider": "Demo MTN MoMo", "account_status": "active",
        "ownership_reference": "demo-owner-mtn"}]
    mtn_batch = PartnerDataSubmissionIn.model_validate({
        "submission_reference": f"fir-pdr-demo-mtn-identity-{bucket}",
        "identities": mtn_identities, "accounts": mtn_accounts,
    })
    await _seed_submission(db, mtn, mtn_batch, settings)

    bank_identities = [{
        "identity_reference": "demo-cross-provider-person",
        "national_id_reference": "GHA-DEMO-SHARED-001",
        "phone_number": "+233550000777", "verified_ownership": True,
        "verification_status": "verified",
    }]
    bank_accounts = [{"identity_reference": "demo-cross-provider-person",
        "account_identifier": f"demo-bank-{role}-{number:02d}", "account_type": "savings",
        "service_provider": "Demo Community Bank", "account_status": "active",
        "ownership_reference": "demo-owner-bank"}
        for role in ("sender", "receiver") for number in range(1, 4)]
    for number in range(1, 4):
        bank_identities.append({
            "identity_reference": f"demo-counterparty-{number:02d}",
            "national_id_reference": f"GHA-DEMO-COUNTERPARTY-{number:02d}",
            "phone_number": f"+2332012350{number:02d}", "verified_ownership": True,
            "verification_status": "verified",
        })
        bank_identities.append({
            "identity_reference": f"demo-recipient-{number:02d}",
            "national_id_reference": f"GHA-DEMO-RECIPIENT-{number:02d}",
            "phone_number": f"+2332012360{number:02d}", "verified_ownership": True,
            "verification_status": "verified",
        })
    # Attach each counterpart account to its own identity, rather than the shared identity.
    for account in bank_accounts:
        role, number = account["account_identifier"].replace("demo-bank-", "").split("-")
        account["identity_reference"] = f"demo-counterparty-{number}" if role == "sender" else f"demo-recipient-{number}"
        account["ownership_reference"] = f"demo-owner-{role}-{number}"

    transactions_in = [{
        "transaction_reference": f"demo-bank-in-{number:02d}",
        "sender_account_reference": f"demo-bank-sender-{number:02d}",
        "receiver_account_reference": "demo-mtn-mule-wallet",
        "sender_partner_code": bank.partner_code, "receiver_partner_code": mtn.partner_code,
        "amount": str(Decimal("150.00") + number), "currency": "GHS",
        "balance": "400.00", "timestamp": (now - timedelta(minutes=number)).isoformat(),
        "transaction_status": "successful",
    } for number in range(1, 4)]
    bank_batch = PartnerDataSubmissionIn.model_validate({
        "submission_reference": f"fir-pdr-demo-bank-{bucket}",
        "identities": bank_identities, "accounts": bank_accounts,
        "transactions": transactions_in,
    })
    await _seed_submission(db, bank, bank_batch, settings)

    transactions_out = [{
        "transaction_reference": f"demo-mtn-out-{number:02d}",
        "sender_account_reference": "demo-mtn-mule-wallet",
        "receiver_account_reference": f"demo-bank-receiver-{number:02d}",
        "sender_partner_code": mtn.partner_code, "receiver_partner_code": bank.partner_code,
        "amount": str(Decimal("90.00") + number), "currency": "GHS",
        "balance": "100.00", "timestamp": (now - timedelta(minutes=number + 4)).isoformat(),
        "transaction_status": "successful",
    } for number in range(1, 4)]
    mtn_transactions = PartnerDataSubmissionIn.model_validate({
        "submission_reference": f"fir-pdr-demo-mtn-transactions-{bucket}",
        "transactions": transactions_out,
    })
    await _seed_submission(db, mtn, mtn_transactions, settings)

    # One clearly labeled verifier result lets the admin view exercise the liveness layer.
    demo_verifier_ref = "demo-liveness-attestation"
    prior_liveness = await db.scalar(select(LivenessAssessment.id).where(
        LivenessAssessment.partner_id == mtn.partner_id,
        LivenessAssessment.provider_reference == demo_verifier_ref,
    ))
    if prior_liveness is None:
        subject = await db.scalar(select(User).where(User.phone == "+233550000777"))
        if subject is None:
            subject = User(phone="+233550000777", role=UserRole.USER)
            db.add(subject)
            await db.flush()
        challenge_nonce = secrets.token_urlsafe(32)
        challenge = LivenessChallenge(
            user_id=subject.id,
            nonce_hash=hashlib.sha256(challenge_nonce.encode()).hexdigest(),
            phone_reference=protect_partner_reference(
                "+233550000777", namespace="phone",
                application_secret=settings.secret_key.get_secret_value(),
            ),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        db.add(challenge)
        await db.flush()
        await record_partner_assessment(db, mtn.partner_id, mtn.partner_code,
            LivenessAssessmentIn(
                challenge_id=challenge.id, challenge_nonce=challenge_nonce,
                identity_reference="demo-cross-provider-person",
                provider_name="Demo Liveness Verifier", provider_reference=demo_verifier_ref,
                liveness_status="spoof", confidence=0.82,
                model_version="demo-attestation.v1", reason_code="demo_simulated_result",
                assessed_at=datetime.now(UTC),
            ), settings)

    reporter_specs = [
        ("+233240000101", "I received an urgent message claiming to be MTN support. It asked for my MoMo PIN and OTP to stop my account from being blocked."),
        ("+233240000102", "A caller posing as a bank officer said my account would close today unless I sent my verification code and transferred a fee."),
        ("+233240000103", "This number sent a fake prize message and a short link, then pressured me to share my OTP to release the reward."),
    ]
    reports_created = 0
    service = CommunityIntelligenceService(db, settings.default_calling_code, settings)
    for index, (phone, description) in enumerate(reporter_specs, start=1):
        reporter = await db.scalar(select(User).where(User.phone == phone))
        if reporter is None:
            reporter = User(phone=phone, role=UserRole.USER)
            db.add(reporter)
            await db.flush()
        prior = await db.scalar(select(CommunityReport.id).where(
            CommunityReport.reporter_id == reporter.id,
            CommunityReport.subject_value == "+233550000777",
        ))
        if prior:
            continue
        await service.submit(reporter, CommunityReportCreate(
            subject="+233550000777", report_type=ReportType.SMS,
            channel=CommunicationChannel.SMS, description=description,
            category="impersonation", evidence_reference=f"demo/evidence/message-{index}.txt",
        ))
        reports_created += 1

    # The input rows are stable per minute; a final refresh also includes any FIR reports.
    from app.services.intelligence_layers import IntelligenceLayers
    counts = await IntelligenceLayers(db, settings).refresh_all()
    trend_charts = await _seed_admin_trend_charts(
        db, now, [mtn.partner_code, bank.partner_code],
    )
    await db.commit()
    return {"demo_data": True, "fir_reports_created": reports_created,
            "demo_liveness_attestation": "spoof sample from Demo Liveness Verifier",
            "demo_partner_codes": [mtn.partner_code, bank.partner_code],
            "projection_counts": counts, "trend_charts": trend_charts}
