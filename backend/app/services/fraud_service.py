"""Fraud Intelligence: reporting, number lookup, report verification and threat management.

How the pieces fit
  * A user submits a FraudReport (status "pending"). The number's automatic `report_volume` ThreatIndicator is
    recomputed from DISTINCT reporters (see scoring.py).
  * A reviewer approves / rejects the report. Approving lifts the number's score; rejecting removes the report's
    weight. Approving with a category also records a `reviewer_classification` indicator.
  * Reviewers can add a manual `blocklist` indicator, admins an `allowlist` one. Manual indicators override the
    automatic score at lookup time.
  * Lookups combine all of that into a risk level, and record a RiskAssessment for numbers we already know.

Recomputation takes a per-number advisory lock so concurrent reports / reviews never produce a stale score.
"""
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import Select, and_, case, distinct, func, select, text, true
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import (
    BadRequestError,
    ConflictError,
    NotFoundError,
    PermissionDenied,
    ValidationFailed,
)
from app.core.phone import country_for_e164, normalize_phone
from app.core.ratelimit import hit
from app.services.nexus_exposure_profile import compute_exposure_profile
from app.enums import (
    MANUAL_INDICATOR_TYPES,
    CommunicationChannel,
    CommunityEntityType,
    CommunityIncidentStatus,
    EvidenceType,
    FeedbackOutcome,
    FraudOutcome,
    IntelligenceStatus,
    ReportStatus,
    ReviewDecision,
    RiskLevel,
    ThreatIndicatorType,
    UserRole,
)
from app.models import (
    CommunityEntity,
    Device,
    FIRReportIncident,
    FIRReportRecord,
    FIRRiskAssessment,
    FraudIncident,
    FraudReport,
    IntelligenceRecord,
    InvestigationActivity,
    PhoneNumber,
    ReportEntity,
    RiskAssessment,
    ScamCategory,
    ThreatIndicator,
    User,
    VerificationRecord,
)
from app.schemas.cases import EvidenceCreate
from app.schemas.common import Page
from app.schemas.fraud import (
    CategoryOut,
    LookupOut,
    MessageIndicatorsIn,
    ReportCreate,
    ReportOut,
    ThreatCreate,
    ThreatOut,
    ThreatUpdate,
    TransactionContextIn,
)
from app.services import scoring
from app.services.case_service import CaseService
from app.services.communication import interpret
from app.services.feedback import FeedbackService
from app.services.fir_ingestion import FIRIngestionService
from app.services.intervention import intervention_engine
from app.services.network_intelligence import NetworkService
from app.services.risk_engine import assess as assess_risk

logger = logging.getLogger(__name__)

OPEN_STATUSES = (ReportStatus.PENDING, ReportStatus.UNDER_REVIEW)
STATUS_FOR_DECISION = {
    ReviewDecision.APPROVED: ReportStatus.VERIFIED,
    ReviewDecision.REJECTED: ReportStatus.REJECTED,
    ReviewDecision.NEEDS_INFO: ReportStatus.UNDER_REVIEW,
}
FINAL_DECISIONS = {ReviewDecision.APPROVED, ReviewDecision.REJECTED}


def _where(stmt: Select, filters: list) -> Select:
    return stmt.where(and_(true(), *filters))


class FraudService:
    def __init__(self, db: AsyncSession, redis: Redis, settings: Settings) -> None:
        self.db, self.redis, self.settings = db, redis, settings

    def _normalize(self, raw: str) -> str:
        return normalize_phone(raw, self.settings.default_calling_code)

    # ================================================================ reporting
    async def submit_report(self, reporter: User, data: ReportCreate) -> ReportOut:
        s = self.settings
        e164 = self._normalize(data.number)
        if e164 == reporter.phone:
            raise BadRequestError("You can't report your own number.", code="own_number")

        await hit(self.redis, f"rl:report:user:{reporter.id}", s.reports_per_user_per_day, 86400)

        if data.device_id is not None:
            device = await self.db.get(Device, data.device_id)
            if device is None or device.user_id != reporter.id:
                raise ValidationFailed("Unknown device.", code="invalid_device")

        phone = await self._get_or_create_phone(e164)
        case = await CaseService(self.db).get_or_create(
            reporter, data.case_id, title=f"Report involving {e164}"
        )

        since = datetime.now(UTC) - timedelta(hours=s.duplicate_report_window_hours)
        duplicate = await self.db.scalar(
            select(FraudReport.id).where(
                FraudReport.user_id == reporter.id,
                FraudReport.phone_number_id == phone.id,
                FraudReport.created_at > since,
            )
        )
        if duplicate:
            raise ConflictError("You already reported this number recently.", code="duplicate_report")

        report = FraudReport(
            user_id=reporter.id,
            device_id=data.device_id,
            phone_number_id=phone.id,
            case_id=case.id,
            report_type=data.report_type.value,
            description=data.description,
            evidence_reference=data.evidence_reference,
        )
        self.db.add(report)
        await self.db.flush()
        fir_service = FIRIngestionService(self.db, s.default_calling_code)
        fir_report, _incident = await fir_service.number_report(
            report, reporter, phone, data.channel.value
        )
        await fir_service.analyze_report_content(
            fir_report, _incident, text=report.description, phone_number=e164,
        )
        await CaseService(self.db).add_internal_evidence(
            case,
            EvidenceCreate(
                evidence_type=EvidenceType.REPORT,
                source="user_report",
                value=data.evidence_reference,
                details={"report_id": str(report.id), "phone": e164, "report_type": data.report_type.value,
                         "communication": interpret(channel=data.channel, phone_number=e164,
                                                     default_calling_code=s.default_calling_code).model_dump(mode="json")},
            ),
        )
        await NetworkService(self.db, s.default_calling_code).record_report(e164, report.id, case.id)
        result = await self._refresh_threat(phone.id)
        _incident.risk_level = result.level
        _incident.confidence = result.confidence
        self.db.add(FIRRiskAssessment(
            report_id=fir_report.id, incident_id=_incident.id,
            risk_level=result.level, risk_score=result.score,
            confidence=result.confidence, reasons=["number report volume and verification status"],
            source="number_report_scoring",
        ))
        await self.db.commit()
        logger.info("report_submitted", extra={"report_id": str(report.id), "user_id": str(reporter.id)})
        return await self._report_out(report.id)

    async def get_report(self, requester: User, report_id: UUID) -> ReportOut:
        row = await self._report_row(report_id)
        report: FraudReport = row[0]
        if report.user_id != requester.id and requester.role == UserRole.USER:
            raise NotFoundError("Report not found.")  # 404, not 403: don't reveal that it exists
        return self._to_report_out(row)

    async def list_reports(self, *, user_id: UUID | None = None, status: ReportStatus | None = None,
                           number: str | None = None, oldest_first: bool = False,
                           limit: int, offset: int) -> Page[ReportOut]:
        filters = []
        if user_id:
            filters.append(FraudReport.user_id == user_id)
        if status:
            filters.append(FraudReport.status == status)
        if number:
            filters.append(PhoneNumber.normalized_number == self._normalize(number))

        total = await self.db.scalar(
            _where(
                select(func.count()).select_from(FraudReport).join(
                    PhoneNumber, PhoneNumber.id == FraudReport.phone_number_id
                ),
                filters,
            )
        )
        order = FraudReport.created_at.asc() if oldest_first else FraudReport.created_at.desc()
        rows = (await self.db.execute(_where(self._report_select(), filters).order_by(order).limit(limit).offset(offset))).all()
        return Page(items=[self._to_report_out(r) for r in rows], total=total or 0, limit=limit, offset=offset)

    # ================================================================ verification
    async def review_report(self, reviewer: User, report_id: UUID, decision: ReviewDecision,
                            category_id: UUID | None) -> ReportOut:
        report = await self.db.scalar(select(FraudReport).where(FraudReport.id == report_id).with_for_update())
        if report is None:
            raise NotFoundError("Report not found.")
        if report.user_id == reviewer.id:
            raise PermissionDenied("You can't review your own report.", code="own_report")
        if category_id is not None:
            if decision != ReviewDecision.APPROVED:
                raise ValidationFailed("A category can only be set when approving.", code="category_not_allowed")
            if await self.db.get(ScamCategory, category_id) is None:
                raise NotFoundError("Scam category not found.", code="category_not_found")

        record = await self.db.scalar(select(VerificationRecord).where(VerificationRecord.report_id == report.id))
        if record is not None and record.decision in FINAL_DECISIONS:
            raise ConflictError("This report has already been reviewed.", code="already_reviewed")

        now = datetime.now(UTC)
        if record is None:
            self.db.add(VerificationRecord(report_id=report.id, decision=decision, reviewer_id=reviewer.id,
                                           reviewed_at=now))
        else:  # an earlier "needs_info" is updated in place until a final decision is made
            record.decision, record.reviewer_id, record.reviewed_at = decision, reviewer.id, now
        report.status = STATUS_FOR_DECISION[decision]
        fir_report = await self.db.scalar(select(FIRReportRecord).where(
            FIRReportRecord.fraud_report_id == report.id
        ))
        if fir_report:
            fir_report.status = report.status.value
            links = (await self.db.scalars(select(FIRReportIncident).where(
                FIRReportIncident.report_id == fir_report.id
            ))).all()
            for link in links:
                incident = await self.db.get(FraudIncident, link.incident_id)
                if incident:
                    if decision == ReviewDecision.APPROVED:
                        incident.status = CommunityIncidentStatus.CONFIRMED
                        incident.outcome = FraudOutcome.CONFIRMED_FRAUD
                    elif decision == ReviewDecision.REJECTED:
                        incident.status = CommunityIncidentStatus.REJECTED
                        incident.outcome = FraudOutcome.FALSE_REPORT
                    elif decision == ReviewDecision.NEEDS_INFO:
                        incident.status = CommunityIncidentStatus.UNDER_REVIEW
                    self.db.add(InvestigationActivity(
                        incident_id=incident.id, actor_id=reviewer.id,
                        action_type="report_reviewed",
                        summary=f"Linked report review decision: {decision.value}.",
                        details={"report_id": str(fir_report.id), "decision": decision.value},
                    ))
        await self.db.flush()

        result = await self._refresh_threat(report.phone_number_id)
        if fir_report:
            self.db.add(FIRRiskAssessment(
                report_id=fir_report.id, risk_level=result.level, risk_score=result.score,
                confidence=result.confidence,
                reasons=[f"review decision: {decision.value}", "number report volume scoring"],
                source="number_report_review_scoring",
            ))
            for link in links:
                incident = await self.db.get(FraudIncident, link.incident_id)
                if incident:
                    incident.risk_level = result.level
                    incident.confidence = result.confidence
                    self.db.add(FIRRiskAssessment(
                        report_id=fir_report.id, incident_id=incident.id,
                        risk_level=result.level, risk_score=result.score,
                        confidence=result.confidence,
                        reasons=[f"report review decision: {decision.value}", "number report scoring"],
                        source="number_report_review_scoring",
                    ))
        if decision == ReviewDecision.APPROVED and category_id is not None:
            await self._upsert_classification(report.phone_number_id, category_id, result)
        if report.case_id is not None:
            await FeedbackService(self.db).record_system(
                case_id=report.case_id, actor=reviewer, outcome=FeedbackOutcome.REVIEWER_DECISION,
                notes=f"review decision: {decision.value}",
                metadata={"report_id": str(report.id), "decision": decision.value,
                          "category_id": str(category_id) if category_id else None},
            )
        await self.db.commit()
        logger.info("report_reviewed", extra={"report_id": str(report.id), "reviewer_id": str(reviewer.id),
                                              "decision": decision.value})
        return await self._report_out(report.id)

    async def _graph_exposure_snippet(self, e164: str) -> tuple[str | None, float | None]:
        entity = await self.db.scalar(select(CommunityEntity).where(
            CommunityEntity.entity_type == CommunityEntityType.PHONE,
            CommunityEntity.normalized_value == e164,
        ))
        if entity is None:
            return None, None
        profile = await compute_exposure_profile(self.db, entity.id)
        pct = float(profile.get("exposed_inflow_pct") or 0)
        if pct <= 0 and profile.get("exposure") not in {"direct_confirmed"}:
            return None, None
        return str(profile.get("sentence") or ""), pct

    # ================================================================ lookup
    async def lookup(self, requester: User, raw_number: str, *,
                     message: MessageIndicatorsIn | None = None,
                     transaction: TransactionContextIn | None = None,
                     case_id: UUID | None = None,
                     channel: CommunicationChannel = CommunicationChannel.APP) -> LookupOut:
        e164 = self._normalize(raw_number)
        communication = interpret(channel=channel, phone_number=e164,
                                  default_calling_code=self.settings.default_calling_code)
        network = await NetworkService(self.db, self.settings.default_calling_code).snapshot(e164)
        community_stats = (await self.db.execute(
            select(
                func.count(distinct(case((FIRReportRecord.status == "accepted", FIRReportRecord.reporter_id)))),
                func.count(distinct(case((FIRReportRecord.status.in_(("submitted", "under_review")), FIRReportRecord.reporter_id)))),
                func.max(FIRReportRecord.created_at),
            ).join(ReportEntity, ReportEntity.report_id == FIRReportRecord.id)
            .join(CommunityEntity, CommunityEntity.id == ReportEntity.entity_id)
            .where(
                CommunityEntity.entity_type == CommunityEntityType.PHONE,
                CommunityEntity.normalized_value == e164,
                FIRReportRecord.source_type == "community",
                FIRReportRecord.status != "rejected",
            )
        )).one()
        community_verified, community_pending, community_last_reported = community_stats
        fir_community_categories = (await self.db.scalars(
            select(FIRReportRecord.category).join(
                ReportEntity, ReportEntity.report_id == FIRReportRecord.id
            ).join(CommunityEntity, CommunityEntity.id == ReportEntity.entity_id).where(
                CommunityEntity.entity_type == CommunityEntityType.PHONE,
                CommunityEntity.normalized_value == e164,
                FIRReportRecord.source_type == "community",
                FIRReportRecord.status != "rejected",
                FIRReportRecord.category.is_not(None),
            ).distinct()
        )).all()
        community_row = (await self.db.execute(
            select(IntelligenceRecord, CommunityEntity).where(
                IntelligenceRecord.entity_id == CommunityEntity.id,
                CommunityEntity.entity_type == CommunityEntityType.PHONE,
                CommunityEntity.normalized_value == e164,
                IntelligenceRecord.status == IntelligenceStatus.ACTIVE,
            ).order_by(IntelligenceRecord.updated_at.desc()).limit(1)
        )).first()
        community_hazard = 0.0
        community_reasons: tuple[str, ...] = ()
        community_provenance: tuple[str, ...] = ()
        if community_verified or community_pending:
            community_reasons = (
                f"Community reports mention this number ({community_verified} accepted, {community_pending} pending review).",
            )
            community_provenance = ("community_fir_reports",)
        community_categories: list[str] = []
        if community_row:
            community_record, _ = community_row
            community_hazard = min(0.6, community_record.confidence * 0.6)
            community_reasons = community_reasons + (
                f"Community intelligence links this number to {community_record.distinct_reporters} distinct reporter(s).",
            )
            community_provenance = community_provenance + ("community_intelligence",)
            community_categories = list(community_record.signals.get("categories", []))
        lookup_case = None
        if case_id is not None:
            lookup_case = await CaseService(self.db).get_or_create(requester, case_id, title=f"Lookup involving {e164}")
        feedback_hazard = 0.0
        feedback_reasons: tuple[str, ...] = ()
        feedback_provenance: tuple[str, ...] = ()
        if lookup_case is not None:
            feedback_hazard, feedback_reasons, feedback_provenance = await FeedbackService(self.db).risk_signals(lookup_case.id)
        await hit(self.redis, f"rl:lookup:user:{requester.id}", self.settings.lookups_per_user_per_minute, 60)

        phone = await self.db.scalar(select(PhoneNumber).where(PhoneNumber.normalized_number == e164))
        if phone is None:
            verified = community_verified
            pending = community_pending
            last_reported = community_last_reported
            assessment = assess_risk(
                scoring.PhoneReputation(
                    verified_reporters=verified,
                    pending_reporters=pending,
                ),
                message=scoring.MessageIndicators(**message.model_dump()) if message else None,
                transaction=scoring.TransactionContext(**transaction.model_dump()) if transaction else None,
                network_score=network.network_score if network.link_count else None,
                additional_hazard=feedback_hazard + community_hazard,
                additional_reasons=network.reasons + feedback_reasons + community_reasons,
                additional_provenance=(("fraud_network_intelligence",) if network.link_count else ()) + feedback_provenance + community_provenance,
            )
            auto = assessment.result
            intervention = intervention_engine.plan(assessment, channel=channel, stage=communication.stage)
            graph_sentence, graph_pct = await self._graph_exposure_snippet(e164)
            short = scoring.short_message(
                e164, auto.level, known=bool(verified or pending),
                verified=verified, pending=pending, override=None,
            )
            if graph_sentence:
                short = f"{short} {graph_sentence}"[:320]
            if lookup_case is not None:
                await CaseService(self.db).add_internal_evidence(
                    lookup_case,
                    EvidenceCreate(
                        evidence_type=EvidenceType.ASSESSMENT,
                        source="number_lookup",
                        value=e164,
                        confidence=assessment.result.confidence,
                        details={"known": bool(verified or pending), "risk_level": auto.level.value, "risk_score": auto.score,
                                 "components": assessment.components, "reasons": list(assessment.reasons),
                                 "signals": assessment.signals(),
                                 "network": {"score": network.network_score, "patterns": list(network.related_patterns),
                                              "campaigns": list(network.campaigns)},
                                 "intervention": intervention.model_dump(mode="json"),
                                 "communication": communication.model_dump(mode="json")},
                    ),
                )
                await self.db.commit()
            return LookupOut(
                case_id=lookup_case.id if lookup_case else None,
                phone=e164, known=bool(verified or pending), risk_level=auto.level, risk_score=auto.score,
                verified_reports=verified, pending_reports=pending,
                categories=sorted(set(fir_community_categories)), last_reported_at=last_reported, override=None,
                advice=scoring.advice_for(auto.level),
                short_message=short,
                graph_exposure_sentence=graph_sentence,
                graph_exposure_pct=graph_pct,
                assessment_components=assessment.components, risk_reasons=list(assessment.reasons),
                risk_confidence=assessment.confidence, risk_evidence=list(assessment.evidence),
                contradictions=list(assessment.contradictions), unknowns=list(assessment.unknowns),
                provenance=list(assessment.provenance), recommended_action=assessment.recommended_action,
                network_score=network.network_score, related_patterns=list(network.related_patterns),
                campaigns=list(network.campaigns),
                intervention=intervention,
            )

        verified, pending, last_reported = await self._report_stats(phone.id)
        verified = max(verified, community_verified)
        pending = max(pending, community_pending)
        last_reported = max((date for date in (last_reported, community_last_reported) if date), default=None)
        indicators = (await self.db.execute(
            select(ThreatIndicator, ScamCategory.name)
            .outerjoin(ScamCategory, ScamCategory.id == ThreatIndicator.category_id)
            .where(ThreatIndicator.phone_number_id == phone.id)
        )).all()

        blocklist_levels = [i.risk_level for i, _ in indicators if i.indicator_type == ThreatIndicatorType.BLOCKLIST.value]
        allowlisted = any(i.indicator_type == ThreatIndicatorType.ALLOWLIST.value for i, _ in indicators)
        categories = sorted({name for _, name in indicators if name} | set(community_categories) | set(fir_community_categories))
        volume = next((i for i, _ in indicators if i.indicator_type == ThreatIndicatorType.REPORT_VOLUME.value), None)

        assessment = assess_risk(
            scoring.PhoneReputation(
                verified_reporters=verified,
                pending_reporters=pending,
                blocklist_levels=tuple(blocklist_levels),
                allowlisted=allowlisted,
            ),
            message=scoring.MessageIndicators(**message.model_dump()) if message else None,
            transaction=scoring.TransactionContext(**transaction.model_dump()) if transaction else None,
            network_score=network.network_score if network.link_count else None,
            additional_hazard=feedback_hazard + community_hazard,
            additional_reasons=network.reasons + feedback_reasons + community_reasons,
            additional_provenance=(("fraud_network_intelligence",) if network.link_count else ()) + feedback_provenance + community_provenance,
        )
        result, override = assessment.result, assessment.override
        intervention = intervention_engine.plan(assessment, channel=channel, stage=communication.stage)
        graph_sentence, graph_pct = await self._graph_exposure_snippet(e164)
        short = scoring.short_message(e164, result.level, known=True, verified=verified, pending=pending,
                                      override=override)
        if graph_sentence:
            short = f"{short} {graph_sentence}"[:320]

        self.db.add(RiskAssessment(
            user_id=requester.id, case_id=lookup_case.id if lookup_case else None, phone_number_id=phone.id,
            threat_indicator_id=volume.id if volume else None,
            risk_level=result.level, risk_score=result.score,
            signals={"verified_reporters": verified, "pending_reporters": pending, "override": override,
                     "categories": categories, **assessment.signals()},
        ))
        if lookup_case is not None:
            await CaseService(self.db).add_internal_evidence(
                lookup_case,
                EvidenceCreate(
                    evidence_type=EvidenceType.ASSESSMENT,
                    source="number_lookup",
                    value=e164,
                    confidence=assessment.result.confidence,
                    details={"known": True, "risk_level": result.level.value, "risk_score": result.score,
                             "components": assessment.components, "reasons": list(assessment.reasons),
                             "communication": communication.model_dump(mode="json"),
                             "network": {"score": network.network_score, "patterns": list(network.related_patterns),
                                         "campaigns": list(network.campaigns)},
                             "intervention": intervention.model_dump(mode="json")},
                ),
            )
        await self.db.commit()

        return LookupOut(
            case_id=lookup_case.id if lookup_case else None,
            phone=e164, known=True, risk_level=result.level, risk_score=result.score, verified_reports=verified,
            pending_reports=pending, categories=categories, last_reported_at=last_reported, override=override,
            advice=scoring.advice_for(result.level),
            short_message=short,
            graph_exposure_sentence=graph_sentence,
            graph_exposure_pct=graph_pct,
            assessment_components=assessment.components, risk_reasons=list(assessment.reasons),
            risk_confidence=assessment.confidence, risk_evidence=list(assessment.evidence),
            contradictions=list(assessment.contradictions), unknowns=list(assessment.unknowns),
            provenance=list(assessment.provenance), recommended_action=assessment.recommended_action,
            network_score=network.network_score, related_patterns=list(network.related_patterns),
            campaigns=list(network.campaigns),
            intervention=intervention,
        )

    # ================================================================ threat management
    async def list_threats(self, *, risk_level: RiskLevel | None, category_id: UUID | None,
                           indicator_type: ThreatIndicatorType | None, number: str | None,
                           limit: int, offset: int) -> Page[ThreatOut]:
        filters = []
        if risk_level:
            filters.append(ThreatIndicator.risk_level == risk_level)
        if category_id:
            filters.append(ThreatIndicator.category_id == category_id)
        if indicator_type:
            filters.append(ThreatIndicator.indicator_type == indicator_type.value)
        if number:
            filters.append(PhoneNumber.normalized_number == self._normalize(number))

        join_on = PhoneNumber.id == ThreatIndicator.phone_number_id
        total = await self.db.scalar(
            _where(select(func.count()).select_from(ThreatIndicator).join(PhoneNumber, join_on), filters)
        )
        rows = (await self.db.execute(
            _where(select(ThreatIndicator, PhoneNumber.normalized_number).join(PhoneNumber, join_on), filters)
            .order_by(ThreatIndicator.last_seen.desc()).limit(limit).offset(offset)
        )).all()
        return Page(items=[self._to_threat_out(i, p) for i, p in rows], total=total or 0, limit=limit, offset=offset)

    async def get_threat(self, threat_id: UUID) -> ThreatOut:
        indicator, phone = await self._threat_row(threat_id)
        return self._to_threat_out(indicator, phone)

    async def create_threat(self, actor: User, data: ThreatCreate) -> ThreatOut:
        self._assert_can_manage(actor, data.indicator_type.value)
        if data.indicator_type == ThreatIndicatorType.ALLOWLIST:
            level = RiskLevel.LOW
        else:
            level = data.risk_level
            self._assert_blocklist_level(level)
        if data.category_id is not None and await self.db.get(ScamCategory, data.category_id) is None:
            raise NotFoundError("Scam category not found.", code="category_not_found")

        phone = await self._get_or_create_phone(self._normalize(data.number))
        indicator = ThreatIndicator(
            phone_number_id=phone.id, category_id=data.category_id, indicator_type=data.indicator_type.value,
            risk_level=level, confidence=data.confidence, last_seen=datetime.now(UTC),
        )
        try:
            async with self.db.begin_nested():
                self.db.add(indicator)
                await self.db.flush()
        except IntegrityError:
            raise ConflictError("This number already has that indicator.", code="threat_exists")
        await self.db.commit()
        logger.info("threat_created", extra={"threat_id": str(indicator.id), "actor_id": str(actor.id),
                                             "type": data.indicator_type.value})
        return await self.get_threat(indicator.id)

    async def update_threat(self, actor: User, threat_id: UUID, data: ThreatUpdate) -> ThreatOut:
        indicator, _ = await self._threat_row(threat_id)
        self._assert_manual(indicator)
        self._assert_can_manage(actor, indicator.indicator_type)
        if data.risk_level is not None:
            if indicator.indicator_type == ThreatIndicatorType.ALLOWLIST.value:
                raise ValidationFailed("An allowlist entry is always low risk.", code="invalid_risk_level")
            self._assert_blocklist_level(data.risk_level)
            indicator.risk_level = data.risk_level
        if data.confidence is not None:
            indicator.confidence = data.confidence
        await self.db.commit()
        logger.info("threat_updated", extra={"threat_id": str(threat_id), "actor_id": str(actor.id)})
        return await self.get_threat(threat_id)

    async def delete_threat(self, actor: User, threat_id: UUID) -> None:
        indicator, _ = await self._threat_row(threat_id)
        self._assert_manual(indicator)
        self._assert_can_manage(actor, indicator.indicator_type)
        await self.db.delete(indicator)
        await self.db.commit()
        logger.info("threat_deleted", extra={"threat_id": str(threat_id), "actor_id": str(actor.id)})

    # ---------------------------------------------------------------- scam categories
    async def list_categories(self) -> list[CategoryOut]:
        rows = (await self.db.scalars(select(ScamCategory).order_by(ScamCategory.name))).all()
        return [CategoryOut(id=c.id, name=c.name) for c in rows]

    async def create_category(self, name: str) -> CategoryOut:
        category = ScamCategory(name=name)
        try:
            async with self.db.begin_nested():
                self.db.add(category)
                await self.db.flush()
        except IntegrityError:
            raise ConflictError("A category with that name already exists.", code="category_exists")
        await self.db.commit()
        return CategoryOut(id=category.id, name=category.name)

    # ================================================================ internals
    async def _get_or_create_phone(self, e164: str) -> PhoneNumber:
        phone = await self.db.scalar(select(PhoneNumber).where(PhoneNumber.normalized_number == e164))
        if phone:
            return phone
        phone = PhoneNumber(normalized_number=e164, country_code=country_for_e164(e164))
        try:
            async with self.db.begin_nested():  # savepoint: a lost race doesn't poison the outer transaction
                self.db.add(phone)
                await self.db.flush()
        except IntegrityError:
            phone = await self.db.scalar(select(PhoneNumber).where(PhoneNumber.normalized_number == e164))
            assert phone is not None
        return phone

    async def _report_stats(self, phone_id: UUID) -> tuple[int, int, datetime | None]:
        row = (await self.db.execute(
            select(
                func.count(distinct(case((FraudReport.status == ReportStatus.VERIFIED, FraudReport.user_id)))),
                func.count(distinct(case((FraudReport.status.in_(OPEN_STATUSES), FraudReport.user_id)))),
                func.max(FraudReport.created_at),
            ).where(FraudReport.phone_number_id == phone_id)
        )).one()
        return row[0], row[1], row[2]

    async def _refresh_threat(self, phone_id: UUID) -> scoring.RiskResult:
        """Recompute the number's automatic `report_volume` indicator. Call inside the transaction that changed reports."""
        await self.db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": str(phone_id)})
        verified, pending, last_reported = await self._report_stats(phone_id)
        result = scoring.score_reports(verified, pending)
        seen = last_reported or datetime.now(UTC)

        indicator = await self.db.scalar(select(ThreatIndicator).where(
            ThreatIndicator.phone_number_id == phone_id,
            ThreatIndicator.indicator_type == ThreatIndicatorType.REPORT_VOLUME.value,
            ThreatIndicator.category_id.is_(None),
        ))
        if indicator is None:
            self.db.add(ThreatIndicator(
                phone_number_id=phone_id, indicator_type=ThreatIndicatorType.REPORT_VOLUME.value,
                risk_level=result.level, confidence=result.confidence, last_seen=seen,
            ))
        else:
            indicator.risk_level, indicator.confidence, indicator.last_seen = result.level, result.confidence, seen
        await self.db.flush()
        return result

    async def _upsert_classification(self, phone_id: UUID, category_id: UUID, result: scoring.RiskResult) -> None:
        # a reviewer confirmed a scam, so never record it below "medium"
        level = scoring.max_level([result.level, RiskLevel.MEDIUM])
        indicator = await self.db.scalar(select(ThreatIndicator).where(
            ThreatIndicator.phone_number_id == phone_id,
            ThreatIndicator.indicator_type == ThreatIndicatorType.REVIEWER_CLASSIFICATION.value,
            ThreatIndicator.category_id == category_id,
        ))
        now = datetime.now(UTC)
        if indicator is None:
            self.db.add(ThreatIndicator(
                phone_number_id=phone_id, category_id=category_id,
                indicator_type=ThreatIndicatorType.REVIEWER_CLASSIFICATION.value,
                risk_level=level, confidence=result.confidence, last_seen=now,
            ))
        else:
            indicator.risk_level, indicator.confidence, indicator.last_seen = level, result.confidence, now
        await self.db.flush()

    # ---------------------------------------------------------------- reads / mapping
    @staticmethod
    def _report_select() -> Select:
        return (
            select(FraudReport, PhoneNumber.normalized_number, VerificationRecord.decision, VerificationRecord.reviewed_at)
            .join(PhoneNumber, PhoneNumber.id == FraudReport.phone_number_id)
            .outerjoin(VerificationRecord, VerificationRecord.report_id == FraudReport.id)
        )

    async def _report_row(self, report_id: UUID):
        # populate_existing: server-generated columns (created_at) must be loaded, never lazily fetched in async
        row = (await self.db.execute(
            self._report_select().where(FraudReport.id == report_id).execution_options(populate_existing=True)
        )).first()
        if row is None:
            raise NotFoundError("Report not found.")
        return row

    async def _report_out(self, report_id: UUID) -> ReportOut:
        return self._to_report_out(await self._report_row(report_id))

    @staticmethod
    def _to_report_out(row) -> ReportOut:
        report, phone, decision, reviewed_at = row
        return ReportOut(
            id=report.id, case_id=report.case_id, phone=phone, report_type=report.report_type, description=report.description,
            evidence_reference=report.evidence_reference, status=report.status, created_at=report.created_at,
            decision=decision, reviewed_at=reviewed_at,
        )

    async def _threat_row(self, threat_id: UUID) -> tuple[ThreatIndicator, str]:
        row = (await self.db.execute(
            select(ThreatIndicator, PhoneNumber.normalized_number)
            .join(PhoneNumber, PhoneNumber.id == ThreatIndicator.phone_number_id)
            .where(ThreatIndicator.id == threat_id)
            .execution_options(populate_existing=True)
        )).first()
        if row is None:
            raise NotFoundError("Threat indicator not found.")
        return row[0], row[1]

    @staticmethod
    def _to_threat_out(i: ThreatIndicator, phone: str) -> ThreatOut:
        return ThreatOut(
            id=i.id, phone=phone, indicator_type=i.indicator_type, risk_level=i.risk_level,
            confidence=i.confidence, category_id=i.category_id, last_seen=i.last_seen,
            created_at=i.created_at, updated_at=i.updated_at,
        )

    # ---------------------------------------------------------------- permission / validation helpers
    @staticmethod
    def _assert_manual(indicator: ThreatIndicator) -> None:
        if indicator.indicator_type not in {t.value for t in MANUAL_INDICATOR_TYPES}:
            raise ConflictError("Automatic indicators are computed from reports and can't be edited.",
                                code="indicator_not_editable")

    @staticmethod
    def _assert_can_manage(actor: User, indicator_type: str) -> None:
        # Allowlisting stops users being warned about a number, so only admins may do it.
        if indicator_type == ThreatIndicatorType.ALLOWLIST.value and actor.role != UserRole.ADMIN:
            raise PermissionDenied("Only an admin can manage allowlist entries.")

    @staticmethod
    def _assert_blocklist_level(level: RiskLevel) -> None:
        if level not in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            raise ValidationFailed("A blocklist entry must be high or critical risk.", code="invalid_risk_level")
