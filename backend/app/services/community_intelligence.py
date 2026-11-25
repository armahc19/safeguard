"""Community reports to privacy-safe shared intelligence."""
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    PermissionDenied,
    ValidationFailed,
)
from app.core.phone import country_for_e164, normalize_phone
from app.enums import (
    CommunityEntityType,
    CommunityIncidentStatus,
    CommunityReportStatus,
    FraudOutcome,
    IntelligenceStatus,
    ReportType,
    ReviewDecision,
    RiskLevel,
)
from app.models import (
    CommunityEntity,
    CommunityReport,
    FIRReportIncident,
    FIRReportRecord,
    FIRRiskAssessment,
    FraudIncident,
    IncidentEntity,
    IntelligenceRecord,
    ReportEntity,
    ReportEvidence,
    ReportReview,
    User,
)
from app.schemas.common import Page
from app.schemas.fraud import (
    CommunityReportCreate,
    CommunityReportOut,
    IntelligenceOut,
)
from app.services.case_service import CaseService
from app.services.fir_ingestion import FIRIngestionService
from app.services.fir_extraction import extract_and_link_report_entities


class CommunityIntelligenceService:
    def __init__(self, db: AsyncSession, default_calling_code: str = "+233",
                 settings: Settings | None = None) -> None:
        self.db = db
        self.default_calling_code = default_calling_code
        self.settings = settings or Settings()

    def _subject(self, raw: str) -> tuple[CommunityEntityType, str, str | None]:
        value = raw.strip()
        try:
            normalized = normalize_phone(value, self.default_calling_code)
        except ValidationFailed:
            return CommunityEntityType.MESSAGE, value.lower(), None
        return CommunityEntityType.PHONE, normalized, country_for_e164(normalized)

    async def submit(self, reporter: User, data: CommunityReportCreate) -> CommunityReportOut:
        case = await CaseService(self.db).get_or_create(
            reporter, data.case_id, title="Community fraud report"
        )
        entity_type, normalized, country = self._subject(data.subject)
        entity = await self.db.scalar(select(CommunityEntity).where(
            CommunityEntity.entity_type == entity_type,
            CommunityEntity.normalized_value == normalized,
        ))
        if entity is None:
            entity = CommunityEntity(
                entity_type=entity_type, normalized_value=normalized,
                display_value=data.subject.strip(), country_code=country,
            )
            self.db.add(entity)
            await self.db.flush()

        duplicate = await self.db.scalar(select(CommunityReport.id).where(
            CommunityReport.reporter_id == reporter.id,
            CommunityReport.entity_id == entity.id,
            CommunityReport.status != CommunityReportStatus.REJECTED,
        ))
        if duplicate:
            existing_report = await self.db.get(CommunityReport, duplicate)
            existing_fir = await self.db.scalar(select(FIRReportRecord).where(
                FIRReportRecord.community_report_id == duplicate,
            ))
            if existing_report and existing_fir:
                existing_incident = await self.db.scalar(select(FraudIncident).join(
                    FIRReportIncident, FIRReportIncident.incident_id == FraudIncident.id
                ).where(FIRReportIncident.report_id == existing_fir.id))
                if existing_incident:
                    # Idempotent retries also backfill extracted identifiers for
                    # reports created before automatic NEXUS extraction existed.
                    await extract_and_link_report_entities(
                        self.db,
                        report=existing_fir,
                        incident=existing_incident,
                        text=existing_report.description,
                        default_calling_code=self.default_calling_code,
                        secret_key=self.settings.secret_key.get_secret_value(),
                        anchor_entity=entity,
                    )
                    await self.db.commit()
                return self._report_out(existing_report)
            raise ConflictError("You already submitted a report for this indicator.", code="duplicate_community_report")

        incident = await self.db.scalar(select(FraudIncident).join(
            FIRReportIncident, FIRReportIncident.incident_id == FraudIncident.id
        ).join(
            FIRReportRecord, FIRReportRecord.id == FIRReportIncident.report_id
        ).join(
            ReportEntity, ReportEntity.report_id == FIRReportRecord.id
        ).where(
            ReportEntity.entity_id == entity.id,
            FraudIncident.status != CommunityIncidentStatus.REJECTED,
        ).order_by(FraudIncident.updated_at.desc()))
        if incident is None:
            # A free-text message can be the reported entity's display value.
            # Keep incident titles short and store the submitted text only in
            # the report/FIR description fields below.
            if entity_type == CommunityEntityType.PHONE:
                incident_title = f"Community reports involving {normalized}"[:160]
            else:
                incident_title = "Community fraud report"
            incident = FraudIncident(
                title=incident_title,
                category=data.category, status=CommunityIncidentStatus.OPEN,
            )
            self.db.add(incident)
            await self.db.flush()
        elif not incident.category and data.category:
            incident.category = data.category

        report = CommunityReport(
            reporter_id=reporter.id, report_type=data.report_type.value, channel=data.channel.value,
            subject_value=data.subject.strip(), description=data.description, category=data.category,
            evidence_reference=data.evidence_reference, entity_id=entity.id, incident_id=incident.id,
        )
        self.db.add(report)
        await self.db.flush()
        fir_report = FIRReportRecord(
            community_report_id=report.id, reporter_id=reporter.id, case_id=case.id,
            source_type="community", source="community_api", report_type=report.report_type,
            channel=report.channel, subject=report.subject_value, description=report.description,
            category=report.category, evidence_reference=report.evidence_reference,
            status=report.status.value,
        )
        self.db.add(fir_report)
        await self.db.flush()
        self.db.add(FIRReportIncident(
            report_id=fir_report.id, incident_id=incident.id,
            confidence=1.0, link_reason="same_reported_subject",
        ))
        self.db.add(ReportEntity(
            report_id=fir_report.id, entity_id=entity.id, source_text=data.subject.strip(),
            source_kind="user_report", confidence=1.0,
        ))
        extracted_entities = await extract_and_link_report_entities(
            self.db,
            report=fir_report,
            incident=incident,
            text=report.description,
            default_calling_code=self.default_calling_code,
            secret_key=self.settings.secret_key.get_secret_value(),
            anchor_entity=entity,
        )
        await FIRIngestionService(self.db, self.default_calling_code, self.settings).analyze_report_content(
            fir_report, incident, text=report.description,
            phone_number=normalized if entity_type == CommunityEntityType.PHONE else None,
        )
        related = await self.db.scalar(select(IncidentEntity).where(
            IncidentEntity.incident_id == incident.id, IncidentEntity.entity_id == entity.id,
            IncidentEntity.role == "related",
        ))
        if related is None:
            self.db.add(IncidentEntity(
                incident_id=incident.id, entity_id=entity.id, role="related",
                confidence=1.0, verification_status="unverified",
            ))
        if data.evidence_reference:
            self.db.add(ReportEvidence(
                report_id=report.id, evidence_type="attachment",
                storage_reference=data.evidence_reference,
            ))
        intelligence = await self._refresh_intelligence(entity, incident)
        self.db.add(FIRRiskAssessment(
            report_id=fir_report.id, incident_id=incident.id,
            risk_level=intelligence.risk_level, risk_score=intelligence.confidence,
            confidence=intelligence.confidence,
            reasons=["distinct community reports", "reviewed report count",
                     f"{len(extracted_entities)} identifier(s) extracted from submitted description"],
            source="community_intelligence_aggregation",
        ))
        await self.db.commit()
        return self._report_out(report)

    async def _refresh_intelligence(self, entity: CommunityEntity, incident: FraudIncident) -> IntelligenceRecord:
        rows = (await self.db.scalars(select(FIRReportRecord).join(
            FIRReportIncident, FIRReportIncident.report_id == FIRReportRecord.id
        ).join(
            ReportEntity, ReportEntity.report_id == FIRReportRecord.id
        ).where(
            FIRReportIncident.incident_id == incident.id,
            ReportEntity.entity_id == entity.id,
            FIRReportRecord.status.not_in((CommunityReportStatus.REJECTED.value, "rejected")),
        ))).all()
        distinct_reporters = len({row.reporter_id for row in rows})
        accepted = sum(row.status in {CommunityReportStatus.ACCEPTED.value, "verified"} for row in rows)
        confidence = min(1.0, 0.15 * distinct_reporters + 0.2 * accepted)
        if confidence >= 0.8:
            risk = RiskLevel.HIGH
        elif confidence >= 0.5:
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.LOW
        incident.confidence = confidence
        incident.risk_level = risk
        fallback_title = (
            f"Community intelligence for {entity.normalized_value}"
            if entity.entity_type == CommunityEntityType.PHONE
            else "Community fraud intelligence"
        )
        incident.title = incident.title or fallback_title[:160]
        record = await self.db.scalar(select(IntelligenceRecord).where(
            IntelligenceRecord.incident_id == incident.id,
            IntelligenceRecord.entity_id == entity.id,
        ))
        signals = {
            "report_count": len(rows),
            "distinct_reporters": distinct_reporters,
            "accepted_reports": accepted,
            "report_types": sorted({row.report_type for row in rows}),
            "channels": sorted({row.channel for row in rows}),
            "categories": sorted({row.category for row in rows if row.category}),
        }
        summary = (
            f"Community reports describe suspected {incident.category or 'fraudulent'} behaviour "
            f"linked to this {entity.entity_type.value}."
        )
        if record is None:
            record = IntelligenceRecord(
                incident_id=incident.id, entity_id=entity.id, summary=summary,
                confidence=confidence, risk_level=risk, distinct_reporters=distinct_reporters,
                signals=signals,
            )
            self.db.add(record)
        else:
            record.summary, record.confidence, record.risk_level = summary, confidence, risk
            record.distinct_reporters, record.signals = distinct_reporters, signals
        if accepted:
            record.status = IntelligenceStatus.ACTIVE
            record.published_at = record.published_at or datetime.now(UTC)
            incident.status = CommunityIncidentStatus.CONFIRMED
        await self.db.flush()
        return record

    async def list_reports(self, reviewer: User, limit: int, offset: int) -> Page[CommunityReportOut]:
        total = await self.db.scalar(select(func.count()).select_from(CommunityReport).where(
            CommunityReport.status.in_((CommunityReportStatus.SUBMITTED, CommunityReportStatus.UNDER_REVIEW))
        ))
        rows = (await self.db.execute(select(CommunityReport).where(
            CommunityReport.status.in_((CommunityReportStatus.SUBMITTED, CommunityReportStatus.UNDER_REVIEW))
        ).order_by(CommunityReport.created_at.asc()).limit(limit).offset(offset))).scalars().all()
        return Page(items=[self._report_out(row) for row in rows], total=total or 0, limit=limit, offset=offset)

    async def review(self, reviewer: User, report_id: UUID, decision: ReviewDecision, notes: str | None) -> CommunityReportOut:
        report = await self.db.scalar(select(CommunityReport).where(CommunityReport.id == report_id).with_for_update())
        if report is None:
            raise NotFoundError("Community report not found.")
        if report.reporter_id == reviewer.id:
            raise PermissionDenied("You can't review your own report.", code="own_report")
        report.status = {
            ReviewDecision.APPROVED: CommunityReportStatus.ACCEPTED,
            ReviewDecision.REJECTED: CommunityReportStatus.REJECTED,
            ReviewDecision.NEEDS_INFO: CommunityReportStatus.UNDER_REVIEW,
        }[decision]
        self.db.add(ReportReview(report_id=report.id, reviewer_id=reviewer.id, decision=decision, notes=notes))
        fir_report = await self.db.scalar(select(FIRReportRecord).where(
            FIRReportRecord.community_report_id == report.id
        ))
        if fir_report:
            fir_report.status = report.status.value
        if report.entity_id:
            entity = await self.db.get(CommunityEntity, report.entity_id)
            if entity and fir_report:
                links = (await self.db.scalars(select(FIRReportIncident).where(
                    FIRReportIncident.report_id == fir_report.id
                ))).all()
                for link in links:
                    incident = await self.db.get(FraudIncident, link.incident_id)
                    if incident:
                        if decision == ReviewDecision.APPROVED:
                            incident.outcome = FraudOutcome.CONFIRMED_FRAUD
                        elif decision == ReviewDecision.REJECTED:
                            incident.outcome = FraudOutcome.FALSE_REPORT
                        await self._refresh_intelligence(entity, incident)
                        if fir_report:
                            self.db.add(FIRRiskAssessment(
                                report_id=fir_report.id, incident_id=incident.id,
                                risk_level=incident.risk_level, risk_score=incident.confidence,
                                confidence=incident.confidence,
                                reasons=[f"community report review: {decision.value}"],
                                source="community_review_aggregation",
                            ))
        await self.db.commit()
        return self._report_out(report)

    async def get_intelligence(self, entity_value: str) -> IntelligenceOut:
        entity_type, normalized, _ = self._subject(entity_value)
        row = (await self.db.execute(select(IntelligenceRecord, CommunityEntity).join(
            CommunityEntity, CommunityEntity.id == IntelligenceRecord.entity_id
        ).where(
            CommunityEntity.entity_type == entity_type,
            CommunityEntity.normalized_value == normalized,
            IntelligenceRecord.status == IntelligenceStatus.ACTIVE,
        ).order_by(IntelligenceRecord.updated_at.desc()))).first()
        if row is None:
            raise NotFoundError("No community intelligence found for this indicator.")
        record, entity = row
        return self._intelligence_out(record, entity)

    @staticmethod
    def _report_out(report: CommunityReport) -> CommunityReportOut:
        return CommunityReportOut(
            id=report.id, subject=report.subject_value, report_type=ReportType(report.report_type),
            channel=report.channel, description=report.description, category=report.category,
            status=report.status, entity_id=report.entity_id, incident_id=report.incident_id,
            created_at=report.created_at,
        )

    @staticmethod
    def _intelligence_out(record: IntelligenceRecord, entity: CommunityEntity) -> IntelligenceOut:
        return IntelligenceOut(
            id=record.id, incident_id=record.incident_id, entity_id=record.entity_id,
            entity_type=entity.entity_type, entity_value=entity.display_value or entity.normalized_value,
            summary=record.summary, status=record.status, confidence=record.confidence,
            risk_level=record.risk_level, distinct_reporters=record.distinct_reporters,
            signals=record.signals, published_at=record.published_at,
        )
