"""Keep the FIR index synchronized with both user-report intake pipelines."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.exceptions import ValidationFailed
from app.core.phone import normalize_phone
from app.enums import (
    CommunicationChannel,
    CommunityEntityType,
    CommunityIncidentStatus,
    RiskLevel,
)
from app.models import (
    CommunityEntity,
    CommunityReport,
    FIRReportIncident,
    FIRReportRecord,
    FIRRiskAssessment,
    FraudIncident,
    FraudReport,
    IncidentEntity,
    IncidentFinding,
    PhoneNumber,
    ReportEntity,
    User,
)
from app.services.fraud_intelligence_orchestrator import fraud_intelligence_orchestrator


class FIRIngestionService:
    def __init__(self, db: AsyncSession, default_calling_code: str = "+233", settings: Settings | None = None):
        self.db = db
        self.default_calling_code = default_calling_code
        self.settings = settings or get_settings()

    async def community_report(self, report: CommunityReport, case_id=None) -> FIRReportRecord:
        existing = await self.db.scalar(select(FIRReportRecord).where(
            FIRReportRecord.community_report_id == report.id
        ))
        if existing:
            existing.status = report.status.value
            return existing

        record = FIRReportRecord(
            community_report_id=report.id,
            reporter_id=report.reporter_id,
            case_id=case_id,
            source_type="community",
            source="community_api",
            report_type=report.report_type,
            channel=report.channel,
            subject=report.subject_value,
            description=report.description,
            category=report.category,
            evidence_reference=report.evidence_reference,
            status=report.status.value,
        )
        self.db.add(record)
        await self.db.flush()
        return record

    async def number_report(
        self, report: FraudReport, reporter: User, phone: PhoneNumber, channel: str,
    ) -> tuple[FIRReportRecord, FraudIncident]:
        entity = await self.db.scalar(select(CommunityEntity).where(
            CommunityEntity.entity_type == CommunityEntityType.PHONE,
            CommunityEntity.normalized_value == phone.normalized_number,
        ))
        if entity is None:
            entity = CommunityEntity(
                entity_type=CommunityEntityType.PHONE,
                normalized_value=phone.normalized_number,
                display_value=phone.normalized_number,
                country_code=phone.country_code,
            )
            self.db.add(entity)
            await self.db.flush()

        incident = await self.db.scalar(select(FraudIncident).join(
            FIRReportIncident, FIRReportIncident.incident_id == FraudIncident.id
        ).join(
            ReportEntity, ReportEntity.report_id == FIRReportIncident.report_id
        ).where(
            ReportEntity.entity_id == entity.id,
            FraudIncident.status != CommunityIncidentStatus.REJECTED,
        ).order_by(FraudIncident.updated_at.desc()).limit(1))
        if incident is None:
            incident = FraudIncident(
                title=f"Reports involving {phone.normalized_number}",
                status=CommunityIncidentStatus.OPEN,
            )
            self.db.add(incident)
            await self.db.flush()

        record = FIRReportRecord(
            fraud_report_id=report.id,
            reporter_id=reporter.id,
            case_id=report.case_id,
            source_type="number_report",
            source="gateway" if channel in {"sms", "ussd"} else "reports_api",
            report_type=report.report_type,
            channel=channel,
            subject=phone.normalized_number,
            description=report.description or "",
            evidence_reference=report.evidence_reference,
            status=report.status.value,
        )
        self.db.add(record)
        await self.db.flush()
        self.db.add(FIRReportIncident(
            report_id=record.id,
            incident_id=incident.id,
            confidence=1.0,
            link_reason="matching_reported_phone",
        ))
        self.db.add(ReportEntity(
            report_id=record.id,
            entity_id=entity.id,
            source_text=phone.normalized_number,
            source_kind="reported_number",
            confidence=1.0,
        ))
        related = await self.db.scalar(select(IncidentEntity).where(
            IncidentEntity.incident_id == incident.id,
            IncidentEntity.entity_id == entity.id,
            IncidentEntity.role == "related",
        ))
        if related is None:
            self.db.add(IncidentEntity(
                incident_id=incident.id, entity_id=entity.id, role="related",
                confidence=1.0, verification_status="unverified",
            ))
        return record, incident

    async def analyze_report_content(
        self,
        report: FIRReportRecord,
        incident: FraudIncident,
        *,
        text: str | None,
        phone_number: str | None,
    ) -> None:
        """Persist shared orchestrator findings for the report's incident."""
        if not text or not text.strip():
            from app.services.nexus_engine import process_fir_report_nexus
            await process_fir_report_nexus(self.db, self.settings, report.id, refresh_layers=True)
            return
        try:
            channel = CommunicationChannel(report.channel)
        except ValueError:
            channel = CommunicationChannel.UNKNOWN
        try:
            phone_number = normalize_phone(phone_number or report.subject, self.default_calling_code)
        except ValidationFailed:
            phone_number = None

        result = fraud_intelligence_orchestrator.analyze_message(
            text=text,
            channel=channel,
            phone_number=phone_number,
            default_calling_code=self.default_calling_code,
        )

        selected_patterns = result.patterns.selected
        for match in selected_patterns:
            self.db.add(IncidentFinding(
                incident_id=incident.id,
                report_id=report.id,
                finding_type="pattern",
                taxonomy_id=match.pattern_id,
                title=match.name,
                description="; ".join(match.evidence) or None,
                confidence=match.probability,
                source="shared_pattern_intelligence",
                model_version=result.patterns.model_version,
                evidence={
                    "category": match.category,
                    "counter_checks": list(match.counter_checks),
                    "campaign_fingerprint": result.patterns.campaign_fingerprint,
                },
            ))
        if not selected_patterns:
            self.db.add(IncidentFinding(
                incident_id=incident.id,
                report_id=report.id,
                finding_type="pattern",
                taxonomy_id="pattern:no_selected_match",
                title="No configured fraud pattern passed the match threshold",
                confidence=0.0,
                source="shared_pattern_intelligence",
                model_version=result.patterns.model_version,
                evidence={"campaign_fingerprint": result.patterns.campaign_fingerprint},
            ))

        identity = result.identity
        self.db.add(IncidentFinding(
            incident_id=incident.id,
            report_id=report.id,
            finding_type="other",
            taxonomy_id=f"identity:{identity.label}",
            title=identity.label.replace("_", " ").title(),
            description="; ".join(identity.reasons) or None,
            confidence=identity.confidence,
            source="shared_identity_intelligence",
            model_version="identity-intelligence.v1",
            evidence=identity.signals(),
        ))

        behaviour = result.behaviour
        if not behaviour.scores:
            self.db.add(IncidentFinding(
                incident_id=incident.id,
                report_id=report.id,
                finding_type="behaviour",
                taxonomy_id="behaviour:no_selected_signal",
                title="No behavioural model label exceeded its threshold",
                confidence=0.0,
                source="shared_behaviour_intelligence",
                model_version=behaviour.version,
                evidence={
                    "model_name": behaviour.model_name,
                    "artifact": behaviour.artifact,
                    "available": behaviour.available,
                },
            ))
        for label, score in sorted(behaviour.scores.items(), key=lambda item: item[1], reverse=True):
            self.db.add(IncidentFinding(
                incident_id=incident.id,
                report_id=report.id,
                finding_type="behaviour",
                taxonomy_id=label,
                title=label.replace("_", " ").replace("-", " ").title(),
                description="Behaviour model signal found in the submitted incident description.",
                confidence=score,
                source="shared_behaviour_intelligence",
                model_version=behaviour.version,
                evidence={
                    "model_name": behaviour.model_name,
                    "artifact": behaviour.artifact,
                    "available": behaviour.available,
                },
            ))

        decision = result.decision
        risk = decision.result
        self.db.add(FIRRiskAssessment(
            report_id=report.id,
            incident_id=incident.id,
            risk_level=risk.level,
            risk_score=risk.score,
            confidence=decision.confidence,
            reasons=list(decision.reasons),
            source="shared_fraud_intelligence_orchestrator",
            model_version="fraud-intelligence.v1",
        ))
        levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        if levels.index(risk.level) > levels.index(incident.risk_level):
            incident.risk_level = risk.level
        incident.confidence = max(incident.confidence, decision.confidence)
        # Keep entity/risk projections current when FIR intelligence is generated.
        from app.services.intelligence_layers import IntelligenceLayers
        from app.services.fir_extraction import extract_and_link_report_entities
        from app.services.nexus_engine import process_fir_report_nexus

        await IntelligenceLayers(self.db, self.settings).refresh_all()
        anchor = await self.db.scalar(select(CommunityEntity).join(
            ReportEntity, ReportEntity.entity_id == CommunityEntity.id
        ).where(ReportEntity.report_id == report.id).limit(1))
        await extract_and_link_report_entities(
            self.db,
            report=report,
            incident=incident,
            text=text,
            default_calling_code=self.default_calling_code,
            secret_key=self.settings.secret_key.get_secret_value(),
            anchor_entity=anchor,
        )
        await process_fir_report_nexus(self.db, self.settings, report.id, refresh_layers=False)
