"""Investigator-facing Fraud Intelligence Repository API."""
from uuid import UUID

from fastapi import APIRouter, Query, status
from sqlalchemy import func, select

from app.api.deps import DbDep, ReviewerUser
from app.core.exceptions import ConflictError, NotFoundError, ValidationFailed
from app.core.phone import country_for_e164, normalize_phone
from app.enums import CommunityEntityType
from app.models import (
    CommunityEntity,
    CommunityReport,
    EntityRelationship,
    FIRReportIncident,
    FIRReportRecord,
    FIRRiskAssessment,
    FraudCase,
    FraudIncident,
    IncidentEntity,
    IncidentFinding,
    IntelligenceRecord,
    InvestigationActivity,
    ReportEntity,
    ReportEvidence,
    ReportReview,
    User,
    VerificationRecord,
)
from app.schemas.common import Page
from app.schemas.fir import (
    FIRAbridgedEntity,
    FIRActivityCreate,
    FIRActivityItem,
    FIRCaseAssignment,
    FIREntityCreate,
    FIREvidenceItem,
    FIRExtractedEntityCreate,
    FIRFindingCreate,
    FIRFindingItem,
    FIRIncidentCreate,
    FIRIncidentDetail,
    FIRIncidentItem,
    FIRIncidentLinkCreate,
    FIRIncidentUpdate,
    FIRRelationshipCreate,
    FIRReportDetail,
    FIRReportItem,
    FIRReportPage,
    FIRReviewItem,
    FIRRiskAssessmentCreate,
    FIRRiskItem,
)
from app.services.fir_ingestion import FIRIngestionService

router = APIRouter(prefix="/fir", tags=["fraud-intelligence-repository"])


async def _report_item(db, report: FIRReportRecord) -> FIRReportItem:
    incident_ids = list((await db.scalars(select(FIRReportIncident.incident_id).where(
        FIRReportIncident.report_id == report.id
    ).order_by(FIRReportIncident.created_at))).all())
    return FIRReportItem(
        id=report.id, reporter_reference=report.reporter_id, report_type=report.report_type,
        source=report.source, channel=report.channel, subject=report.subject,
        description=report.description, category=report.category,
        evidence_reference=report.evidence_reference, status=report.status,
        incident_ids=incident_ids, created_at=report.created_at,
    )


def _risk_item(row: FIRRiskAssessment) -> FIRRiskItem:
    return FIRRiskItem(
        id=row.id, report_id=row.report_id, incident_id=row.incident_id,
        risk_level=row.risk_level, risk_score=row.risk_score, confidence=row.confidence,
        reasons=row.reasons, source=row.source, model_version=row.model_version,
        created_at=row.created_at,
    )


def _finding_item(row: IncidentFinding) -> FIRFindingItem:
    return FIRFindingItem(
        id=row.id, finding_type=row.finding_type, taxonomy_id=row.taxonomy_id,
        title=row.title, description=row.description, confidence=row.confidence,
        source=row.source, model_version=row.model_version, evidence=row.evidence,
        created_at=row.created_at,
    )


async def _incident_item(db, incident: FraudIncident) -> FIRIncidentItem:
    report_ids = list((await db.scalars(select(FIRReportIncident.report_id).where(
        FIRReportIncident.incident_id == incident.id
    ).order_by(FIRReportIncident.created_at))).all())
    case_ids = list((await db.scalars(select(FIRReportRecord.case_id).join(
        FIRReportIncident, FIRReportIncident.report_id == FIRReportRecord.id
    ).where(
        FIRReportIncident.incident_id == incident.id,
        FIRReportRecord.case_id.is_not(None),
    ).distinct())).all())
    return FIRIncidentItem(
        id=incident.id, title=incident.title, description=incident.description,
        category=incident.category, incident_at=incident.incident_at, location=incident.location,
        status=incident.status, outcome=incident.outcome, risk_level=incident.risk_level,
        confidence=incident.confidence, assigned_investigator_id=incident.assigned_investigator_id,
        report_ids=report_ids, case_ids=case_ids,
        created_at=incident.created_at, updated_at=incident.updated_at,
    )


@router.get("/reports", response_model=FIRReportPage)
async def list_fir_reports(
    reviewer: ReviewerUser,
    db: DbDep,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status_filter: str | None = Query(None, alias="status", max_length=32),
    source_type: str | None = Query(None, max_length=32),
    incident_id: UUID | None = None,
    search: str | None = Query(None, max_length=128),
) -> FIRReportPage:
    filters = []
    if status_filter:
        filters.append(FIRReportRecord.status == status_filter)
    if source_type:
        filters.append(FIRReportRecord.source_type == source_type)
    if incident_id:
        filters.append(FIRReportIncident.incident_id == incident_id)
    if search:
        term = f"%{search.strip()}%"
        filters.append((FIRReportRecord.subject.ilike(term)) | (FIRReportRecord.description.ilike(term)))
    stmt = select(FIRReportRecord)
    count_stmt = select(func.count(func.distinct(FIRReportRecord.id))).select_from(FIRReportRecord)
    if incident_id:
        stmt = stmt.join(FIRReportIncident, FIRReportIncident.report_id == FIRReportRecord.id)
        count_stmt = count_stmt.join(FIRReportIncident, FIRReportIncident.report_id == FIRReportRecord.id)
    stmt = stmt.where(*filters).order_by(FIRReportRecord.created_at.desc()).limit(limit).offset(offset)
    rows = (await db.scalars(stmt)).all()
    total = await db.scalar(count_stmt.where(*filters))
    return FIRReportPage(
        items=[await _report_item(db, row) for row in rows], total=total or 0, limit=limit, offset=offset,
    )


@router.get("/reports/{report_id}", response_model=FIRReportDetail)
async def get_fir_report(report_id: UUID, reviewer: ReviewerUser, db: DbDep) -> FIRReportDetail:
    report = await db.get(FIRReportRecord, report_id)
    if report is None:
        raise NotFoundError("FIR report not found.")
    base = (await _report_item(db, report)).model_dump()
    base["case_id"] = report.case_id
    case = await db.get(FraudCase, report.case_id) if report.case_id else None
    base["case"] = ({
        "id": case.id, "title": case.title, "summary": case.summary,
        "investigation_status": case.status.value,
        "assigned_investigator_id": case.assigned_investigator_id,
        "created_at": case.created_at, "updated_at": case.updated_at,
    } if case else None)

    evidence_rows = []
    reviews = []
    if report.community_report_id:
        evidence_rows = (await db.scalars(select(ReportEvidence).where(
            ReportEvidence.report_id == report.community_report_id
        ).order_by(ReportEvidence.created_at))).all()
        review_rows = (await db.scalars(select(ReportReview).where(
            ReportReview.report_id == report.community_report_id
        ).order_by(ReportReview.created_at))).all()
        reviews = [FIRReviewItem(
            id=row.id, reviewer_reference=row.reviewer_id, decision=row.decision.value,
            notes=row.notes, created_at=row.created_at,
        ) for row in review_rows]
    elif report.fraud_report_id:
        verification = await db.scalar(select(VerificationRecord).where(
            VerificationRecord.report_id == report.fraud_report_id
        ))
        if verification:
            reviews = [FIRReviewItem(
                id=verification.id, reviewer_reference=verification.reviewer_id,
                decision=verification.decision.value, notes=None, created_at=verification.reviewed_at,
            )]
    base["evidence"] = [FIREvidenceItem(
        id=row.id, evidence_type=row.evidence_type, storage_reference=row.storage_reference,
        content_hash=row.content_hash, metadata=row.evidence_metadata, created_at=row.created_at,
    ) for row in evidence_rows]

    extracted = (await db.execute(select(ReportEntity, CommunityEntity).join(
        CommunityEntity, CommunityEntity.id == ReportEntity.entity_id
    ).where(ReportEntity.report_id == report.id).order_by(ReportEntity.created_at))).all()
    base["extracted_entities"] = [FIRAbridgedEntity(
        id=entity.id, entity_type=entity.entity_type,
        value=entity.display_value or entity.normalized_value, confidence=link.confidence,
        source_text=link.source_text, source_kind=link.source_kind, verified=link.verified,
    ) for link, entity in extracted]
    linked = (await db.execute(select(FIRReportIncident, FraudIncident).join(
        FraudIncident, FraudIncident.id == FIRReportIncident.incident_id
    ).where(FIRReportIncident.report_id == report.id))).all()
    base["incidents"] = [
        {"id": event.id, "title": event.title, "category": event.category,
         "status": event.status, "link_confidence": link.confidence, "link_reason": link.link_reason}
        for link, event in linked
    ]
    base["reviews"] = reviews
    risks = (await db.scalars(select(FIRRiskAssessment).where(
        FIRRiskAssessment.report_id == report.id
    ).order_by(FIRRiskAssessment.created_at))).all()
    base["risk_assessments"] = [_risk_item(row) for row in risks]
    findings = (await db.scalars(select(IncidentFinding).where(
        IncidentFinding.report_id == report.id
    ).order_by(IncidentFinding.created_at))).all()
    base["findings"] = [_finding_item(row) for row in findings]
    return FIRReportDetail.model_validate(base)


@router.post("/reports/{report_id}/reanalyze")
async def reanalyze_fir_report(report_id: UUID, reviewer: ReviewerUser, db: DbDep) -> dict:
    """Re-run shared intelligence for migrated reports or after model updates."""
    report = await db.get(FIRReportRecord, report_id)
    if report is None:
        raise NotFoundError("FIR report not found.")
    if not report.description.strip():
        raise ValidationFailed("This report has no description to analyze.", code="empty_report_description")
    links = (await db.scalars(select(FIRReportIncident).where(
        FIRReportIncident.report_id == report.id
    ))).all()
    if not links:
        raise ValidationFailed("Link this report to an incident before analysis.", code="report_without_incident")
    ingestion = FIRIngestionService(db)
    for link in links:
        incident = await db.get(FraudIncident, link.incident_id)
        if incident:
            await ingestion.analyze_report_content(
                report, incident, text=report.description, phone_number=None,
            )
    await db.commit()
    return {
        "report_id": report.id,
        "incidents_analyzed": len(links),
        "analysis_version": "fraud-intelligence.v1",
        "findings_are_append_only": True,
    }


@router.post("/reports/{report_id}/entities", response_model=FIRAbridgedEntity, status_code=status.HTTP_201_CREATED)
async def add_extracted_entity(
    report_id: UUID, body: FIRExtractedEntityCreate, reviewer: ReviewerUser, db: DbDep,
) -> FIRAbridgedEntity:
    report = await db.get(FIRReportRecord, report_id)
    if report is None:
        raise NotFoundError("FIR report not found.")
    value = body.value.strip()
    if body.entity_type == CommunityEntityType.PHONE:
        normalized = normalize_phone(value)
        country = country_for_e164(normalized)
    else:
        normalized, country = value.casefold(), None
    entity = await db.scalar(select(CommunityEntity).where(
        CommunityEntity.entity_type == body.entity_type,
        CommunityEntity.normalized_value == normalized,
    ))
    if entity is None:
        entity = CommunityEntity(
            entity_type=body.entity_type, normalized_value=normalized,
            display_value=value, country_code=country,
        )
        db.add(entity)
        await db.flush()
    existing = await db.scalar(select(ReportEntity).where(
        ReportEntity.report_id == report.id, ReportEntity.entity_id == entity.id,
        ReportEntity.source_kind == body.source_kind,
    ))
    if existing:
        raise ConflictError("This extracted entity is already attached to the report.", code="fir_entity_exists")
    link = ReportEntity(
        report_id=report.id, entity_id=entity.id, source_text=body.source_text,
        source_kind=body.source_kind, confidence=body.confidence, verified=body.verified,
    )
    db.add(link)
    await db.commit()
    return FIRAbridgedEntity(
        id=entity.id, entity_type=entity.entity_type,
        value=entity.display_value or entity.normalized_value, confidence=link.confidence,
        source_text=link.source_text, source_kind=link.source_kind, verified=link.verified,
    )


@router.get("/incidents", response_model=Page[FIRIncidentItem])
async def list_fir_incidents(
    reviewer: ReviewerUser,
    db: DbDep,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status_filter: str | None = Query(None, alias="status", max_length=32),
    outcome: str | None = Query(None, max_length=32),
    investigator_id: UUID | None = None,
) -> Page[FIRIncidentItem]:
    filters = []
    if status_filter:
        filters.append(FraudIncident.status == status_filter)
    if outcome:
        filters.append(FraudIncident.outcome == outcome)
    if investigator_id:
        filters.append(FraudIncident.assigned_investigator_id == investigator_id)
    total = await db.scalar(select(func.count()).select_from(FraudIncident).where(*filters))
    rows = (await db.scalars(select(FraudIncident).where(*filters).order_by(
        FraudIncident.updated_at.desc()
    ).limit(limit).offset(offset))).all()
    return Page(items=[await _incident_item(db, row) for row in rows], total=total or 0, limit=limit, offset=offset)


@router.get("/incidents/{incident_id}", response_model=FIRIncidentDetail)
async def get_fir_incident(incident_id: UUID, reviewer: ReviewerUser, db: DbDep) -> FIRIncidentDetail:
    incident = await db.get(FraudIncident, incident_id)
    if incident is None:
        raise NotFoundError("FIR incident not found.")
    base = (await _incident_item(db, incident)).model_dump()
    entity_rows = (await db.execute(select(IncidentEntity, CommunityEntity).join(
        CommunityEntity, CommunityEntity.id == IncidentEntity.entity_id
    ).where(IncidentEntity.incident_id == incident.id).order_by(IncidentEntity.created_at))).all()
    base["entities"] = [FIRAbridgedEntity(
        id=entity.id, entity_type=entity.entity_type,
        value=entity.display_value or entity.normalized_value, role=link.role,
        confidence=link.confidence, verification_status=link.verification_status,
        details=link.details,
    ) for link, entity in entity_rows]
    entity_ids = [entity.id for _, entity in entity_rows]
    relationship_rows = []
    if entity_ids:
        relationship_rows = (await db.scalars(select(EntityRelationship).where(
            (EntityRelationship.source_entity_id.in_(entity_ids)) |
            (EntityRelationship.target_entity_id.in_(entity_ids))
        ).order_by(EntityRelationship.created_at))).all()
    base["relationships"] = [{
        "id": row.id, "source_entity_id": row.source_entity_id,
        "target_entity_id": row.target_entity_id, "relationship_type": row.relationship_type,
        "confidence": row.confidence, "metadata": row.relationship_metadata,
        "created_at": row.created_at,
    } for row in relationship_rows]
    findings = (await db.scalars(select(IncidentFinding).where(
        IncidentFinding.incident_id == incident.id
    ).order_by(IncidentFinding.created_at))).all()
    base["findings"] = [_finding_item(row) for row in findings]
    risks = (await db.scalars(select(FIRRiskAssessment).where(
        FIRRiskAssessment.incident_id == incident.id
    ).order_by(FIRRiskAssessment.created_at))).all()
    base["risk_assessments"] = [_risk_item(row) for row in risks]
    base["intelligence"] = (await db.execute(
        select(IntelligenceRecord, CommunityEntity).join(
            CommunityEntity, CommunityEntity.id == IntelligenceRecord.entity_id
        ).where(IntelligenceRecord.incident_id == incident.id)
    )).all()
    base["intelligence"] = [{
        "id": record.id, "entity_id": entity.id,
        "entity_type": entity.entity_type.value,
        "entity": entity.display_value or entity.normalized_value,
        "summary": record.summary, "status": record.status.value,
        "confidence": record.confidence, "risk_level": record.risk_level.value,
        "distinct_reporters": record.distinct_reporters, "signals": record.signals,
        "published_at": record.published_at,
    } for record, entity in base["intelligence"]]
    activities = (await db.scalars(select(InvestigationActivity).where(
        InvestigationActivity.incident_id == incident.id
    ).order_by(InvestigationActivity.created_at))).all()
    base["investigation_activity"] = [FIRActivityItem(
        id=row.id, actor_reference=row.actor_id, action_type=row.action_type,
        summary=row.summary, details=row.details, created_at=row.created_at,
    ) for row in activities]
    return FIRIncidentDetail.model_validate(base)


@router.post("/incidents", response_model=FIRIncidentDetail, status_code=status.HTTP_201_CREATED)
async def create_fir_incident(body: FIRIncidentCreate, reviewer: ReviewerUser, db: DbDep) -> FIRIncidentDetail:
    report = await db.get(FIRReportRecord, body.report_id)
    if report is None:
        raise NotFoundError("FIR report not found.")
    incident = FraudIncident(
        title=body.title, description=body.description, category=body.category,
        incident_at=body.incident_at, location=body.location,
        assigned_investigator_id=reviewer.id,
    )
    db.add(incident)
    await db.flush()
    db.add(FIRReportIncident(
        report_id=report.id, incident_id=incident.id,
        confidence=body.link_confidence, link_reason=body.link_reason,
    ))
    await FIRIngestionService(db).analyze_report_content(
        report, incident, text=report.description, phone_number=None,
    )
    if report.community_report_id:
        legacy = await db.get(CommunityReport, report.community_report_id)
        if legacy and legacy.incident_id is None:
            legacy.incident_id = incident.id
    db.add(InvestigationActivity(
        incident_id=incident.id, actor_id=reviewer.id, action_type="incident_created",
        summary="Incident created and linked to a report.",
        details={"report_id": str(report.id), "link_reason": body.link_reason},
    ))
    await db.commit()
    return await get_fir_incident(incident.id, reviewer, db)


@router.post("/reports/{report_id}/incidents/{incident_id}", status_code=status.HTTP_201_CREATED)
async def link_fir_report_to_incident(
    report_id: UUID, incident_id: UUID, body: FIRIncidentLinkCreate, reviewer: ReviewerUser, db: DbDep,
) -> dict:
    report = await db.get(FIRReportRecord, report_id)
    incident = await db.get(FraudIncident, incident_id)
    if report is None or incident is None:
        raise NotFoundError("FIR report or incident not found.")
    existing = await db.scalar(select(FIRReportIncident).where(
        FIRReportIncident.report_id == report.id, FIRReportIncident.incident_id == incident.id
    ))
    if existing:
        raise ConflictError("Report is already linked to this incident.", code="fir_link_exists")
    link = FIRReportIncident(
        report_id=report.id, incident_id=incident.id,
        confidence=body.confidence, link_reason=body.reason,
    )
    db.add(link)
    await FIRIngestionService(db).analyze_report_content(
        report, incident, text=report.description, phone_number=None,
    )
    if report.community_report_id:
        legacy = await db.get(CommunityReport, report.community_report_id)
        if legacy and legacy.incident_id is None:
            legacy.incident_id = incident.id
    db.add(InvestigationActivity(
        incident_id=incident.id, actor_id=reviewer.id, action_type="report_linked",
        summary="Report linked to an incident.",
        details={"report_id": str(report.id), "confidence": body.confidence, "reason": body.reason},
    ))
    await db.commit()
    return {"report_id": report.id, "incident_id": incident.id, "confidence": link.confidence,
            "reason": link.link_reason}


@router.patch("/incidents/{incident_id}", response_model=FIRIncidentDetail)
async def update_fir_incident(
    incident_id: UUID, body: FIRIncidentUpdate, reviewer: ReviewerUser, db: DbDep,
) -> FIRIncidentDetail:
    incident = await db.get(FraudIncident, incident_id)
    if incident is None:
        raise NotFoundError("FIR incident not found.")
    changes = body.model_dump(exclude_unset=True)
    assigned = changes.get("assigned_investigator_id")
    if assigned:
        investigator = await db.get(User, assigned)
        if investigator is None or investigator.role.value not in {"reviewer", "admin"}:
            raise ValidationFailed("Assigned investigator must be a reviewer or admin.", code="invalid_investigator")
    for name, value in changes.items():
        setattr(incident, name, value)
    if changes:
        db.add(InvestigationActivity(
            incident_id=incident.id, actor_id=reviewer.id, action_type="incident_updated",
            summary="Incident details or investigation status updated.",
            details={name: str(value.value if hasattr(value, "value") else value) for name, value in changes.items()},
        ))
    await db.commit()
    return await get_fir_incident(incident.id, reviewer, db)


@router.post("/incidents/{incident_id}/entities", response_model=FIRAbridgedEntity, status_code=status.HTTP_201_CREATED)
async def add_fir_entity(
    incident_id: UUID, body: FIREntityCreate, reviewer: ReviewerUser, db: DbDep,
) -> FIRAbridgedEntity:
    incident = await db.get(FraudIncident, incident_id)
    if incident is None:
        raise NotFoundError("FIR incident not found.")
    value = body.value.strip()
    if body.entity_type == CommunityEntityType.PHONE:
        normalized = normalize_phone(value)
        country = country_for_e164(normalized)
    else:
        normalized, country = value.casefold(), None
    entity = await db.scalar(select(CommunityEntity).where(
        CommunityEntity.entity_type == body.entity_type,
        CommunityEntity.normalized_value == normalized,
    ))
    if entity is None:
        entity = CommunityEntity(
            entity_type=body.entity_type, normalized_value=normalized,
            display_value=value, country_code=country,
        )
        db.add(entity)
        await db.flush()
    link = await db.scalar(select(IncidentEntity).where(
        IncidentEntity.incident_id == incident.id,
        IncidentEntity.entity_id == entity.id,
        IncidentEntity.role == body.role,
    ))
    if link:
        raise ConflictError("This entity already has that role in the incident.", code="fir_entity_exists")
    link = IncidentEntity(
        incident_id=incident.id, entity_id=entity.id, role=body.role,
        confidence=body.confidence, verification_status=body.verification_status, details=body.details,
    )
    db.add(link)
    db.add(InvestigationActivity(
        incident_id=incident.id, actor_id=reviewer.id, action_type="entity_added",
        summary=f"{body.role.title()} entity added to incident.",
        details={"entity_type": body.entity_type.value, "entity": normalized, "role": body.role,
                 "verification_status": body.verification_status},
    ))
    await db.commit()
    return FIRAbridgedEntity(
        id=entity.id, entity_type=entity.entity_type, value=entity.display_value or entity.normalized_value,
        role=link.role, confidence=link.confidence, verification_status=link.verification_status,
        details=link.details,
    )


@router.post("/incidents/{incident_id}/relationships", status_code=status.HTTP_201_CREATED)
async def add_fir_relationship(
    incident_id: UUID, body: FIRRelationshipCreate, reviewer: ReviewerUser, db: DbDep,
) -> dict:
    incident = await db.get(FraudIncident, incident_id)
    if incident is None:
        raise NotFoundError("FIR incident not found.")
    attached = (await db.scalars(select(IncidentEntity.entity_id).where(
        IncidentEntity.incident_id == incident.id,
        IncidentEntity.entity_id.in_([body.source_entity_id, body.target_entity_id]),
    ))).all()
    if body.source_entity_id == body.target_entity_id or len(set(attached)) != 2:
        raise ValidationFailed("Both distinct entities must be attached to this incident.", code="invalid_incident_entities")
    existing = await db.scalar(select(EntityRelationship).where(
        EntityRelationship.source_entity_id == body.source_entity_id,
        EntityRelationship.target_entity_id == body.target_entity_id,
        EntityRelationship.relationship_type == body.relationship_type,
    ))
    if existing:
        raise ConflictError("This entity relationship already exists.", code="fir_relationship_exists")
    row = EntityRelationship(
        source_entity_id=body.source_entity_id, target_entity_id=body.target_entity_id,
        relationship_type=body.relationship_type, confidence=body.confidence,
        relationship_metadata=body.metadata,
    )
    db.add(row)
    db.add(InvestigationActivity(
        incident_id=incident.id, actor_id=reviewer.id, action_type="entity_relationship_added",
        summary=f"Entity relationship recorded: {body.relationship_type}.",
        details={"source_entity_id": str(body.source_entity_id),
                 "target_entity_id": str(body.target_entity_id), "confidence": body.confidence},
    ))
    await db.commit()
    await db.refresh(row)
    return {"id": row.id, "source_entity_id": row.source_entity_id,
            "target_entity_id": row.target_entity_id, "relationship_type": row.relationship_type,
            "confidence": row.confidence, "metadata": row.relationship_metadata,
            "created_at": row.created_at}


@router.post("/incidents/{incident_id}/findings", response_model=FIRFindingItem, status_code=status.HTTP_201_CREATED)
async def add_fir_finding(
    incident_id: UUID, body: FIRFindingCreate, reviewer: ReviewerUser, db: DbDep,
) -> FIRFindingItem:
    incident = await db.get(FraudIncident, incident_id)
    if incident is None:
        raise NotFoundError("FIR incident not found.")
    if body.report_id:
        linked = await db.scalar(select(FIRReportIncident.id).where(
            FIRReportIncident.report_id == body.report_id,
            FIRReportIncident.incident_id == incident.id,
        ))
        if linked is None:
            raise ValidationFailed("Finding report must be linked to this incident.", code="report_not_linked")
    row = IncidentFinding(
        incident_id=incident.id, report_id=body.report_id, finding_type=body.finding_type,
        taxonomy_id=body.taxonomy_id, title=body.title, description=body.description,
        confidence=body.confidence, source=body.source, model_version=body.model_version,
        evidence=body.evidence,
    )
    db.add(row)
    await db.flush()
    db.add(InvestigationActivity(
        incident_id=incident.id, actor_id=reviewer.id, action_type=f"{body.finding_type}_finding_added",
        summary=f"{body.finding_type.title()} finding recorded: {body.title}",
        details={"finding_id": str(row.id), "taxonomy_id": body.taxonomy_id,
                 "confidence": body.confidence, "source": body.source},
    ))
    await db.commit()
    await db.refresh(row)
    return _finding_item(row)


@router.post("/incidents/{incident_id}/assessments", response_model=FIRRiskItem, status_code=status.HTTP_201_CREATED)
async def add_fir_assessment(
    incident_id: UUID, body: FIRRiskAssessmentCreate, reviewer: ReviewerUser, db: DbDep,
) -> FIRRiskItem:
    incident = await db.get(FraudIncident, incident_id)
    if incident is None:
        raise NotFoundError("FIR incident not found.")
    if body.report_id:
        linked = await db.scalar(select(FIRReportIncident.id).where(
            FIRReportIncident.report_id == body.report_id,
            FIRReportIncident.incident_id == incident.id,
        ))
        if linked is None:
            raise ValidationFailed("Assessment report must be linked to this incident.", code="report_not_linked")
    row = FIRRiskAssessment(
        report_id=body.report_id, incident_id=incident.id, risk_level=body.risk_level,
        risk_score=body.risk_score, confidence=body.confidence, reasons=body.reasons,
        source=body.source, model_version=body.model_version,
    )
    db.add(row)
    incident.risk_level = body.risk_level
    incident.confidence = body.confidence
    db.add(InvestigationActivity(
        incident_id=incident.id, actor_id=reviewer.id, action_type="risk_assessment_added",
        summary=f"Risk assessment recorded: {body.risk_level.value}.",
        details={"risk_score": body.risk_score, "confidence": body.confidence,
                 "source": body.source, "reasons": body.reasons},
    ))
    await db.commit()
    await db.refresh(row)
    return _risk_item(row)


@router.post("/incidents/{incident_id}/activity", response_model=FIRActivityItem, status_code=status.HTTP_201_CREATED)
async def add_fir_activity(
    incident_id: UUID, body: FIRActivityCreate, reviewer: ReviewerUser, db: DbDep,
) -> FIRActivityItem:
    incident = await db.get(FraudIncident, incident_id)
    if incident is None:
        raise NotFoundError("FIR incident not found.")
    row = InvestigationActivity(
        incident_id=incident.id, actor_id=reviewer.id,
        action_type=body.action_type, summary=body.summary, details=body.details,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return FIRActivityItem(
        id=row.id, actor_reference=row.actor_id, action_type=row.action_type,
        summary=row.summary, details=row.details, created_at=row.created_at,
    )


@router.post("/cases/{case_id}/assign", status_code=status.HTTP_204_NO_CONTENT)
async def assign_fir_case(
    case_id: UUID, body: FIRCaseAssignment, reviewer: ReviewerUser, db: DbDep,
) -> None:
    case = await db.get(FraudCase, case_id)
    investigator = await db.get(User, body.investigator_id)
    if case is None:
        raise NotFoundError("Case not found.")
    if investigator is None or investigator.role.value not in {"reviewer", "admin"}:
        raise ValidationFailed("Assigned investigator must be a reviewer or admin.", code="invalid_investigator")
    case.assigned_investigator_id = investigator.id
    incident_ids = (await db.scalars(select(FIRReportIncident.incident_id).join(
        FIRReportRecord, FIRReportRecord.id == FIRReportIncident.report_id
    ).where(FIRReportRecord.case_id == case.id).distinct())).all()
    for incident_id in incident_ids:
        db.add(InvestigationActivity(
            incident_id=incident_id, actor_id=reviewer.id, action_type="case_assigned",
            summary="Case investigator assignment updated.",
            details={"case_id": str(case.id), "investigator_id": str(investigator.id)},
        ))
    await db.commit()
