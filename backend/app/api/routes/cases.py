from uuid import UUID

from fastapi import APIRouter, Query, status

from app.api.deps import CurrentUser, DbDep, ReviewerUser, SettingsDep
from app.core.exceptions import ConflictError, NotFoundError
from app.core.partner_secrets import protect_partner_reference
from app.enums import EvidenceType
from app.models import (
    CommunityEntity,
    FIRReportRecord,
    FraudCase,
    PartnerAccount,
    PartnerIdentity,
    PartnerTransaction,
)
from app.schemas.cases import (
    CaseCreate,
    CaseDetailOut,
    CaseIntakeCreate,
    CaseOut,
    EvidenceCreate,
    EvidenceOut,
)
from app.schemas.feedback import FeedbackCreate, FeedbackOut
from app.services.case_service import CaseService
from app.services.feedback import FeedbackService

router = APIRouter(prefix="/cases", tags=["cases"])


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
async def create_case(body: CaseCreate, user: CurrentUser, db: DbDep) -> CaseOut:
    service = CaseService(db)
    result = await service.create(user, body)
    await db.commit()
    return result


@router.post("/intake", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
async def start_nexus_investigation(
    body: CaseIntakeCreate, user: ReviewerUser, db: DbDep, settings: SettingsDep,
) -> CaseOut:
    """Create a case and atomically attach its NEXUS starting point as typed evidence."""
    source_record = None
    if body.source_system == "fir":
        source_record = await db.get(FIRReportRecord, body.source_record_id)
        if source_record is None:
            raise NotFoundError("FIR report not found.", code="fir_report_not_found")
        if source_record.case_id:
            raise ConflictError("This FIR report is already linked to an investigation.",
                                code="report_already_investigated")
    elif body.source_system == "pdr":
        record_model = {
            "identity": PartnerIdentity,
            "account": PartnerAccount,
            "wallet": PartnerAccount,
            "transaction": PartnerTransaction,
        }[body.intake_type]
        source_record = await db.get(record_model, body.source_record_id)
        if source_record is None:
            raise NotFoundError("PDR record not found.", code="pdr_record_not_found")
    elif body.entity_id is not None:
        if await db.get(CommunityEntity, body.entity_id) is None:
            raise NotFoundError("Graph entity not found.", code="entity_not_found")

    service = CaseService(db)
    created = await service.create(user, CaseCreate(title=body.title, summary=body.summary))
    case = await db.get(FraudCase, created.id)
    case.assigned_investigator_id = user.id
    if body.source_system == "fir":
        source_record.case_id = case.id

    if body.source_record_id is not None:
        evidence_value = str(body.source_record_id)
    elif body.entity_id is not None:
        evidence_value = str(body.entity_id)
    else:
        protected = protect_partner_reference(body.identifier or "",
            namespace=f"nexus-intake:{body.intake_type}",
            application_secret=settings.secret_key.get_secret_value())
        evidence_value = f"protected:{protected}"

    evidence_type = {
        "report": EvidenceType.REPORT,
        "transaction": EvidenceType.TRANSACTION,
        "phone": EvidenceType.PHONE_NUMBER,
        "identity": EvidenceType.IDENTITY,
        "person": EvidenceType.IDENTITY,
        "business": EvidenceType.IDENTITY,
        "account": EvidenceType.OTHER,
        "wallet": EvidenceType.OTHER,
        "agent": EvidenceType.IDENTITY,
    }[body.intake_type]
    await service.add_internal_evidence(case, EvidenceCreate(
        evidence_type=evidence_type,
        source=f"nexus_{body.source_system}",
        value=evidence_value,
        details={"intake_type": body.intake_type, "source_system": body.source_system,
                 "source_record_id": str(body.source_record_id) if body.source_record_id else None,
                 "entity_id": str(body.entity_id) if body.entity_id else None},
    ))
    await db.commit()
    await db.refresh(case)
    return CaseService._to_case(case, 1)


@router.get("", response_model=list[CaseOut])
async def list_cases(
    user: CurrentUser, db: DbDep,
    limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
) -> list[CaseOut]:
    return await CaseService(db).list(user, limit=limit, offset=offset)


@router.get("/{case_id}", response_model=CaseDetailOut)
async def get_case(case_id: UUID, user: CurrentUser, db: DbDep) -> CaseDetailOut:
    return await CaseService(db).get(user, case_id)


@router.post("/{case_id}/evidence", response_model=EvidenceOut, status_code=status.HTTP_201_CREATED)
async def add_evidence(case_id: UUID, body: EvidenceCreate, user: CurrentUser, db: DbDep) -> EvidenceOut:
    service = CaseService(db)
    result = await service.add_evidence(user, case_id, body)
    await db.commit()
    return result


@router.post("/{case_id}/close", response_model=CaseOut)
async def close_case(case_id: UUID, user: CurrentUser, db: DbDep) -> CaseOut:
    service = CaseService(db)
    result = await service.close(user, case_id)
    await db.commit()
    return result


@router.post("/{case_id}/feedback", response_model=FeedbackOut, status_code=status.HTTP_201_CREATED)
async def add_feedback(case_id: UUID, body: FeedbackCreate, user: CurrentUser, db: DbDep) -> FeedbackOut:
    service = FeedbackService(db)
    result = await service.create(user, case_id, body)
    await db.commit()
    return result


@router.get("/{case_id}/feedback", response_model=list[FeedbackOut])
async def list_feedback(case_id: UUID, user: CurrentUser, db: DbDep) -> list[FeedbackOut]:
    return await FeedbackService(db).list(user, case_id)
