import uuid

from app.enums import CaseStatus, EvidenceType
from app.schemas.cases import CaseCreate, EvidenceCreate
from app.schemas.fraud import ReportCreate


def test_case_and_evidence_schemas_are_typed():
    case = CaseCreate(title="  Suspicious caller  ", summary="Caller claimed to be support")
    evidence = EvidenceCreate(
        evidence_type=EvidenceType.PHONE_NUMBER,
        source="number_lookup",
        value="+233241234567",
        confidence=0.8,
        details={"risk_level": "medium"},
    )

    assert case.title == "  Suspicious caller  "
    assert evidence.evidence_type == EvidenceType.PHONE_NUMBER
    assert evidence.confidence == 0.8


def test_existing_interaction_schemas_accept_case_ids():
    case_id = uuid.uuid4()
    report = ReportCreate(number="0241234567", report_type="call", case_id=case_id)
    assert report.case_id == case_id


def test_case_status_values_are_stable():
    assert CaseStatus.OPEN.value == "open"
    assert CaseStatus.CLOSED.value == "closed"
