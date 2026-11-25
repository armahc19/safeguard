import pytest
from pydantic import ValidationError

from app.core.phone import country_for_e164
from app.enums import ReportType, RiskLevel, ThreatIndicatorType
from app.schemas.fraud import CategoryCreate, ReportCreate, ThreatCreate, ThreatUpdate


def test_report_create_ok_and_blank_description_becomes_none():
    r = ReportCreate(number="0241234567", report_type="call", description="   ")
    assert r.report_type == ReportType.CALL and r.description is None


@pytest.mark.parametrize("kwargs", [
    {"number": "123", "report_type": "call"},                                        # too short
    {"number": "0241234567", "report_type": "carrier_pigeon"},                       # bad type
    {"number": "0241234567", "report_type": "sms", "description": "x" * 2001},       # too long
    {"number": "0241234567", "report_type": "sms", "evidence_reference": "http://evil.example/x"},  # URL, not a key
    {"number": "0241234567", "report_type": "sms", "evidence_reference": "../../etc/passwd"},
    {"number": "0241234567", "report_type": "sms", "evidence_reference": "/abs/path.png"},
])
def test_report_create_rejects(kwargs):
    with pytest.raises(ValidationError):
        ReportCreate(**kwargs)


def test_evidence_key_accepted():
    ReportCreate(number="0241234567", report_type="sms", evidence_reference="reports/2026/11/abc-123.png")


def test_threat_create_only_manual_types():
    ok = ThreatCreate(number="0241234567", indicator_type="blocklist")
    assert ok.indicator_type == ThreatIndicatorType.BLOCKLIST and ok.risk_level == RiskLevel.HIGH
    with pytest.raises(ValidationError):
        ThreatCreate(number="0241234567", indicator_type="report_volume")  # automatic: not creatable


def test_threat_bounds():
    with pytest.raises(ValidationError):
        ThreatCreate(number="0241234567", indicator_type="blocklist", confidence=1.5)
    with pytest.raises(ValidationError):
        ThreatUpdate(confidence=-0.1)


def test_category_name_is_whitespace_normalised():
    assert CategoryCreate(name="  Fake   mobile  money ").name == "Fake mobile money"
    with pytest.raises(ValidationError):
        CategoryCreate(name=" a ")


@pytest.mark.parametrize("number, country", [
    ("+233241234567", "GH"), ("+2348031234567", "NG"), ("+14155550132", "US"), ("+27821234567", "ZA"),
    ("+998901234567", "ZZ"),
])
def test_country_for_e164(number, country):
    assert country_for_e164(number) == country
