"""Unit tests for signal-driven awareness copy suggestions."""
from uuid import uuid4

import pytest

from app.enums import RiskLevel
from app.models import CrossInstitutionSignal
from app.services.awareness import suggest_campaign_copy


@pytest.mark.parametrize("signal_type,severity", [
    ("mule_network_candidate", "high_risk"),
    ("real_time_entity_risk", "education"),
    ("unknown_pattern", "education"),
])
def test_suggest_campaign_copy_templates(signal_type, severity):
    signal = CrossInstitutionSignal(
        id=uuid4(),
        signal_key=f"test-{signal_type}",
        signal_type=signal_type,
        status="active",
        risk_level=RiskLevel.HIGH if severity == "high_risk" else RiskLevel.MEDIUM,
        score=0.82 if severity == "high_risk" else 0.4,
        confidence=0.75,
        partner_codes=["demo_bank"],
        entity_ids=[],
        reasons=["demo reason"],
        evidence={},
    )
    payload = suggest_campaign_copy(signal)
    assert len(payload["title"]) >= 4
    assert len(payload["message"]) >= 20
    if signal_type == "mule_network_candidate":
        assert payload["suggested_severity"] == "high_risk"
    else:
        assert payload["suggested_severity"] == "education"