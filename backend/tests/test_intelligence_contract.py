import pytest

from app.api.routes.intelligence import capabilities


@pytest.mark.asyncio
async def test_fastapi_is_canonical_intelligence_source():
    result = await capabilities()

    assert result.source_of_truth == "fastapi"
    assert result.risk_decision_owner == "risk_engine"
    assert "chat" in result.supported_channels
    assert {item.name for item in result.capabilities} >= {
        "case_context", "risk_decision", "intervention", "client_surfaces",
    }
