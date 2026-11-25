from pydantic import BaseModel, Field


class IntelligenceCapability(BaseModel):
    name: str
    status: str
    owner: str
    description: str


class IntelligenceCapabilitiesOut(BaseModel):
    """Public contract describing the canonical FastAPI intelligence boundary."""

    source_of_truth: str = "fastapi"
    contract_version: str = "intelligence.v1"
    risk_decision_owner: str = "risk_engine"
    case_context_owner: str = "case_service"
    supported_channels: list[str] = Field(default_factory=list)
    capabilities: list[IntelligenceCapability] = Field(default_factory=list)
