import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from app.enums import CaseStatus, EvidenceType


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    summary: str | None = Field(default=None, max_length=2000)


class CaseIntakeCreate(CaseCreate):
    """Create a case from a NEXUS starting entity without persisting raw identifiers."""

    intake_type: Literal["report", "transaction", "account", "wallet", "phone",
                         "identity", "person", "business", "agent"]
    source_system: Literal["fir", "pdr", "graph", "manual"]
    source_record_id: uuid.UUID | None = None
    entity_id: uuid.UUID | None = None
    identifier: str | None = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_intake_source(self) -> "CaseIntakeCreate":
        if self.source_system in {"fir", "pdr"} and self.source_record_id is None:
            raise ValueError("A FIR or PDR intake must include its source record ID.")
        if self.source_system == "graph" and self.entity_id is None:
            raise ValueError("A graph intake must include its entity ID.")
        if self.source_system == "manual" and not self.identifier:
            raise ValueError("Enter an identifier when starting a manual investigation.")
        if self.intake_type == "report" and self.source_system == "pdr":
            raise ValueError("PDR intake cannot use report as its starting type.")
        if self.source_system == "pdr" and self.intake_type not in {"identity", "account", "wallet", "transaction"}:
            raise ValueError("PDR intake must identify an identity, account, wallet, or transaction.")
        return self


class EvidenceCreate(BaseModel):
    evidence_type: EvidenceType
    source: str = Field(min_length=1, max_length=64)
    value: str | None = Field(default=None, max_length=512)
    confidence: float = Field(default=1.0, ge=0, le=1)
    observed_at: datetime | None = None
    details: dict[str, object] = Field(default_factory=dict)


class EvidenceOut(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    evidence_type: EvidenceType
    source: str
    value: str | None
    confidence: float
    observed_at: datetime
    created_at: datetime
    details: dict[str, object] = Field(default_factory=dict)


class CaseOut(BaseModel):
    id: uuid.UUID
    title: str
    summary: str | None
    status: CaseStatus
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    evidence_count: int = 0


class CaseDetailOut(CaseOut):
    evidence: list[EvidenceOut] = Field(default_factory=list)
