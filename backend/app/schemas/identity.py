from pydantic import BaseModel, Field


class IdentityAnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=5000)
    phone_number: str | None = Field(default=None, min_length=7, max_length=20)


class IdentityAnalyzeOut(BaseModel):
    label: str
    claimed_identity: str | None
    identity_score: float
    confidence: float
    official_domain_match: bool | None
    reasons: list[str]
    contradictions: list[str]
    unknowns: list[str]
    provenance: list[str]
