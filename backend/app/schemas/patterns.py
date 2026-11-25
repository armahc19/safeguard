from pydantic import BaseModel, Field


class PatternAnalyzeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


class PatternMatchOut(BaseModel):
    pattern_id: str
    name: str
    category: str
    probability: float
    selected: bool
    evidence: list[str]
    counter_checks: list[str]


class PatternAnalyzeOut(BaseModel):
    matches: list[PatternMatchOut]
    selected_patterns: list[str]
    model_version: str
    campaign_fingerprint: str
    hazard: float
    reasons: list[str]
