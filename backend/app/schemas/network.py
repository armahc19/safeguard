from pydantic import BaseModel, Field


class NetworkLookupRequest(BaseModel):
    number: str = Field(min_length=7, max_length=20)


class NetworkLookupOut(BaseModel):
    number: str
    link_count: int
    network_score: float
    related_patterns: list[str]
    campaigns: list[str]
    reasons: list[str]
