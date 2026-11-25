from fastapi import APIRouter

from app.api.deps import CurrentUser
from app.schemas.patterns import (
    PatternAnalyzeOut,
    PatternAnalyzeRequest,
    PatternMatchOut,
)
from app.services.pattern_intelligence import analyze_patterns

router = APIRouter(prefix="/patterns", tags=["fraud-pattern-intelligence"])


@router.post("/analyze", response_model=PatternAnalyzeOut)
async def analyze_pattern(body: PatternAnalyzeRequest, user: CurrentUser) -> PatternAnalyzeOut:
    analysis = analyze_patterns(body.text)
    return PatternAnalyzeOut(
        matches=[PatternMatchOut(
            pattern_id=match.pattern_id, name=match.name, category=match.category,
            probability=match.probability, selected=match.selected,
            evidence=list(match.evidence), counter_checks=list(match.counter_checks),
        ) for match in analysis.matches],
        selected_patterns=[match.pattern_id for match in analysis.selected],
        model_version=analysis.model_version,
        campaign_fingerprint=analysis.campaign_fingerprint,
        hazard=analysis.hazard,
        reasons=list(analysis.reasons),
    )
