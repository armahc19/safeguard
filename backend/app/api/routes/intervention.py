from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser
from app.enums import CommunicationChannel, ConversationStage, RiskLevel
from app.schemas.intervention import InterventionPlan
from app.services.intervention import intervention_engine
from app.services.risk_engine import reassess_external_result

router = APIRouter(prefix="/interventions", tags=["intervention-engine"])


class InterventionPlanRequest(BaseModel):
    risk_level: RiskLevel
    risk_score: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    unknowns: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    channel: CommunicationChannel = CommunicationChannel.APP
    stage: ConversationStage = ConversationStage.UNCLEAR
    potential_harm: bool = False


@router.post("/plan", response_model=InterventionPlan)
async def make_plan(body: InterventionPlanRequest, user: CurrentUser) -> InterventionPlan:
    decision = reassess_external_result(
        score=body.risk_score, reported_level=body.risk_level,
        confidence=body.confidence, reasons=tuple(body.reasons),
        unknowns=tuple(body.unknowns),
    )
    return intervention_engine.plan(
        decision, channel=body.channel, stage=body.stage, potential_harm=body.potential_harm,
    )
