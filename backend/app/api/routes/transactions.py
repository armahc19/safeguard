from fastapi import APIRouter

from app.api.deps import CurrentUser, FraudServiceDep
from app.schemas.transactions import TransactionAssessOut, TransactionAssessRequest
from app.services.transaction_intelligence import assess_transaction, recommendation_for

router = APIRouter(prefix="/transactions", tags=["transaction-intelligence"])


@router.post("/assess", response_model=TransactionAssessOut)
async def assess(body: TransactionAssessRequest, user: CurrentUser, fraud: FraudServiceDep) -> TransactionAssessOut:
    lookup, questionnaire, final, reasons, assessment_id, case_id, decision, behaviour, intervention = await assess_transaction(
        user, body, fraud
    )
    recommendation = recommendation_for(final.level, questionnaire.score)
    return TransactionAssessOut(
        assessment_id=assessment_id,
        case_id=case_id,
        recipient_phone=lookup.phone,
        recipient_known=lookup.known,
        phone_risk_level=lookup.risk_level,
        risk_level=final.level,
        risk_score=final.score,
        questionnaire_score=questionnaire.score,
        recommendation=recommendation,
        reasons=list(reasons),
        recipient_report_summary={
            "verified_reports": lookup.verified_reports,
            "pending_reports": lookup.pending_reports,
            "categories": lookup.categories,
        },
        risk_confidence=decision.confidence,
        risk_evidence=list(decision.evidence),
        contradictions=list(decision.contradictions),
        unknowns=list(decision.unknowns),
        provenance=list(decision.provenance),
        recommended_action=decision.recommended_action,
        behavior_signals=behaviour.signals,
        intervention=intervention,
    )
