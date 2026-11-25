import hashlib

from fastapi import APIRouter

from app.api.deps import CurrentUser, DbDep
from app.enums import EvidenceType
from app.models import ShieldAnalysis
from app.schemas.cases import EvidenceCreate
from app.schemas.patterns import PatternMatchOut
from app.schemas.shield import (
    ShieldAIOut,
    ShieldAnalyzeOut,
    ShieldAnalyzeRequest,
    ShieldRuleOut,
)
from app.services.case_service import CaseService
from app.services.feedback import FeedbackService
from app.services.fraud_intelligence_orchestrator import fraud_intelligence_orchestrator
from app.services.network_intelligence import NetworkService

router = APIRouter(prefix="/shield", tags=["intelligent-shield"])


@router.post("/analyze", response_model=ShieldAnalyzeOut)
async def analyze_message(body: ShieldAnalyzeRequest, user: CurrentUser, db: DbDep) -> ShieldAnalyzeOut:
    result = fraud_intelligence_orchestrator.analyze_message(
        channel=body.channel, text=body.text, phone_number=body.phone_number,
    )
    communication, assessment, patterns = result.communication, result.shield, result.patterns
    identity, decision, intervention = result.identity, result.decision, result.intervention
    case = await CaseService(db).get_or_create(user, body.case_id, title="SMS safety analysis")
    record = ShieldAnalysis(
        user_id=user.id, case_id=case.id,
        risk_level=decision.result.level,
        risk_score=decision.result.score,
        ai_label=assessment.ai.label,
        ai_confidence=assessment.ai.confidence,
        indicators={
            "suspicious_keyword_score": assessment.indicators.suspicious_keyword_score,
            "malicious_link_score": assessment.indicators.malicious_link_score,
            "impersonation_score": assessment.indicators.impersonation_score,
            "urgency_score": assessment.indicators.urgency_score,
            "indicator_count": assessment.indicators.indicator_count,
        },
        rules=[{
            "code": rule.code, "label": rule.label, "score": rule.score,
            "explanation": rule.explanation, "evidence": list(rule.evidence),
        } for rule in assessment.rules],
        explanation=assessment.explanation,
    )
    db.add(record)
    await db.flush()
    if body.phone_number:
        network_service = NetworkService(db)
        await network_service.record_patterns(body.phone_number, patterns, case.id)
        await network_service.record_identity(body.phone_number, identity, case.id)
    await CaseService(db).add_internal_evidence(
        case,
        EvidenceCreate(
            evidence_type=EvidenceType.MESSAGE,
            source="intelligent_shield",
            value=hashlib.sha256(assessment.message.normalized.encode()).hexdigest(),
            confidence=decision.confidence,
            details={"risk_level": decision.result.level.value, "risk_score": decision.result.score,
                     "ai_label": assessment.ai.label, "rules": [rule.code for rule in assessment.rules],
                     "communication": communication.model_dump(mode="json"),
                     "patterns": [{"id": match.pattern_id, "probability": match.probability,
                                   "selected": match.selected} for match in patterns.matches],
                     "pattern_model_version": patterns.model_version,
                     "campaign_fingerprint": patterns.campaign_fingerprint,
                     "identity": identity.signals(),
                     "intervention": intervention.model_dump(mode="json"),
                     **decision.signals()},
        ),
    )
    await FeedbackService(db).record_delivery(
        case_id=case.id, user=user, action=intervention.action, channel=body.channel.value,
    )
    await db.commit()
    return ShieldAnalyzeOut(
        assessment_id=record.id,
        case_id=case.id,
        normalized_text=assessment.message.normalized,
        risk_level=decision.result.level,
        risk_score=decision.result.score,
        indicators={
            "suspicious_keyword_score": assessment.indicators.suspicious_keyword_score,
            "malicious_link_score": assessment.indicators.malicious_link_score,
            "impersonation_score": assessment.indicators.impersonation_score,
            "urgency_score": assessment.indicators.urgency_score,
            "indicator_count": assessment.indicators.indicator_count,
        },
        rules=[ShieldRuleOut(
            code=rule.code, label=rule.label, score=rule.score,
            explanation=rule.explanation, evidence=list(rule.evidence),
        ) for rule in assessment.rules],
        ai=ShieldAIOut(**assessment.ai.__dict__),
        explanation=assessment.explanation,
        risk_confidence=decision.confidence,
        risk_evidence=list(decision.evidence),
        contradictions=list(decision.contradictions),
        unknowns=list(decision.unknowns),
        provenance=list(decision.provenance),
        recommended_action=decision.recommended_action,
        patterns=[PatternMatchOut(
            pattern_id=match.pattern_id, name=match.name, category=match.category,
            probability=match.probability, selected=match.selected,
            evidence=list(match.evidence), counter_checks=list(match.counter_checks),
        ) for match in patterns.matches],
        pattern_model_version=patterns.model_version,
        campaign_fingerprint=patterns.campaign_fingerprint,
        identity=identity.signals(),
        intervention=intervention,
    )
