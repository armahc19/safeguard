import hashlib

from fastapi import APIRouter

from app.api.deps import CurrentUser, DbDep, FraudServiceDep, SettingsDep
from app.core.phone import normalize_phone
from app.enums import CommunicationChannel, EvidenceType
from app.models import CallAnalysis
from app.schemas.calls import CallAnalyzeOut, CallAnalyzeRequest
from app.schemas.cases import EvidenceCreate
from app.schemas.fraud import MessageIndicatorsIn
from app.schemas.patterns import PatternMatchOut
from app.services import scoring
from app.services.case_service import CaseService
from app.services.feedback import FeedbackService
from app.services.fraud_intelligence_orchestrator import fraud_intelligence_orchestrator
from app.services.network_intelligence import NetworkService

router = APIRouter(prefix="/calls", tags=["call-protection"])


@router.post("/analyze", response_model=CallAnalyzeOut)
async def analyze_call(
    body: CallAnalyzeRequest, user: CurrentUser, db: DbDep, settings: SettingsDep,
    fraud: FraudServiceDep,
) -> CallAnalyzeOut:
    caller = normalize_phone(body.caller_number, settings.default_calling_code)
    case = await CaseService(db).get_or_create(user, body.case_id, title="Call safety assessment")
    analysis_text = body.transcript or (
        f"caller claims to be {body.claimed_identity}" if body.claimed_identity else "call metadata only"
    )
    lookup = await fraud.lookup(
        user, caller, case_id=case.id, channel=CommunicationChannel.CALL,
    )
    result = fraud_intelligence_orchestrator.analyze_message(
        channel=CommunicationChannel.CALL, text=analysis_text, phone_number=caller,
        default_calling_code=settings.default_calling_code,
        phone_reputation=scoring.PhoneReputation(
            verified_reporters=lookup.verified_reports,
            pending_reporters=lookup.pending_reports,
            blocklist_levels=(lookup.risk_level,) if lookup.override == "blocklist" else (),
            allowlisted=lookup.override == "allowlist",
        ),
        additional_provenance=("call_protection",),
    )
    communication, shield, patterns = result.communication, result.shield, result.patterns
    identity, decision, intervention = result.identity, result.decision, result.intervention
    message = MessageIndicatorsIn(
        suspicious_keyword_score=shield.indicators.suspicious_keyword_score,
        malicious_link_score=shield.indicators.malicious_link_score,
        impersonation_score=shield.indicators.impersonation_score,
        urgency_score=shield.indicators.urgency_score,
        indicator_count=shield.indicators.indicator_count,
    )
    transcript_hash = hashlib.sha256(analysis_text.encode()).hexdigest() if body.transcript else None
    record = CallAnalysis(
        user_id=user.id, case_id=case.id, caller_phone=caller, transcript_hash=transcript_hash,
        consented_transcript=body.consented_transcript, risk_level=decision.result.level,
        risk_score=decision.result.score, confidence=decision.confidence,
        signals={"communication": communication.model_dump(mode="json"),
                 "identity": identity.signals(),
                 "patterns": [{"id": match.pattern_id, "probability": match.probability}
                              for match in patterns.matches] if patterns else [],
                 "intervention": intervention.model_dump(mode="json"), **decision.signals()},
        explanation=(shield.explanation if shield else "No transcript was supplied; this assessment used call metadata and available number intelligence."),
    )
    db.add(record)
    await db.flush()
    network = NetworkService(db, settings.default_calling_code)
    if patterns:
        await network.record_patterns(caller, patterns, case.id)
    await network.record_identity(caller, identity, case.id)
    await CaseService(db).add_internal_evidence(
        case,
        EvidenceCreate(
            evidence_type=EvidenceType.CALL, source="call_protection", value=transcript_hash,
            confidence=decision.confidence,
            details={"transcript_stored": False, "consented_transcript": body.consented_transcript,
                     "caller_phone": caller, "duration_seconds": body.call_duration_seconds,
                     "identity": identity.signals(), "intervention": intervention.model_dump(mode="json"),
                     "decision": decision.signals()},
        ),
    )
    await FeedbackService(db).record_delivery(
        case_id=case.id, user=user, action=intervention.action, channel=CommunicationChannel.CALL.value,
    )
    await db.commit()
    return CallAnalyzeOut(
        analysis_id=record.id, case_id=case.id, caller_phone=caller,
        risk_level=decision.result.level, risk_score=decision.result.score,
        confidence=decision.confidence, transcript_recorded=False, transcript_hash=transcript_hash,
        indicators={
            "suspicious_keyword_score": message.suspicious_keyword_score if message else 0.0,
            "malicious_link_score": message.malicious_link_score if message else 0.0,
            "impersonation_score": message.impersonation_score if message else 0.0,
            "urgency_score": message.urgency_score if message else 0.0,
            "indicator_count": message.indicator_count if message else 0,
        },
        patterns=[PatternMatchOut(
            pattern_id=match.pattern_id, name=match.name, category=match.category,
            probability=match.probability, selected=match.selected,
            evidence=list(match.evidence), counter_checks=list(match.counter_checks),
        ) for match in patterns.matches] if patterns else [],
        identity=identity.signals(), intervention=intervention,
        explanation=record.explanation,
        privacy_notice="SafeGuard does not record call audio or retain raw transcripts; only derived signals and a content hash are stored.",
    )
