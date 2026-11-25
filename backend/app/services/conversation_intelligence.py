"""Canonical conversation orchestration for every SafeGuard client.

This service owns the safe, structured handoff that used to live in the
Gradio prototype: communication context, case notes, retrieval, intelligence,
risk and intervention. Adapter-based message checks also create an FIR record.
"""
from __future__ import annotations

import json
import math
import os
import re
import uuid
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import CommunityEntityType, EvidenceType, FraudOutcome
from app.models import (
    CaseEvidence,
    CommunityEntity,
    FIRReportIncident,
    FIRReportRecord,
    FIRRiskAssessment,
    FraudIncident,
    IncidentFinding,
    ReportEntity,
    User,
    UserAwarenessPreference,
)
from app.schemas.cases import EvidenceCreate
from app.schemas.conversation import (
    ConversationIntelligence,
    ConversationNotes,
    ConversationTurnOut,
    SharedCaseContext,
    SimilarCase,
)
from app.services.case_service import CaseService
from app.services.fir_extraction import extract_and_link_report_entities
from app.services.fraud_intelligence_orchestrator import fraud_intelligence_orchestrator
from app.services.network_intelligence import NetworkService

_ROOT = Path(__file__).resolve().parents[3]
_KB_PATH = Path(os.environ.get(
    "SAFEGUARD_KNOWLEDGE_BASE_PATH", str(_ROOT / "safeguard_fraud_knowledge_base_v1.json")
))


def _tokens(value: str) -> set[str]:
    return {item for item in re.findall(r"[a-z0-9]+", value.lower()) if len(item) > 2}


def _load_cases() -> list[dict[str, Any]]:
    try:
        bundle = json.loads(_KB_PATH.read_text(encoding="utf-8"))
        return list(bundle.get("case_evidence_records", []))
    except (OSError, json.JSONDecodeError):
        return []


def _retrieve_cases(query: str, limit: int = 3) -> list[SimilarCase]:
    query_tokens = _tokens(query)
    if not query_tokens:
        return []
    matches: list[tuple[float, dict[str, Any]]] = []
    for case in _load_cases():
        text = " ".join([
            case.get("summary", ""), case.get("source_summary", ""),
            " ".join(case.get("channels", [])),
        ])
        case_tokens = _tokens(text)
        overlap = query_tokens & case_tokens
        if len(overlap) < 2:
            continue
        score = len(overlap) / math.sqrt(len(query_tokens) * len(case_tokens))
        matches.append((score, case))
    matches.sort(key=lambda item: item[0], reverse=True)
    return [SimilarCase(
        case_id=item.get("case_id", ""), summary=item.get("summary", ""),
        retrieval_score=round(score, 3),
        verification_status=item.get("verification_status", ""),
        fraud_pattern_ids=item.get("fraud_pattern_ids", []),
        behaviour_tactic_ids=item.get("behaviour_tactic_ids", []),
    ) for score, item in matches[:limit]]


def _context_key(user_id, case_id) -> str:
    return f"safeguard:conversation-context:{user_id}:{case_id}"


async def _load_context(db: AsyncSession, redis: Redis, user: User, case_id) -> SharedCaseContext:
    cached = await redis.get(_context_key(user.id, case_id))
    if cached:
        try:
            return SharedCaseContext.model_validate_json(cached)
        except (TypeError, ValueError, ValidationError):
            pass
    evidence = (await db.scalars(
        select(CaseEvidence).where(
            CaseEvidence.case_id == case_id,
            CaseEvidence.source == "conversation_context",
        ).order_by(CaseEvidence.observed_at.desc()).limit(1)
    )).first()
    if evidence and evidence.details.get("context"):
        try:
            context = SharedCaseContext.model_validate(evidence.details["context"])
            await redis.set(_context_key(user.id, case_id), context.model_dump_json(), ex=86400)
            return context
        except (TypeError, ValueError, ValidationError):
            pass
    return SharedCaseContext(case_id=case_id)
    try:
        return ConversationNotes.model_validate(evidence.details.get("notes", {}))
    except (TypeError, ValueError, ValidationError):
        return ConversationNotes()


def _notes(previous: ConversationNotes, communication, text: str, identity, decision) -> ConversationNotes:
    signals = list(dict.fromkeys(previous.signals + list(identity.reasons)))
    requests = list(previous.requests_made)
    if communication.requested_action:
        requests.append(communication.requested_action)
    if re.search(r"\b(pin|otp|password|passcode|code|send|transfer|pay|refund)\b", text.lower()):
        requests.append("the message involves a payment or credential action")
    actions = list(previous.user_actions_taken)
    if communication.stage.value == "loss" or re.search(r"\b(already paid|sent money|shared the code)\b", text.lower()):
        actions.append("the user may already have taken an action")
    return ConversationNotes(
        channel=communication.channel.value,
        claimed_identity=identity.claimed_identity or previous.claimed_identity,
        story=f"Latest user message was analyzed as {communication.intent.value} at the {communication.stage.value} stage.",
        requests_made=list(dict.fromkeys(requests))[:8],
        signals=signals[:8],
        user_actions_taken=list(dict.fromkeys(actions))[:8],
        stage=communication.stage,
        risk=decision.result.level,
        confidence="high" if decision.confidence >= .75 else "medium" if decision.confidence >= .4 else "low",
    )


async def analyze_turn(*, db: AsyncSession, redis: Redis, user: User, settings, request,
                       persist_message_to_fir: bool = False,
                       persist_case: bool = True) -> ConversationTurnOut:
    case = await CaseService(db).get_or_create(user, request.case_id, title="Conversational safety assessment")
    similar = _retrieve_cases(request.message)
    result = fraud_intelligence_orchestrator.analyze_message(
        channel=request.channel, text=request.message, phone_number=request.phone_number,
        default_calling_code=settings.default_calling_code,
        additional_hazard=min(.3, len(similar) * .05),
        additional_provenance=("conversation_intelligence",) if similar else (),
    )
    communication = result.communication
    normalized = communication.normalized_text or request.message
    patterns = result.patterns
    identity = result.identity
    memory_enabled = await db.scalar(select(UserAwarenessPreference.conversation_memory_enabled).where(
        UserAwarenessPreference.user_id == user.id)) or False
    context = (await _load_context(db, redis, user, case.id)
               if memory_enabled else SharedCaseContext(case_id=case.id))
    previous = context.notes
    decision = result.decision
    notes = _notes(previous, communication, normalized, identity, decision)
    intervention = result.intervention
    context = SharedCaseContext(
        case_id=case.id,
        turn_count=context.turn_count + 1,
        channels_seen=list(dict.fromkeys(context.channels_seen + [communication.channel.value])),
        known_facts=list(dict.fromkeys(context.known_facts + [notes.story]))[-12:],
        requested_actions=list(dict.fromkeys(context.requested_actions + notes.requests_made))[-12:],
        user_actions_taken=list(dict.fromkeys(context.user_actions_taken + notes.user_actions_taken))[-12:],
        signals=list(dict.fromkeys(context.signals + notes.signals))[-12:],
        unknowns=list(dict.fromkeys(
            context.unknowns + list(decision.unknowns)
        ))[-12:],
        notes=notes,
    )
    intelligence = ConversationIntelligence(
        context_summary={
            "channel": communication.channel.value, "language": communication.language,
            "intent": communication.intent.value, "stage": communication.stage.value,
            "requested_action": communication.requested_action,
        },
        evidence={"positive": list(decision.evidence), "negative": [], "missing": list(decision.unknowns)},
        similar_cases=similar,
        detected_patterns=[{"id": item.pattern_id, "name": item.name, "probability": item.probability,
                            "selected": item.selected, "evidence": list(item.evidence)} for item in patterns.matches],
        behaviour_indicators=[
            {"id": label, "probability": probability}
            for label, probability in result.behaviour.scores.items()
        ], risk_level=decision.result.level, risk_score=decision.result.score,
        confidence=decision.confidence, risk_evidence=list(decision.evidence),
        unknowns=list(decision.unknowns), recommended_action=decision.recommended_action,
    )
    if memory_enabled:
        await CaseService(db).add_internal_evidence(
            case,
            EvidenceCreate(
                evidence_type=EvidenceType.ASSESSMENT, source="conversation_context",
                confidence=decision.confidence,
                details={"context": context.model_dump(mode="json"), "notes": notes.model_dump(mode="json"), "communication": communication.model_dump(mode="json"),
                         "intelligence": intelligence.model_dump(mode="json"),
                         "behaviour_model": {"version": result.behaviour.version,
                                             "artifact": result.behaviour.artifact,
                                             "available": result.behaviour.available},
                         "intervention": intervention.model_dump(mode="json")},
            ),
        )
    if request.phone_number:
        await NetworkService(db, settings.default_calling_code).record_identity(
            request.phone_number, identity, case.id,
        )
    fir_report_id = None
    extracted_identifiers: list[dict[str, str | float]] = []
    if persist_message_to_fir:
        fir_report_id, extracted_identifiers = await _store_message_analysis(
            db=db, user=user, case=case, settings=settings, request=request,
            intelligence=intelligence,
        )
        from app.services.nexus_engine import process_fir_report_nexus
        await process_fir_report_nexus(db, settings, fir_report_id, refresh_layers=True)
    if not persist_case:
        # A non-opted-in voice turn may be analyzed for an immediate response,
        # but its otherwise-empty temporary case must not be retained.
        await db.delete(case)
    await db.commit()
    if memory_enabled:
        await redis.set(_context_key(user.id, case.id), context.model_dump_json(), ex=86400)
    return ConversationTurnOut(
        case_id=case.id, context=context, communication=communication, notes=notes,
        intelligence=intelligence, intervention=intervention,
        privacy_notice=(
            "This analyzed message and its risk assessment are stored in the Fraud Intelligence Repository. "
            "Extracted identifiers are linked in NEXUS as unverified evidence. "
            "Ongoing conversation memory is retained only when you opt in."
            if persist_message_to_fir else
            "Raw conversation text is not stored. Structured case context is retained only when you opt in."
        ),
        fir_report_id=fir_report_id,
        extracted_identifiers=extracted_identifiers,
    )


async def _store_message_analysis(*, db: AsyncSession, user: User, case, settings, request,
                                  intelligence: ConversationIntelligence) -> tuple[uuid.UUID, list[dict[str, str | float]]]:
    """Create a distinct FIR analysis record and NEXUS links for one analyzed message."""
    pattern_names = [str(item.get("name", "")) for item in intelligence.detected_patterns if item.get("name")]
    category = next((str(item.get("category")) for item in intelligence.detected_patterns
                     if item.get("category")), "message_analysis")
    anchor_title = "Analyzed message"
    incident = FraudIncident(
        title=anchor_title,
        description="Automated message risk assessment; this is not a verified fraud finding.",
        category=category[:64],
        risk_level=intelligence.risk_level,
        confidence=intelligence.confidence,
        outcome=FraudOutcome.UNRESOLVED,
        incident_metadata={"source": "message_analysis", "verified": False},
    )
    db.add(incident)
    await db.flush()
    report = FIRReportRecord(
        reporter_id=user.id,
        case_id=case.id,
        source_type="message_analysis",
        source="conversation_adapter",
        report_type=("sms" if request.channel.value == "sms" else "other"),
        channel=request.channel.value,
        subject=anchor_title,
        description=request.message,
        category=category[:64],
        status="analyzed",
    )
    db.add(report)
    await db.flush()
    incident.title = f"Message analysis: {pattern_names[0]}"[:160] if pattern_names else anchor_title
    db.add(FIRReportIncident(
        report_id=report.id,
        incident_id=incident.id,
        confidence=intelligence.confidence,
        link_reason="automated_message_analysis",
        details={"verified": False, "case_id": str(case.id)},
    ))

    anchor = CommunityEntity(
        entity_type=CommunityEntityType.MESSAGE,
        normalized_value=f"fir-message-analysis:{report.id}",
        display_value="Analyzed message",
        entity_metadata={"source": "fir_message_analysis", "report_id": str(report.id), "verified": False},
    )
    db.add(anchor)
    await db.flush()
    db.add(ReportEntity(
        report_id=report.id,
        entity_id=anchor.id,
        source_text="Analyzed message",
        source_kind="message_analysis",
        confidence=1.0,
        verified=False,
    ))
    extracted = await extract_and_link_report_entities(
        db,
        report=report,
        incident=incident,
        text=request.message,
        default_calling_code=settings.default_calling_code,
        secret_key=settings.secret_key.get_secret_value(),
        anchor_entity=anchor,
    )

    for item in intelligence.detected_patterns:
        if not item.get("name"):
            continue
        db.add(IncidentFinding(
            incident_id=incident.id,
            report_id=report.id,
            finding_type="pattern",
            taxonomy_id=str(item.get("id") or "")[:128] or None,
            title=str(item["name"])[:160],
            description="; ".join(str(value) for value in item.get("evidence", [])) or None,
            confidence=max(0.0, min(1.0, float(item.get("probability", 0.0)))),
            source="conversation_intelligence",
            evidence={"selected": bool(item.get("selected")), "verified": False},
        ))
    for item in intelligence.behaviour_indicators:
        if not item.get("id"):
            continue
        db.add(IncidentFinding(
            incident_id=incident.id,
            report_id=report.id,
            finding_type="behaviour",
            taxonomy_id=str(item["id"])[:128],
            title=str(item["id"]).replace("_", " ").title()[:160],
            confidence=max(0.0, min(1.0, float(item.get("probability", 0.0)))),
            source="conversation_intelligence",
            evidence={"verified": False},
        ))
    db.add(FIRRiskAssessment(
        report_id=report.id,
        incident_id=incident.id,
        risk_level=intelligence.risk_level,
        risk_score=intelligence.risk_score,
        confidence=intelligence.confidence,
        reasons=list(dict.fromkeys(intelligence.risk_evidence + intelligence.unknowns)),
        source="conversation_intelligence",
    ))
    return report.id, extracted


async def get_context(*, db: AsyncSession, redis: Redis, user: User, case_id: uuid.UUID) -> SharedCaseContext:
    """Return the shared context for a user's case, preferring active Redis state."""
    await CaseService(db)._owned_case(user, case_id)
    memory_enabled = await db.scalar(select(UserAwarenessPreference.conversation_memory_enabled).where(
        UserAwarenessPreference.user_id == user.id)) or False
    if not memory_enabled:
        return SharedCaseContext(case_id=case_id)
    return await _load_context(db, redis, user, case_id)
