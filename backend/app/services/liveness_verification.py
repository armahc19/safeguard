"""Manage short-lived liveness challenges and trusted verifier attestations."""
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import ConflictError, NotFoundError, ValidationFailed
from app.core.partner_secrets import protect_partner_reference
from app.core.phone import normalize_phone
from app.enums import CommunityEntityType
from app.models import (
    CommunityEntity,
    LivenessAssessment,
    LivenessChallenge,
    PartnerIdentity,
    User,
)
from app.schemas.liveness import (
    LivenessAssessmentIn,
    LivenessAssessmentOut,
    LivenessChallengeOut,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def create_challenge(db: AsyncSession, user: User, settings: Settings) -> LivenessChallengeOut:
    try:
        phone = normalize_phone(user.phone, settings.default_calling_code)
    except ValidationFailed:
        raise ValidationFailed("A verified phone number is required for liveness verification.",
                               code="liveness_phone_required") from None
    now = datetime.now(UTC)
    nonce = secrets.token_urlsafe(32)
    challenge = LivenessChallenge(
        user_id=user.id,
        nonce_hash=_digest(nonce),
        phone_reference=protect_partner_reference(
            phone, namespace="phone", application_secret=settings.secret_key.get_secret_value()
        ),
        expires_at=now + timedelta(minutes=5),
    )
    db.add(challenge)
    await db.commit()
    await db.refresh(challenge)
    return LivenessChallengeOut(challenge_id=challenge.id, challenge_nonce=nonce,
                                expires_at=challenge.expires_at)


async def record_partner_assessment(
    db: AsyncSession, partner_id: UUID, partner_code: str,
    body: LivenessAssessmentIn, settings: Settings,
) -> LivenessAssessmentOut:
    challenge = await db.get(LivenessChallenge, body.challenge_id)
    now = datetime.now(UTC)
    if challenge is None or not hmac.compare_digest(challenge.nonce_hash, _digest(body.challenge_nonce)):
        raise NotFoundError("Liveness challenge not found.", code="liveness_challenge_not_found")
    if challenge.completed_at is not None:
        raise ConflictError("Liveness challenge has already been used.", code="liveness_challenge_used")
    if challenge.expires_at <= now:
        raise ConflictError("Liveness challenge has expired.", code="liveness_challenge_expired")
    if body.assessed_at.astimezone(UTC) < challenge.created_at - timedelta(seconds=30):
        raise ValidationFailed("Assessment timestamp predates the liveness challenge.",
                               code="liveness_assessment_timestamp_invalid")
    if body.assessed_at.astimezone(UTC) > now + timedelta(seconds=30):
        raise ValidationFailed("Assessment timestamp is in the future.",
                               code="liveness_assessment_timestamp_invalid")

    identity_reference = protect_partner_reference(
        body.identity_reference, namespace=f"{partner_code}:identity",
        application_secret=settings.secret_key.get_secret_value(),
    )
    identity = await db.scalar(select(PartnerIdentity).where(
        PartnerIdentity.partner_id == partner_id,
        PartnerIdentity.identity_reference == identity_reference,
    ))
    if identity is None or not identity.verified_ownership or identity.verification_status != "verified":
        raise ValidationFailed("A verified partner identity is required for liveness results.",
                               code="liveness_identity_unverified")
    if not identity.phone_number_reference or not hmac.compare_digest(
        identity.phone_number_reference, challenge.phone_reference
    ):
        raise ValidationFailed("Partner identity does not match the challenged phone.",
                               code="liveness_subject_mismatch")

    duplicate = await db.scalar(select(LivenessAssessment.id).where(
        LivenessAssessment.partner_id == partner_id,
        LivenessAssessment.provider_reference == body.provider_reference,
    ))
    if duplicate:
        raise ConflictError("Provider assessment reference has already been submitted.",
                            code="liveness_assessment_reused")

    entity_key = f"pdr-identity:{partner_code}:{identity.identity_reference}"
    entity = await db.scalar(select(CommunityEntity).where(
        CommunityEntity.entity_type == CommunityEntityType.PERSON,
        CommunityEntity.normalized_value == entity_key,
    ))
    if entity is None:
        entity = CommunityEntity(entity_type=CommunityEntityType.PERSON,
            normalized_value=entity_key, entity_metadata={"source": "pdr", "partner_code": partner_code})
        db.add(entity)
        await db.flush()

    assessment = LivenessAssessment(
        challenge_id=challenge.id, partner_id=partner_id, partner_identity_id=identity.id,
        entity_id=entity.id, provider_name=body.provider_name,
        provider_reference=body.provider_reference, liveness_status=body.liveness_status,
        confidence=body.confidence, model_version=body.model_version,
        reason_code=body.reason_code, assessed_at=body.assessed_at.astimezone(UTC),
    )
    db.add(assessment)
    challenge.completed_at = now
    await db.flush()

    # Update fused entity risk from the attestation and current FIR/PDR graph.
    from app.services.intelligence_layers import IntelligenceLayers
    await IntelligenceLayers(db, settings).refresh_all()
    await db.commit()
    await db.refresh(assessment)
    return LivenessAssessmentOut(assessment_id=assessment.id,
        liveness_status=assessment.liveness_status, confidence=assessment.confidence,
        assessed_at=assessment.assessed_at)
