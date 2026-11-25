"""Persist extracted report identifiers as unverified FIR/NEXUS graph evidence."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.partner_secrets import protect_partner_reference
from app.enums import CommunityEntityType
from app.models import (
    CommunityEntity,
    EntityRelationship,
    FIRReportRecord,
    FraudIncident,
    IncidentEntity,
    ReportEntity,
)
from app.services.nexus_extraction import extract_report_identifiers


_ENTITY_TYPES = {
    "phone": CommunityEntityType.PHONE,
    "link": CommunityEntityType.LINK,
    "email": CommunityEntityType.EMAIL,
    "wallet": CommunityEntityType.WALLET,
    "account": CommunityEntityType.ACCOUNT,
    "identity": CommunityEntityType.PERSON,
    "national_id": CommunityEntityType.PERSON,
    "person": CommunityEntityType.PERSON,
    "business": CommunityEntityType.ORGANIZATION,
    "agent": CommunityEntityType.PERSON,
}
_PROTECTED_KINDS = {"national_id", "identity", "account", "wallet", "email"}


async def extract_and_link_report_entities(
    db: AsyncSession,
    *,
    report: FIRReportRecord,
    incident: FraudIncident,
    text: str,
    default_calling_code: str,
    secret_key: str,
    anchor_entity: CommunityEntity | None = None,
) -> list[dict[str, str | float]]:
    """Extract identifiers, mask sensitive references, and link them to FIR records.

    Extracted values are evidence only: all links remain unverified and carry
    extractor confidence/provenance. A co-mention edge means only that two
    entities appeared in the same submitted text.
    """
    extracted = extract_report_identifiers(text, default_calling_code)[:30]
    linked: list[tuple[CommunityEntity, dict[str, str | float]]] = []
    for item in extracted:
        kind = str(item["kind"])
        entity_type = _ENTITY_TYPES.get(kind)
        if entity_type is None:
            continue
        value = str(item["value"])
        original_normalized = str(item["normalized_value"])
        if kind in _PROTECTED_KINDS:
            namespace = f"fir-extracted:{kind}"
            protected = protect_partner_reference(
                value, namespace=namespace, application_secret=secret_key
            )
            normalized = f"{namespace}:{protected}"
            display = (
                f"National ID ••••{value[-4:]}" if kind == "national_id"
                else f"{kind.title()} ••••{value[-4:]}" if len(value) > 4
                else f"{kind.title()} reference"
            )
        elif kind in {"person", "business", "agent"}:
            normalized, display = original_normalized.casefold(), value
        elif kind == "phone":
            normalized, display = original_normalized, value
        else:
            normalized, display = original_normalized.casefold(), value

        entity = await db.scalar(select(CommunityEntity).where(
            CommunityEntity.entity_type == entity_type,
            CommunityEntity.normalized_value == normalized,
        ))
        if entity is None:
            entity = CommunityEntity(
                entity_type=entity_type,
                normalized_value=normalized,
                display_value=display,
                entity_metadata={"source": "fir_report_extraction", "verified": False},
            )
            db.add(entity)
            await db.flush()
        if await db.scalar(select(ReportEntity.id).where(
            ReportEntity.report_id == report.id,
            ReportEntity.entity_id == entity.id,
            ReportEntity.source_kind == "nexus_auto",
        )) is None:
            db.add(ReportEntity(
                report_id=report.id,
                entity_id=entity.id,
                source_text=str(item.get("source_text") or value)[:512],
                source_kind="nexus_auto",
                confidence=float(item["confidence"]),
                verified=False,
            ))
        if await db.scalar(select(IncidentEntity.id).where(
            IncidentEntity.incident_id == incident.id,
            IncidentEntity.entity_id == entity.id,
            IncidentEntity.role == "related",
        )) is None:
            db.add(IncidentEntity(
                incident_id=incident.id,
                entity_id=entity.id,
                role="related",
                confidence=float(item["confidence"]),
                verification_status="unverified",
                details={"source": "fir_report_extraction", "report_id": str(report.id)},
            ))
        linked.append((entity, item))

    if anchor_entity is not None:
        for entity, item in linked:
            if entity.id == anchor_entity.id:
                continue
            existing = await db.scalar(select(EntityRelationship.id).where(
                EntityRelationship.source_entity_id == anchor_entity.id,
                EntityRelationship.target_entity_id == entity.id,
                EntityRelationship.relationship_type == "co_mentioned_in_report",
            ))
            if existing is None:
                db.add(EntityRelationship(
                    source_entity_id=anchor_entity.id,
                    target_entity_id=entity.id,
                    relationship_type="co_mentioned_in_report",
                    confidence=float(item["confidence"]),
                    relationship_metadata={
                        "report_id": str(report.id),
                        "evidence": "same submitted message",
                        "verified": False,
                    },
                ))
    await db.flush()
    return [{"kind": str(item["kind"]), "value": entity.display_value or entity.normalized_value,
             "entity_id": str(entity.id), "confidence": float(item["confidence"])}
            for entity, item in linked]
