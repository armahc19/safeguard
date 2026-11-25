"""NEXUS engine: auto extract, PDR match, roles, and investigation graph on FIR intake."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import ValidationFailed
from app.core.partner_secrets import protect_partner_reference
from app.core.phone import normalize_phone
from app.enums import CommunityEntityType
from app.models import (
    CommunityEntity,
    EntityRelationship,
    FIRReportIncident,
    FIRReportRecord,
    FraudIncident,
    IncidentEntity,
    ReportEntity,
    User,
)
from app.services.intelligence_layers import IntelligenceLayers
from app.services.nexus_case_graph import _phone_role, build_fir_report_graph
from app.services.nexus_extraction import extract_report_identifiers
from app.services.nexus_pdr_search import search_pdr_identifiers

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


async def build_nexus_output_for_report(
    db: AsyncSession,
    report: FIRReportRecord,
    settings: Settings,
) -> list[dict[str, Any]]:
    """Re-extract report text and match it to PDR without persisting new labels."""
    existing_rows = (await db.execute(select(ReportEntity, CommunityEntity).join(
        CommunityEntity, CommunityEntity.id == ReportEntity.entity_id
    ).where(ReportEntity.report_id == report.id))).all()
    items_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    kind_map = {
        CommunityEntityType.PHONE: "phone",
        CommunityEntityType.WALLET: "wallet",
        CommunityEntityType.ACCOUNT: "account",
        CommunityEntityType.PERSON: "person",
        CommunityEntityType.ORGANIZATION: "business",
    }
    for link, entity in existing_rows:
        kind = kind_map.get(entity.entity_type, "person")
        value = entity.display_value or entity.normalized_value
        key = (kind, str(entity.normalized_value or value).casefold())
        current = items_by_key.get(key)
        if current is None:
            items_by_key[key] = {
                "kind": kind, "value": value, "confidence": float(link.confidence),
                "entity_id": str(entity.id),
            }
        else:
            current["confidence"] = max(current["confidence"], float(link.confidence))

    for candidate in extract_report_identifiers(
        f"{report.subject or ''}\n{report.description or ''}", settings.default_calling_code,
    ):
        kind = str(candidate["kind"])
        value = str(candidate["value"])
        key = (kind, str(candidate["normalized_value"]).casefold())
        if key not in items_by_key:
            items_by_key[key] = {
                "kind": kind, "value": value,
                "confidence": float(candidate["confidence"]), "entity_id": None,
            }

    output: list[dict[str, Any]] = []
    for item in items_by_key.values():
        kind, value = item["kind"], item["value"]
        if kind in {"link", "email"}:
            pdr_items = []
        else:
            search_kind = kind if kind in {"phone", "account", "wallet", "transaction"} else "all"
            pdr_items = (await search_pdr_identifiers(
                db, settings, value, kind=search_kind, include_fir=False,
            ))["items"]
        deduped = {}
        for match in pdr_items:
            if kind == "transaction" and match.get("matched_field") == "transaction reference":
                match = {**match, "transaction_reference": value}
            match_key = (match.get("kind"), match.get("record_id"))
            deduped.setdefault(match_key, match)
        output.append({**item, "pdr_matches": list(deduped.values())})
    return output


async def _upsert_incident_entity(
    db: AsyncSession,
    incident_id: UUID,
    entity_id: UUID,
    role: str,
    confidence: float,
    verification_status: str,
) -> None:
    row = await db.scalar(select(IncidentEntity).where(
        IncidentEntity.incident_id == incident_id,
        IncidentEntity.entity_id == entity_id,
        IncidentEntity.role == role,
    ))
    if row is None:
        db.add(IncidentEntity(
            incident_id=incident_id,
            entity_id=entity_id,
            role=role,
            confidence=confidence,
            verification_status=verification_status,
            details={"source": "nexus_engine_auto"},
        ))
    else:
        row.confidence = max(row.confidence, confidence)
        row.verification_status = verification_status


async def _assign_investigation_roles(
    db: AsyncSession,
    report: FIRReportRecord,
    output: list[dict[str, Any]],
    settings: Settings,
) -> None:
    text = f"{report.subject or ''}\n{report.description or ''}"
    incident_ids = list((await db.scalars(select(FIRReportIncident.incident_id).where(
        FIRReportIncident.report_id == report.id,
    ))).all())
    if not incident_ids:
        return

    victim_entity_id: UUID | None = None
    reporter = await db.get(User, report.reporter_id)
    if reporter:
        try:
            phone = normalize_phone(reporter.phone, settings.default_calling_code)
        except ValidationFailed:
            phone = reporter.phone
        victim_entity = await db.scalar(select(CommunityEntity).where(
            CommunityEntity.entity_type == CommunityEntityType.PHONE,
            CommunityEntity.normalized_value == phone,
        ))
        if victim_entity is None:
            victim_entity = CommunityEntity(
                entity_type=CommunityEntityType.PHONE,
                normalized_value=phone,
                display_value=phone,
                entity_metadata={"source": "reporter_account", "verified": False},
            )
            db.add(victim_entity)
            await db.flush()
        victim_entity_id = victim_entity.id

    for incident_id in incident_ids:
        if victim_entity_id:
            await _upsert_incident_entity(
                db, incident_id, victim_entity_id, "victim", 0.85, "reporter_account")
        for item in output:
            if item.get("kind") != "phone" or not item.get("entity_id"):
                continue
            phone_role = _phone_role(text, str(item.get("value", "")))
            entity_id = UUID(str(item["entity_id"]))
            if phone_role in {"alleged_recipient_phone"} and victim_entity_id != entity_id:
                await _upsert_incident_entity(
                    db, incident_id, entity_id, "suspect", float(item.get("confidence", 0.6)),
                    "alleged_recipient",
                )
            elif phone_role == "alleged_suspect_phone":
                await _upsert_incident_entity(
                    db, incident_id, entity_id, "suspect", float(item.get("confidence", 0.7)),
                    "alleged_suspect",
                )
    await db.flush()


def _cash_out_hints(graph: dict[str, Any]) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    for node in graph.get("nodes", []):
        details = node.get("details") or {}
        account_type = str(details.get("account_type", "")).casefold()
        provider = str(details.get("service_provider", "")).casefold()
        if "agent" in account_type or "agent" in provider:
            hints.append({
                "entity_id": str(node.get("id")),
                "label": str(node.get("display_value") or "Agent wallet"),
                "reason": "agent_or_cash_out_provider",
            })
    return hints[:20]


async def process_fir_report_nexus(
    db: AsyncSession,
    settings: Settings,
    report_id: UUID,
    *,
    refresh_layers: bool = True,
    ledger_walk_depth: int = 3,
) -> dict[str, Any]:
    """Extract identifiers, match PDR, assign roles, refresh ledger, build investigation graph."""
    report = await db.get(FIRReportRecord, report_id)
    if report is None:
        return {"status": "skipped", "reason": "report_not_found"}

    combined = f"{report.subject}\n{report.description}".strip()
    if not combined:
        return {"status": "skipped", "reason": "empty_report_text", "report_id": str(report_id)}

    candidates = extract_report_identifiers(combined, settings.default_calling_code)
    existing_rows = (await db.execute(select(ReportEntity, CommunityEntity).join(
        CommunityEntity, CommunityEntity.id == ReportEntity.entity_id
    ).where(ReportEntity.report_id == report.id))).all()
    extracted_by_key = {(item["kind"], item["normalized_value"]): item for item in candidates}
    existing_kind_map = {
        CommunityEntityType.PHONE: "phone",
        CommunityEntityType.LINK: "link",
        CommunityEntityType.EMAIL: "email",
        CommunityEntityType.WALLET: "wallet",
        CommunityEntityType.ACCOUNT: "account",
        CommunityEntityType.PERSON: "person",
        CommunityEntityType.ORGANIZATION: "business",
    }
    for link, entity in existing_rows:
        if link.source_kind == "nexus_auto" or entity.entity_metadata.get("source") == "pdr" or entity.normalized_value.startswith("pdr-"):
            continue
        kind = existing_kind_map.get(entity.entity_type)
        value = entity.display_value or entity.normalized_value
        if kind and value:
            key = (kind, entity.normalized_value.casefold())
            extracted_by_key.setdefault(key, {
                "kind": kind, "value": value,
                "normalized_value": entity.normalized_value.casefold(),
                "source_text": link.source_text or value,
                "confidence": link.confidence,
                "existing_entity_id": str(entity.id),
            })
    candidates = list(extracted_by_key.values())[:30]

    output: list[dict[str, Any]] = []
    entity_ids: set[UUID] = set()
    secret = settings.secret_key.get_secret_value()

    for item in candidates:
        kind = str(item["kind"])
        value = str(item["value"])
        community_type = _ENTITY_TYPES.get(kind)
        graph_entity = None
        if community_type is not None:
            legacy_normalized = str(item["normalized_value"])
            if kind in {"national_id", "identity", "account", "wallet", "email"}:
                namespace = f"fir-extracted:{kind}"
                normalized = f"{namespace}:{protect_partner_reference(value, namespace=namespace, application_secret=secret)}"
                display = (
                    f"National ID ••••{value[-4:]}" if kind == "national_id"
                    else f"{kind.title()} ••••{value[-4:]}" if len(value) > 4
                    else f"{kind.title()} reference"
                )
            elif kind == "phone":
                normalized = str(item["normalized_value"])
                display = value
            elif kind in {"person", "business"}:
                normalized, display = value.casefold(), value
            else:
                normalized, display = value.casefold(), value
            graph_entity = await db.scalar(select(CommunityEntity).where(
                CommunityEntity.entity_type == community_type,
                CommunityEntity.normalized_value == legacy_normalized,
            ))
            if graph_entity is None and normalized != legacy_normalized:
                graph_entity = await db.scalar(select(CommunityEntity).where(
                    CommunityEntity.entity_type == community_type,
                    CommunityEntity.normalized_value == normalized,
                ))
            if graph_entity is None:
                graph_entity = CommunityEntity(
                    entity_type=community_type,
                    normalized_value=normalized,
                    display_value=display,
                    entity_metadata={"source": "fir_report_extraction", "verified": False},
                )
                db.add(graph_entity)
                await db.flush()
            existing_link = await db.scalar(select(ReportEntity).where(
                ReportEntity.report_id == report.id,
                ReportEntity.entity_id == graph_entity.id,
                ReportEntity.source_kind == "nexus_auto",
            ))
            if existing_link is None:
                db.add(ReportEntity(
                    report_id=report.id,
                    entity_id=graph_entity.id,
                    source_text=f"NEXUS extracted {kind} identifier",
                    source_kind="nexus_auto",
                    confidence=float(item["confidence"]),
                    verified=False,
                ))
                await db.flush()
            item["entity_id"] = str(graph_entity.id)
            entity_ids.add(graph_entity.id)

        pdr_items: list[dict] = []
        if kind not in {"link", "email"}:
            pdr_items = (await search_pdr_identifiers(db, settings, value, include_fir=False))["items"]
        for partner_match in pdr_items:
            partner_entity_id = partner_match.get("entity_id")
            if graph_entity and partner_entity_id and str(graph_entity.id) != partner_entity_id:
                partner_entity = await db.get(CommunityEntity, UUID(partner_entity_id))
                if partner_entity is not None:
                    relationship = await db.scalar(select(EntityRelationship).where(
                        EntityRelationship.source_entity_id == graph_entity.id,
                        EntityRelationship.target_entity_id == partner_entity.id,
                        EntityRelationship.relationship_type == "exact_identifier_match",
                    ))
                    if relationship is None:
                        db.add(EntityRelationship(
                            source_entity_id=graph_entity.id,
                            target_entity_id=partner_entity.id,
                            relationship_type="exact_identifier_match",
                            confidence=min(0.99, float(item["confidence"])),
                            relationship_metadata={
                                "source": "nexus_auto_extraction",
                                "matched_field": partner_match["matched_field"],
                                "partner": partner_match["partner"],
                            },
                        ))
        output.append({
            "kind": kind,
            "value": value,
            "confidence": float(item["confidence"]),
            "entity_id": item.get("entity_id"),
            "pdr_matches": pdr_items,
        })

    await _assign_investigation_roles(db, report, output, settings)

    duplicate_rows = []
    if entity_ids:
        duplicate_rows = (await db.execute(select(FIRReportRecord, ReportEntity.entity_id).join(
            ReportEntity, ReportEntity.report_id == FIRReportRecord.id
        ).where(
            ReportEntity.entity_id.in_(entity_ids),
            FIRReportRecord.id != report.id,
        ).order_by(FIRReportRecord.created_at.desc()).limit(100))).all()
    duplicates_by_id: dict[str, dict] = {}
    for duplicate, matched_entity_id in duplicate_rows:
        bucket = duplicates_by_id.setdefault(str(duplicate.id), {
            "report_id": str(duplicate.id),
            "subject": duplicate.subject,
            "report_type": duplicate.report_type,
            "status": duplicate.status,
            "category": duplicate.category,
            "created_at": duplicate.created_at.isoformat(),
            "shared_entity_ids": [],
        })
        bucket["shared_entity_ids"].append(str(matched_entity_id))

    layers: dict[str, int] = {}
    if refresh_layers:
        layers = await IntelligenceLayers(db, settings).refresh_all()

    nexus_graph = await build_fir_report_graph(db, report.id, output, settings)
    cash_out = _cash_out_hints(nexus_graph)

    incident_ids = list((await db.scalars(select(FIRReportIncident.incident_id).where(
        FIRReportIncident.report_id == report.id,
    ))).all())
    nexus_meta = {
        "processed_at": datetime.now(UTC).isoformat(),
        "auto": True,
        "report_id": str(report.id),
        "ledger_walk_depth": ledger_walk_depth,
        "summary": nexus_graph.get("summary", {}),
        "cash_out_hints": cash_out,
    }
    for incident_id in incident_ids:
        incident = await db.get(FraudIncident, incident_id)
        if incident:
            incident_metadata = dict(incident.incident_metadata or {})
            prior_nexus = dict(incident_metadata.get("nexus") or {})
            # Refreshing extraction/graph projections must not erase investigator
            # decisions already stored on this incident.
            for decision_key in ("confirmed_entity_ids", "rejected_entity_ids", "last_decision_at"):
                if decision_key in prior_nexus:
                    nexus_meta[decision_key] = prior_nexus[decision_key]
            incident_metadata["nexus"] = nexus_meta
            incident.incident_metadata = incident_metadata

    await db.flush()
    return {
        "status": "processed",
        "report_id": str(report.id),
        "extracted_count": len(output),
        "linked_to_fir": sum(bool(item.get("entity_id")) for item in output),
        "items": output,
        "possible_duplicate_reports": list(duplicates_by_id.values()),
        "layers_refreshed": layers,
        "nexus_graph": nexus_graph,
        "nexus_meta": nexus_meta,
    }
