"""Reviewer/admin API for derived FIR + Partner Data Repository intelligence."""
from typing import Literal
from uuid import UUID

from datetime import UTC, datetime
from fastapi import APIRouter, Body, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import String, func, or_, select

from app.api.deps import AdminUser, DbDep, ReviewerUser, SettingsDep
from app.core.exceptions import NotFoundError, PermissionDenied, ValidationFailed
from app.core.partner_secrets import protect_partner_reference
from app.core.phone import normalize_phone
from app.enums import CommunityEntityType, UserRole
from app.models import (
    Base,
    CommunityEntity,
    CrossInstitutionSignal,
    EntityIntelligenceProfile,
    EntityRelationship,
    FIRReportIncident,
    FIRReportRecord,
    FraudCase,
    FraudIncident,
    IdentityResolutionCluster,
    IdentityResolutionMember,
    Partner,
    PartnerActionReferral,
    PartnerAccount,
    PartnerIdentity,
    PartnerTransaction,
    ReportEntity,
)
from app.services.intelligence_layers import IntelligenceLayers
from app.services.nexus_case_graph import build_fir_report_graph
from app.services.nexus_collection import collect_entity_intelligence
from app.services.nexus_engine import build_nexus_output_for_report, process_fir_report_nexus
from app.services.nexus_extraction import extract_report_identifiers
from app.services.nexus_exposure_profile import compute_exposure_profile
from app.services.nexus_ledger import collect_ledger_subgraph, confirmed_fraud_entity_ids, exposure_hop_count
from app.services.nexus_trace import apply_trace_decision, build_report_trace_bundle, trust_tier_from_status
from app.services.nexus_pdr_search import search_pdr_identifiers
from app.services.atlas_ecosystem import build_atlas_network_graph
from app.services.atlas_graph import (
    ATLAS_SCOPED_TABLES,
    atlas_record,
    atlas_semantic_relationships,
    atlas_source,
    atlas_transaction_accounts,
)

router = APIRouter(prefix="/intelligence/layers", tags=["intelligence-layers"])


class PartnerReferralCreate(BaseModel):
    partner_id: UUID
    requested_action: Literal["review_account", "preserve_records", "assess_restriction", "assess_recall_recovery", "other"]
    target_label: str = Field(min_length=1, max_length=256)
    target_reference: str = Field(min_length=1, max_length=256)
    rationale: str = Field(min_length=10, max_length=5000)
    case_id: UUID | None = None
    evidence_snapshot: dict = Field(default_factory=dict)


class ReferralReview(BaseModel):
    decision: Literal["approved", "declined"]
    note: str = Field(min_length=3, max_length=2000)


class ReferralResponse(BaseModel):
    response: str = Field(min_length=3, max_length=5000)

_atlas_source = atlas_source
_atlas_record = atlas_record
_atlas_semantic_relationships = atlas_semantic_relationships
_atlas_transaction_accounts = atlas_transaction_accounts


def _referral_out(row: PartnerActionReferral, partner: Partner) -> dict:
    return {
        "id": row.id, "partner_id": row.partner_id, "partner_name": partner.partner_name,
        "created_by": row.created_by,
        "status": row.status, "requested_action": row.requested_action,
        "target_label": row.target_label, "target_reference": row.target_reference,
        "rationale": row.rationale, "case_id": row.case_id,
        "evidence_snapshot": row.evidence_snapshot, "review_note": row.review_note,
        "partner_response": row.partner_response, "sent_at": row.sent_at,
        "created_at": row.created_at, "updated_at": row.updated_at,
    }


@router.get("/partner-referrals/partners")
async def partner_referral_partners(db: DbDep, _reviewer: ReviewerUser):
    rows = (await db.scalars(select(Partner).where(Partner.partner_status == "active").order_by(Partner.partner_name))).all()
    return [{"id": row.id, "partner_name": row.partner_name, "partner_code": row.partner_code,
             "partner_type": row.partner_type} for row in rows]


@router.post("/partner-referrals", status_code=status.HTTP_201_CREATED)
async def create_partner_referral(body: PartnerReferralCreate, user: ReviewerUser, db: DbDep):
    partner = await db.get(Partner, body.partner_id)
    if partner is None or partner.partner_status != "active":
        raise NotFoundError("Active partner not found.", code="partner_not_found")
    if body.case_id:
        case = await db.get(FraudCase, body.case_id)
        if case is None:
            raise NotFoundError("Investigation case not found.", code="case_not_found")
        if user.role != UserRole.ADMIN and user.id not in {case.user_id, case.assigned_investigator_id}:
            raise PermissionDenied("You cannot refer evidence from this investigation.")
    import json
    if len(json.dumps(body.evidence_snapshot, default=str)) > 150_000:
        raise ValidationFailed("The evidence snapshot is too large. Narrow the referral evidence.", code="referral_snapshot_too_large")
    row = PartnerActionReferral(
        partner_id=partner.id, created_by=user.id, requested_action=body.requested_action,
        target_label=body.target_label, target_reference=body.target_reference,
        rationale=body.rationale, case_id=body.case_id,
        evidence_snapshot=body.evidence_snapshot, status="draft",
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _referral_out(row, partner)


@router.get("/partner-referrals")
async def list_partner_referrals(user: ReviewerUser, db: DbDep, limit: int = Query(30, ge=1, le=100)):
    query = select(PartnerActionReferral, Partner).join(Partner, Partner.id == PartnerActionReferral.partner_id)
    if user.role != UserRole.ADMIN:
        query = query.where(or_(PartnerActionReferral.created_by == user.id,
                                PartnerActionReferral.status == "pending_review"))
    rows = (await db.execute(query.order_by(PartnerActionReferral.created_at.desc()).limit(limit))).all()
    return [_referral_out(row, partner) for row, partner in rows]


@router.post("/partner-referrals/{referral_id}/submit")
async def submit_partner_referral(referral_id: UUID, user: ReviewerUser, db: DbDep):
    row = await db.get(PartnerActionReferral, referral_id)
    if row is None:
        raise NotFoundError("Partner referral not found.", code="referral_not_found")
    if row.created_by != user.id and user.role != UserRole.ADMIN:
        raise PermissionDenied("Only the referral author can submit it for review.")
    if row.status != "draft":
        raise ValidationFailed("Only a draft referral can be submitted for review.", code="invalid_referral_transition")
    row.status = "pending_review"
    await db.commit()
    return {"id": row.id, "status": row.status}


@router.post("/partner-referrals/{referral_id}/review")
async def review_partner_referral(referral_id: UUID, body: ReferralReview, reviewer: ReviewerUser, db: DbDep):
    row = await db.get(PartnerActionReferral, referral_id)
    if row is None:
        raise NotFoundError("Partner referral not found.", code="referral_not_found")
    if row.status != "pending_review":
        raise ValidationFailed("Only a referral awaiting review can receive a decision.", code="invalid_referral_transition")
    if row.created_by == reviewer.id:
        raise PermissionDenied("A different reviewer must approve or decline this referral.")
    row.status = body.decision
    row.reviewed_by = reviewer.id
    row.review_note = body.note
    await db.commit()
    return {"id": row.id, "status": row.status, "review_note": row.review_note}


@router.post("/partner-referrals/{referral_id}/mark-sent")
async def mark_partner_referral_sent(referral_id: UUID, user: ReviewerUser, db: DbDep):
    row = await db.get(PartnerActionReferral, referral_id)
    if row is None:
        raise NotFoundError("Partner referral not found.", code="referral_not_found")
    if row.status != "approved":
        raise ValidationFailed("Only an approved referral can be marked sent.", code="invalid_referral_transition")
    row.status = "sent"
    row.sent_at = datetime.now(UTC)
    row.sent_by = user.id
    await db.commit()
    return {"id": row.id, "status": row.status, "sent_at": row.sent_at}


@router.post("/partner-referrals/{referral_id}/response")
async def record_partner_referral_response(referral_id: UUID, body: ReferralResponse, user: ReviewerUser, db: DbDep):
    row = await db.get(PartnerActionReferral, referral_id)
    if row is None:
        raise NotFoundError("Partner referral not found.", code="referral_not_found")
    if row.status != "sent":
        raise ValidationFailed("Record a partner response after the referral is marked sent.", code="invalid_referral_transition")
    row.partner_response = body.response
    row.response_recorded_by = user.id
    row.status = "responded"
    await db.commit()
    return {"id": row.id, "status": row.status}


@router.get("/atlas/catalog")
async def atlas_catalog(db: DbDep, _reviewer: ReviewerUser):
    """List every FIR, PDR, and shared intelligence table in the ATLAS ecosystem."""
    table_rows = []
    tables = Base.metadata.tables
    for name in sorted(ATLAS_SCOPED_TABLES):
        if name not in tables:
            continue
        count = int((await db.scalar(select(func.count()).select_from(tables[name]))) or 0)
        table_rows.append({"name": name, "source": atlas_source(name), "row_count": count})
    return {
        "tables": table_rows,
        "table_count": len(table_rows),
        "record_count": sum(row["row_count"] for row in table_rows),
        "scoped_tables": sorted(ATLAS_SCOPED_TABLES),
    }


@router.get("/atlas")
async def atlas_network_map(
    db: DbDep,
    _reviewer: ReviewerUser,
    settings: SettingsDep,
    query: str | None = Query(None, max_length=128),
    table_name: str = Query("all", alias="table", max_length=64),
    source_filter: Literal["all", "fir", "pdr", "shared"] = Query("all", alias="source"),
    record_type: str | None = Query(None, alias="type", max_length=64),
    risk_level: str | None = Query(None, max_length=24),
    verification_status: str | None = Query(None, max_length=24),
    date_from: str | None = Query(None, max_length=32),
    date_to: str | None = Query(None, max_length=32),
    relationship_type: str | None = Query(None, max_length=64),
    limit: int = Query(5000, ge=20, le=15000),
    offset: int = Query(0, ge=0, le=1000000),
    coverage: Literal["ecosystem", "sample"] = Query("ecosystem"),
):
    """Unified FIR + PDR + shared ecosystem graph (every scoped table row, linked by FK and projection)."""
    tables = Base.metadata.tables
    if table_name != "all" and table_name not in ATLAS_SCOPED_TABLES:
        raise ValidationFailed("Unknown ATLAS table.", code="invalid_atlas_table")
    if record_type and record_type not in ATLAS_SCOPED_TABLES:
        raise ValidationFailed("Unknown ATLAS record type.", code="invalid_atlas_type")
    if table_name != "all" and table_name not in tables:
        raise ValidationFailed("ATLAS table is not mapped.", code="invalid_atlas_table")
    return await build_atlas_network_graph(
        db,
        query=query,
        table_name=table_name,
        source_filter=source_filter,
        record_type=record_type,
        risk_level=risk_level,
        verification_status=verification_status,
        date_from=date_from,
        date_to=date_to,
        relationship_type=relationship_type,
        limit=limit,
        offset=offset,
        coverage=coverage,
        settings=settings,
    )


async def _expand_atlas_records(db, node_id: str, depth: int, limit: int) -> dict:
    try:
        repository_key, source_key = node_id.split(".", 1)
        table_name, record_id = source_key.split(":", 1)
    except ValueError as exc:
        raise ValidationFailed("ATLAS node ID must include its source table and record ID.",
                               code="invalid_atlas_node_id") from exc
    tables = Base.metadata.tables
    if table_name not in tables or "id" not in tables[table_name].c:
        raise NotFoundError("ATLAS source record not found.")
    if repository_key != _atlas_source(table_name):
        raise ValidationFailed("ATLAS node repository does not match its source table.",
                               code="invalid_atlas_node_id")
    table = tables[table_name]
    root = (await db.execute(select(table).where(table.c.id.cast(String) == record_id).limit(1))).mappings().first()
    if root is None:
        raise NotFoundError("ATLAS source record not found.")

    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}
    raw_rows: dict[str, dict[str, dict]] = {}
    frontier: list[tuple[str, dict]] = []
    visited: set[str] = set()

    def put_record(name: str, values: dict, enqueue: bool = True) -> str:
        node = _atlas_record(name, values)
        nodes.setdefault(node["id"], node)
        raw_rows.setdefault(name, {})[node["record_id"]] = values
        if enqueue and node["id"] not in visited:
            visited.add(node["id"])
            frontier.append((name, values))
        return node["id"]

    def put_link(child_name: str, child: dict, column_name: str, target_name: str, target_id: str):
        child_id = f"{_atlas_source(child_name)}.{child_name}:{child['id']}"
        target_node_id = f"{_atlas_source(target_name)}.{target_name}:{target_id}"
        edges[(child_id, target_node_id, column_name)] = {
            "source": child_id, "target": target_node_id,
            "relationship": column_name.removesuffix("_id").replace("_", " "),
            "confidence": 1.0, "repository": _atlas_source(child_name),
            "source_table": child_name, "source_record_id": str(child["id"]),
            "verification_status": "database_foreign_key",
        }

    put_record(table_name, dict(root))
    for _ in range(depth):
        current, frontier = frontier, []
        if not current or len(nodes) >= limit:
            break

        # Follow outbound FKs from the current records, batched by target table.
        outbound: dict[str, dict[str, list[tuple[str, dict, str]]]] = {}
        for child_name, values in current:
            for column in tables[child_name].columns:
                for fk in column.foreign_keys:
                    target_name = fk.column.table.name
                    if target_name not in tables or "id" not in tables[target_name].c:
                        continue
                    target_id = values.get(column.name)
                    if target_id is not None:
                        outbound.setdefault(target_name, {}).setdefault(str(target_id), []).append(
                            (child_name, values, column.name))
        for target_name, refs in outbound.items():
            budget = max(1, limit - len(nodes))
            target_table = tables[target_name]
            target_rows = (await db.execute(select(target_table).where(
                target_table.c.id.cast(String).in_(list(refs))
            ).limit(budget))).mappings().all()
            found = {str(row["id"]): dict(row) for row in target_rows}
            for target_id, ref_rows in refs.items():
                target_values = found.get(target_id)
                if not target_values:
                    continue
                put_record(target_name, target_values)
                for child_name, child_values, column_name in ref_rows:
                    put_link(child_name, child_values, column_name, target_name, target_id)

        # Follow inbound FKs too, so selecting an incident, account, or case
        # reveals its linked reports, transactions, evidence, and assessments.
        current_by_table: dict[str, set[str]] = {}
        for name, values in current:
            current_by_table.setdefault(name, set()).add(str(values["id"]))
        for child_name, child_table in tables.items():
            if child_name not in ATLAS_SCOPED_TABLES or len(nodes) >= limit:
                continue
            for column in child_table.columns:
                target_name = next((fk.column.table.name for fk in column.foreign_keys
                                    if fk.column.table.name in current_by_table), None)
                if not target_name:
                    continue
                budget = max(1, limit - len(nodes))
                child_rows = (await db.execute(select(child_table).where(
                    column.cast(String).in_(current_by_table[target_name])
                ).order_by(child_table.c.id).limit(budget))).mappings().all()
                for row in child_rows:
                    values = dict(row)
                    put_record(child_name, values)
                    put_link(child_name, values, column.name, target_name, str(values[column.name]))

        # Bridge PDR identity/account source rows to their exact FIR graph
        # projections. These are labelled as projection links, never identity proof.
        for pdr_table, key_kind, value_column in (
            ("partner_identities", "pdr-identity", "identity_reference"),
            ("partner_accounts", "pdr-account", "account_identifier"),
        ):
            for name, values in current:
                if name != pdr_table:
                    continue
                partner_code = await db.scalar(select(Partner.partner_code).where(Partner.id == values["partner_id"]))
                if not partner_code or not values.get(value_column):
                    continue
                entity = await db.scalar(select(CommunityEntity).where(
                    CommunityEntity.normalized_value == f"{key_kind}:{partner_code}:{values[value_column]}"
                ))
                if entity is None:
                    continue
                entity_values = {column.name: getattr(entity, column.name)
                                 for column in CommunityEntity.__table__.columns}
                entity_id = put_record("community_entities", entity_values)
                edges[(f"pdr.{name}:{values['id']}", entity_id, "projected_entity")] = {
                    "source": f"pdr.{name}:{values['id']}", "target": entity_id,
                    "relationship": "projected entity", "confidence": 1.0,
                    "repository": "shared", "source_table": name,
                    "source_record_id": str(values["id"]),
                    "verification_status": "exact_projection_key",
                }

        for name, values in current:
            if name == "partner_transactions":
                transaction_node_id = f"pdr.partner_transactions:{values['id']}"
                for direction, account in await _atlas_transaction_accounts(db, values):
                    account_values = {column.name: getattr(account, column.name)
                                      for column in PartnerAccount.__table__.columns}
                    account_node_id = put_record("partner_accounts", account_values)
                    edges[(transaction_node_id, account_node_id, f"{direction}_account_reference")] = {
                        "source": transaction_node_id, "target": account_node_id,
                        "relationship": f"{direction} account reference", "confidence": 1.0,
                        "repository": "pdr", "source_table": name,
                        "source_record_id": str(values["id"]),
                        "verification_status": "exact_partner_scoped_reference",
                    }
            elif name == "partner_accounts":
                partner_code = await db.scalar(select(Partner.partner_code).where(
                    Partner.id == values["partner_id"]))
                if not partner_code:
                    continue
                transaction_rows = (await db.execute(select(PartnerTransaction).where(or_(
                    (PartnerTransaction.sender_partner_code == partner_code)
                    & (PartnerTransaction.sender_account_reference == values["account_identifier"]),
                    (PartnerTransaction.receiver_partner_code == partner_code)
                    & (PartnerTransaction.receiver_account_reference == values["account_identifier"]),
                )).order_by(PartnerTransaction.transaction_datetime.desc()).limit(limit))).scalars().all()
                for transaction in transaction_rows:
                    transaction_values = {column.name: getattr(transaction, column.name)
                                          for column in PartnerTransaction.__table__.columns}
                    transaction_node_id = put_record("partner_transactions", transaction_values)
                    if (transaction.sender_partner_code == partner_code
                            and transaction.sender_account_reference == values["account_identifier"]):
                        relation = "sender account reference"
                    else:
                        relation = "receiver account reference"
                    account_node_id = f"pdr.partner_accounts:{values['id']}"
                    edges[(transaction_node_id, account_node_id, relation)] = {
                        "source": transaction_node_id, "target": account_node_id,
                        "relationship": relation, "confidence": 1.0,
                        "repository": "pdr", "source_table": "partner_transactions",
                        "source_record_id": str(transaction.id),
                        "verification_status": "exact_partner_scoped_reference",
                    }

    for link in _atlas_semantic_relationships(raw_rows, nodes):
        key = (link["source"], link["target"],
               f"{link['source_table']}:{link['source_record_id']}:{link['relationship']}")
        edges[key] = link
    return {"nodes": list(nodes.values()), "edges": list(edges.values()),
        "summary": {"node_count": len(nodes), "edge_count": len(edges),
                    "root": node_id, "depth": depth, "limit": limit,
                    "truncated": len(nodes) >= limit}}


@router.get("/atlas/expand")
async def atlas_expand(
    db: DbDep, _reviewer: ReviewerUser,
    node_id: str = Query(min_length=3, max_length=256),
    depth: int = Query(1, ge=1, le=4),
    limit: int = Query(250, ge=20, le=500),
):
    """Expand a record through verified database links and exact PDR projections."""
    return await _expand_atlas_records(db, node_id, depth, limit)


@router.get("/atlas/path")
async def atlas_trace_path(
    db: DbDep, _reviewer: ReviewerUser,
    source_id: str = Query(min_length=3, max_length=256),
    target_id: str = Query(min_length=3, max_length=256),
    depth: int = Query(3, ge=1, le=5),
    limit: int = Query(500, ge=20, le=500),
):
    """Find a shortest path through the bounded, provenance-preserving record graph."""
    graph = await _expand_atlas_records(db, source_id, depth, limit)
    nodes = {node["id"]: node for node in graph["nodes"]}
    if target_id not in nodes:
        return {"found": False, "complete": False, "nodes": [], "edges": [],
            "summary": {**graph["summary"], "source": source_id, "target": target_id,
                "message": "No path found in the explored depth and record limit. This does not prove the records are unrelated."}}
    adjacency: dict[str, list[tuple[str, dict]]] = {}
    for edge in graph["edges"]:
        adjacency.setdefault(edge["source"], []).append((edge["target"], edge))
        adjacency.setdefault(edge["target"], []).append((edge["source"], edge))
    queue = [source_id]
    previous: dict[str, tuple[str, dict] | None] = {source_id: None}
    for current in queue:
        if current == target_id:
            break
        for neighbor, edge in adjacency.get(current, []):
            if neighbor not in previous:
                previous[neighbor] = (current, edge)
                queue.append(neighbor)
    if target_id not in previous:
        return {"found": False, "complete": False, "nodes": [], "edges": [],
            "summary": {**graph["summary"], "source": source_id, "target": target_id,
                "message": "No path found in the explored depth and record limit. This does not prove the records are unrelated."}}
    path_nodes = [target_id]
    path_edges = []
    cursor = target_id
    while previous[cursor] is not None:
        parent, edge = previous[cursor]
        path_edges.append(edge)
        path_nodes.append(parent)
        cursor = parent
    path_nodes.reverse()
    path_edges.reverse()
    path_node_records = [nodes[node_id] for node_id in path_nodes]
    path_source_counts = {"fir": 0, "pdr": 0, "shared": 0}
    for node in path_node_records:
        path_source_counts[node["source"]] += 1
    return {"found": True, "complete": True,
        "nodes": path_node_records, "edges": path_edges,
        "summary": {"node_count": len(path_node_records), "edge_count": len(path_edges),
                    "by_source": path_source_counts, "source": source_id,
                    "target": target_id, "path_length": len(path_edges),
                    "depth_limit": depth, "verification_status": "links retain per-edge provenance"}}


@router.get("/records/detail")
async def source_record_detail(
    db: DbDep,
    _reviewer: ReviewerUser,
    source_table: str = Query(..., min_length=1, max_length=64),
    source_record_id: str = Query(..., min_length=1, max_length=64),
):
    """Return a reviewer-safe FIR or PDR source row for the NEXUS selected-item panel."""
    tables = Base.metadata.tables
    if source_table not in tables or "id" not in tables[source_table].c:
        raise NotFoundError("Source record not found.", code="source_record_not_found")
    table = tables[source_table]
    row = (await db.execute(
        select(table).where(table.c.id.cast(String) == source_record_id).limit(1)
    )).mappings().first()
    if row is None:
        raise NotFoundError("Source record not found.", code="source_record_not_found")
    values = dict(row)
    if source_table in ATLAS_SCOPED_TABLES:
        return _atlas_record(source_table, values)
    safe_keys = {
        "id", "status", "created_at", "updated_at", "subject", "description", "category",
        "report_type", "channel", "title", "amount", "currency", "transaction_status",
        "account_type", "account_status", "verification_status", "role",
        "transaction_datetime", "processing_status",
    }
    details: dict[str, str] = {}
    for key in safe_keys:
        if key not in values or values[key] is None:
            continue
        value = values[key]
        value = getattr(value, "value", value)
        details[key] = value.isoformat() if hasattr(value, "isoformat") else str(value)
    label = next(
        (str(values[key]) for key in ("subject", "title", "display_value", "category") if values.get(key)),
        f"{source_table.replace('_', ' ')} · {source_record_id[:8]}",
    )
    return {
        "label": label[:110],
        "source": _atlas_source(source_table) if source_table in ATLAS_SCOPED_TABLES else "fir",
        "table": source_table,
        "record_id": source_record_id,
        "verification_status": details.get("verification_status", "source_record"),
        "details": details,
    }


@router.get("/search")
async def search_partner_identifiers(
    db: DbDep, settings: SettingsDep, _reviewer: ReviewerUser,
    query: str = Query(min_length=1, max_length=256),
    kind: Literal["all", "person", "business", "phone", "account", "wallet", "transaction", "agent", "report"] = "all",
    include_fir: bool = True,
):
    """Search exact protected PDR identifiers and broader FIR entities/reports for NEXUS."""
    return await search_pdr_identifiers(db, settings, query, kind=kind, include_fir=include_fir)


@router.get("/reports/{report_id}/nexus-graph")
async def report_nexus_graph(report_id: UUID, db: DbDep, settings: SettingsDep, _reviewer: ReviewerUser):
    """Return the auto-built NEXUS investigation graph for a FIR report."""
    report = await db.get(FIRReportRecord, report_id)
    if report is None:
        raise NotFoundError("FIR report not found.", code="fir_report_not_found")
    output = await build_nexus_output_for_report(db, report, settings)
    graph = await build_fir_report_graph(db, report.id, output, settings)
    meta = {}
    incident_links = (await db.scalars(select(FIRReportIncident.incident_id).where(
        FIRReportIncident.report_id == report.id))).all()
    if incident_links:
        incident = await db.get(FraudIncident, incident_links[0])
        meta = (incident.incident_metadata or {}).get("nexus", {}) if incident else {}
    return {"report_id": str(report.id), "nexus_graph": graph, "nexus_meta": meta, "items": output}


class NexusTraceDecisionIn(BaseModel):
    target_type: Literal["entity", "edge"] = "entity"
    target_id: str = Field(min_length=1, max_length=256)
    decision: Literal["confirm", "reject"]
    role: str | None = Field(None, max_length=48)
    notes: str | None = Field(None, max_length=512)


@router.get("/reports/{report_id}/nexus-trace")
async def report_nexus_trace(report_id: UUID, db: DbDep, settings: SettingsDep, _reviewer: ReviewerUser):
    """FIR→PDR trace steps, pattern candidates, and exposure for a report investigation."""
    report = await db.get(FIRReportRecord, report_id)
    if report is None:
        raise NotFoundError("FIR report not found.", code="fir_report_not_found")
    output = await build_nexus_output_for_report(db, report, settings)
    graph = await build_fir_report_graph(db, report.id, output, settings)
    bundle = await build_report_trace_bundle(db, report, graph, output)
    exposure_entity_id: UUID | None = None
    for step in bundle.get("steps") or []:
        if step.get("kind") in {"wallet_or_account", "ledger_wallet"}:
            nid = str(step.get("node_id") or "")
            if len(nid) == 36:
                exposure_entity_id = UUID(nid)
                break
            if nid.startswith("pdr-account:"):
                try:
                    exposure_entity_id = UUID(nid.split(":", 1)[1])
                except ValueError:
                    pass
    for node in graph.get("nodes") or []:
        nid = str(node.get("id") or "")
        if node.get("type") in {"wallet", "account"} and len(nid) == 36:
            exposure_entity_id = UUID(nid)
            break
    exposure = None
    if exposure_entity_id:
        exposure = await compute_exposure_profile(db, exposure_entity_id)
    bundle["exposure"] = exposure
    bundle["graph"] = graph
    return bundle


@router.post("/reports/{report_id}/nexus-trace/decisions")
async def report_nexus_trace_decision(
    report_id: UUID,
    body: NexusTraceDecisionIn,
    db: DbDep,
    settings: SettingsDep,
    reviewer: ReviewerUser,
):
    """Investigator confirm/reject for trace links; persists on FIR/incident."""
    report = await db.get(FIRReportRecord, report_id)
    if report is None:
        raise NotFoundError("FIR report not found.", code="fir_report_not_found")
    result = await apply_trace_decision(
        db, report,
        target_type=body.target_type,
        target_id=body.target_id,
        decision=body.decision,
        role=body.role,
        actor_id=reviewer.id,
    )
    output = await build_nexus_output_for_report(db, report, settings)
    graph = await build_fir_report_graph(db, report.id, output, settings)
    bundle = await build_report_trace_bundle(db, report, graph, output)
    if body.decision == "confirm" and body.target_type == "entity":
        entity_uuid = None
        if body.target_id.startswith("fir-entity:"):
            entity_uuid = UUID(body.target_id.split(":", 1)[1])
        elif len(body.target_id) == 36:
            entity_uuid = UUID(body.target_id)
        if entity_uuid:
            bundle["exposure"] = await compute_exposure_profile(db, entity_uuid)
    await db.commit()
    return {"decision": result, "trace": bundle}


@router.get("/exposure")
async def wallet_exposure(
    db: DbDep,
    _reviewer: ReviewerUser,
    entity_id: UUID = Query(),
    days: int = Query(7, ge=1, le=30),
    max_hops: int = Query(2, ge=1, le=4),
):
    """Auditable exposure sentence for a wallet/entity (investigator or graph use)."""
    return await compute_exposure_profile(db, entity_id, days=days, max_hops=max_hops)


@router.post("/reports/{report_id}/extract-match")
async def extract_and_match_report(
    report_id: UUID, db: DbDep, settings: SettingsDep, _reviewer: ReviewerUser,
):
    """Re-run NEXUS extract/match/graph for a FIR report (reviewer manual refresh)."""
    report = await db.get(FIRReportRecord, report_id)
    if report is None:
        raise NotFoundError("FIR report not found.", code="fir_report_not_found")
    result = await process_fir_report_nexus(db, settings, report.id, refresh_layers=True)
    await db.commit()
    return result


@router.post("/rebuild")
async def rebuild_intelligence(db: DbDep, settings: SettingsDep, _admin: AdminUser):
    """Recompute all five projection layers from current FIR and PDR records."""
    result = await IntelligenceLayers(db, settings).refresh_all()
    await db.commit()
    return {"status": "rebuilt", "layers": result}


@router.get("/identity-clusters")
async def identity_clusters(db: DbDep, _reviewer: ReviewerUser,
                            limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    rows = (await db.scalars(select(IdentityResolutionCluster).order_by(
        IdentityResolutionCluster.updated_at.desc()).offset(offset).limit(limit))).all()
    result = []
    for cluster in rows:
        members = (await db.execute(select(IdentityResolutionMember, PartnerIdentity, Partner).join(
            PartnerIdentity, PartnerIdentity.id == IdentityResolutionMember.partner_identity_id
        ).join(Partner, Partner.id == PartnerIdentity.partner_id).where(
            IdentityResolutionMember.cluster_id == cluster.id))).all()
        result.append({"id": cluster.id, "match_type": cluster.match_type,
            "resolution_status": cluster.resolution_status, "confidence": cluster.confidence,
            "partner_count": cluster.partner_count, "identity_count": cluster.identity_count,
            "evidence": cluster.evidence,
            "members": [{"partner_code": partner.partner_code, "partner_name": partner.partner_name,
                         "verification_status": identity.verification_status,
                         "verified_ownership": identity.verified_ownership,
                         "confidence": member.confidence}
                        for member, identity, partner in members]})
    return {"items": result, "limit": limit, "offset": offset}


@router.get("/entities/{entity_id}")
async def entity_intelligence(entity_id: UUID, db: DbDep, _reviewer: ReviewerUser):
    entity = await db.get(CommunityEntity, entity_id)
    if entity is None:
        from app.core.exceptions import NotFoundError
        raise NotFoundError("Entity not found.", code="entity_not_found")
    profile = await db.scalar(select(EntityIntelligenceProfile).where(
        EntityIntelligenceProfile.entity_id == entity_id))
    return {"entity": {"id": entity.id, "type": entity.entity_type.value,
                        "display_value": entity.display_value,
                        "metadata": entity.entity_metadata},
            "profile": None if profile is None else {
                "partner_count": profile.partner_count, "transaction_count": profile.transaction_count,
                "report_count": profile.report_count, "linked_entity_count": profile.linked_entity_count,
                "activity_summary": profile.activity_summary, "ai_features": profile.ai_features,
                "graph_features": profile.graph_features, "fusion_version": profile.fusion_version,
                "risk_score": profile.risk_score,
                "risk_level": profile.risk_level.value, "risk_confidence": profile.risk_confidence,
                "risk_reasons": profile.risk_reasons, "computed_at": profile.computed_at}}


@router.get("/entities/{entity_id}/graph")
async def entity_graph(entity_id: UUID, db: DbDep, _reviewer: ReviewerUser,
                       limit: int = Query(100, ge=1, le=500)):
    entity = await db.get(CommunityEntity, entity_id)
    if entity is None:
        raise NotFoundError("Entity not found.", code="entity_not_found")
    rows = (await db.execute(select(EntityRelationship, CommunityEntity).join(
        CommunityEntity, ((CommunityEntity.id == EntityRelationship.target_entity_id)
                          & (EntityRelationship.source_entity_id == entity_id))
        | ((CommunityEntity.id == EntityRelationship.source_entity_id)
           & (EntityRelationship.target_entity_id == entity_id))
    ).limit(limit))).all()
    return {"entity_id": entity_id, "nodes": [{"id": entity.id, "type": entity.entity_type.value,
            "display_value": entity.display_value, "metadata": entity.entity_metadata}],
            "edges": [{"relationship_type": edge.relationship_type,
                "direction": "outgoing" if edge.source_entity_id == entity_id else "incoming",
                "confidence": edge.confidence, "metadata": edge.relationship_metadata,
                "node": {"id": neighbor.id, "type": neighbor.entity_type.value,
                         "display_value": neighbor.display_value, "metadata": neighbor.entity_metadata}}
                for edge, neighbor in rows]}


@router.get("/entities/{entity_id}/ledger")
async def entity_ledger_graph(
    entity_id: UUID,
    db: DbDep,
    _reviewer: ReviewerUser,
    depth: int = Query(2, ge=1, le=5),
    limit: int = Query(250, ge=1, le=500),
):
    """Chainalysis-style money graph: wallet nodes and directed PDR transfer edges."""
    entity = await db.get(CommunityEntity, entity_id)
    if entity is None:
        raise NotFoundError("Entity not found.", code="entity_not_found")
    graph = await collect_ledger_subgraph(db, [entity_id], depth=depth, edge_limit=limit)
    confirmed = await confirmed_fraud_entity_ids(db)
    exposure = await exposure_hop_count(db, entity_id, confirmed_entity_ids=confirmed)
    graph["entity_id"] = str(entity_id)
    graph["exposure"] = exposure
    graph["summary"] = {**(graph.get("summary") or {}), "confirmed_fraud_entity_count": len(confirmed)}
    return graph


@router.get("/entities/{entity_id}/collection")
async def entity_intelligence_collection(entity_id: UUID, db: DbDep, _reviewer: ReviewerUser):
    """Return the collected FIR/PDR records and investigation context for NEXUS."""
    collection = await collect_entity_intelligence(db, entity_id)
    if collection is None:
        raise NotFoundError("Entity not found.", code="entity_not_found")
    return collection


@router.get("/cross-institution-signals")
async def cross_institution_signals(db: DbDep, _reviewer: ReviewerUser,
                                    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    rows = (await db.scalars(select(CrossInstitutionSignal).where(
        CrossInstitutionSignal.status == "active").order_by(
            CrossInstitutionSignal.last_seen_at.desc()).offset(offset).limit(limit))).all()
    return {"items": [{"id": row.id, "signal_type": row.signal_type,
        "risk_level": row.risk_level.value, "score": row.score, "confidence": row.confidence,
        "partner_codes": row.partner_codes, "entity_ids": row.entity_ids,
        "reasons": row.reasons, "evidence": row.evidence,
        "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at}
        for row in rows], "limit": limit, "offset": offset}
