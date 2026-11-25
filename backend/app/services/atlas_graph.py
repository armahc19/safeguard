"""ATLAS graph primitives: scoped tables, node shaping, and relationship projection."""
from __future__ import annotations

from typing import Any

from sqlalchemy import String, and_, func, or_, select, tuple_

from app.models import Base, CommunityEntity, Partner, PartnerAccount, PartnerTransaction

PDR_TABLES = {
    "partners", "partner_submissions", "partner_identities", "partner_accounts",
    "partner_transactions", "identity_resolution_clusters", "identity_resolution_members",
    "partner_intelligence_deliveries", "liveness_challenges", "liveness_assessments",
    "cross_institution_signals",
}
SHARED_TABLES = {"community_entities", "entity_relationships", "entity_intelligence_profiles"}
FIR_TABLES = {
    "fraud_cases", "case_evidence", "case_feedback", "network_links", "fraud_reports",
    "community_reports", "fir_reports", "report_evidence", "fir_risk_assessments",
    "report_incidents", "report_entities", "incident_entities", "fraud_incidents",
    "intelligence_records", "incident_findings",
    "investigation_activities", "report_reviews", "threat_indicators", "verification_records",
    "risk_assessments", "shield_analyses", "call_analyses", "transaction_assessments",
    "phone_numbers", "scam_categories",
}
ATLAS_SCOPED_TABLES = FIR_TABLES | PDR_TABLES | SHARED_TABLES

ATLAS_TABLE_LOAD_ORDER: tuple[str, ...] = (
    "community_entities",
    "entity_relationships",
    *sorted(SHARED_TABLES - {"community_entities", "entity_relationships"}),
    "partners",
    *sorted(FIR_TABLES - {"community_entities", "entity_relationships"}),
    *sorted(PDR_TABLES - {"partners"}),
)

ATLAS_SEARCH_COLUMNS = {
    "id", "name", "title", "subject", "category", "report_type", "channel", "partner_code", "partner_name",
    "description",
    "partner_type", "signal_type", "status", "relation", "relationship_type", "entity_type",
    "display_value", "normalized_value", "account_type", "service_provider", "risk_level",
    "source", "decision", "finding_type", "outcome", "verification_status", "processing_status",
    "identity_reference", "account_identifier", "transaction_reference", "subject_value",
    "normalized_number", "phone_number_reference", "national_id_reference",
    "sender_account_reference", "receiver_account_reference",
}
ATLAS_SAFE_DETAILS = {
    "status", "account_status", "partner_status", "partner_type", "partner_code", "partner_name",
    "report_type", "channel", "category", "risk_level", "risk_score", "confidence", "decision",
    "verification_status", "verified_ownership", "relationship_type", "relation", "role", "source",
    "source_type", "signal_type", "finding_type", "outcome", "amount", "currency", "transaction_datetime",
    "incident_at", "created_at", "updated_at", "published_at", "received_at", "service_provider",
    "account_type", "processing_status", "schema_version", "entity_type", "resolution_status", "match_type",
    "model_version", "taxonomy_id", "partner_count", "transaction_count", "report_count",
    "linked_entity_count", "risk_confidence", "computed_at",
}


def atlas_source(table_name: str) -> str:
    if table_name in SHARED_TABLES:
        return "shared"
    if table_name in FIR_TABLES:
        return "fir"
    if table_name in PDR_TABLES:
        return "pdr"
    return "shared"


def atlas_record(table_name: str, values: dict) -> dict:
    table = Base.metadata.tables[table_name]
    record_id = str(values.get("id", "unknown"))
    source = atlas_source(table_name)
    origin = source
    if table_name == "community_entities":
        metadata = values.get("entity_metadata") or {}
        declared_origin = metadata.get("source") if isinstance(metadata, dict) else None
        if declared_origin in {"fir", "pdr"}:
            origin = declared_origin
        elif str(values.get("normalized_value", "")).startswith("pdr-"):
            origin = "pdr"
    label_value = next((values.get(key) for key in (
        "partner_name", "title", "display_value", "name", "report_type", "category", "signal_type",
        "relationship_type", "finding_type", "account_type", "entity_type", "status",
    ) if values.get(key)), record_id[:10])
    if table_name == "entity_intelligence_profiles":
        risk_level = getattr(values.get("risk_level"), "value", values.get("risk_level")) or "unknown"
        risk_score = values.get("risk_score")
        label_value = f"{risk_level} risk · {risk_score if risk_score is not None else 'unscored'}"
    entity_type = getattr(values.get("entity_type"), "value", values.get("entity_type"))
    if table_name == "community_entities" and str(entity_type).lower() == "phone":
        digits = "".join(character for character in str(label_value) if character.isdigit())
        label_value = f"••••{digits[-4:]}" if digits else "Protected phone reference"
    details = {}
    for key in ATLAS_SAFE_DETAILS:
        value = values.get(key)
        if value is not None and key in table.c:
            value = getattr(value, "value", value)
            details[key] = value.isoformat() if hasattr(value, "isoformat") else str(value)
    verified = values.get("verification_status")
    if verified is None and "verified_ownership" in values:
        verified = "verified" if values["verified_ownership"] else "unverified"
    return {
        "id": f"{source}.{table_name}:{record_id}",
        "type": table_name,
        "label": f"{table_name.replace('_', ' ')} · {label_value}"[:110],
        "source": source,
        "origin_repository": origin,
        "table": table_name,
        "record_id": record_id,
        "verification_status": str(getattr(verified, "value", verified) or "source_record"),
        "details": details,
    }


async def atlas_transaction_accounts(db, transaction_values: dict) -> list[tuple[str, PartnerAccount]]:
    matches = []
    for direction in ("sender", "receiver"):
        partner_code = transaction_values.get(f"{direction}_partner_code")
        account_reference = transaction_values.get(f"{direction}_account_reference")
        if not partner_code or not account_reference:
            continue
        account = await db.scalar(select(PartnerAccount).join(
            Partner, Partner.id == PartnerAccount.partner_id
        ).where(
            Partner.partner_code == partner_code,
            PartnerAccount.account_identifier == account_reference,
        ).limit(1))
        if account is not None:
            matches.append((direction, account))
    return matches


def atlas_semantic_relationships(raw_rows: dict[str, dict[str, dict]], nodes: dict[str, dict]) -> list[dict]:
    links = []
    tables = Base.metadata.tables
    for table_name, records in raw_rows.items():
        table = tables[table_name]
        for values in records.values():
            refs = []
            for column in table.columns:
                if not column.foreign_keys:
                    continue
                target_id = values.get(column.name)
                target_name = next(iter(column.foreign_keys)).column.table.name
                node_id = f"{atlas_source(target_name)}.{target_name}:{target_id}" if target_id is not None else None
                if node_id in nodes:
                    refs.append((node_id, column.name))
            if len(refs) < 2:
                continue
            relation = next((values.get(field) for field in (
                "relationship_type", "role", "relation", "decision", "finding_type",
            ) if values.get(field)), table_name.replace("_", " "))
            relation = getattr(relation, "value", relation)
            confidence = values.get("confidence")
            try:
                confidence = float(confidence) if confidence is not None else None
            except (TypeError, ValueError):
                confidence = None
            verification = values.get("verification_status")
            if verification is None:
                verification = "confidence_scored_relationship" if confidence is not None else "source_relationship_record"
            else:
                verification = getattr(verification, "value", verification)
            for index, (left_id, left_column) in enumerate(refs):
                for right_id, right_column in refs[index + 1:]:
                    if left_id == right_id:
                        continue
                    links.append({
                        "source": left_id, "target": right_id, "relationship": str(relation),
                        "confidence": confidence, "repository": atlas_source(table_name),
                        "source_table": table_name, "source_record_id": str(values["id"]),
                        "verification_status": str(verification),
                        "source_field": left_column, "target_field": right_column,
                    })
    return links


def atlas_filter_statements(table, table_name: str, *, risk_level: str | None, verification_status: str | None,
                            date_from: str | None, date_to: str | None, escaped: str | None,
                            record_ids: set[str] | None = None):
    """Return (statement_filters_ok, conditions_list, fail_reason). fail_reason='skip' means table has zero matches."""
    search_conditions = [
        table.c[column].cast(String).ilike(f"%{escaped}%", escape="\\")
        for column in ATLAS_SEARCH_COLUMNS if column in table.c
    ] if escaped else []
    if record_ids and "id" in table.c:
        search_conditions.append(table.c.id.cast(String).in_(record_ids))
    if escaped and not search_conditions:
        return False, [], "skip"
    conditions = [or_(*search_conditions)] if search_conditions else []
    table_filters: list[Any] = []
    if risk_level:
        if "risk_level" not in table.c:
            return False, [], "skip"
        table_filters.append(table.c.risk_level.cast(String).ilike(risk_level))
    if verification_status:
        if verification_status == "source_record":
            source_record_conditions = []
            if "verification_status" in table.c:
                source_record_conditions.append(or_(
                    table.c.verification_status.is_(None),
                    table.c.verification_status.cast(String).ilike("source_record"),
                ))
            if "resolution_status" in table.c:
                source_record_conditions.append(table.c.resolution_status.is_(None))
            if "verified_ownership" in table.c:
                source_record_conditions.append(table.c.verified_ownership.is_(None))
            if source_record_conditions:
                table_filters.append(and_(*source_record_conditions))
        else:
            verification_conditions = []
            if "verification_status" in table.c:
                verification_conditions.append(table.c.verification_status.cast(String).ilike(verification_status))
            if "resolution_status" in table.c and verification_status in {"resolved", "candidate"}:
                verification_conditions.append(table.c.resolution_status.cast(String).ilike(verification_status))
            if "verified_ownership" in table.c and verification_status in {"verified", "unverified"}:
                verification_conditions.append(table.c.verified_ownership.is_(verification_status == "verified"))
            if not verification_conditions:
                return False, [], "skip"
            table_filters.append(or_(*verification_conditions))
    date_column_name = next((column for column in (
        "transaction_datetime", "incident_at", "assessed_at", "published_at", "received_at",
        "observed_at", "registration_datetime", "created_at", "updated_at",
    ) if column in table.c), None)
    if date_from or date_to:
        if not date_column_name:
            return False, [], "skip"
        date_column = table.c[date_column_name].cast(String)
        if date_from:
            table_filters.append(date_column >= date_from)
        if date_to:
            upper_date = f"{date_to}T23:59:59.999999" if len(date_to) == 10 else date_to
            table_filters.append(date_column <= upper_date)
    return True, conditions + table_filters, None


def atlas_row_matches_search(
    table_name: str,
    values: dict,
    *,
    escaped: str | None,
    record_ids: set[str] | None = None,
) -> bool:
    """True when a row matches the active ATLAS text/ID search (for jump/highlight)."""
    if record_ids and str(values.get("id")) in record_ids:
        return True
    if not escaped:
        return False
    table = Base.metadata.tables.get(table_name)
    if table is None:
        return False
    needle = escaped.casefold()
    for column in ATLAS_SEARCH_COLUMNS:
        if column not in table.c:
            continue
        raw = values.get(column)
        if raw is None:
            continue
        raw = getattr(raw, "value", raw)
        if hasattr(raw, "isoformat"):
            raw = raw.isoformat()
        if needle in str(raw).casefold():
            return True
    return False


async def atlas_attach_foreign_keys(
    db,
    raw_rows: dict[str, dict[str, dict]],
    nodes: dict[str, dict],
    edges: dict[tuple[str, str, str], dict],
    *,
    fetch_budget: int,
) -> None:
    tables = Base.metadata.tables
    # Referenced source rows are added to raw_rows below; iterate over a
    # snapshot so resolving a foreign key cannot invalidate this traversal.
    for child_name, rows in list(raw_rows.items()):
        child_table = tables[child_name]
        for column in child_table.columns:
            for foreign_key in column.foreign_keys:
                target_table = foreign_key.column.table
                target_name = target_table.name
                if target_name not in ATLAS_SCOPED_TABLES or "id" not in target_table.c:
                    continue
                target_ids = {
                    str(values[column.name]) for values in rows.values()
                    if values.get(column.name) is not None
                }
                if not target_ids:
                    continue
                referenced = (await db.execute(select(target_table).where(
                    target_table.c.id.cast(String).in_(target_ids)
                ).limit(fetch_budget))).mappings().all()
                for target_row in referenced:
                    target_node = atlas_record(target_name, dict(target_row))
                    nodes.setdefault(target_node["id"], target_node)
                    raw_rows.setdefault(target_name, {}).setdefault(target_node["record_id"], dict(target_row))
                for values in rows.values():
                    target_id = values.get(column.name)
                    if target_id is None:
                        continue
                    source_id = f"{atlas_source(child_name)}.{child_name}:{values['id']}"
                    destination_id = f"{atlas_source(target_name)}.{target_name}:{target_id}"
                    key = (source_id, destination_id, column.name)
                    edges[key] = {
                        "source": source_id, "target": destination_id,
                        "relationship": column.name.removesuffix("_id").replace("_", " "),
                        "confidence": 1.0, "repository": atlas_source(child_name),
                        "source_table": child_name, "source_record_id": str(values["id"]),
                        "verification_status": "database_foreign_key",
                    }


async def atlas_attach_pdr_projections(
    db,
    raw_rows: dict[str, dict[str, dict]],
    nodes: dict[str, dict],
    edges: dict[tuple[str, str, str], dict],
    partner_codes: dict[str, str],
) -> None:
    projection_rows: list[tuple[str, str, str, dict]] = []
    for pdr_table, key_kind, value_column in (
        ("partner_identities", "pdr-identity", "identity_reference"),
        ("partner_accounts", "pdr-account", "account_identifier"),
    ):
        for values in raw_rows.get(pdr_table, {}).values():
            partner_code = partner_codes.get(str(values.get("partner_id")))
            if not partner_code or not values.get(value_column):
                continue
            normalized_key = f"{key_kind}:{partner_code}:{values[value_column]}"
            projection_rows.append((pdr_table, normalized_key, str(values["id"]), values))

    projection_keys = list(dict.fromkeys(row[1] for row in projection_rows))
    projected_entities: dict[str, CommunityEntity] = {}
    for start in range(0, len(projection_keys), 500):
        batch = projection_keys[start:start + 500]
        found = (await db.scalars(select(CommunityEntity).where(
            CommunityEntity.normalized_value.in_(batch)
        ))).all()
        projected_entities.update({entity.normalized_value: entity for entity in found})

    for pdr_table, normalized_key, record_id, _values in projection_rows:
        entity = projected_entities.get(normalized_key)
        if entity is None:
            continue
        entity_values = {column.name: getattr(entity, column.name) for column in CommunityEntity.__table__.columns}
        entity_node = atlas_record("community_entities", entity_values)
        nodes.setdefault(entity_node["id"], entity_node)
        raw_rows.setdefault("community_entities", {}).setdefault(entity_node["record_id"], entity_values)
        pdr_node_id = f"pdr.{pdr_table}:{record_id}"
        edge_key = (pdr_node_id, entity_node["id"], "projected_entity")
        edges[edge_key] = {
            "source": pdr_node_id, "target": entity_node["id"],
            "relationship": "projected entity", "confidence": 1.0,
            "repository": "shared", "source_table": pdr_table,
            "source_record_id": record_id,
            "verification_status": "exact_projection_key",
        }


async def atlas_attach_transaction_links(
    db,
    raw_rows: dict[str, dict[str, dict]],
    nodes: dict[str, dict],
    edges: dict[tuple[str, str, str], dict],
) -> None:
    transaction_rows = list(raw_rows.get("partner_transactions", {}).values())
    account_keys = list(dict.fromkeys(
        (str(values.get(f"{direction}_partner_code") or ""),
         str(values.get(f"{direction}_account_reference") or ""))
        for values in transaction_rows for direction in ("sender", "receiver")
        if values.get(f"{direction}_partner_code") and values.get(f"{direction}_account_reference")
    ))
    accounts_by_key: dict[tuple[str, str], PartnerAccount] = {}
    for start in range(0, len(account_keys), 500):
        batch = account_keys[start:start + 500]
        rows = (await db.execute(select(Partner.partner_code, PartnerAccount).join(
            PartnerAccount, PartnerAccount.partner_id == Partner.id
        ).where(tuple_(Partner.partner_code, PartnerAccount.account_identifier).in_(batch)))).all()
        accounts_by_key.update({(str(partner_code), account.account_identifier): account
                                for partner_code, account in rows})

    for values in transaction_rows:
        transaction_id = f"pdr.partner_transactions:{values['id']}"
        for direction in ("sender", "receiver"):
            account_key = (str(values.get(f"{direction}_partner_code") or ""),
                           str(values.get(f"{direction}_account_reference") or ""))
            account = accounts_by_key.get(account_key)
            if account is None:
                continue
            account_values = {column.name: getattr(account, column.name)
                              for column in PartnerAccount.__table__.columns}
            account_node = atlas_record("partner_accounts", account_values)
            nodes.setdefault(account_node["id"], account_node)
            raw_rows.setdefault("partner_accounts", {}).setdefault(account_node["record_id"], account_values)
            source_id, target_id = (
                (account_node["id"], transaction_id)
                if direction == "sender" else (transaction_id, account_node["id"])
            )
            relation = "sent transaction" if direction == "sender" else "received by account"
            edge_key = (source_id, target_id, relation)
            edges[edge_key] = {
                "source": source_id, "target": target_id,
                "relationship": relation, "confidence": 1.0,
                "directed": True,
                "repository": "pdr", "source_table": "partner_transactions",
                "source_record_id": str(values["id"]),
                "verification_status": "exact_partner_scoped_reference",
            }


def atlas_attach_entity_relationships(
    raw_rows: dict[str, dict[str, dict]],
    nodes: dict[str, dict],
    edges: dict[tuple[str, str, str], dict],
) -> None:
    for values in raw_rows.get("entity_relationships", {}).values():
        source_id = values.get("source_entity_id")
        target_id = values.get("target_entity_id")
        if not source_id or not target_id:
            continue
        src = f"shared.community_entities:{source_id}"
        tgt = f"shared.community_entities:{target_id}"
        rel_type = getattr(values.get("relationship_type"), "value", values.get("relationship_type")) or "linked"
        confidence = values.get("confidence")
        try:
            confidence = float(confidence) if confidence is not None else 1.0
        except (TypeError, ValueError):
            confidence = 1.0
        if src in nodes and tgt in nodes:
            key = (src, tgt, f"entity_relationship:{values['id']}")
            edges[key] = {
                "source": src, "target": tgt, "relationship": str(rel_type),
                "confidence": confidence, "repository": "shared",
                "source_table": "entity_relationships", "source_record_id": str(values["id"]),
                "verification_status": "intelligence_relationship",
            }
