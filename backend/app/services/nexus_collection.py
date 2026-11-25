"""Collect the FIR, PDR, graph and investigation context around a NEXUS entity."""
from __future__ import annotations

from collections import defaultdict, deque
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    CaseEvidence,
    CommunityEntity,
    CrossInstitutionSignal,
    EntityIntelligenceProfile,
    EntityRelationship,
    FIRReportIncident,
    FIRReportRecord,
    FIRRiskAssessment,
    FraudCase,
    FraudIncident,
    IdentityResolutionCluster,
    IdentityResolutionMember,
    IncidentEntity,
    IncidentFinding,
    InvestigationActivity,
    Partner,
    PartnerAccount,
    PartnerIdentity,
    PartnerTransaction,
    ReportEntity,
    ReportEvidence,
)


async def collect_entity_intelligence(db: AsyncSession, entity_id: UUID) -> dict:
    entity = await db.get(CommunityEntity, entity_id)
    if entity is None:
        return None

    nodes = {entity.id: entity}
    edge_map = {}
    frontier = {entity.id}
    for _depth in range(4):
        if not frontier or len(nodes) >= 400:
            break
        frontier_ids = list(frontier)
        relations = (await db.scalars(select(EntityRelationship).where(or_(
            EntityRelationship.source_entity_id.in_(frontier_ids),
            EntityRelationship.target_entity_id.in_(frontier_ids),
        )).limit(500))).all()
        related_ids = set()
        for relation in relations:
            edge_map[relation.id] = relation
            if relation.source_entity_id in frontier:
                related_ids.add(relation.target_entity_id)
            if relation.target_entity_id in frontier:
                related_ids.add(relation.source_entity_id)
        new_ids = related_ids.difference(nodes)
        if len(nodes) + len(new_ids) > 400:
            new_ids = set(list(new_ids)[:400 - len(nodes)])
        new_nodes = (await db.scalars(select(CommunityEntity).where(
            CommunityEntity.id.in_(new_ids)))).all() if new_ids else []
        nodes.update({row.id: row for row in new_nodes})
        frontier = {row.id for row in new_nodes
            if not (row.entity_type.value == "organization" and row.entity_metadata.get("source") == "pdr")}

    edges = [{"source_entity_id": str(row.source_entity_id),
        "target_entity_id": str(row.target_entity_id),
        "relationship_type": row.relationship_type,
        "confidence": row.confidence,
        "metadata": row.relationship_metadata}
        for row in edge_map.values() if row.source_entity_id in nodes and row.target_entity_id in nodes]
    entity_ids = list(nodes)
    entity_id_strings = {str(value) for value in entity_ids}

    profile = await db.scalar(select(EntityIntelligenceProfile).where(
        EntityIntelligenceProfile.entity_id == entity_id))
    report_links = (await db.execute(select(ReportEntity, CommunityEntity).join(
        CommunityEntity, CommunityEntity.id == ReportEntity.entity_id
    ).where(ReportEntity.entity_id.in_(entity_ids)).order_by(ReportEntity.created_at.desc()))).all()
    report_ids = {link.report_id for link, _ in report_links}
    report_incident_rows = (await db.execute(select(FIRReportIncident, FraudIncident).join(
        FraudIncident, FraudIncident.id == FIRReportIncident.incident_id
    ).where(FIRReportIncident.report_id.in_(report_ids)))).all() if report_ids else []
    incident_map = {incident.id: incident for _, incident in report_incident_rows}
    incident_ids = set(incident_map)
    directly_linked_incidents = (await db.scalars(select(FraudIncident).join(
        IncidentEntity, IncidentEntity.incident_id == FraudIncident.id
    ).where(IncidentEntity.entity_id.in_(entity_ids)))).all()
    incident_map.update({row.id: row for row in directly_linked_incidents})
    incident_ids.update(row.id for row in directly_linked_incidents)
    if incident_ids:
        incident_report_rows = (await db.execute(select(FIRReportIncident, FraudIncident).join(
            FraudIncident, FraudIncident.id == FIRReportIncident.incident_id
        ).where(FIRReportIncident.incident_id.in_(incident_ids)))).all()
        report_incident_rows = list({link.id: (link, incident)
            for link, incident in [*report_incident_rows, *incident_report_rows]}.values())
        report_ids.update(link.report_id for link, _ in incident_report_rows)

    reports = (await db.scalars(select(FIRReportRecord).where(
        FIRReportRecord.id.in_(report_ids)).order_by(FIRReportRecord.created_at.desc()).limit(200))).all() if report_ids else []
    reports_by_id = {row.id: row for row in reports}
    all_report_links = (await db.execute(select(ReportEntity, CommunityEntity).join(
        CommunityEntity, CommunityEntity.id == ReportEntity.entity_id
    ).where(ReportEntity.report_id.in_(report_ids)).order_by(ReportEntity.created_at.desc()))).all() if report_ids else []
    extracted_by_report: dict[UUID, list[dict]] = {}
    for link, linked_entity in all_report_links:
        if link.report_id not in reports_by_id:
            continue
        extracted_by_report.setdefault(link.report_id, []).append({
            "entity_id": str(linked_entity.id), "entity_type": linked_entity.entity_type.value,
            "display_value": linked_entity.display_value or linked_entity.normalized_value,
            "source_kind": link.source_kind, "confidence": link.confidence,
            "verified": link.verified,
        })
    report_items = [{"id": str(row.id), "subject": row.subject,
        "report_type": row.report_type, "channel": row.channel, "status": row.status,
        "category": row.category, "description": row.description, "source": row.source,
        "created_at": row.created_at.isoformat(), "case_id": str(row.case_id) if row.case_id else None,
        "extracted_entities": extracted_by_report.get(row.id, [])} for row in reports]

    incident_entity_rows = (await db.execute(select(IncidentEntity, CommunityEntity).join(
        CommunityEntity, CommunityEntity.id == IncidentEntity.entity_id
    ).where(IncidentEntity.incident_id.in_(incident_ids)))).all() if incident_ids else []
    incident_entities: dict[UUID, list[dict]] = {}
    for link, linked_entity in incident_entity_rows:
        incident_entities.setdefault(link.incident_id, []).append({
            "entity_id": str(linked_entity.id), "entity_type": linked_entity.entity_type.value,
            "display_value": linked_entity.display_value or linked_entity.normalized_value,
            "role": link.role, "confidence": link.confidence,
            "verification_status": link.verification_status,
        })
    incident_reports: dict[UUID, list[str]] = {}
    for report_link, incident in report_incident_rows:
        incident_reports.setdefault(incident.id, []).append(str(report_link.report_id))
    incidents = [{"id": str(row.id), "title": row.title, "description": row.description,
        "category": row.category, "status": row.status.value, "outcome": row.outcome.value,
        "risk_level": row.risk_level.value, "confidence": row.confidence,
        "incident_at": row.incident_at.isoformat() if row.incident_at else None,
        "location": row.location, "report_ids": incident_reports.get(row.id, []),
        "entities": incident_entities.get(row.id, [])} for row in incident_map.values()]

    findings = (await db.scalars(select(IncidentFinding).where(or_(
        IncidentFinding.report_id.in_(report_ids) if report_ids else False,
        IncidentFinding.incident_id.in_(incident_ids) if incident_ids else False,
    )).order_by(IncidentFinding.created_at.desc()).limit(200))).all() if (report_ids or incident_ids) else []
    risk_rows = (await db.scalars(select(FIRRiskAssessment).where(or_(
        FIRRiskAssessment.report_id.in_(report_ids) if report_ids else False,
        FIRRiskAssessment.incident_id.in_(incident_ids) if incident_ids else False,
    )).order_by(FIRRiskAssessment.created_at.desc()).limit(200))).all() if (report_ids or incident_ids) else []
    finding_items = [{"id": str(row.id), "report_id": str(row.report_id) if row.report_id else None,
        "incident_id": str(row.incident_id), "type": row.finding_type, "title": row.title,
        "description": row.description, "taxonomy_id": row.taxonomy_id,
        "confidence": row.confidence, "source": row.source, "model_version": row.model_version,
        "evidence": row.evidence, "created_at": row.created_at.isoformat()} for row in findings]
    risk_items = [{"id": str(row.id), "report_id": str(row.report_id) if row.report_id else None,
        "incident_id": str(row.incident_id) if row.incident_id else None,
        "level": row.risk_level.value, "score": row.risk_score, "confidence": row.confidence,
        "reasons": row.reasons, "source": row.source, "model_version": row.model_version,
        "created_at": row.created_at.isoformat()} for row in risk_rows]

    community_report_ids = [row.community_report_id for row in reports if row.community_report_id]
    report_evidence = (await db.scalars(select(ReportEvidence).where(
        ReportEvidence.report_id.in_(community_report_ids)).order_by(ReportEvidence.created_at.desc()).limit(200)
    )).all() if community_report_ids else []
    evidence_items = [{"id": str(row.id), "kind": row.evidence_type, "source": "FIR report",
        "reference": row.storage_reference, "content_hash": row.content_hash,
        "metadata": row.evidence_metadata, "created_at": row.created_at.isoformat()} for row in report_evidence]
    for row in reports:
        if row.evidence_reference:
            evidence_items.append({"id": f"report-reference:{row.id}", "kind": "report_reference",
                "source": "FIR", "reference": row.evidence_reference, "content_hash": None,
                "metadata": {"report_id": str(row.id)}, "created_at": row.created_at.isoformat()})

    account_graph_keys: dict[tuple[str, str], UUID] = {}
    identity_graph_keys: dict[tuple[str, str], UUID] = {}
    protected_phone_keys: set[str] = set()
    cluster_graph_keys: set[tuple[str, str]] = set()
    for node in nodes.values():
        normalized = node.normalized_value
        if normalized.startswith("pdr-account:"):
            _, code, account_ref = normalized.split(":", 2)
            account_graph_keys[(code, account_ref)] = node.id
        elif normalized.startswith("pdr-identity:"):
            _, code, identity_ref = normalized.split(":", 2)
            identity_graph_keys[(code, identity_ref)] = node.id
        elif normalized.startswith("pdr-phone:"):
            protected_phone_keys.add(normalized.removeprefix("pdr-phone:"))
        elif normalized.startswith("identity-cluster:"):
            _, match_type, match_key = normalized.split(":", 2)
            cluster_graph_keys.add((match_type, match_key))

    partner_codes = {code for code, _ in [*account_graph_keys, *identity_graph_keys]}
    partners = (await db.scalars(select(Partner).where(Partner.partner_code.in_(partner_codes)))).all() if partner_codes else []
    partner_by_code = {row.partner_code: row for row in partners}
    account_conditions = [and_(PartnerAccount.partner_id == partner_by_code[code].id,
        PartnerAccount.account_identifier == account_ref) for code, account_ref in account_graph_keys
        if code in partner_by_code]
    account_rows = (await db.execute(select(PartnerAccount, Partner).join(
        Partner, Partner.id == PartnerAccount.partner_id).where(or_(*account_conditions)))).all() if account_conditions else []
    account_id_to_entity: dict[UUID, UUID] = {}
    account_items = []
    for account, partner in account_rows:
        graph_id = account_graph_keys.get((partner.partner_code, account.account_identifier))
        if graph_id:
            account_id_to_entity[account.id] = graph_id
        account_items.append(account)
    account_ids = list(account_id_to_entity)
    transaction_rows = (await db.execute(select(PartnerTransaction).where(or_(
        PartnerTransaction.sender_account_id.in_(account_ids),
        PartnerTransaction.receiver_account_id.in_(account_ids),
    )).order_by(PartnerTransaction.transaction_datetime.desc()).limit(200))).scalars().all() if account_ids else []
    transactions = [{"id": str(row.id), "sender_entity_id": str(account_id_to_entity[row.sender_account_id]) if row.sender_account_id in account_id_to_entity else None,
        "receiver_entity_id": str(account_id_to_entity[row.receiver_account_id]) if row.receiver_account_id in account_id_to_entity else None,
        "sender_partner": row.sender_partner_code, "receiver_partner": row.receiver_partner_code,
        "amount": str(row.amount), "currency": row.currency, "status": row.transaction_status,
        "timestamp": row.transaction_datetime.isoformat()} for row in transaction_rows]

    identity_conditions = [and_(PartnerIdentity.partner_id == partner_by_code[code].id,
        PartnerIdentity.identity_reference == reference) for code, reference in identity_graph_keys
        if code in partner_by_code]
    if protected_phone_keys:
        identity_conditions.append(PartnerIdentity.phone_number_reference.in_(protected_phone_keys))
    identity_rows = (await db.scalars(select(PartnerIdentity).where(or_(*identity_conditions)))).all() if identity_conditions else []
    identity_ids = {row.id for row in identity_rows}
    member_rows = (await db.execute(select(IdentityResolutionMember, IdentityResolutionCluster,
        PartnerIdentity, Partner).join(IdentityResolutionCluster,
        IdentityResolutionCluster.id == IdentityResolutionMember.cluster_id).join(
        PartnerIdentity, PartnerIdentity.id == IdentityResolutionMember.partner_identity_id).join(
        Partner, Partner.id == PartnerIdentity.partner_id).where(
            IdentityResolutionMember.partner_identity_id.in_(identity_ids)
        ))).all() if identity_ids else []
    direct_clusters = (await db.scalars(select(IdentityResolutionCluster).where(or_(*[
        and_(IdentityResolutionCluster.match_type == match_type,
             IdentityResolutionCluster.match_key == match_key)
        for match_type, match_key in cluster_graph_keys
    ])))).all() if cluster_graph_keys else []
    cluster_map: dict[UUID, dict] = {}
    for cluster in direct_clusters:
        cluster_map[cluster.id] = {"id": str(cluster.id), "match_type": cluster.match_type,
            "status": cluster.resolution_status, "confidence": cluster.confidence,
            "partner_count": cluster.partner_count, "identity_count": cluster.identity_count,
            "members": []}
    for member, cluster, identity, partner in member_rows:
        item = cluster_map.setdefault(cluster.id, {"id": str(cluster.id),
            "match_type": cluster.match_type, "status": cluster.resolution_status,
            "confidence": cluster.confidence, "partner_count": cluster.partner_count,
            "identity_count": cluster.identity_count, "members": []})
        item["members"].append({"partner": partner.partner_name,
            "verification_status": identity.verification_status,
            "verified_ownership": identity.verified_ownership,
            "member_confidence": member.confidence})
    clusters = list(cluster_map.values())

    signal_conditions = [CrossInstitutionSignal.entity_ids.contains([entity_value])
                         for entity_value in entity_id_strings]
    signals = (await db.scalars(select(CrossInstitutionSignal).where(
        CrossInstitutionSignal.status == "active", or_(*signal_conditions)).order_by(
            CrossInstitutionSignal.last_seen_at.desc()).limit(200))).all() if signal_conditions else []
    signal_items = [{"id": str(row.id), "type": row.signal_type,
        "risk_level": row.risk_level.value, "score": row.score, "confidence": row.confidence,
        "partner_codes": row.partner_codes, "reasons": row.reasons,
        "evidence": row.evidence, "last_seen_at": row.last_seen_at.isoformat()}
        for row in signals]

    # Explainable relationship findings derived only from the already collected FIR/PDR rows.
    reports_by_entity: dict[UUID, set[UUID]] = defaultdict(set)
    entities_by_id = {linked_entity.id: linked_entity for _, linked_entity in all_report_links}
    for report_link, linked_entity in all_report_links:
        reports_by_entity[linked_entity.id].add(report_link.report_id)
    shared_identifiers = [{"entity_id": str(entity_id),
        "entity_type": entities_by_id[entity_id].entity_type.value,
        "display_value": entities_by_id[entity_id].display_value or
            (f"Protected {entities_by_id[entity_id].entity_type.value} reference"
             if entities_by_id[entity_id].entity_metadata.get("source") == "pdr"
             else f"{entities_by_id[entity_id].entity_type.value.title()} entity"),
        "report_count": len(linked_reports), "report_ids": [str(value) for value in sorted(linked_reports, key=str)]}
        for entity_id, linked_reports in reports_by_entity.items() if len(linked_reports) > 1]
    shared_identifiers.sort(key=lambda row: (-row["report_count"], row["entity_type"], row["display_value"]))

    pair_transactions: dict[tuple[str, str], list[dict]] = defaultdict(list)
    transaction_adjacency: dict[str, list[dict]] = defaultdict(list)
    cross_institution_transactions = []
    for transaction in transactions:
        sender = transaction["sender_entity_id"]
        receiver = transaction["receiver_entity_id"]
        if sender and receiver:
            pair_transactions[(sender, receiver)].append(transaction)
            transaction_adjacency[sender].append(transaction)
        if transaction["sender_partner"] != transaction["receiver_partner"]:
            cross_institution_transactions.append(transaction)
    repeated_counterparties = [{"sender_entity_id": sender, "receiver_entity_id": receiver,
        "transaction_count": len(rows),
        "partner_routes": sorted({f"{row['sender_partner']} → {row['receiver_partner']}" for row in rows}),
        "transaction_ids": [row["id"] for row in rows],
        "statuses": sorted({row["status"] for row in rows})}
        for (sender, receiver), rows in pair_transactions.items() if len(rows) > 1]
    repeated_counterparties.sort(key=lambda row: (-row["transaction_count"], row["sender_entity_id"], row["receiver_entity_id"]))

    # Start transaction-path traversal at the selected account, or account nodes
    # within two relationship hops when the selected item is a person/phone/etc.
    account_entity_ids = {str(value) for value in account_id_to_entity.values()}
    relationship_adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        relationship_adjacency[edge["source_entity_id"]].add(edge["target_entity_id"])
        relationship_adjacency[edge["target_entity_id"]].add(edge["source_entity_id"])
    start_accounts = []
    if str(entity_id) in account_entity_ids:
        start_accounts = [str(entity_id)]
    else:
        seen = {str(entity_id)}
        queue = deque([(str(entity_id), 0)])
        while queue and len(start_accounts) < 5:
            current, depth = queue.popleft()
            if current in account_entity_ids:
                start_accounts.append(current)
            if depth >= 2:
                continue
            for neighbor in relationship_adjacency.get(current, ()):
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append((neighbor, depth + 1))
    transaction_paths = []
    for start_id in start_accounts:
        path_queue = deque([(start_id, [start_id], [])])
        while path_queue and len(transaction_paths) < 25:
            current, path_entities, path_transactions = path_queue.popleft()
            if len(path_transactions) >= 4:
                continue
            for transaction in transaction_adjacency.get(current, ()):
                next_id = transaction["receiver_entity_id"]
                if not next_id or next_id in path_entities:
                    continue
                next_entities = [*path_entities, next_id]
                next_transactions = [*path_transactions, transaction]
                transaction_paths.append({"start_entity_id": start_id, "end_entity_id": next_id,
                    "entity_ids": next_entities, "transaction_ids": [row["id"] for row in next_transactions],
                    "hop_count": len(next_transactions),
                    "partner_routes": [f"{row['sender_partner']} → {row['receiver_partner']}" for row in next_transactions],
                    "statuses": [row["status"] for row in next_transactions]})
                path_queue.append((next_id, next_entities, next_transactions))
                if len(transaction_paths) >= 25:
                    break
    cross_provider_identity_clusters = [cluster for cluster in clusters if cluster["partner_count"] > 1]
    relationship_type_counts: dict[str, int] = defaultdict(int)
    for edge in edges:
        relationship_type_counts[edge["relationship_type"]] += 1
    relationship_analysis = {
        "method": "Descriptive rules over the collected FIR/PDR records; findings are leads for review, not fraud determinations.",
        "summary": {"shared_identifiers": len(shared_identifiers),
            "repeated_counterparty_pairs": len(repeated_counterparties),
            "cross_institution_transactions": len(cross_institution_transactions),
            "cross_provider_identity_clusters": len(cross_provider_identity_clusters),
            "transaction_paths": len(transaction_paths), "graph_relationships": len(edges)},
        "shared_identifiers": shared_identifiers[:100],
        "repeated_counterparties": repeated_counterparties[:100],
        "cross_institution_transactions": cross_institution_transactions[:100],
        "cross_provider_identity_clusters": cross_provider_identity_clusters[:100],
        "transaction_paths": transaction_paths,
        "relationship_type_counts": dict(relationship_type_counts),
        "analysis_scope": {"transaction_rows_considered": len(transactions),
            "transaction_path_max_hops": 4, "transaction_path_limit": 25,
            "collected_graph_hops": 4, "graph_entity_limit": 400},
    }

    report_case_ids = {row.case_id for row in reports if row.case_id}
    pdr_record_ids = [row.id for row in account_items] + [row.id for row in identity_rows] + [row.id for row in transaction_rows]
    case_evidence_query = select(CaseEvidence).where(or_(
        CaseEvidence.details["entity_id"].as_string().in_(entity_id_strings),
        CaseEvidence.details["source_record_id"].as_string().in_({str(value) for value in pdr_record_ids}),
        CaseEvidence.case_id.in_(report_case_ids) if report_case_ids else False,
    )) if entity_id_strings else select(CaseEvidence).where(CaseEvidence.case_id.in_(report_case_ids))
    case_evidence = (await db.scalars(case_evidence_query.order_by(CaseEvidence.observed_at.desc()).limit(300))).all()
    case_ids = report_case_ids | {row.case_id for row in case_evidence}
    case_rows = (await db.scalars(select(FraudCase).where(FraudCase.id.in_(case_ids))
        .order_by(FraudCase.updated_at.desc()))).all() if case_ids else []
    cases = [{"id": str(row.id), "title": row.title, "summary": row.summary,
        "status": row.status.value, "assigned_investigator_id": str(row.assigned_investigator_id) if row.assigned_investigator_id else None,
        "created_at": row.created_at.isoformat(), "updated_at": row.updated_at.isoformat(),
        "evidence_count": sum(1 for evidence in case_evidence if evidence.case_id == row.id)} for row in case_rows]
    evidence_items.extend({"id": str(row.id), "kind": row.evidence_type.value,
        "source": row.source, "reference": row.value, "content_hash": None,
        "metadata": row.details, "case_id": str(row.case_id), "created_at": row.created_at.isoformat()}
        for row in case_evidence)

    activities = (await db.scalars(select(InvestigationActivity).where(
        InvestigationActivity.incident_id.in_(incident_ids)).order_by(
            InvestigationActivity.created_at.desc()).limit(200))).all() if incident_ids else []
    activity_items = [{"id": str(row.id), "incident_id": str(row.incident_id),
        "action_type": row.action_type, "summary": row.summary,
        "details": row.details, "created_at": row.created_at.isoformat()} for row in activities]

    return {"entity": {"id": str(entity.id), "type": entity.entity_type.value,
        "display_value": entity.display_value or entity.normalized_value,
        "metadata": entity.entity_metadata},
        "profile": None if profile is None else {"risk_level": profile.risk_level.value,
            "risk_score": profile.risk_score, "risk_confidence": profile.risk_confidence,
            "risk_reasons": profile.risk_reasons, "activity_summary": profile.activity_summary,
            "graph_features": profile.graph_features, "computed_at": profile.computed_at.isoformat()},
        "graph": {"nodes": [{"id": str(node.id), "type": node.entity_type.value,
            "display_value": node.display_value, "metadata": node.entity_metadata} for node in nodes.values()],
            "edges": edges},
        "collection_scope": {"max_hops": 4, "entity_limit": 400,
            "truncated": len(nodes) >= 400},
        "reports": report_items, "incidents": incidents, "transactions": transactions,
        "identity_clusters": clusters, "evidence": evidence_items, "findings": finding_items,
        "risk_assessments": risk_items, "investigations": cases, "activities": activity_items,
        "signals": signal_items, "relationship_analysis": relationship_analysis,
        "counts": {"reports": len(report_items), "incidents": len(incidents),
            "transactions": len(transactions), "identity_clusters": len(clusters),
            "evidence": len(evidence_items), "findings": len(finding_items),
            "investigations": len(cases), "signals": len(signal_items)}}
