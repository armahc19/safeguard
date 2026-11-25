"""Build a provenance-preserving NEXUS graph anchored on a FIR report."""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.exceptions import ValidationFailed
from app.core.partner_secrets import protect_partner_reference
from app.core.phone import normalize_phone
from app.models import (
    CommunityEntity,
    EntityRelationship,
    FIRReportIncident,
    FIRReportRecord,
    FraudCase,
    FraudIncident,
    IncidentEntity,
    Partner,
    PartnerAccount,
    PartnerIdentity,
    PartnerTransaction,
    ReportEntity,
    User,
)
from app.services.nexus_ledger import account_normalized_key, collect_ledger_subgraph

_AMOUNT = re.compile(
    r"(?:GH₵|GH¢|GHS|₵)\s*([\d,]+(?:\.\d{1,2})?)|"
    r"([\d,]+(?:\.\d{1,2})?)\s*(?:GH₵|GH¢|GHS|₵)", re.IGNORECASE,
)


def _amount_from_report(text: str) -> Decimal | None:
    match = _AMOUNT.search(text or "")
    if not match:
        return None
    try:
        return Decimal((match.group(1) or match.group(2)).replace(",", ""))
    except InvalidOperation:
        return None


def _phone_role(text: str, value: str) -> str:
    text = text or ""
    for match in re.finditer(re.escape(value), text, re.IGNORECASE):
        prefix = text[max(0, match.start() - 100):match.start()].casefold()
        if re.search(r"\b(to|into|sent to|transferred to|paid to|recipient|receiver)\s*$", prefix) or re.search(
            r"\b(to|into|sent to|transferred to|paid to)\b.{0,80}\b(account|wallet|number|phone)\s+holder\s*$",
            prefix,
        ):
            return "alleged_recipient_phone"
        if re.search(r"\b(using|called from|scammer|fraudster|suspect|caller)\s*$", prefix):
            return "alleged_suspect_phone"
    return "reported_phone"


async def build_fir_report_graph(
    db: AsyncSession,
    report_id: UUID,
    extraction_items: list[dict],
    settings: Settings | None = None,
) -> dict:
    """Create the FIR starting graph and a bounded two-hop PDR transaction view.

    FIR-to-PDR links are explicitly marked as allegations, exact identifier
    matches, ownership links, or transaction candidates. A candidate match is
    never presented as a confirmed fraud finding.
    """
    settings = settings or get_settings()
    report = await db.get(FIRReportRecord, report_id)
    if report is None:
        return {"nodes": [], "edges": [], "summary": {"node_count": 0, "edge_count": 0}}

    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str], dict] = {}

    def add_node(node_id: str, kind: str, label: str, source: str, *,
                 verification_status: str, record_id: str | None = None,
                 details: dict | None = None) -> str:
        source_tables = {
            ("fir", "report"): "fir_reports", ("fir", "person"): "users",
            ("fir", "case"): "fraud_cases", ("fir", "incident"): "fraud_incidents",
            ("fir", "phone"): "community_entities", ("fir", "identity"): "community_entities",
            ("fir", "account"): "community_entities", ("fir", "transaction"): "community_entities",
            ("fir", "business"): "community_entities", ("fir", "agent"): "community_entities",
            ("pdr", "identity"): "partner_identities", ("pdr", "account"): "partner_accounts",
            ("pdr", "wallet"): "partner_accounts", ("pdr", "transaction"): "partner_transactions",
        }
        nodes.setdefault(node_id, {
            "id": node_id, "type": kind, "display_value": label,
            "source": source, "source_record_id": record_id,
            "source_table": source_tables.get((source, kind)),
            "verification_status": verification_status, "details": details or {},
        })
        return node_id

    def add_edge(source: str, target: str, relationship: str, *, confidence: float | None,
                 evidence_status: str, source_table: str, source_record_id: str,
                 details: dict | None = None) -> None:
        edges[(source, target, relationship)] = {
            "source": source, "target": target, "relationship_type": relationship,
            "confidence": confidence, "direction": "outgoing",
            "verification_status": evidence_status,
            "source_repository": "FIR" if source_table.startswith(("fir_", "report_", "incident_")) else "PDR",
            "source_table": source_table, "source_record_id": source_record_id,
            "metadata": details or {},
        }

    report_node = add_node(
        f"fir-report:{report.id}", "report", report.subject or "FIR report", "fir",
        verification_status="user_report", record_id=str(report.id),
        details={"status": report.status, "category": report.category,
                 "report_type": report.report_type, "channel": report.channel,
                 "created_at": report.created_at.isoformat() if report.created_at else None},
    )

    reporter = await db.get(User, report.reporter_id)
    reporter_id = None
    if reporter:
        text = f"{report.subject or ''} {report.description or ''}"
        first_person = bool(re.search(r"\b(i|my|me)\b", text, re.IGNORECASE)
                            and re.search(r"\b(deceived|scammed|transferred|sent|paid|lost)\b", text, re.IGNORECASE))
        reporter_role = "alleged_victim" if first_person else "reporter"
        reporter_id = add_node(
            f"fir-reporter:{reporter.id}", "person", "Reporting user", "fir",
            verification_status="reporter_account", record_id=str(reporter.id),
            details={"reported_role": reporter_role},
        )
        add_edge(report_node, reporter_id, "reported_by", confidence=1.0,
                 evidence_status="FIR_source_record", source_table="fir_reports",
                 source_record_id=str(report.id), details={"role_basis": reporter_role})

    if report.case_id:
        case = await db.get(FraudCase, report.case_id)
        if case:
            case_node = add_node(f"fir-case:{case.id}", "case", case.title, "fir",
                verification_status="investigation_record", record_id=str(case.id),
                details={"status": case.status.value})
            add_edge(case_node, report_node, "includes_report", confidence=1.0,
                     evidence_status="FIR_case_link", source_table="fir_reports",
                     source_record_id=str(report.id))

    linked_entities = (await db.execute(select(ReportEntity, CommunityEntity).join(
        CommunityEntity, CommunityEntity.id == ReportEntity.entity_id
    ).where(ReportEntity.report_id == report.id))).all()
    entity_nodes: dict[str, str] = {}
    entity_roles: dict[str, str] = {}
    for link, entity in linked_entities:
        entity_id = add_node(
            f"fir-entity:{entity.id}", entity.entity_type.value,
            entity.display_value or entity.normalized_value, "fir",
            verification_status="reviewer_verified" if link.verified else "alleged",
            record_id=str(entity.id),
            details={"extraction_source": link.source_kind, "verified": bool(link.verified),
                     "source_text": link.source_text,
                     "reported_role": _phone_role(
                         f"{report.subject or ''} {report.description or ''}",
                         entity.display_value or entity.normalized_value,
                     ) if entity.entity_type.value == "phone" else "reported_identifier"},
        )
        entity_nodes[str(entity.id)] = entity_id
        if entity.entity_type.value == "phone":
            entity_roles[str(entity.id)] = _phone_role(
                f"{report.subject or ''} {report.description or ''}", entity.display_value or "")
        add_edge(report_node, entity_id, "mentions", confidence=float(link.confidence),
                 evidence_status="reviewer_verified" if link.verified else "allegation",
                 source_table="report_entities", source_record_id=str(link.id),
                 details={"source_kind": link.source_kind, "source_text": link.source_text})

    for item in extraction_items:
        entity_id_value = item.get("entity_id")
        if not entity_id_value:
            continue
        entity_key = str(entity_id_value)
        if entity_key in entity_nodes:
            continue
        entity = await db.get(CommunityEntity, UUID(entity_key))
        if entity is None:
            continue
        entity_node = add_node(
            f"fir-entity:{entity.id}", entity.entity_type.value,
            entity.display_value or str(item.get("value") or entity.entity_type.value), "fir",
            verification_status="alleged", record_id=str(entity.id),
            details={"extraction_source": "nexus_auto", "extraction_confidence": item.get("confidence"),
                     "reported_role": _phone_role(f"{report.subject or ''} {report.description or ''}", str(item.get("value", "")))
                     if item.get("kind") == "phone" else "reported_identifier"},
        )
        entity_nodes[entity_key] = entity_node
        if item.get("kind") == "phone":
            entity_roles[entity_key] = _phone_role(
                f"{report.subject or ''} {report.description or ''}", str(item.get("value", "")))
        add_edge(report_node, entity_node, "mentions", confidence=float(item.get("confidence", 0.5)),
                 evidence_status="allegation", source_table="report_entities",
                 source_record_id=str(report.id), details={"source_kind": "nexus_auto"})

    # Existing incident assignments carry investigator-maintained roles. They
    # are shown with their stored verification state instead of inferred labels.
    incident_links = (await db.execute(select(FIRReportIncident, FraudIncident).join(
        FraudIncident, FraudIncident.id == FIRReportIncident.incident_id
    ).where(FIRReportIncident.report_id == report.id))).all()
    for report_incident, incident in incident_links:
        incident_node = add_node(f"fir-incident:{incident.id}", "incident", incident.title,
            "fir", verification_status="FIR_incident", record_id=str(incident.id),
            details={"status": incident.status.value, "risk_level": incident.risk_level.value,
                     "outcome": incident.outcome.value})
        add_edge(report_node, incident_node, "describes_incident", confidence=float(report_incident.confidence),
                 evidence_status="FIR_incident_link", source_table="report_incidents",
                 source_record_id=str(report_incident.id), details={"link_reason": report_incident.link_reason})
        incident_entities = (await db.execute(select(IncidentEntity, CommunityEntity).join(
            CommunityEntity, CommunityEntity.id == IncidentEntity.entity_id
        ).where(IncidentEntity.incident_id == incident.id))).all()
        for association, entity in incident_entities:
            entity_key = entity_nodes.get(str(entity.id)) or add_node(
                f"fir-entity:{entity.id}", entity.entity_type.value,
                entity.display_value or entity.normalized_value, "fir",
                verification_status=association.verification_status,
                record_id=str(entity.id), details={"incident_role": association.role})
            entity_nodes[str(entity.id)] = entity_key
            add_edge(incident_node, entity_key, association.role,
                confidence=float(association.confidence), evidence_status=association.verification_status,
                source_table="incident_entities", source_record_id=str(association.id))

    # Resolve exact reported phones to partner identities using the same keyed
    # phone reference as PDR ingestion. A phone match is not proof of identity.
    pdr_identity_nodes: dict[str, tuple[PartnerIdentity, Partner]] = {}
    pdr_account_nodes: dict[str, PartnerAccount] = {}
    account_nodes: dict[str, str] = {}
    recipient_identity_ids: set[str] = set()
    partner_rows = (await db.scalars(select(Partner).order_by(Partner.partner_name))).all()
    for entity_id_value, role in entity_roles.items():
        entity = await db.get(CommunityEntity, UUID(entity_id_value))
        if entity is None:
            continue
        try:
            normalized_phone = normalize_phone(entity.display_value or entity.normalized_value,
                                               settings.default_calling_code)
        except ValidationFailed:
            continue
        for partner in partner_rows:
            protected_phone = protect_partner_reference(
                normalized_phone, namespace="phone", application_secret=settings.secret_key.get_secret_value())
            identity_rows = (await db.execute(select(PartnerIdentity).where(
                PartnerIdentity.partner_id == partner.id,
                PartnerIdentity.phone_number_reference == protected_phone,
            ).limit(25))).scalars().all()
            for identity in identity_rows:
                identity_key = str(identity.id)
                pdr_identity_nodes[identity_key] = (identity, partner)
                if role == "alleged_recipient_phone":
                    recipient_identity_ids.add(identity_key)
                identity_node = add_node(
                    f"pdr-identity:{identity.id}", "identity",
                    f"PDR identity · {partner.partner_name} · …{identity.identity_reference[-4:]}", "pdr",
                    verification_status=identity.verification_status, record_id=identity_key,
                    details={"partner": partner.partner_name,
                             "ownership_verified": bool(identity.verified_ownership),
                             "matched_field": "exact protected phone reference"},
                )
                add_edge(entity_nodes[entity_id_value], identity_node,
                    "same_phone_reference", confidence=0.98,
                    evidence_status="phone_reference_match_not_identity_proof",
                    source_table="partner_identities", source_record_id=identity_key,
                    details={"reported_role": role, "verification_status": identity.verification_status})

    for identity, partner in pdr_identity_nodes.values():
        accounts = (await db.scalars(select(PartnerAccount).where(or_(
            PartnerAccount.identity_id == identity.id,
            and_(PartnerAccount.partner_id == identity.partner_id,
                 PartnerAccount.identity_reference == identity.identity_reference),
        )).order_by(PartnerAccount.created_at.desc()).limit(30))).all()
        for account in accounts:
            account_key = str(account.id)
            pdr_account_nodes[account_key] = account
            masked = account.account_identifier[-4:] if account.account_identifier else "????"
            account_node = add_node(
                f"pdr-account:{account.id}", "wallet" if "momo" in account.account_type.lower() or "wallet" in account.account_type.lower() else "account",
                f"{account.account_type} · {partner.partner_name} · …{masked}", "pdr",
                verification_status="verified_owner_link" if identity.verified_ownership and identity.verification_status == "verified" else "unverified_owner_link",
                record_id=account_key,
                details={"partner": partner.partner_name, "account_type": account.account_type,
                         "service_provider": account.service_provider, "account_status": account.account_status,
                         "ownership_verification": identity.verification_status},
            )
            account_nodes[account_key] = account_node
            add_edge(f"pdr-identity:{identity.id}", account_node, "registered_account",
                confidence=0.98 if identity.verified_ownership else 0.75,
                evidence_status="verified_ownership" if identity.verified_ownership else "unverified_owner_link",
                source_table="partner_accounts", source_record_id=account_key)

    recipient_account_refs = {
        (partner.partner_code, account.account_identifier)
        for identity_id, (identity, partner) in pdr_identity_nodes.items()
        if identity_id in recipient_identity_ids
        for account in pdr_account_nodes.values()
        if account.partner_id == identity.partner_id and (
            account.identity_id == identity.id or account.identity_reference == identity.identity_reference
        )
    }

    partner_by_id = {partner.id: partner for partner in partner_rows}
    seed_entity_ids: list[UUID] = []
    ledger_entity_by_account: dict[str, str] = {}
    for account in pdr_account_nodes.values():
        partner = partner_by_id.get(account.partner_id)
        if not partner:
            continue
        ledger_entity = await db.scalar(select(CommunityEntity).where(
            CommunityEntity.normalized_value == account_normalized_key(partner.partner_code, account.account_identifier),
        ))
        if ledger_entity:
            seed_entity_ids.append(ledger_entity.id)
            ledger_entity_by_account[str(account.id)] = str(ledger_entity.id)
    for entity_key in entity_nodes:
        entity = await db.get(CommunityEntity, UUID(entity_key))
        if entity and entity.entity_type.value in {"wallet", "account"}:
            seed_entity_ids.append(entity.id)

    ledger = await collect_ledger_subgraph(db, seed_entity_ids, depth=3, edge_limit=250)
    transfer_count = 0
    for ledger_node in ledger.get("nodes", []):
        nodes.setdefault(ledger_node["id"], ledger_node)
    for account_id, ledger_entity_id in ledger_entity_by_account.items():
        account_node_id = account_nodes.get(account_id)
        if not account_node_id or ledger_entity_id not in nodes:
            continue
        add_edge(
            account_node_id, ledger_entity_id, "ledger_wallet_mapping",
            confidence=1.0, evidence_status="exact_partner_account_mapping",
            source_table="partner_accounts", source_record_id=account_id,
            details={"mapping_basis": "partner-scoped protected account reference"},
        )
    for ledger_edge in ledger.get("edges", []):
        relationship = ledger_edge.get("ledger_relationship") or ledger_edge.get("relationship_type", "linked")
        edge_key = (ledger_edge["source"], ledger_edge["target"], relationship)
        edges[edge_key] = ledger_edge
        if ledger_edge.get("ledger_relationship") == "pdr_transfer":
            transfer_count += 1

    exact_transaction_ids = {
        match.get("record_id")
        for item in extraction_items for match in item.get("pdr_matches", [])
        if match.get("kind") == "transaction" and match.get("matched_field") == "transaction reference"
    }
    report_amount = _amount_from_report(f"{report.subject or ''} {report.description or ''}")
    candidate_tx_ids: set[str] = set()
    tx_rows: list[PartnerTransaction] = []
    if exact_transaction_ids:
        tx_rows = (await db.scalars(select(PartnerTransaction).where(
            PartnerTransaction.id.in_([UUID(value) for value in exact_transaction_ids]),
        ))).all()
    elif report_amount is not None:
        ledger_tx_ids = [
            UUID(edge["source_record_id"])
            for edge in ledger.get("edges", [])
            if edge.get("source_record_id") and edge.get("ledger_relationship") == "pdr_transfer"
        ]
        if ledger_tx_ids:
            tx_rows = (await db.scalars(select(PartnerTransaction).where(
                PartnerTransaction.id.in_(ledger_tx_ids),
            ))).all()
    for transaction in tx_rows:
            tx_id = str(transaction.id)
            ref_match = tx_id in exact_transaction_ids
            matched_reference = next((
                match.get("transaction_reference")
                for item in extraction_items for match in item.get("pdr_matches", [])
                if match.get("record_id") == tx_id and match.get("transaction_reference")
            ), None)
            amount_match = report_amount is not None and Decimal(str(transaction.amount)) == report_amount
            receiver_is_reported_recipient = (
                transaction.receiver_partner_code, transaction.receiver_account_reference
            ) in recipient_account_refs
            if not (ref_match or (amount_match and receiver_is_reported_recipient)):
                continue
            candidate_tx_ids.add(tx_id)
            receiver_entity = await db.scalar(select(CommunityEntity).where(
                CommunityEntity.normalized_value == account_normalized_key(
                    transaction.receiver_partner_code, transaction.receiver_account_reference,
                ),
            ))
            wallet_node = str(receiver_entity.id) if receiver_entity else None
            transaction_node = add_node(
                f"pdr-transaction:{transaction.id}", "transaction",
                f"{transaction.amount} {transaction.currency} · {matched_reference or 'PDR transaction'}",
                "pdr", verification_status="observed_pdr_transaction",
                record_id=str(transaction.id),
                details={"transaction_reference": matched_reference,
                         "amount": str(transaction.amount), "currency": transaction.currency,
                         "timestamp": transaction.transaction_datetime.isoformat(),
                         "status": transaction.transaction_status,
                         "partner": (partner_by_id.get(transaction.partner_id).partner_name
                                     if partner_by_id.get(transaction.partner_id) else None)},
            )
            add_edge(report_node, transaction_node,
                    "exact_transaction_reference" if ref_match else "possible_transfer_match",
                    confidence=0.99 if ref_match else 0.75,
                    evidence_status="exact_reference_match" if ref_match else "candidate_amount_and_recipient_match",
                    source_table="fir_reports", source_record_id=str(report.id),
                    details={"partner_transaction_id": tx_id, "amount_match": amount_match,
                             "recipient_account_match": receiver_is_reported_recipient,
                             "requires_investigator_confirmation": not ref_match})
            if wallet_node:
                add_edge(transaction_node, wallet_node, "transferred_to",
                         confidence=1.0, evidence_status="PDR_transaction_record",
                         source_table="partner_transactions", source_record_id=tx_id,
                         details={"amount": str(transaction.amount), "currency": transaction.currency,
                                  "timestamp": transaction.transaction_datetime.isoformat(),
                                  "direction": "outgoing_to_receiver"})
            rel = await db.scalar(select(EntityRelationship).where(
                EntityRelationship.partner_transaction_id == transaction.id,
            ))
            if rel and str(rel.target_entity_id) not in nodes:
                target = await db.get(CommunityEntity, rel.target_entity_id)
                if target:
                    meta = target.entity_metadata or {}
                    partner_account_id = meta.get("partner_account_id")
                    nodes[str(target.id)] = {
                        "id": str(target.id),
                        "type": target.entity_type.value,
                        "display_value": target.display_value or target.normalized_value,
                        "source": "pdr",
                        "verification_status": meta.get("verification_status", "PDR_account_record"),
                        "source_table": "partner_accounts" if partner_account_id else "community_entities",
                        "source_record_id": str(partner_account_id or target.id),
                        "details": {k: v for k, v in meta.items() if k not in {"account_reference_protected"}},
                    }

    transactions = list(candidate_tx_ids)

    # A report may link to many same-amount transactions. Show every supported
    # candidate; never choose one by amount alone or label it confirmed fraud.
    incident_count = len(incident_links)
    by_type: dict[str, int] = {}
    for node in nodes.values():
        by_type[node["type"]] = by_type.get(node["type"], 0) + 1
    return {
        "root_id": report_node, "nodes": list(nodes.values()), "edges": list(edges.values()),
        "summary": {"node_count": len(nodes), "edge_count": len(edges), "by_type": by_type,
                    "report_id": str(report.id), "case_id": str(report.case_id) if report.case_id else None,
                    "pdr_identity_count": len(pdr_identity_nodes), "pdr_account_count": len(pdr_account_nodes),
                    "transaction_count": transfer_count, "candidate_transaction_count": len(candidate_tx_ids),
                    "incident_count": incident_count,
                    "transaction_candidates_are_unconfirmed": True,
                    "ledger_model": "chainalysis_mobile_money",
                    "network_scope": ledger.get("summary", {}).get("network_scope",
                        "pdr_transfer wallet graph around FIR-matched accounts")},
    }
