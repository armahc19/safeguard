"""Chainalysis-style mobile money ledger: PDR transfers materialize wallet-to-wallet graph edges."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import UUID

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.enums import CommunityEntityType
from app.models import (
    CommunityEntity,
    EntityRelationship,
    IdentityResolutionCluster,
    IdentityResolutionMember,
    Partner,
    PartnerAccount,
    PartnerIdentity,
    PartnerTransaction,
    ReportEntity,
)

LEDGER_EDGE = "pdr_transfer"


def account_normalized_key(partner_code: str, account_reference: str) -> str:
    return f"pdr-account:{partner_code}:{account_reference}"


def _account_kind(account_type: str) -> CommunityEntityType:
    lowered = (account_type or "").lower()
    return CommunityEntityType.WALLET if "momo" in lowered or "wallet" in lowered else CommunityEntityType.ACCOUNT


def _masked_label(account_reference: str) -> str:
    return f"…{account_reference[-4:]}" if len(account_reference) >= 4 else "…"


async def upsert_account_entity(
    db: AsyncSession,
    *,
    partner_code: str,
    partner_name: str,
    account_reference: str,
    account_type: str = "momo",
    account_status: str | None = None,
    partner_account_id: UUID | None = None,
) -> CommunityEntity:
    normalized = account_normalized_key(partner_code, account_reference)
    row = await db.scalar(select(CommunityEntity).where(
        CommunityEntity.normalized_value == normalized,
    ))
    kind = _account_kind(account_type)
    label = f"{account_type} · {partner_name} · {_masked_label(account_reference)}"
    metadata = {
        "source": "pdr",
        "partner_code": partner_code,
        "partner_name": partner_name,
        "account_type": account_type,
        "account_reference_protected": True,
    }
    if account_status:
        metadata["account_status"] = account_status
    if partner_account_id:
        metadata["partner_account_id"] = str(partner_account_id)
    if row is None:
        row = CommunityEntity(entity_type=kind, normalized_value=normalized, display_value=label, entity_metadata=metadata)
        db.add(row)
        await db.flush()
    else:
        row.entity_metadata = {**(row.entity_metadata or {}), **metadata}
        if not row.display_value:
            row.display_value = label
    return row


async def upsert_transfer_edge(
    db: AsyncSession,
    transaction: PartnerTransaction,
    sender: CommunityEntity,
    receiver: CommunityEntity,
    *,
    partner_name: str | None,
) -> None:
    row = await db.scalar(select(EntityRelationship).where(
        EntityRelationship.partner_transaction_id == transaction.id,
    ))
    metadata = {
        "source": "partner_transactions",
        "ledger_model": "wallet_to_wallet",
        "amount": str(transaction.amount),
        "currency": transaction.currency,
        "transaction_reference_protected": True,
        "transaction_status": transaction.transaction_status,
        "timestamp": transaction.transaction_datetime.isoformat(),
        "provider": partner_name or transaction.sender_partner_code,
        "sender_partner_code": transaction.sender_partner_code,
        "receiver_partner_code": transaction.receiver_partner_code,
    }
    if row is None:
        db.add(EntityRelationship(
            source_entity_id=sender.id,
            target_entity_id=receiver.id,
            relationship_type=LEDGER_EDGE,
            confidence=1.0,
            partner_transaction_id=transaction.id,
            relationship_metadata=metadata,
        ))
    else:
        row.source_entity_id = sender.id
        row.target_entity_id = receiver.id
        row.relationship_metadata = metadata


async def resolve_account_entity(
    db: AsyncSession,
    settings: Settings,
    transaction: PartnerTransaction,
    *,
    side: str,
    partners: dict[UUID, Partner],
    account_by_id: dict[UUID, PartnerAccount],
) -> CommunityEntity | None:
    if side == "sender":
        partner_code = transaction.sender_partner_code
        account_reference = transaction.sender_account_reference
        account_id = transaction.sender_account_id
    else:
        partner_code = transaction.receiver_partner_code
        account_reference = transaction.receiver_account_reference
        account_id = transaction.receiver_account_id
    account = account_by_id.get(account_id) if account_id else None
    if account is None and account_id:
        account = await db.get(PartnerAccount, account_id)
    partner = partners.get(transaction.partner_id)
    if account:
        partner = partners.get(account.partner_id) or partner
        if partner:
            partner_code = partner.partner_code
        account_reference = account.account_identifier
    partner_name = partner.partner_name if partner else partner_code
    account_type = account.account_type if account else "momo"
    account_status = account.account_status if account else None
    return await upsert_account_entity(
        db,
        partner_code=partner_code,
        partner_name=partner_name,
        account_reference=account_reference,
        account_type=account_type,
        account_status=account_status,
        partner_account_id=account.id if account else None,
    )


async def materialize_pdr_ledger(db: AsyncSession, settings: Settings | None = None) -> int:
    """Rebuild the partner money graph from PDR (one directed edge per successful transfer)."""
    settings = settings or get_settings()
    await db.execute(delete(EntityRelationship).where(
        or_(
            EntityRelationship.partner_transaction_id.is_not(None),
            EntityRelationship.relationship_type.in_((LEDGER_EDGE, "transferred_to")),
        ),
    ))

    partners = {partner.id: partner for partner in (await db.scalars(select(Partner))).all()}
    partner_nodes: dict[UUID, CommunityEntity] = {}

    async def entity(
        kind: CommunityEntityType,
        value: str,
        display: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CommunityEntity:
        row = await db.scalar(select(CommunityEntity).where(
            CommunityEntity.entity_type == kind,
            CommunityEntity.normalized_value == value,
        ))
        if row is None:
            row = CommunityEntity(entity_type=kind, normalized_value=value, display_value=display, entity_metadata=metadata or {})
            db.add(row)
            await db.flush()
        elif metadata:
            row.entity_metadata = {**(row.entity_metadata or {}), **metadata}
            if display:
                row.display_value = display
        return row

    async def link(
        source: CommunityEntity,
        target: CommunityEntity,
        kind: str,
        confidence: float,
        metadata: dict[str, Any],
    ) -> None:
        row = await db.scalar(select(EntityRelationship).where(
            EntityRelationship.source_entity_id == source.id,
            EntityRelationship.target_entity_id == target.id,
            EntityRelationship.relationship_type == kind,
            EntityRelationship.partner_transaction_id.is_(None),
        ))
        if row is None:
            db.add(EntityRelationship(
                source_entity_id=source.id,
                target_entity_id=target.id,
                relationship_type=kind,
                confidence=confidence,
                relationship_metadata=metadata,
            ))
        else:
            row.confidence = max(row.confidence, confidence)
            row.relationship_metadata = {**(row.relationship_metadata or {}), **metadata}

    for partner in partners.values():
        partner_nodes[partner.id] = await entity(
            CommunityEntityType.ORGANIZATION,
            f"partner:{partner.partner_code}",
            partner.partner_name,
            {"source": "pdr", "partner_code": partner.partner_code},
        )

    accounts = (await db.scalars(select(PartnerAccount))).all()
    account_by_id = {account.id: account for account in accounts}
    account_nodes: dict[UUID, CommunityEntity] = {}
    for account in accounts:
        partner = partners.get(account.partner_id)
        if not partner:
            continue
        node = await upsert_account_entity(
            db,
            partner_code=partner.partner_code,
            partner_name=partner.partner_name,
            account_reference=account.account_identifier,
            account_type=account.account_type,
            account_status=account.account_status,
            partner_account_id=account.id,
        )
        account_nodes[account.id] = node
        await link(node, partner_nodes[partner.id], "held_at", 0.95, {"source": "partner_data_repository"})

    identities = (await db.scalars(select(PartnerIdentity))).all()
    identity_nodes: dict[UUID, CommunityEntity] = {}
    for identity in identities:
        partner = partners.get(identity.partner_id)
        if not partner:
            continue
        node = await entity(
            CommunityEntityType.PERSON,
            f"pdr-identity:{partner.partner_code}:{identity.identity_reference}",
            None,
            {"source": "pdr", "partner_code": partner.partner_code, "verification_status": identity.verification_status},
        )
        identity_nodes[identity.id] = node
        await link(node, partner_nodes[partner.id], "registered_with", 0.95, {"source": "partner_data_repository"})
        if identity.phone_number_reference:
            phone = await entity(
                CommunityEntityType.PHONE,
                f"pdr-phone:{identity.phone_number_reference}",
                None,
                {"source": "pdr", "protected_reference": True},
            )
            await link(node, phone, "associated_phone", 0.9, {"source": "partner_data_repository"})
        for linked_account in accounts:
            if linked_account.identity_id != identity.id:
                continue
            wallet = account_nodes.get(linked_account.id)
            if wallet:
                await link(node, wallet, "owns", 0.9, {"source": "partner_data_repository"})

    clusters = (await db.scalars(select(IdentityResolutionCluster))).all()
    for cluster in clusters:
        members = (await db.scalars(select(IdentityResolutionMember).where(
            IdentityResolutionMember.cluster_id == cluster.id,
        ))).all()
        if not members:
            continue
        canonical = await entity(
            CommunityEntityType.PERSON,
            f"identity-cluster:{cluster.match_type}:{cluster.match_key}",
            None,
            {"source": "identity_intelligence", "resolution_status": cluster.resolution_status, "confidence": cluster.confidence},
        )
        for member in members:
            node = identity_nodes.get(member.partner_identity_id)
            if node:
                await link(
                    node,
                    canonical,
                    "resolved_as" if cluster.resolution_status == "resolved" else "candidate_match",
                    member.confidence,
                    {"match_type": cluster.match_type},
                )

    transactions = (await db.scalars(select(PartnerTransaction).where(
        PartnerTransaction.transaction_status == "successful",
    ))).all()
    for txn in transactions:
        sender = await resolve_account_entity(db, settings, txn, side="sender", partners=partners, account_by_id=account_by_id)
        receiver = await resolve_account_entity(db, settings, txn, side="receiver", partners=partners, account_by_id=account_by_id)
        if not sender or not receiver or sender.id == receiver.id:
            continue
        partner = partners.get(txn.partner_id)
        await upsert_transfer_edge(db, txn, sender, receiver, partner_name=partner.partner_name if partner else None)

    await db.flush()
    return len(partner_nodes) + len(identity_nodes) + len(account_nodes)


def _entity_node_payload(entity: CommunityEntity) -> dict[str, Any]:
    meta = entity.entity_metadata or {}
    kind = entity.entity_type.value
    if kind in {"wallet", "account"}:
        node_type = kind
    elif kind == "person":
        node_type = "identity"
    else:
        node_type = kind
    source = "pdr" if (meta.get("source") == "pdr" or str(entity.normalized_value).startswith("pdr-")) else "shared"
    return {
        "id": str(entity.id),
        "type": node_type,
        "display_value": entity.display_value or entity.normalized_value,
        "source": source,
        "source_record_id": meta.get("partner_account_id"),
        "source_table": "partner_accounts" if kind in {"wallet", "account"} else "community_entities",
        "verification_status": meta.get("verification_status", "PDR_account_record"),
        "details": {k: v for k, v in meta.items() if k not in {"account_reference_protected"}},
    }


def _transfer_edge_payload(edge: EntityRelationship) -> dict[str, Any]:
    meta = edge.relationship_metadata or {}
    amount = meta.get("amount")
    currency = meta.get("currency", "")
    label = f"{amount} {currency}".strip() if amount else LEDGER_EDGE.replace("_", " ")
    return {
        "source": str(edge.source_entity_id),
        "target": str(edge.target_entity_id),
        "relationship_type": label,
        "ledger_relationship": LEDGER_EDGE,
        "confidence": edge.confidence,
        "direction": "outgoing",
        "verification_status": "PDR_transaction_record",
        "source_repository": "PDR",
        "source_table": "partner_transactions",
        "source_record_id": str(edge.partner_transaction_id) if edge.partner_transaction_id else None,
        "metadata": meta,
    }


async def collect_ledger_subgraph(
    db: AsyncSession,
    seed_entity_ids: Iterable[UUID],
    *,
    depth: int = 2,
    edge_limit: int = 200,
    include_ownership: bool = True,
) -> dict[str, Any]:
    """Walk the materialized money graph from wallet/account seeds (bounded BFS)."""
    seeds = list({UUID(str(value)) for value in seed_entity_ids})
    if not seeds:
        return {"nodes": [], "edges": [], "root_id": None, "summary": {"node_count": 0, "edge_count": 0}}

    entities: dict[UUID, CommunityEntity] = {}
    for seed in seeds:
        row = await db.get(CommunityEntity, seed)
        if row:
            entities[row.id] = row

    edge_rows: dict[UUID, EntityRelationship] = {}
    frontier = set(entities)
    expanded: set[UUID] = set(frontier)
    allowed_types = {LEDGER_EDGE} | ({"owns", "resolved_as", "candidate_match"} if include_ownership else set())

    for _ in range(max(1, depth)):
        if not frontier or len(edge_rows) >= edge_limit:
            break
        frontier_ids = list(frontier)
        rows = (await db.scalars(select(EntityRelationship).where(
            EntityRelationship.relationship_type.in_(tuple(allowed_types)),
            or_(
                EntityRelationship.source_entity_id.in_(frontier_ids),
                EntityRelationship.target_entity_id.in_(frontier_ids),
            ),
        ).limit(edge_limit))).all()
        next_frontier: set[UUID] = set()
        for row in rows:
            if row.relationship_type not in allowed_types:
                continue
            edge_rows[row.id] = row
            if row.source_entity_id in frontier:
                next_frontier.add(row.target_entity_id)
            if row.target_entity_id in frontier:
                next_frontier.add(row.source_entity_id)
        missing = next_frontier.difference(entities.keys())
        if missing:
            for entity in (await db.scalars(select(CommunityEntity).where(CommunityEntity.id.in_(missing)))).all():
                entities[entity.id] = entity
        frontier = next_frontier - expanded
        expanded.update(frontier)

    nodes = [_entity_node_payload(entity) for entity in entities.values()]
    edges = [_transfer_edge_payload(edge) for edge in edge_rows.values() if edge.relationship_type == LEDGER_EDGE]
    ownership = [
        {
            "source": str(edge.source_entity_id),
            "target": str(edge.target_entity_id),
            "relationship_type": edge.relationship_type,
            "confidence": edge.confidence,
            "verification_status": "PDR_ownership_link",
            "source_repository": "PDR",
            "metadata": edge.relationship_metadata or {},
        }
        for edge in edge_rows.values()
        if edge.relationship_type != LEDGER_EDGE
    ]
    root_id = str(seeds[0]) if seeds else None
    return {
        "root_id": root_id,
        "nodes": nodes,
        "edges": edges + ownership,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "transfer_count": len(edges),
            "network_scope": f"pdr_transfer walk depth={depth}",
            "ledger_model": "chainalysis_mobile_money",
        },
    }


async def exposure_hop_count(
    db: AsyncSession,
    source_entity_id: UUID,
    *,
    confirmed_entity_ids: set[UUID],
    max_depth: int = 3,
) -> dict[str, Any]:
    """Count shortest ledger hops from a wallet to any confirmed-fraud-labeled entity."""
    if source_entity_id in confirmed_entity_ids:
        return {"entity_id": str(source_entity_id), "hops": 0, "exposure": "direct"}
    seen = {source_entity_id}
    frontier = {source_entity_id}
    for hops in range(1, max_depth + 1):
        rows = (await db.scalars(select(EntityRelationship).where(
            EntityRelationship.relationship_type == LEDGER_EDGE,
            or_(
                EntityRelationship.source_entity_id.in_(frontier),
                EntityRelationship.target_entity_id.in_(frontier),
            ),
        ))).all()
        next_frontier: set[UUID] = set()
        for row in rows:
            neighbors = {row.source_entity_id, row.target_entity_id} - frontier
            for neighbor in neighbors:
                if neighbor in seen:
                    continue
                if neighbor in confirmed_entity_ids:
                    return {"entity_id": str(source_entity_id), "hops": hops, "exposure": "indirect",
                            "via_entity_id": str(neighbor)}
                seen.add(neighbor)
                next_frontier.add(neighbor)
        frontier = next_frontier
        if not frontier:
            break
    return {"entity_id": str(source_entity_id), "hops": None, "exposure": "none_within_depth", "max_depth": max_depth}


async def confirmed_fraud_entity_ids(db: AsyncSession) -> set[UUID]:
    """Entities that seed exposure walks (verified allegations, confirmed roles; victims excluded)."""
    from app.services.nexus_trace import confirmed_fraud_entity_ids_for_exposure

    return await confirmed_fraud_entity_ids_for_exposure(db)
