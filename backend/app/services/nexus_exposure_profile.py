"""Exposure sentences from directed, time-bounded PDR transfer paths."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CommunityEntity, EntityRelationship, PartnerTransaction

from app.services.nexus_trace import confirmed_fraud_entity_ids_for_exposure, victim_entity_ids


async def _wallet_entity_ids(db: AsyncSession, entity_id: UUID) -> set[UUID]:
    entity = await db.get(CommunityEntity, entity_id)
    if entity is None:
        return set()
    if entity.entity_type.value in {"wallet", "account"}:
        return {entity_id}
    return set()


async def compute_exposure_profile(
    db: AsyncSession,
    entity_id: UUID,
    *,
    days: int = 7,
    max_hops: int = 2,
) -> dict[str, Any]:
    """Amount-weighted inflow exposure to investigator-confirmed fraud seeds (victims excluded)."""
    wallets = await _wallet_entity_ids(db, entity_id)
    if not wallets and entity_id:
        wallets = {entity_id}
    confirmed = await confirmed_fraud_entity_ids_for_exposure(db)
    victims = await victim_entity_ids(db)
    confirmed -= victims
    if entity_id in victims:
        return {
            "entity_id": str(entity_id),
            "exposure": "excluded_victim_role",
            "sentence": "This entity is recorded as a victim; exposure scoring does not treat victims as fraud labels.",
            "exposed_inflow_pct": 0.0,
            "window_days": days,
            "max_hops": max_hops,
        }
    if entity_id in confirmed:
        return {
            "entity_id": str(entity_id),
            "exposure": "direct_confirmed",
            "hops": 0,
            "sentence": "This wallet is investigator-confirmed in a fraud investigation.",
            "exposed_inflow_pct": 100.0,
            "window_days": days,
            "max_hops": max_hops,
        }
    since = datetime.now(UTC) - timedelta(days=days)
    transfers = (await db.scalars(select(PartnerTransaction).where(
        PartnerTransaction.transaction_status == "successful",
        PartnerTransaction.transaction_datetime >= since,
    ).order_by(PartnerTransaction.transaction_datetime.desc()).limit(500))).all()
    ledger_edges = (await db.scalars(select(EntityRelationship).where(
        EntityRelationship.relationship_type == "pdr_transfer",
    ))).all()
    edge_by_tx: dict[UUID, EntityRelationship] = {}
    for edge in ledger_edges:
        if edge.partner_transaction_id:
            edge_by_tx[edge.partner_transaction_id] = edge
    outgoing_edges: dict[UUID, list[EntityRelationship]] = {}
    for edge in ledger_edges:
        outgoing_edges.setdefault(edge.source_entity_id, []).append(edge)
    totals_by_currency: dict[str, Decimal] = {}
    exposed_by_currency: dict[str, Decimal] = {}
    paths: list[dict[str, Any]] = []
    target_wallet = next(iter(wallets), entity_id)
    for txn in transfers:
        edge = edge_by_tx.get(txn.id)
        if not edge:
            continue
        receiver = edge.target_entity_id
        if receiver != target_wallet:
            continue
        amount = Decimal(str(txn.amount or 0))
        if amount <= 0:
            continue
        currency = str(txn.currency or "UNKNOWN").upper()
        totals_by_currency[currency] = totals_by_currency.get(currency, Decimal("0")) + amount
        sender = edge.source_entity_id
        hop_info = await _shortest_hops_to_confirmed(
            sender, confirmed, transfers, outgoing_edges,
            min_timestamp=txn.transaction_datetime, currency=txn.currency,
            max_hops=max_hops,
        )
        if hop_info:
            exposed_by_currency[currency] = exposed_by_currency.get(currency, Decimal("0")) + amount
            paths.append({
                "transaction_id": str(txn.id),
                "amount": str(amount),
                "currency": currency,
                "timestamp": txn.transaction_datetime.isoformat() if txn.transaction_datetime else None,
                "hops_to_confirmed": hop_info["hops"],
                "via_entity_id": hop_info.get("via_entity_id"),
                "path_transaction_ids": hop_info.get("path_transaction_ids", []),
            })
    total_in = sum(totals_by_currency.values(), Decimal("0"))
    exposed_in = sum(exposed_by_currency.values(), Decimal("0"))
    # Comparing different currencies as if they shared a unit would create a
    # misleading percentage. Report currency-specific shares instead.
    percentages = {
        currency: round(float(exposed_by_currency.get(currency, Decimal("0")) / total * 100), 1)
        for currency, total in totals_by_currency.items() if total > 0
    }
    pct = max(percentages.values(), default=0.0)
    pct = round(min(100.0, pct), 1)
    typology = "none"
    if pct >= 40:
        typology = "elevated_inflow_to_confirmed_ring"
    elif pct > 0:
        typology = "partial_inflow_to_confirmed_ring"
    hop_phrase = f"{max_hops} hop(s)" if max_hops else "direct"
    if not totals_by_currency:
        sentence = f"No successful inflows to this wallet were observed in PDR in the last {days} days."
    else:
        shares = "; ".join(
            f"{share}% of {currency} inflows ({exposed_by_currency.get(currency, Decimal('0'))}/{total} {currency})"
            for currency, total in sorted(totals_by_currency.items())
        )
        sentence = (
            f"In the last {days} days, {shares} had a directed, time-ordered transfer path "
            f"within {hop_phrase} of an investigator-confirmed fraud entity."
        )
    return {
        "entity_id": str(entity_id),
        "exposure": "indirect" if pct > 0 else "none_within_window",
        "exposed_inflow_pct": pct,
        "exposed_inflow_pct_by_currency": percentages,
        "total_inflow": str(total_in) if len(totals_by_currency) <= 1 else None,
        "exposed_inflow": str(exposed_in) if len(totals_by_currency) <= 1 else None,
        "total_inflow_by_currency": {key: str(value) for key, value in totals_by_currency.items()},
        "exposed_inflow_by_currency": {key: str(value) for key, value in exposed_by_currency.items()},
        "window_days": days,
        "max_hops": max_hops,
        "typology": typology,
        "sentence": sentence,
        "sample_paths": paths[:5],
        "confirmed_seed_count": len(confirmed),
    }


async def _shortest_hops_to_confirmed(
    start: UUID,
    confirmed: set[UUID],
    transfers: list[PartnerTransaction],
    outgoing_edges: dict[UUID, list[EntityRelationship]],
    *,
    min_timestamp: datetime,
    currency: str | None,
    max_hops: int,
) -> dict[str, Any] | None:
    if start in confirmed:
        return {"hops": 0, "via_entity_id": str(start)}
    transaction_by_id = {txn.id: txn for txn in transfers if txn.transaction_datetime}
    def as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    frontier: dict[UUID, tuple[datetime, list[str], list[UUID]]] = {
        start: (as_utc(min_timestamp), [], [start]),
    }
    for hops in range(1, max_hops + 1):
        next_frontier: dict[UUID, tuple[datetime, list[str], list[UUID]]] = {}
        for source, (prior_timestamp, prior_path, prior_entities) in frontier.items():
            for row in outgoing_edges.get(source, []):
                txn = transaction_by_id.get(row.partner_transaction_id)
                if txn is None or txn.transaction_datetime is None:
                    continue
                txn_timestamp = as_utc(txn.transaction_datetime)
                if txn_timestamp < prior_timestamp:
                    continue
                if currency and str(txn.currency or "").upper() != str(currency).upper():
                    continue
                # Transfers were constrained to the analysis window when loaded.
                target = row.target_entity_id
                path = [*prior_path, str(txn.id)]
                if target in confirmed:
                    return {"hops": hops, "via_entity_id": str(target), "path_transaction_ids": path}
                if target in prior_entities:
                    continue
                previous = next_frontier.get(target)
                if previous is None or txn_timestamp < previous[0]:
                    next_frontier[target] = (txn_timestamp, path, [*prior_entities, target])
        frontier = next_frontier
        if not frontier:
            break
    return None
