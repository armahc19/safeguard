"""FIR→PDR investigation trace, trust tiers, pattern candidates, and investigator decisions."""
from __future__ import annotations

from collections import deque
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    CommunityEntity,
    EntityRelationship,
    FIRReportIncident,
    FIRReportRecord,
    FraudIncident,
    IncidentEntity,
    PartnerTransaction,
    ReportEntity,
)

TRUST_TIERS = ("allegation", "observed", "candidate", "investigator_confirmed")


def trust_tier_from_status(status: str | None, *, source: str | None = None) -> str:
    text = str(status or "").lower()
    if "investigator" in text or "reviewer_verified" in text or "confirmed" in text and "not" not in text:
        return "investigator_confirmed"
    if source == "pdr" or "pdr_" in text or "transaction" in text or "partner" in text:
        return "observed"
    if "candidate" in text or "alleged" in text or "allegation" in text or "phone_reference" in text:
        return "candidate"
    if "verified" in text and "unverified" not in text:
        return "investigator_confirmed"
    return "allegation"


def _node_label(node: dict | None) -> str:
    if not node:
        return "Unknown"
    return str(node.get("display_value") or node.get("type") or node.get("id", "record"))


def _edge_time(edge: dict[str, Any]) -> datetime | None:
    raw = (edge.get("metadata") or {}).get("timestamp") or edge.get("timestamp")
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _cashout_node(node: dict[str, Any] | None) -> bool:
    if not node:
        return False
    details = node.get("details") or {}
    descriptor = " ".join(str(details.get(key) or "") for key in (
        "account_type", "service_provider", "display_value", "cashout_type",
    )).casefold().replace("-", "_").replace(" ", "_")
    return any(marker in descriptor for marker in ("agent", "cash_out", "cashout"))


def _forward_path_to_cashout(
    start_id: str,
    loss_timestamp: datetime | None,
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    max_hops: int = 12,
) -> tuple[list[dict[str, Any]], str | None]:
    """Follow only directed, chronological PDR transfers from the loss receiver."""
    outgoing: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if edge.get("ledger_relationship") != "pdr_transfer":
            continue
        outgoing.setdefault(str(edge.get("source")), []).append(edge)
    for transfers in outgoing.values():
        transfers.sort(key=lambda edge: _edge_time(edge) or datetime.min.replace(tzinfo=UTC))

    queue = deque([(start_id, loss_timestamp, [], {start_id})])
    while queue:
        current, last_time, path, visited = queue.popleft()
        if _cashout_node(nodes.get(current)):
            return path, current
        if len(path) >= max_hops:
            continue
        for edge in outgoing.get(current, []):
            target = str(edge.get("target"))
            if target in visited or target not in nodes:
                continue
            timestamp = _edge_time(edge)
            if last_time and timestamp and timestamp < last_time:
                continue
            # Edges without timestamps remain visible in the graph but cannot
            # support a time-ordered cash-out path.
            if timestamp is None:
                continue
            next_path = [*path, edge]
            if _cashout_node(nodes.get(target)):
                return next_path, target
            queue.append((target, timestamp, next_path, visited | {target}))
    return [], None


def build_fir_pdr_trace(graph: dict[str, Any], output: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Build the report-specific loss transfer and directed onward cash-out trace."""
    nodes = {str(n["id"]): n for n in graph.get("nodes") or []}
    edges = graph.get("edges") or []
    root_id = str(graph.get("root_id") or "")
    if not root_id and nodes:
        root_id = next((nid for nid, n in nodes.items() if n.get("type") == "report"), next(iter(nodes), ""))
    steps: list[dict[str, Any]] = []
    if root_id in nodes:
        rep = nodes[root_id]
        steps.append({
            "step": len(steps) + 1,
            "phase": "fir",
            "kind": "report",
            "node_id": root_id,
            "label": _node_label(rep),
            "source": "FIR",
            "trust_tier": trust_tier_from_status(rep.get("verification_status"), source="fir"),
            "detail": rep.get("details") or {},
        })

    report_phones = [
        n for n in nodes.values()
        if n.get("type") == "phone" and any(
            e.get("source") == root_id and e.get("target") == n.get("id") for e in edges
        )
    ]
    for phone in report_phones:
        steps.append({
            "step": len(steps) + 1,
            "phase": "fir",
            "kind": "reported_phone",
            "node_id": phone["id"],
            "label": _node_label(phone),
            "source": "FIR",
            "trust_tier": "allegation",
            "detail": {"reported_role": (phone.get("details") or {}).get("reported_role", "reported_phone")},
        })
        for edge in edges:
            if edge.get("source") != phone["id"] or edge.get("relationship_type") != "same_phone_reference":
                continue
            pdr = nodes.get(str(edge.get("target")))
            if not pdr or pdr.get("type") != "identity":
                continue
            steps.append({
                "step": len(steps) + 1,
                "phase": "pdr",
                "kind": "matched_identity",
                "node_id": pdr["id"],
                "label": _node_label(pdr),
                "source": "PDR",
                "trust_tier": "candidate",
                "edge_id": f"{edge.get('source')}:{edge.get('target')}",
                "detail": {"relationship": edge.get("relationship_type"),
                           "match_basis": "protected phone reference; identity is not proven by phone alone"},
            })

    transaction_matches = [
        match for item in (output or []) for match in (item.get("pdr_matches") or [])
        if match.get("kind") == "transaction"
    ]
    transaction_matches.sort(key=lambda match: match.get("matched_field") != "transaction reference")
    loss_match = transaction_matches[0] if transaction_matches else None
    loss_id = str(loss_match.get("record_id")) if loss_match and loss_match.get("record_id") else None
    loss_edge = next((edge for edge in edges if edge.get("ledger_relationship") == "pdr_transfer"
                      and str(edge.get("source_record_id")) == loss_id), None) if loss_id else None
    if not loss_edge:
        report_match_edge = next((edge for edge in edges if edge.get("source") == root_id and
                                  edge.get("relationship_type") in {"exact_transaction_reference", "possible_transfer_match"}), None)
        loss_id = str(((report_match_edge or {}).get("metadata") or {}).get("partner_transaction_id") or "") or None
        loss_edge = next((edge for edge in edges if edge.get("ledger_relationship") == "pdr_transfer"
                          and str(edge.get("source_record_id")) == loss_id), None) if loss_id else None

    if loss_match:
        exact_reference = loss_match.get("matched_field") == "transaction reference"
        label = f"{loss_match.get('amount', '')} {loss_match.get('currency', '')} · loss transfer"
        if loss_match.get("transaction_reference"):
            label += f" · {loss_match['transaction_reference']}"
        if loss_match.get("timestamp"):
            label += f" · {loss_match['timestamp']}"
        steps.append({
            "step": len(steps) + 1,
            "phase": "pdr",
            "kind": "exact_transaction_match" if exact_reference else "candidate_transaction_match",
            "node_id": f"pdr-transaction:{loss_id or 'unresolved'}",
            "label": label.strip(" ·"),
            "source": "PDR",
            "trust_tier": "observed" if exact_reference else "candidate",
            "detail": {**loss_match, "report_link_status": "exact_reference_match" if exact_reference else "candidate_match"},
        })
    elif loss_id:
        steps.append({
            "step": len(steps) + 1, "phase": "pdr", "kind": "candidate_transaction_match",
            "node_id": f"pdr-transaction:{loss_id}", "label": "Candidate loss transfer",
            "source": "PDR", "trust_tier": "candidate",
            "detail": {"transaction_id": loss_id, "requires_investigator_confirmation": True},
        })

    if loss_edge:
        receiver_id = str(loss_edge.get("target"))
        receiver = nodes.get(receiver_id)
        steps.append({
            "step": len(steps) + 1, "phase": "pdr", "kind": "wallet_or_account",
            "node_id": receiver_id, "label": _node_label(receiver), "source": "PDR",
            "trust_tier": "observed",
            "detail": {"role": "receiver of the reported loss transfer", "transaction_id": loss_id},
        })
        onward_edges, cashout_id = _forward_path_to_cashout(
            receiver_id, _edge_time(loss_edge), nodes, edges,
        )
        for edge in onward_edges:
            meta = edge.get("metadata") or {}
            source_label = _node_label(nodes.get(str(edge.get("source"))))
            target_label = _node_label(nodes.get(str(edge.get("target"))))
            amount = " ".join(str(value) for value in (meta.get("amount"), meta.get("currency")) if value)
            flow_label = f"{amount} · {source_label} → {target_label}"
            if meta.get("timestamp"):
                flow_label += f" · {meta['timestamp']}"
            steps.append({
                "step": len(steps) + 1, "phase": "pdr", "kind": "money_flow",
                "node_id": f"{edge.get('source')}->{edge.get('target')}",
                "label": flow_label,
                "source": "PDR", "trust_tier": "observed",
                "detail": {"transaction_id": edge.get("source_record_id"),
                           "timestamp": meta.get("timestamp"),
                           "provider": meta.get("provider"),
                           "from": source_label,
                           "to": target_label},
            })
        if cashout_id:
            cashout = nodes.get(cashout_id) or {}
            steps.append({
                "step": len(steps) + 1, "phase": "pdr", "kind": "cash_out",
                "node_id": cashout_id, "label": f"Potential cash-out agent account · {_node_label(cashout)}",
                "source": "PDR", "trust_tier": "observed",
                "detail": {"physical_withdrawal_confirmed": False,
                           "account_type": (cashout.get("details") or {}).get("account_type")},
            })
        else:
            steps.append({
                "step": len(steps) + 1, "phase": "pdr", "kind": "cash_out_not_found",
                "node_id": f"cashout-not-found:{receiver_id}",
                "label": "No time-ordered path to a cash-out agent in the observed PDR graph",
                "source": "PDR", "trust_tier": "candidate",
                "detail": {"starts_from_transaction_id": loss_id},
            })
    return steps


def detect_pattern_candidates(graph: dict[str, Any], *, window_hours: int = 72) -> list[dict[str, Any]]:
    """Find time-bounded fan-in and chronological pass-through candidates."""
    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=window_hours)
    edges: list[dict[str, Any]] = []
    for edge in graph.get("edges") or []:
        if not (edge.get("ledger_relationship") == "pdr_transfer" or (
            str(edge.get("source_repository", "")).upper() == "PDR"
            and "transfer" in str(edge.get("relationship_type", "")).lower()
        )):
            continue
        metadata = edge.get("metadata") or {}
        raw_timestamp = metadata.get("timestamp") or edge.get("timestamp")
        try:
            timestamp = datetime.fromisoformat(str(raw_timestamp).replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
        except (TypeError, ValueError):
            continue
        if timestamp < cutoff or timestamp > now:
            continue
        edges.append({**edge, "_timestamp": timestamp})
    inflow: dict[str, list[dict]] = {}
    outflow: dict[str, list[dict]] = {}
    for edge in edges:
        src, tgt = str(edge.get("source")), str(edge.get("target"))
        inflow.setdefault(tgt, []).append(edge)
        outflow.setdefault(src, []).append(edge)
    candidates: list[dict[str, Any]] = []
    for wallet, flows in inflow.items():
        ordered = sorted(flows, key=lambda edge: edge["_timestamp"])
        window_flows: list[dict[str, Any]] = []
        for anchor in ordered:
            start = anchor["_timestamp"] - timedelta(hours=window_hours)
            active = [edge for edge in ordered if start <= edge["_timestamp"] <= anchor["_timestamp"]]
            if len(active) > len(window_flows):
                window_flows = active
        senders = {e.get("source") for e in window_flows}
        if len(window_flows) >= 3 and len(senders) >= 2:
            candidates.append({
                "pattern": "fan_in",
                "status": "review_candidate",
                "wallet_entity_id": wallet,
                "inbound_transfer_count": len(window_flows),
                "distinct_senders": len(senders),
                "trust_tier": "candidate",
                "window_hours": window_hours,
                "summary": f"{len(senders)} distinct senders paid this wallet in {len(window_flows)} observed transfer(s) within {window_hours} hours.",
            })
    for wallet, ins in inflow.items():
        outs = outflow.get(wallet, [])
        chronological_pairs = [
            (in_edge, out_edge) for in_edge in ins for out_edge in outs
            if in_edge["_timestamp"] <= out_edge["_timestamp"]
            and out_edge["_timestamp"] - in_edge["_timestamp"] <= timedelta(hours=window_hours)
            and str((in_edge.get("metadata") or {}).get("currency") or "").upper()
            == str((out_edge.get("metadata") or {}).get("currency") or "").upper()
        ]
        if chronological_pairs:
            first_in, first_out = min(
                chronological_pairs,
                key=lambda pair: pair[1]["_timestamp"] - pair[0]["_timestamp"],
            )
            candidates.append({
                "pattern": "pass_through",
                "status": "review_candidate",
                "wallet_entity_id": wallet,
                "inbound_transfer_count": len({edge.get("source_record_id") for edge, _ in chronological_pairs}),
                "outbound_transfer_count": len({edge.get("source_record_id") for _, edge in chronological_pairs}),
                "trust_tier": "candidate",
                "window_hours": window_hours,
                "elapsed_seconds": int((first_out["_timestamp"] - first_in["_timestamp"]).total_seconds()),
                "summary": f"Funds arrived and left this wallet in chronological order within {window_hours} hours.",
            })
    return candidates


async def victim_entity_ids(db: AsyncSession, *, report_id: UUID | None = None) -> set[UUID]:
    rows = (await db.execute(select(IncidentEntity.entity_id).where(IncidentEntity.role == "victim"))).all()
    victims = {row[0] for row in rows}
    if report_id:
        incident_ids = (await db.scalars(select(FIRReportIncident.incident_id).where(
            FIRReportIncident.report_id == report_id,
        ))).all()
        if incident_ids:
            scoped = (await db.execute(select(IncidentEntity.entity_id).where(
                IncidentEntity.incident_id.in_(incident_ids),
                IncidentEntity.role == "victim",
            ))).all()
            victims.update(row[0] for row in scoped)
    return victims


async def confirmed_fraud_entity_ids_for_exposure(db: AsyncSession) -> set[UUID]:
    """Entities explicitly confirmed in NEXUS decisions; allegations are not seeds."""
    confirmed: set[UUID] = set()
    meta_rows = (await db.scalars(select(FraudIncident))).all()
    for incident in meta_rows:
        nexus = (incident.incident_metadata or {}).get("nexus", {})
        for value in nexus.get("confirmed_entity_ids") or []:
            try:
                confirmed.add(UUID(str(value)))
            except ValueError:
                continue
    victims = await victim_entity_ids(db)
    return confirmed - victims


async def apply_trace_decision(
    db: AsyncSession,
    report: FIRReportRecord,
    *,
    target_type: str,
    target_id: str,
    decision: str,
    role: str | None,
    actor_id: UUID,
) -> dict[str, Any]:
    """Persist confirm/reject on FIR entities and incident metadata."""
    decision = decision.lower()
    if decision not in {"confirm", "reject"}:
        return {"status": "invalid_decision"}
    entity_uuid: UUID | None = None
    if target_type == "entity":
        if target_id.startswith("fir-entity:"):
            entity_uuid = UUID(target_id.split(":", 1)[1])
        elif len(target_id) == 36:
            entity_uuid = UUID(target_id)
    if entity_uuid and decision == "confirm":
        link = await db.scalar(select(ReportEntity).where(
            ReportEntity.report_id == report.id,
            ReportEntity.entity_id == entity_uuid,
        ))
        if link:
            link.verified = True
    incident_link = await db.scalar(select(FIRReportIncident).where(
        FIRReportIncident.report_id == report.id,
    ))
    if incident_link and entity_uuid:
        incident = await db.get(FraudIncident, incident_link.incident_id)
        if incident:
            meta = dict(incident.incident_metadata or {})
            nexus = dict(meta.get("nexus", {}))
            confirmed = list(nexus.get("confirmed_entity_ids") or [])
            rejected = list(nexus.get("rejected_entity_ids") or [])
            value = str(entity_uuid)
            if decision == "confirm":
                if value not in confirmed:
                    confirmed.append(value)
                rejected = [item for item in rejected if item != value]
                if role:
                    row = await db.scalar(select(IncidentEntity).where(
                        IncidentEntity.incident_id == incident.id,
                        IncidentEntity.entity_id == entity_uuid,
                    ))
                    if row:
                        row.verification_status = "investigator_confirmed"
                        row.role = role
                    else:
                        db.add(IncidentEntity(
                            incident_id=incident.id,
                            entity_id=entity_uuid,
                            role=role,
                            confidence=0.95,
                            verification_status="investigator_confirmed",
                            details={"source": "nexus_trace_decision", "actor_id": str(actor_id)},
                        ))
            else:
                rejected.append(value)
                confirmed = [item for item in confirmed if item != value]
            nexus["confirmed_entity_ids"] = confirmed
            nexus["rejected_entity_ids"] = rejected
            nexus["last_decision_at"] = datetime.now(UTC).isoformat()
            meta["nexus"] = nexus
            incident.incident_metadata = meta
    await db.flush()
    return {"status": "recorded", "decision": decision, "target_id": target_id, "role": role}


async def build_report_trace_bundle(
    db: AsyncSession,
    report: FIRReportRecord,
    graph: dict[str, Any],
    output: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    steps = build_fir_pdr_trace(graph, output)
    patterns = detect_pattern_candidates(graph)
    incident_meta = {}
    link = await db.scalar(select(FIRReportIncident).where(FIRReportIncident.report_id == report.id))
    if link:
        incident = await db.get(FraudIncident, link.incident_id)
        if incident:
            incident_meta = (incident.incident_metadata or {}).get("nexus", {})
    return {
        "report_id": str(report.id),
        "trust_tiers": list(TRUST_TIERS),
        "steps": steps,
        "pattern_candidates": patterns,
        "investigator_decisions": {
            "confirmed_entity_ids": incident_meta.get("confirmed_entity_ids") or [],
            "rejected_entity_ids": incident_meta.get("rejected_entity_ids") or [],
        },
    }
