"""Build persisted, explainable intelligence projections from FIR and PDR data."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import ValidationFailed
from app.core.partner_secrets import protect_partner_reference
from app.core.phone import normalize_phone
from app.enums import CommunityEntityType, RiskLevel
from app.services.nexus_ledger import LEDGER_EDGE, materialize_pdr_ledger

from app.models import (
    CommunityEntity,
    CrossInstitutionSignal,
    EntityIntelligenceProfile,
    EntityRelationship,
    FIRRiskAssessment,
    IdentityResolutionCluster,
    IdentityResolutionMember,
    IncidentFinding,
    LivenessAssessment,
    Partner,
    PartnerAccount,
    PartnerIdentity,
    PartnerIntelligenceDelivery,
    PartnerTransaction,
    ReportEntity,
)


class IntelligenceLayers:
    """Refresh MVP identity, entity, graph, risk, and cross-provider projections."""

    def __init__(self, db: AsyncSession, settings: Settings):
        self.db = db
        self.settings = settings
        self.secret = settings.secret_key.get_secret_value()

    def _hash(self, value: str, namespace: str) -> str:
        return protect_partner_reference(value, namespace=namespace, application_secret=self.secret)

    async def _entity(self, kind: CommunityEntityType, value: str, display: str | None = None,
                      metadata: dict[str, Any] | None = None) -> CommunityEntity:
        row = await self.db.scalar(select(CommunityEntity).where(
            CommunityEntity.entity_type == kind, CommunityEntity.normalized_value == value,
        ))
        if row is None:
            row = CommunityEntity(entity_type=kind, normalized_value=value, display_value=display,
                                  entity_metadata=metadata or {})
            self.db.add(row)
            await self.db.flush()
        elif metadata:
            row.entity_metadata = {**(row.entity_metadata or {}), **metadata}
            if display:
                row.display_value = display
        return row

    async def _link(self, source: CommunityEntity, target: CommunityEntity, kind: str,
                    confidence: float, metadata: dict[str, Any]) -> None:
        row = await self.db.scalar(select(EntityRelationship).where(
            EntityRelationship.source_entity_id == source.id,
            EntityRelationship.target_entity_id == target.id,
            EntityRelationship.relationship_type == kind,
        ))
        if row is None:
            self.db.add(EntityRelationship(source_entity_id=source.id, target_entity_id=target.id,
                                           relationship_type=kind, confidence=confidence,
                                           relationship_metadata=metadata))
        else:
            row.confidence = max(row.confidence, confidence)
            row.relationship_metadata = {**(row.relationship_metadata or {}), **metadata}

    async def refresh_all(self) -> dict[str, int]:
        identity_count = await self._identity_intelligence()
        graph_count = await self._graph()
        signal_count = await self._cross_institution()
        entity_count = await self._entity_and_risk_intelligence()
        await self.db.flush()
        return {"identity_clusters": identity_count, "graph_entities": graph_count,
                "entity_profiles": entity_count, "cross_institution_signals": signal_count}

    async def _identity_intelligence(self) -> int:
        rows = (await self.db.execute(select(PartnerIdentity, Partner.partner_code).join(
            Partner, Partner.id == PartnerIdentity.partner_id
        ).where(Partner.partner_status == "active"))).all()
        groups: dict[tuple[str, str], list[PartnerIdentity]] = defaultdict(list)
        for identity, _code in rows:
            # National ID references are protected at ingestion; phones share a global HMAC namespace.
            if identity.national_id_reference:
                groups[("national_id", identity.national_id_reference)].append(identity)
            if identity.phone_number_reference:
                groups[("phone", identity.phone_number_reference)].append(identity)
        desired: set[tuple[str, str]] = set()
        count = 0
        for (match_type, protected_value), members in groups.items():
            partner_ids = {member.partner_id for member in members}
            if len(partner_ids) < 2:
                continue
            key = self._hash(protected_value, f"identity-cluster:{match_type}")
            desired.add((match_type, key))
            unique_members = {m.id: m for m in members}
            members = list(unique_members.values())
            verified = all(m.verified_ownership and m.verification_status == "verified" for m in members)
            # Phone sharing is an association candidate, never proof of identity.
            resolved = match_type == "national_id" and verified
            confidence = 0.98 if resolved else (0.55 if match_type == "phone" else 0.65)
            cluster = await self.db.scalar(select(IdentityResolutionCluster).where(
                IdentityResolutionCluster.match_type == match_type,
                IdentityResolutionCluster.match_key == key,
            ))
            if cluster is None:
                cluster = IdentityResolutionCluster(match_type=match_type, match_key=key,
                    resolution_status="resolved" if resolved else "candidate", confidence=confidence,
                    partner_count=len(partner_ids), identity_count=len(members), evidence={})
                self.db.add(cluster)
                await self.db.flush()
            else:
                cluster.resolution_status = "resolved" if resolved else "candidate"
                cluster.confidence = confidence
                cluster.partner_count = len(partner_ids)
                cluster.identity_count = len(members)
                cluster.evidence = {"verified_member_count": sum(
                    m.verified_ownership and m.verification_status == "verified" for m in members
                ), "match_type": match_type}
            existing = {m.partner_identity_id: m for m in (await self.db.scalars(
                select(IdentityResolutionMember).where(IdentityResolutionMember.cluster_id == cluster.id)
            )).all()}
            for member in members:
                row = existing.pop(member.id, None)
                if row is None:
                    row = IdentityResolutionMember(cluster_id=cluster.id, partner_identity_id=member.id,
                        confidence=confidence, match_evidence={"match_type": match_type,
                        "ownership_verified": bool(member.verified_ownership)})
                    self.db.add(row)
                else:
                    row.confidence = confidence
                    row.match_evidence = {"match_type": match_type,
                                          "ownership_verified": bool(member.verified_ownership)}
            for stale in existing.values():
                await self.db.delete(stale)
            count += 1
        # A full rebuild resolves old cluster rows that no longer have multi-provider support.
        for cluster in (await self.db.scalars(select(IdentityResolutionCluster))).all():
            if (cluster.match_type, cluster.match_key) not in desired:
                cluster.resolution_status = "candidate"
                cluster.confidence = 0.0
                cluster.partner_count = 1
                cluster.identity_count = 1
                cluster.evidence = {"inactive": True, "reason": "No longer supported by multi-provider data."}
                stale_members = (await self.db.scalars(select(IdentityResolutionMember).where(
                    IdentityResolutionMember.cluster_id == cluster.id))).all()
                for member in stale_members:
                    await self.db.delete(member)
        return count

    async def _graph(self) -> int:
        count = await materialize_pdr_ledger(self.db, self.settings)
        # Bridge FIR phone entities to protected PDR phone references without copying raw
        # phone values into partner identity or account rows.
        fir_phone_entities = (await self.db.scalars(select(CommunityEntity).where(
            CommunityEntity.entity_type == CommunityEntityType.PHONE))).all()
        for fir_phone in fir_phone_entities:
            value = fir_phone.normalized_value
            if value.startswith("pdr-phone:"):
                continue
            try:
                normalized = normalize_phone(value, self.settings.default_calling_code)
            except ValidationFailed:
                continue
            protected_phone = self._hash(normalized, "phone")
            pdr_phone = await self.db.scalar(select(CommunityEntity).where(
                CommunityEntity.entity_type == CommunityEntityType.PHONE,
                CommunityEntity.normalized_value == f"pdr-phone:{protected_phone}"))
            if pdr_phone:
                await self._link(fir_phone, pdr_phone, "same_phone_reference", 0.9,
                                 {"source": "protected_reference_match"})
        return count

    async def _all_entities(self) -> list[CommunityEntity]:
        return (await self.db.scalars(select(CommunityEntity))).all()

    async def _entity_and_risk_intelligence(self) -> int:
        entities = (await self.db.scalars(select(CommunityEntity))).all()
        entity_by_id = {entity.id: entity for entity in entities}
        report_links = (await self.db.execute(select(ReportEntity.entity_id, ReportEntity.report_id))).all()
        report_ids_by_entity: dict[UUID, set[UUID]] = defaultdict(set)
        for linked_entity_id, linked_report_id in report_links:
            report_ids_by_entity[linked_entity_id].add(linked_report_id)
        liveness_rows = (await self.db.scalars(select(LivenessAssessment).where(
            LivenessAssessment.entity_id.is_not(None)).order_by(LivenessAssessment.assessed_at.desc()))).all()
        liveness_by_entity: dict[UUID, LivenessAssessment] = {}
        for assessment in liveness_rows:
            liveness_by_entity.setdefault(assessment.entity_id, assessment)
        active_signals = (await self.db.scalars(select(CrossInstitutionSignal).where(
            CrossInstitutionSignal.status == "active"))).all()
        for entity in entities:
            direct_report_count = len(report_ids_by_entity[entity.id])
            links = await self.db.execute(select(
                EntityRelationship.source_entity_id,
                EntityRelationship.target_entity_id,
                EntityRelationship.relationship_type,
                EntityRelationship.relationship_metadata,
            ).where(
                (EntityRelationship.source_entity_id == entity.id)
                | (EntityRelationship.target_entity_id == entity.id),
            ))
            link_rows = links.all()
            partners: set[str] = set()
            if entity.entity_metadata and entity.entity_metadata.get("partner_code"):
                partners.add(entity.entity_metadata["partner_code"])
            transactions = 0
            inbound = 0
            outbound = 0
            inbound_counterparties: set[UUID] = set()
            outbound_counterparties: set[UUID] = set()
            neighbor_ids = {entity.id}
            for source_id, target_id, rel_type, metadata in link_rows:
                metadata = metadata or {}
                partners.update(metadata.get("partner_codes", []))
                for code in (metadata.get("sender_partner_code"), metadata.get("receiver_partner_code")):
                    if code:
                        partners.add(code)
                if "partner_code" in metadata:
                    partners.add(metadata["partner_code"])
                neighbor_id = target_id if source_id == entity.id else source_id
                neighbor_ids.add(neighbor_id)
                neighbor = entity_by_id.get(neighbor_id)
                if neighbor and neighbor.entity_metadata:
                    partner_code = neighbor.entity_metadata.get("partner_code")
                    if partner_code:
                        partners.add(partner_code)
                if metadata.get("source") == "partner_transactions" or rel_type == LEDGER_EDGE:
                    count = int(metadata.get("transaction_count", 1))
                    transactions += count
                    if source_id == entity.id:
                        outbound += count
                        outbound_counterparties.add(target_id)
                    if target_id == entity.id:
                        inbound += count
                        inbound_counterparties.add(source_id)
            linked_report_ids = set().union(*(report_ids_by_entity[neighbor_id] for neighbor_id in neighbor_ids))
            linked_report_count = len(linked_report_ids)
            fir_risks = (await self.db.scalars(select(FIRRiskAssessment).join(
                ReportEntity, ReportEntity.report_id == FIRRiskAssessment.report_id
            ).where(ReportEntity.entity_id.in_(neighbor_ids)).order_by(FIRRiskAssessment.created_at.desc()))).all()
            findings = (await self.db.scalars(select(IncidentFinding).join(
                ReportEntity, ReportEntity.report_id == IncidentFinding.report_id
            ).where(ReportEntity.entity_id.in_(neighbor_ids)))).all()
            finding_types = {"pattern": 0, "behaviour": 0}
            for finding in findings:
                if finding.finding_type in finding_types and finding.confidence >= 0.5:
                    finding_types[finding.finding_type] += 1
            fir_score = max((item.risk_score for item in fir_risks), default=0.0)
            fir_confidence = max((item.confidence for item in fir_risks), default=0.0)
            liveness = liveness_by_entity.get(entity.id)
            relevant_signals = [signal for signal in active_signals if str(entity.id) in (signal.entity_ids or [])]
            graph_score = max((signal.score for signal in relevant_signals), default=0.0)
            # Explanatory MVP score uses FIR assessments and corroborated graph activity; no ML claim.
            reasons: list[str] = []
            risk = min(0.99, max(fir_score, graph_score, linked_report_count * 0.12 + min(transactions, 10) * 0.025
                + max(0, len(partners)-1) * 0.04 + min(sum(finding_types.values()), 4) * 0.025))
            if liveness and liveness.liveness_status == "spoof":
                risk = min(0.99, max(risk, 0.85 * liveness.confidence))
            confidence = min(0.95, max(fir_confidence,
                min(linked_report_count, 3) * 0.15 + min(transactions, 5) * 0.05
                + max(0, len(partners) - 1) * 0.1))
            if liveness and liveness.liveness_status == "spoof":
                confidence = max(confidence, liveness.confidence)
            if linked_report_count:
                reasons.append(f"Linked through the entity graph to {linked_report_count} FIR report(s).")
            if fir_risks:
                reasons.extend(fir_risks[0].reasons[:3])
            if finding_types["pattern"]:
                reasons.append(f"{finding_types['pattern']} shared pattern finding(s) support this profile.")
            if finding_types["behaviour"]:
                reasons.append(f"{finding_types['behaviour']} shared behavioural finding(s) support this profile.")
            if transactions:
                reasons.append(f"Observed in {transactions} successful partner transaction(s).")
            if len(partners) > 1:
                reasons.append(f"Associated with {len(partners)} partner institutions.")
            if liveness and liveness.liveness_status == "spoof":
                reasons.append(f"Trusted liveness provider reported a spoof result ({liveness.confidence:.0%} confidence).")
            if relevant_signals:
                reasons.extend(reason for signal in relevant_signals for reason in (signal.reasons or [])[:2])
            level = RiskLevel.CRITICAL if risk >= .8 else RiskLevel.HIGH if risk >= .6 else RiskLevel.MEDIUM if risk >= .3 else RiskLevel.LOW
            profile = await self.db.scalar(select(EntityIntelligenceProfile).where(EntityIntelligenceProfile.entity_id == entity.id))
            summary = {"inbound_transactions": inbound, "outbound_transactions": outbound,
                       "linked_report_count": linked_report_count,
                       "distinct_inbound_counterparties": len(inbound_counterparties),
                       "distinct_outbound_counterparties": len(outbound_counterparties),
                       "pattern_findings": finding_types["pattern"],
                       "behaviour_findings": finding_types["behaviour"],
                       "entity_type": entity.entity_type.value, "source": "fir+pdr_projection"}
            if profile is None:
                profile = EntityIntelligenceProfile(entity_id=entity.id)
                self.db.add(profile)
            profile.partner_count = len(partners)
            profile.transaction_count = transactions
            profile.report_count = direct_report_count
            profile.linked_entity_count = len({(s if t == entity.id else t) for s, t, _r, _m in link_rows})
            profile.activity_summary = summary
            profile.ai_features = {
                "fir_risk_score": fir_score,
                "fir_risk_confidence": fir_confidence,
                "pattern_findings": finding_types["pattern"],
                "behaviour_findings": finding_types["behaviour"],
                "latest_liveness": ({"status": liveness.liveness_status,
                    "confidence": liveness.confidence, "provider": liveness.provider_name,
                    "assessed_at": liveness.assessed_at.isoformat()} if liveness else None),
            }
            profile.graph_features = {
                "distinct_inbound_counterparties": len(inbound_counterparties),
                "distinct_outbound_counterparties": len(outbound_counterparties),
                "partner_count": len(partners), "transaction_count": transactions,
                "active_signal_types": sorted({signal.signal_type for signal in relevant_signals}),
                "graph_signal_score": graph_score,
            }
            profile.fusion_version = "ai-graph-fusion.v1"
            profile.risk_score = risk
            profile.risk_level = level
            profile.risk_confidence = confidence
            profile.risk_reasons = reasons
            profile.computed_at = datetime.now(UTC)
            if risk >= 0.6 and partners and not any(signal.score >= 0.6 for signal in relevant_signals):
                window = datetime.now(UTC).date().isoformat()
                signal_key = hashlib.sha256(f"entity-risk:{entity.id}:{window}".encode()).hexdigest()
                risk_signal = await self.db.scalar(select(CrossInstitutionSignal).where(
                    CrossInstitutionSignal.signal_key == signal_key))
                risk_reasons = list(dict.fromkeys(reasons))[:5]
                if risk_signal is None:
                    risk_signal = CrossInstitutionSignal(signal_key=signal_key,
                        signal_type="real_time_entity_risk", risk_level=level,
                        score=risk, confidence=confidence, partner_codes=sorted(partners),
                        entity_ids=[str(entity.id)], reasons=risk_reasons,
                        evidence={"fusion_version": profile.fusion_version,
                                  "source_count": sum((bool(fir_risks), bool(sum(finding_types.values())),
                                                       bool(transactions), bool(liveness)))})
                    self.db.add(risk_signal)
                else:
                    risk_signal.status = "active"
                    risk_signal.risk_level = level
                    risk_signal.score = risk
                    risk_signal.confidence = confidence
                    risk_signal.partner_codes = sorted(partners)
                    risk_signal.entity_ids = [str(entity.id)]
                    risk_signal.reasons = risk_reasons
                    risk_signal.last_seen_at = datetime.now(UTC)
                await self._queue_partner_deliveries(risk_signal)
        return len(entities)

    async def _cross_institution(self) -> int:
        for old_signal in (await self.db.scalars(select(CrossInstitutionSignal).where(
            CrossInstitutionSignal.status == "active"))).all():
            old_signal.status = "resolved"
        clusters = (await self.db.scalars(select(IdentityResolutionCluster).where(
            IdentityResolutionCluster.partner_count >= 2))).all()
        count = 0
        for cluster in clusters:
            members = (await self.db.execute(select(IdentityResolutionMember, Partner.partner_code).join(
                PartnerIdentity, PartnerIdentity.id == IdentityResolutionMember.partner_identity_id
            ).join(Partner, Partner.id == PartnerIdentity.partner_id).where(
                IdentityResolutionMember.cluster_id == cluster.id))).all()
            codes = sorted({code for _, code in members})
            if len(codes) < 2:
                continue
            signal_key = hashlib.sha256(f"identity:{cluster.match_type}:{cluster.match_key}".encode()).hexdigest()
            signal = await self.db.scalar(select(CrossInstitutionSignal).where(CrossInstitutionSignal.signal_key == signal_key))
            resolved = cluster.resolution_status == "resolved"
            level = RiskLevel.LOW
            reasons = [f"A protected {cluster.match_type.replace('_', ' ')} reference appears at {len(codes)} partner institutions."]
            if not resolved:
                reasons.append("This is an association candidate and does not establish common ownership.")
            evidence = {"match_type": cluster.match_type, "partner_count": len(codes),
                        "identity_count": cluster.identity_count, "resolution_status": cluster.resolution_status}
            canonical_entity_id = await self.db.scalar(select(CommunityEntity.id).where(
                CommunityEntity.entity_type == CommunityEntityType.PERSON,
                CommunityEntity.normalized_value == f"identity-cluster:{cluster.match_type}:{cluster.match_key}",
            ))
            signal_entities = [str(canonical_entity_id)] if canonical_entity_id else []
            if signal is None:
                signal = CrossInstitutionSignal(signal_key=signal_key, signal_type="cross_provider_identity",
                    risk_level=level, score=0.0, confidence=cluster.confidence, partner_codes=codes,
                    entity_ids=signal_entities, reasons=reasons, evidence=evidence)
                self.db.add(signal)
            else:
                signal.status = "active"
                signal.risk_level = level
                signal.score = 0.0
                signal.confidence = cluster.confidence
                signal.partner_codes = codes
                signal.entity_ids = signal_entities
                signal.reasons = reasons
                signal.evidence = evidence
                signal.last_seen_at = datetime.now(UTC)
            await self._queue_partner_deliveries(signal)
            count += 1
        # Transfers spanning more than one registered provider are recorded as observed
        # cross-institution activity, not labeled as fraud without additional evidence.
        transfers = (await self.db.scalars(select(EntityRelationship).where(
            EntityRelationship.relationship_type == "transferred_to"))).all()
        for edge in transfers:
            evidence = edge.relationship_metadata or {}
            codes = sorted(set(evidence.get("partner_codes", [])))
            if len(codes) < 2:
                continue
            signal_key = hashlib.sha256(
                f"transfer:{edge.source_entity_id}:{edge.target_entity_id}".encode()
            ).hexdigest()
            signal = await self.db.scalar(select(CrossInstitutionSignal).where(
                CrossInstitutionSignal.signal_key == signal_key))
            reasons = ["Successful transfers connect accounts associated with multiple partner institutions."]
            if signal is None:
                signal = CrossInstitutionSignal(signal_key=signal_key,
                    signal_type="cross_institution_transfer", risk_level=RiskLevel.LOW,
                    score=0.0, confidence=edge.confidence, partner_codes=codes,
                    entity_ids=[str(edge.source_entity_id), str(edge.target_entity_id)],
                    reasons=reasons, evidence=evidence)
                self.db.add(signal)
            else:
                signal.status = "active"
                signal.partner_codes = codes
                signal.entity_ids = [str(edge.source_entity_id), str(edge.target_entity_id)]
                signal.reasons = reasons
                signal.evidence = evidence
                signal.last_seen_at = datetime.now(UTC)
            await self._queue_partner_deliveries(signal)
            count += 1
        count += await self._detect_mule_candidates()
        return count

    async def _queue_partner_deliveries(self, signal: CrossInstitutionSignal) -> None:
        await self.db.flush()
        partner_codes = set(signal.partner_codes or [])
        if not partner_codes:
            return
        partners = (await self.db.scalars(select(Partner).where(
            Partner.partner_code.in_(partner_codes), Partner.partner_status == "active"))).all()
        payload = {
            "signal_id": str(signal.id), "signal_type": signal.signal_type,
            "risk_level": signal.risk_level.value, "score": signal.score,
            "confidence": signal.confidence, "partner_codes": sorted(partner_codes),
            "reasons": signal.reasons or [], "created_at": signal.created_at.isoformat(),
        }
        for partner in partners:
            delivery = await self.db.scalar(select(PartnerIntelligenceDelivery).where(
                PartnerIntelligenceDelivery.partner_id == partner.id,
                PartnerIntelligenceDelivery.signal_id == signal.id,
            ))
            if delivery is None:
                self.db.add(PartnerIntelligenceDelivery(partner_id=partner.id,
                    signal_id=signal.id, payload=payload))
            elif delivery.delivery_status == "pending":
                delivery.payload = payload

    async def _detect_mule_candidates(self) -> int:
        """Detect high fan-in/fan-out accounts across providers in a rolling 24-hour window."""
        now = datetime.now(UTC)
        cutoff = now - timedelta(hours=24)
        account_rows = (await self.db.execute(select(
            PartnerAccount.id, Partner.partner_code, PartnerAccount.account_identifier
        ).join(Partner, Partner.id == PartnerAccount.partner_id))).all()
        account_entities: dict[UUID, UUID] = {}
        for account_id, partner_code, account_reference in account_rows:
            entity_id = await self.db.scalar(select(CommunityEntity.id).where(
                CommunityEntity.normalized_value == f"pdr-account:{partner_code}:{account_reference}"
            ))
            if entity_id:
                account_entities[account_id] = entity_id
        recent = (await self.db.scalars(select(PartnerTransaction).where(
            PartnerTransaction.transaction_status == "successful",
            PartnerTransaction.transaction_datetime >= cutoff,
        ))).all()
        activity: dict[UUID, dict[str, Any]] = {}
        for transaction in recent:
            sender, receiver = transaction.sender_account_id, transaction.receiver_account_id
            if sender not in account_entities or receiver not in account_entities or sender == receiver:
                continue
            outgoing = activity.setdefault(sender, {"in": set(), "out": set(), "partners": set(), "count": 0})
            incoming = activity.setdefault(receiver, {"in": set(), "out": set(), "partners": set(), "count": 0})
            outgoing["out"].add(receiver)
            incoming["in"].add(sender)
            outgoing["partners"].update((transaction.sender_partner_code, transaction.receiver_partner_code))
            incoming["partners"].update((transaction.sender_partner_code, transaction.receiver_partner_code))
            outgoing["count"] += 1
            incoming["count"] += 1

        detected = 0
        for account_id, metrics in activity.items():
            inbound_count, outbound_count = len(metrics["in"]), len(metrics["out"])
            partner_codes = sorted(set(metrics["partners"]))
            if inbound_count < 3 or outbound_count < 3 or len(partner_codes) < 2:
                continue
            entity_id = account_entities[account_id]
            score = min(0.9, 0.45 + min(inbound_count, 10) * 0.02
                        + min(outbound_count, 10) * 0.02
                        + min(len(partner_codes) - 1, 3) * 0.04)
            signal_key = hashlib.sha256(
                f"mule-candidate:{entity_id}:{now.date().isoformat()}".encode()
            ).hexdigest()
            signal = await self.db.scalar(select(CrossInstitutionSignal).where(
                CrossInstitutionSignal.signal_key == signal_key))
            reasons = ["Account shows high transaction fan-in and fan-out across multiple providers in the last 24 hours.",
                       "This is a review candidate, not a confirmed mule finding."]
            evidence = {"window_hours": 24, "inbound_counterparties": inbound_count,
                        "outbound_counterparties": outbound_count,
                        "transaction_count": metrics["count"], "partner_count": len(partner_codes)}
            if signal is None:
                signal = CrossInstitutionSignal(signal_key=signal_key,
                    signal_type="mule_network_candidate",
                    risk_level=RiskLevel.HIGH if score >= 0.6 else RiskLevel.MEDIUM,
                    score=score, confidence=0.65, partner_codes=partner_codes,
                    entity_ids=[str(entity_id)], reasons=reasons, evidence=evidence)
                self.db.add(signal)
            else:
                signal.status = "active"
                signal.risk_level = RiskLevel.HIGH if score >= 0.6 else RiskLevel.MEDIUM
                signal.score = score
                signal.confidence = 0.65
                signal.partner_codes = partner_codes
                signal.entity_ids = [str(entity_id)]
                signal.reasons = reasons
                signal.evidence = evidence
                signal.last_seen_at = now
            await self._queue_partner_deliveries(signal)
            detected += 1
        return detected
