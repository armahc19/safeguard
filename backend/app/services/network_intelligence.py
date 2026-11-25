"""Fraud-network correlation without exposing reporter identities."""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.phone import normalize_phone
from app.models import NetworkLink
from app.services.identity_intelligence import IdentityAnalysis
from app.services.pattern_intelligence import PatternAnalysis


@dataclass(frozen=True)
class NetworkSnapshot:
    number: str
    link_count: int
    network_score: float
    related_patterns: tuple[str, ...]
    campaigns: tuple[str, ...]
    reasons: tuple[str, ...]


class NetworkService:
    def __init__(self, db: AsyncSession, default_calling_code: str = "233") -> None:
        self.db = db
        self.default_calling_code = default_calling_code

    def normalize_number(self, value: str) -> str:
        return normalize_phone(value, self.default_calling_code)

    async def link(
        self,
        *,
        source_type: str,
        source_value: str,
        target_type: str,
        target_value: str,
        relation: str,
        confidence: float,
        case_id: UUID | None = None,
        metadata: dict[str, object] | None = None,
    ) -> NetworkLink:
        existing = await self.db.scalar(select(NetworkLink).where(
            NetworkLink.source_type == source_type,
            NetworkLink.source_value == source_value,
            NetworkLink.target_type == target_type,
            NetworkLink.target_value == target_value,
            NetworkLink.relation == relation,
        ))
        confidence = min(1.0, max(0.0, confidence))
        if existing is not None:
            existing.confidence = max(existing.confidence, confidence)
            if case_id is not None:
                existing.case_id = case_id
            if metadata:
                existing.link_metadata = {**existing.link_metadata, **metadata}
            return existing
        link = NetworkLink(
            source_type=source_type, source_value=source_value,
            target_type=target_type, target_value=target_value,
            relation=relation, case_id=case_id, confidence=confidence,
            link_metadata=metadata or {},
        )
        self.db.add(link)
        await self.db.flush()
        return link

    async def record_report(self, number: str, report_id: UUID, case_id: UUID | None) -> None:
        await self.link(
            source_type="phone", source_value=self.normalize_number(number),
            target_type="report", target_value=str(report_id), relation="reported_in",
            confidence=0.5, case_id=case_id,
        )

    async def record_patterns(
        self, number: str, analysis: PatternAnalysis, case_id: UUID | None,
    ) -> None:
        normalized = self.normalize_number(number)
        for match in analysis.selected:
            await self.link(
                source_type="phone", source_value=normalized,
                target_type="pattern", target_value=match.pattern_id,
                relation="matches_pattern", confidence=match.probability, case_id=case_id,
                metadata={"name": match.name, "category": match.category},
            )
        if analysis.selected:
            await self.link(
                source_type="phone", source_value=normalized,
                target_type="campaign", target_value=analysis.campaign_fingerprint,
                relation="matches_campaign", confidence=analysis.hazard, case_id=case_id,
                metadata={"model_version": analysis.model_version},
            )

    async def record_identity(
        self, number: str, analysis: IdentityAnalysis, case_id: UUID | None,
    ) -> None:
        if not analysis.claimed_identity:
            return
        await self.link(
            source_type="phone", source_value=self.normalize_number(number),
            target_type="identity", target_value=analysis.claimed_identity,
            relation="claims_identity", confidence=analysis.identity_score, case_id=case_id,
            metadata={"label": analysis.label, "official_domain_match": analysis.official_domain_match},
        )

    async def snapshot(self, number: str) -> NetworkSnapshot:
        normalized = self.normalize_number(number)
        links = (await self.db.scalars(select(NetworkLink).where(or_(
            (NetworkLink.source_type == "phone") & (NetworkLink.source_value == normalized),
            (NetworkLink.target_type == "phone") & (NetworkLink.target_value == normalized),
        )))).all()
        suspicious = [link for link in links if link.relation in {"matches_pattern", "matches_campaign", "claims_identity"}]
        patterns = tuple(sorted({link.target_value for link in suspicious if link.target_type == "pattern"}))
        campaigns = tuple(sorted({link.target_value for link in suspicious if link.target_type == "campaign"}))
        score = round(min(1.0, max((link.confidence for link in suspicious), default=0.0) * 0.7
                          + min(0.3, len(suspicious) * 0.05)), 4)
        reasons = []
        if patterns:
            reasons.append(f"number matches {len(patterns)} known fraud pattern(s)")
        if campaigns:
            reasons.append(f"number is linked to {len(campaigns)} campaign fingerprint(s)")
        if any(link.relation == "claims_identity" for link in suspicious):
            reasons.append("number is linked to an identity claim")
        return NetworkSnapshot(
            number=normalized, link_count=len(links), network_score=score,
            related_patterns=patterns, campaigns=campaigns, reasons=tuple(reasons),
        )

