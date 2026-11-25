"""PDR/FIR identifier search for NEXUS."""
from typing import Literal
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import ValidationFailed
from app.core.partner_secrets import protect_partner_reference
from app.core.phone import normalize_phone
from app.enums import CommunityEntityType
from app.models import (
    CommunityEntity,
    FIRReportRecord,
    Partner,
    PartnerAccount,
    PartnerIdentity,
    PartnerTransaction,
    ReportEntity,
)


async def search_pdr_identifiers(
    db: AsyncSession,
    settings: Settings,
    query: str,
    kind: Literal["all", "person", "business", "phone", "account", "wallet", "transaction", "agent", "report"] = "all",
    include_fir: bool = True,
) -> dict:
    value = query.strip()
    if not value:
        return {"items": [], "count": 0}
    secret = settings.secret_key.get_secret_value()
    partners = (await db.scalars(select(Partner).order_by(Partner.partner_name))).all()
    identity_refs = {partner.id: protect_partner_reference(value,
        namespace=f"{partner.partner_code}:identity", application_secret=secret) for partner in partners}
    account_refs = {partner.id: protect_partner_reference(value,
        namespace=f"{partner.partner_code}:account", application_secret=secret) for partner in partners}
    ownership_refs = {partner.id: protect_partner_reference(value,
        namespace=f"{partner.partner_code}:ownership", application_secret=secret) for partner in partners}
    transaction_refs = {partner.id: protect_partner_reference(value,
        namespace=f"{partner.partner_code}:transaction", application_secret=secret) for partner in partners}
    protected_national_id = protect_partner_reference(value, namespace="national_id", application_secret=secret)
    protected_phone = None
    try:
        normalized_phone = normalize_phone(value, settings.default_calling_code)
        protected_phone = protect_partner_reference(normalized_phone, namespace="phone", application_secret=secret)
    except ValidationFailed:
        pass

    matches: list[dict] = []
    graph_keys: set[str] = set()

    identity_conditions = [PartnerIdentity.identity_reference.in_(identity_refs.values()),
        PartnerIdentity.national_id_reference == protected_national_id,
        PartnerIdentity.phone_number_reference == value]
    if protected_phone:
        identity_conditions.append(PartnerIdentity.phone_number_reference == protected_phone)
    identity_rows = (await db.execute(select(PartnerIdentity, Partner).join(
        Partner, Partner.id == PartnerIdentity.partner_id).where(or_(*identity_conditions))
        .order_by(Partner.partner_name).limit(50))).all() if kind in {"all", "person", "agent", "phone"} else []
    for identity, partner in identity_rows:
        if identity.identity_reference == identity_refs[partner.id]:
            matched_field = "identity reference"
        elif identity.national_id_reference == protected_national_id:
            matched_field = "national ID reference"
        elif identity.phone_number_reference == value or (
            protected_phone and identity.phone_number_reference == protected_phone
        ):
            matched_field = "phone number"
        else:
            matched_field = "national ID reference"
        graph_key = f"pdr-identity:{partner.partner_code}:{identity.identity_reference}"
        graph_keys.add(graph_key)
        matches.append({"kind": "identity", "title": f"Identity · {partner.partner_name}",
            "partner": partner.partner_name, "matched_field": matched_field,
            "summary": f"{identity.verification_status} · ownership {'verified' if identity.verified_ownership else 'not verified'}",
            "verification_status": identity.verification_status,
            "verified_ownership": identity.verified_ownership, "record_id": str(identity.id),
            "_graph_key": graph_key})

    account_conditions = [PartnerAccount.account_identifier.in_(account_refs.values()),
        PartnerAccount.ownership_reference.in_(ownership_refs.values())]
    account_rows = (await db.execute(select(PartnerAccount, Partner).join(
        Partner, Partner.id == PartnerAccount.partner_id).where(or_(*account_conditions))
        .order_by(Partner.partner_name).limit(50))).all() if kind in {"all", "account", "wallet"} else []
    for account, partner in account_rows:
        matched_field = "account identifier" if account.account_identifier == account_refs[partner.id] else "ownership reference"
        graph_key = f"pdr-account:{partner.partner_code}:{account.account_identifier}"
        graph_keys.add(graph_key)
        matches.append({"kind": "account", "title": f"{account.account_type} account · {partner.partner_name}",
            "partner": partner.partner_name, "matched_field": matched_field,
            "summary": f"{account.account_status} · {account.service_provider}",
            "account_type": account.account_type, "account_status": account.account_status,
            "service_provider": account.service_provider, "record_id": str(account.id),
            "_graph_key": graph_key})

    transaction_conditions = [PartnerTransaction.transaction_reference.in_(transaction_refs.values()),
        PartnerTransaction.sender_account_reference.in_(account_refs.values()),
        PartnerTransaction.receiver_account_reference.in_(account_refs.values())]
    transaction_rows = (await db.execute(select(PartnerTransaction, Partner).join(
        Partner, Partner.id == PartnerTransaction.partner_id).where(or_(*transaction_conditions))
        .order_by(PartnerTransaction.transaction_datetime.desc()).limit(50))).all() if kind in {"all", "transaction"} else []
    for transaction, partner in transaction_rows:
        if transaction.transaction_reference == transaction_refs[partner.id]:
            matched_field = "transaction reference"
        elif transaction.sender_account_reference in account_refs.values():
            matched_field = "sender account reference"
        else:
            matched_field = "receiver account reference"
        sender_key = f"pdr-account:{transaction.sender_partner_code}:{transaction.sender_account_reference}"
        receiver_key = f"pdr-account:{transaction.receiver_partner_code}:{transaction.receiver_account_reference}"
        graph_keys.update((sender_key, receiver_key))
        matches.append({"kind": "transaction", "title": f"Transaction · {partner.partner_name}",
            "partner": partner.partner_name, "matched_field": matched_field,
            "summary": f"{transaction.transaction_status} · {transaction.amount} {transaction.currency}",
            "amount": str(transaction.amount), "currency": transaction.currency,
            "transaction_status": transaction.transaction_status,
            "timestamp": transaction.transaction_datetime.isoformat(),
            "record_id": str(transaction.id),
            "_graph_keys": [sender_key, receiver_key]})

    if graph_keys:
        entity_rows = (await db.execute(select(CommunityEntity.normalized_value, CommunityEntity.id)
            .where(CommunityEntity.normalized_value.in_(graph_keys)))).all()
        entity_ids = {key: str(entity_id) for key, entity_id in entity_rows}
    else:
        entity_ids = {}
    for item in matches:
        key = item.pop("_graph_key", None)
        related_keys = item.pop("_graph_keys", [])
        item["entity_id"] = entity_ids.get(key) if key else next(
            (entity_ids[k] for k in related_keys if k in entity_ids), None)
        item["related_entity_ids"] = list(dict.fromkeys(entity_ids[k] for k in related_keys if k in entity_ids))
    pdr_kinds = {"person": {"identity"}, "agent": {"identity"},
        "phone": {"identity"}, "account": {"account"}, "wallet": {"account"},
        "transaction": {"transaction"}, "business": set(), "report": set(), "all": None}
    if kind != "all":
        matches = [item for item in matches if item["kind"] in pdr_kinds[kind]]
        if kind in {"account", "wallet"}:
            matches = [item for item in matches if ("wallet" in str(item.get("account_type", "")).lower()
                or "momo" in str(item.get("account_type", "")).lower()) == (kind == "wallet")]

    items = [{**item, "source": "pdr"} for item in matches]
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped}%"
    if include_fir and kind in {"all", "person", "business", "phone", "account", "wallet", "agent"} and len(value) >= 2:
        entity_type_map = {"person": [CommunityEntityType.PERSON],
            "business": [CommunityEntityType.ORGANIZATION], "phone": [CommunityEntityType.PHONE],
            "account": [CommunityEntityType.ACCOUNT], "wallet": [CommunityEntityType.WALLET],
            "agent": [CommunityEntityType.PERSON]}
        entity_types = entity_type_map.get(kind, [CommunityEntityType.PERSON, CommunityEntityType.ORGANIZATION,
            CommunityEntityType.PHONE, CommunityEntityType.ACCOUNT, CommunityEntityType.WALLET,
            CommunityEntityType.LINK, CommunityEntityType.EMAIL])
        protected_kinds = {
            "all": ("national_id", "identity", "account", "wallet", "email"),
            "person": ("national_id", "identity"),
            "account": ("account",),
            "wallet": ("wallet",),
        }.get(kind, ())
        exact_entity_values = [
            f"fir-extracted:{protected_kind}:" + protect_partner_reference(
                value, namespace=f"fir-extracted:{protected_kind}", application_secret=secret
            )
            for protected_kind in protected_kinds
        ]
        try:
            exact_entity_values.append(normalize_phone(value, settings.default_calling_code))
        except ValidationFailed:
            pass
        graph_rows = (await db.execute(select(CommunityEntity,
            func.count(func.distinct(ReportEntity.report_id)).label("report_count")
        ).outerjoin(ReportEntity, ReportEntity.entity_id == CommunityEntity.id)
         .where(CommunityEntity.entity_type.in_(entity_types), or_(
            CommunityEntity.display_value.ilike(pattern, escape="\\"),
            CommunityEntity.normalized_value.ilike(pattern, escape="\\"),
            CommunityEntity.normalized_value.in_(exact_entity_values) if exact_entity_values else False))
         .group_by(CommunityEntity.id).order_by(func.count(func.distinct(ReportEntity.report_id)).desc(),
            CommunityEntity.updated_at.desc()).limit(50))).all()
        for entity, report_count in graph_rows:
            # PDR graph nodes contain protected references and are returned only by exact PDR matching.
            if entity.entity_metadata.get("source") == "pdr" or entity.normalized_value.startswith("pdr-"):
                continue
            entity_kind = {CommunityEntityType.PERSON: "agent" if kind == "agent" else "person",
                CommunityEntityType.ORGANIZATION: "business", CommunityEntityType.PHONE: "phone",
                CommunityEntityType.ACCOUNT: "account", CommunityEntityType.WALLET: "wallet",
                CommunityEntityType.LINK: "link", CommunityEntityType.EMAIL: "email"}[entity.entity_type]
            if kind == "wallet" and entity.entity_type != CommunityEntityType.WALLET:
                continue
            exact = str(entity.display_value or "").casefold() == value.casefold()
            items.append({"kind": "entity", "source": "fir", "entity_type": entity_kind,
                "title": entity.display_value or f"{entity_kind.title()} entity",
                "matched_field": "exact entity name" if exact else "partial entity match",
                "summary": f"FIR graph entity · {report_count} linked report(s)",
                "entity_id": str(entity.id), "report_count": report_count})

    if include_fir and kind in {"all", "report"} and len(value) >= 2:
        reports = (await db.scalars(select(FIRReportRecord).where(or_(
            FIRReportRecord.subject.ilike(pattern, escape="\\"),
            FIRReportRecord.description.ilike(pattern, escape="\\"),
            FIRReportRecord.category.ilike(pattern, escape="\\")))
            .order_by(FIRReportRecord.created_at.desc()).limit(50))).all()
        items.extend({"kind": "report", "source": "fir", "title": row.subject or "FIR report",
            "matched_field": "report text", "summary": f"{row.status} · {row.category or 'Unclassified'} · {row.created_at.date()}",
            "record_id": str(row.id), "report_type": row.report_type, "status": row.status,
            "category": row.category, "created_at": row.created_at.isoformat(),
            "case_id": str(row.case_id) if row.case_id else None} for row in reports)

    # A stable score puts protected exact PDR matches first, followed by graph and report matches.
    order = {"pdr": 0, "fir": 1}
    items.sort(key=lambda item: (order.get(item["source"], 2), item["kind"] != "report"))
    items = items[:100]
    return {"items": items, "count": len(items), "query": value, "kind": kind}

