"""Adapter boundary that validates and normalizes partner data before core ingestion."""
import hashlib
import secrets
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.exceptions import ConflictError
from app.core.partner_secrets import (
    encrypt_partner_payload,
    encrypt_partner_secret,
    protect_partner_reference,
)
from app.core.phone import normalize_phone
from app.models import (
    Partner,
    PartnerAccount,
    PartnerIdentity,
    PartnerSubmission,
    PartnerTransaction,
)
from app.schemas.partners import (
    PartnerCreate,
    PartnerCreated,
    PartnerDataSubmissionIn,
    PartnerSubmissionOut,
)


@dataclass(frozen=True)
class PartnerContext:
    partner_id: UUID
    partner_code: str
    partner_name: str
    partner_type: str


class PartnerAdapter:
    """Base adapter; provider-specific adapters can map native fields into these typed payloads."""

    def __init__(self, context: PartnerContext, settings: Settings):
        self.context = context
        self.settings = settings

    def normalize_phone_reference(self, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = normalize_phone(value, self.settings.default_calling_code)
        return protect_partner_reference(
            normalized, namespace="phone", application_secret=self.settings.secret_key.get_secret_value()
        )

    def reference(self, value: str, namespace: str) -> str:
        return protect_partner_reference(
            value, namespace=f"{self.context.partner_code}:{namespace}",
            application_secret=self.settings.secret_key.get_secret_value(),
        )


class TelecomAdapter(PartnerAdapter):
    """Telecom partner adapter."""


class BankAdapter(PartnerAdapter):
    """Bank partner adapter."""


class MomoAdapter(PartnerAdapter):
    """Mobile money partner adapter."""


_ADAPTERS = {"telecom": TelecomAdapter, "bank": BankAdapter, "momo": MomoAdapter}


async def register_partner(db: AsyncSession, admin_id: UUID, body: PartnerCreate,
                           settings: Settings) -> PartnerCreated:
    existing = await db.scalar(select(Partner.id).where(Partner.partner_code == body.partner_code))
    if existing:
        raise ConflictError("A partner with this code already exists.", code="partner_id_in_use")
    shared_secret = secrets.token_urlsafe(32)
    partner = Partner(
        partner_code=body.partner_code,
        partner_name=body.partner_name,
        partner_type=body.partner_type,
        encrypted_secret=encrypt_partner_secret(shared_secret, settings.secret_key.get_secret_value()),
        created_by=admin_id,
    )
    db.add(partner)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictError("A partner with this code already exists.", code="partner_id_in_use") from exc
    await db.refresh(partner)
    return PartnerCreated(
        id=partner.id, partner_code=partner.partner_code, partner_name=partner.partner_name,
        partner_type=partner.partner_type, partner_status=partner.partner_status,
        registration_datetime=partner.registration_datetime, shared_secret=shared_secret,
    )


def partner_adapter_for(context: PartnerContext, settings: Settings) -> PartnerAdapter:
    return _ADAPTERS[context.partner_type](context, settings)


async def ingest_partner_submission(
    db: AsyncSession,
    context: PartnerContext,
    batch: PartnerDataSubmissionIn,
    raw_payload: bytes,
    settings: Settings,
) -> PartnerSubmissionOut:
    adapter = partner_adapter_for(context, settings)
    payload_hash = hashlib.sha256(raw_payload).hexdigest()
    existing = await db.scalar(select(PartnerSubmission).where(
        PartnerSubmission.partner_id == context.partner_id,
        PartnerSubmission.submission_reference == batch.submission_reference,
    ))
    if existing:
        if existing.payload_sha256 != payload_hash:
            raise ConflictError("Submission reference was already used for different data.", code="submission_reference_reused")
        counts = existing.record_counts
        return PartnerSubmissionOut(
            submission_id=existing.id, submission_reference=existing.submission_reference,
            processing_status="accepted", identity_count=counts.get("identities", 0),
            account_count=counts.get("accounts", 0), transaction_count=counts.get("transactions", 0),
        )

    counts = {"identities": len(batch.identities), "accounts": len(batch.accounts),
              "transactions": len(batch.transactions)}
    submission = PartnerSubmission(
        partner_id=context.partner_id,
        submission_reference=batch.submission_reference,
        schema_version=batch.schema_version,
        raw_payload_encrypted=encrypt_partner_payload(raw_payload, settings.secret_key.get_secret_value()),
        payload_sha256=payload_hash,
        record_counts=counts,
    )
    db.add(submission)
    try:
        await db.flush()
        normalized = {"identities": [], "accounts": [], "transactions": []}
        identity_ids: dict[str, UUID] = {}
        for item in batch.identities:
            reference = adapter.reference(item.identity_reference, "identity")
            phone_reference = (
                adapter.normalize_phone_reference(item.phone_number)
                if item.phone_number else item.phone_number_reference
            )
            identity = await db.scalar(select(PartnerIdentity).where(
                PartnerIdentity.partner_id == context.partner_id,
                PartnerIdentity.identity_reference == reference,
            ))
            if identity is None:
                identity = PartnerIdentity(partner_id=context.partner_id, identity_reference=reference)
                db.add(identity)
            identity.submission_id = submission.id
            identity.national_id_reference = (
                protect_partner_reference(
                    item.national_id_reference, namespace="national_id",
                    application_secret=settings.secret_key.get_secret_value(),
                )
                if item.national_id_reference else None
            )
            identity.phone_number_reference = phone_reference
            identity.verified_ownership = item.verified_ownership
            identity.verification_status = item.verification_status
            await db.flush()
            identity_ids[item.identity_reference] = identity.id
            normalized["identities"].append({
                "identity_reference": reference,
                "national_id_reference": identity.national_id_reference,
                "phone_number_reference": phone_reference,
                "verified_ownership": item.verified_ownership,
                "verification_status": item.verification_status,
            })

        for item in batch.accounts:
            identity_id = identity_ids.get(item.identity_reference or "")
            if identity_id is None and item.identity_reference:
                identity_reference = adapter.reference(item.identity_reference, "identity")
                identity_id = await db.scalar(select(PartnerIdentity.id).where(
                    PartnerIdentity.partner_id == context.partner_id,
                    PartnerIdentity.identity_reference == identity_reference,
                ))
            account_reference = adapter.reference(item.account_identifier, "account")
            account = await db.scalar(select(PartnerAccount).where(
                PartnerAccount.partner_id == context.partner_id,
                PartnerAccount.account_identifier == account_reference,
            ))
            if account is None:
                account = PartnerAccount(partner_id=context.partner_id, account_identifier=account_reference)
                db.add(account)
            account.submission_id = submission.id
            account.identity_id = identity_id
            account.identity_reference = adapter.reference(item.identity_reference, "identity") if item.identity_reference else None
            account.account_type = item.account_type
            account.service_provider = item.service_provider or context.partner_name
            account.account_status = item.account_status
            account.ownership_reference = adapter.reference(item.ownership_reference, "ownership") if item.ownership_reference else None
            await db.flush()
            normalized["accounts"].append({
                "identity_reference": account.identity_reference,
                "account_identifier": account_reference,
                "account_type": account.account_type,
                "service_provider": account.service_provider,
                "account_status": account.account_status,
                "ownership_reference": account.ownership_reference,
            })
            pending_senders = await db.scalars(select(PartnerTransaction).where(
                PartnerTransaction.sender_account_id.is_(None),
                PartnerTransaction.sender_partner_code == context.partner_code,
                PartnerTransaction.sender_account_reference == account_reference,
            ))
            for pending in pending_senders:
                pending.sender_account_id = account.id
                pending.sender_partner_id = context.partner_id
            pending_receivers = await db.scalars(select(PartnerTransaction).where(
                PartnerTransaction.receiver_account_id.is_(None),
                PartnerTransaction.receiver_partner_code == context.partner_code,
                PartnerTransaction.receiver_account_reference == account_reference,
            ))
            for pending in pending_receivers:
                pending.receiver_account_id = account.id
                pending.receiver_partner_id = context.partner_id

        partner_codes = {context.partner_code}
        for item in batch.transactions:
            if item.sender_partner_code:
                partner_codes.add(item.sender_partner_code)
            if item.receiver_partner_code:
                partner_codes.add(item.receiver_partner_code)
        partners_by_code = {row.partner_code: row for row in (await db.scalars(
            select(Partner).where(Partner.partner_code.in_(partner_codes))
        )).all()}
        for item in batch.transactions:
            sender_code = item.sender_partner_code or context.partner_code
            receiver_code = item.receiver_partner_code or context.partner_code
            sender_partner = partners_by_code.get(sender_code)
            receiver_partner = partners_by_code.get(receiver_code)
            sender_ref = protect_partner_reference(
                item.sender_account_reference, namespace=f"{sender_code}:account",
                application_secret=settings.secret_key.get_secret_value(),
            )
            receiver_ref = protect_partner_reference(
                item.receiver_account_reference, namespace=f"{receiver_code}:account",
                application_secret=settings.secret_key.get_secret_value(),
            )
            sender_account_id = None
            if sender_partner:
                sender_account_id = await db.scalar(select(PartnerAccount.id).where(
                    PartnerAccount.partner_id == sender_partner.id,
                    PartnerAccount.account_identifier == sender_ref,
                ))
            receiver_account_id = None
            if receiver_partner:
                receiver_account_id = await db.scalar(select(PartnerAccount.id).where(
                    PartnerAccount.partner_id == receiver_partner.id,
                    PartnerAccount.account_identifier == receiver_ref,
                ))
            transaction_reference = adapter.reference(item.transaction_reference, "transaction")
            transaction = await db.scalar(select(PartnerTransaction).where(
                PartnerTransaction.partner_id == context.partner_id,
                PartnerTransaction.transaction_reference == transaction_reference,
            ))
            if transaction is None:
                transaction = PartnerTransaction(partner_id=context.partner_id,
                                                 transaction_reference=transaction_reference)
                db.add(transaction)
            transaction.submission_id = submission.id
            transaction.sender_account_id = sender_account_id
            transaction.receiver_account_id = receiver_account_id
            transaction.sender_partner_id = sender_partner.id if sender_partner else None
            transaction.receiver_partner_id = receiver_partner.id if receiver_partner else None
            transaction.sender_partner_code = sender_code
            transaction.receiver_partner_code = receiver_code
            transaction.sender_account_reference = sender_ref
            transaction.receiver_account_reference = receiver_ref
            transaction.amount = item.amount
            transaction.currency = item.currency.upper()
            transaction.balance = item.balance
            transaction.transaction_datetime = item.timestamp
            transaction.transaction_status = item.transaction_status
            normalized["transactions"].append({
                "transaction_reference": transaction_reference,
                "sender_partner_code": sender_code,
                "sender_partner_id": str(sender_partner.id) if sender_partner else None,
                "sender_account_reference": sender_ref,
                "receiver_partner_code": receiver_code,
                "receiver_partner_id": str(receiver_partner.id) if receiver_partner else None,
                "receiver_account_reference": receiver_ref,
                "amount": str(item.amount),
                "currency": item.currency.upper(),
                "balance": str(item.balance) if item.balance is not None else None,
                "timestamp": item.timestamp.isoformat(),
                "transaction_status": item.transaction_status,
            })

        submission.normalized_payload = normalized
        from app.services.intelligence_layers import IntelligenceLayers
        await IntelligenceLayers(db, settings).refresh_all()
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    return PartnerSubmissionOut(
        submission_id=submission.id, submission_reference=submission.submission_reference,
        processing_status="accepted", identity_count=counts["identities"],
        account_count=counts["accounts"], transaction_count=counts["transactions"],
    )
