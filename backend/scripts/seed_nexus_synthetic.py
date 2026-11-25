"""Seed a repeatable, synthetic NEXUS FIR/PDR investigation network.

Run from ``backend`` after applying migrations:
    python scripts/seed_nexus_synthetic.py

Creates exactly 50 core demo records: 10 PDR identities, 10 PDR accounts,
20 PDR transactions, and 10 FIR reports. All values are synthetic and the
reports are explicitly marked as training material, not real complaints.
"""
from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.engine import make_url

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings
from app.core.exceptions import PermissionDenied
from app.db.session import create_engine, create_session_factory
from app.enums import CommunicationChannel, ReportType, UserRole
from app.models import CommunityReport, FIRReportRecord, User
from app.schemas.fraud import CommunityReportCreate
from app.schemas.partners import PartnerDataSubmissionIn
from app.services.admin_intelligence import _ensure_partner, _seed_submission
from app.services.community_intelligence import CommunityIntelligenceService
from app.services.intelligence_layers import IntelligenceLayers

SYNTHETIC_CATEGORY = "synthetic_training_fraud"
BASE_TIME = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
TRACE_DAY = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
TRACE_DATE = TRACE_DAY.strftime("%Y%m%d")


async def _ensure_user(db, phone: str, role: UserRole = UserRole.USER) -> User:
    user = await db.scalar(select(User).where(User.phone == phone))
    if user is None:
        user = User(phone=phone, role=role)
        db.add(user)
        await db.flush()
    return user


def _synthetic_data(momo_code: str, bank_code: str) -> tuple[dict, dict, list[dict]]:
    victims = [
        {"identity_reference": f"SYN-VICTIM-{i:02d}", "national_id_reference": f"GHA-DEMO-V-{i:02d}",
         "phone_number": f"+233000000{i:03d}", "verified_ownership": True,
         "verification_status": "verified"}
        for i in range(1, 6)
    ]
    suspects = [
        {"identity_reference": f"SYN-SUSPECT-{i:02d}", "national_id_reference": f"GHA-DEMO-S-{i:02d}",
         "phone_number": f"+233000000{200 + i:03d}", "verified_ownership": True,
         "verification_status": "verified"}
        for i in range(1, 6)
    ]
    bank_accounts = [{
        "identity_reference": f"SYN-VICTIM-{i:02d}", "account_identifier": f"SYN-BANK-VICTIM-{i:02d}",
        "account_type": "bank", "service_provider": "Synthetic Training Bank",
        "account_status": "active", "ownership_reference": f"SYN-OWNER-V-{i:02d}",
    } for i in range(1, 6)]
    momo_accounts = [{
        "identity_reference": f"SYN-SUSPECT-{i:02d}", "account_identifier": f"SYN-MOMO-FRAUD-{i:02d}",
        "account_type": "momo_wallet", "service_provider": "Synthetic Training MoMo",
        "account_status": "active", "ownership_reference": f"SYN-OWNER-S-{i:02d}",
    } for i in range(1, 6)]

    loss_transfers: list[dict] = []
    for index in range(10):
        victim_index = index % 5
        # Each victim reports two different recipient accounts, avoiding
        # duplicate-report suppression while making each suspect recur.
        suspect_index = (victim_index + index // 5) % 5
        loss_transfers.append({
            "transaction_reference": f"SYN-LOSS-{index + 1:03d}",
            "sender_account_reference": f"SYN-BANK-VICTIM-{victim_index + 1:02d}",
            "receiver_account_reference": f"SYN-MOMO-FRAUD-{suspect_index + 1:02d}",
            "sender_partner_code": bank_code, "receiver_partner_code": momo_code,
            "amount": str(Decimal("125.00") + Decimal("37.00") * index), "currency": "GHS",
            "timestamp": (BASE_TIME + timedelta(minutes=index)).isoformat(),
            "transaction_status": "successful",
        })

    onward_transfers: list[dict] = []
    for index in range(10):
        sender = index % 5
        receiver = (sender + 1 + (index // 5)) % 5
        onward_transfers.append({
            "transaction_reference": f"SYN-ROUTE-{index + 1:03d}",
            "sender_account_reference": f"SYN-MOMO-FRAUD-{sender + 1:02d}",
            "receiver_account_reference": f"SYN-MOMO-FRAUD-{receiver + 1:02d}",
            "sender_partner_code": momo_code, "receiver_partner_code": momo_code,
            "amount": str(Decimal("60.00") + Decimal("10.00") * index), "currency": "GHS",
            "timestamp": (BASE_TIME + timedelta(hours=2, minutes=index)).isoformat(),
            "transaction_status": "successful",
        })

    bank_batch = {
        "submission_reference": "nexus-synthetic-training-v1-bank",
        "identities": victims, "accounts": bank_accounts, "transactions": loss_transfers,
    }
    momo_batch = {
        "submission_reference": "nexus-synthetic-training-v1-momo",
        "identities": suspects, "accounts": momo_accounts, "transactions": onward_transfers,
    }
    return bank_batch, momo_batch, loss_transfers


async def _seed_cashout_trace(db, settings, momo, bank) -> tuple[str, list[str]]:
    """Add a recent, repeatable three-transfer FIR→suspect→mule→cash-out path."""
    victim_phone = "+233000009901"
    suspect_phone = "+233000000201"
    loss_ref = f"SYN-TRACE-{TRACE_DATE}-LOSS"
    route_ref = f"SYN-TRACE-{TRACE_DATE}-ROUTE"
    cashout_ref = f"SYN-TRACE-{TRACE_DATE}-CASHOUT"

    bank_batch = PartnerDataSubmissionIn.model_validate({
        "submission_reference": f"nexus-synthetic-cashout-bank-{TRACE_DATE}",
        "identities": [{
            "identity_reference": "SYN-TRACE-VICTIM",
            "national_id_reference": "GHA-DEMO-TRACE-VICTIM",
            "phone_number": victim_phone,
            "verified_ownership": True,
            "verification_status": "verified",
        }],
        "accounts": [{
            "identity_reference": "SYN-TRACE-VICTIM",
            "account_identifier": "SYN-TRACE-BANK-SENDER",
            "account_type": "bank",
            "service_provider": "Synthetic Training Bank",
            "account_status": "active",
            "ownership_reference": "SYN-TRACE-OWNER-VICTIM",
        }],
        "transactions": [{
            "transaction_reference": loss_ref,
            "sender_account_reference": "SYN-TRACE-BANK-SENDER",
            "receiver_account_reference": "SYN-MOMO-FRAUD-01",
            "sender_partner_code": bank.partner_code,
            "receiver_partner_code": momo.partner_code,
            "amount": "500.00", "currency": "GHS",
            "timestamp": (TRACE_DAY + timedelta(hours=9)).isoformat(),
            "transaction_status": "successful",
        }],
    })
    await _seed_submission(db, bank, bank_batch, settings)

    momo_batch = PartnerDataSubmissionIn.model_validate({
        "submission_reference": f"nexus-synthetic-cashout-momo-{TRACE_DATE}",
        "identities": [
            {
                "identity_reference": "SYN-TRACE-MULE",
                "national_id_reference": "GHA-DEMO-TRACE-MULE",
                "phone_number": "+233000009902",
                "verified_ownership": True,
                "verification_status": "verified",
            },
            {
                "identity_reference": "SYN-TRACE-CASHOUT-AGENT",
                "national_id_reference": "GHA-DEMO-TRACE-AGENT",
                "phone_number": "+233000009903",
                "verified_ownership": True,
                "verification_status": "verified",
            },
        ],
        "accounts": [
            {
                "identity_reference": "SYN-TRACE-MULE",
                "account_identifier": "SYN-TRACE-MULE-WALLET",
                "account_type": "momo_wallet",
                "service_provider": "Synthetic Training MoMo",
                "account_status": "active",
                "ownership_reference": "SYN-TRACE-OWNER-MULE",
            },
            {
                "identity_reference": "SYN-TRACE-CASHOUT-AGENT",
                "account_identifier": "SYN-TRACE-CASHOUT-AGENT-WALLET",
                "account_type": "momo_agent_wallet",
                "service_provider": "Synthetic Training Cash-out Agent",
                "account_status": "active",
                "ownership_reference": "SYN-TRACE-OWNER-AGENT",
            },
        ],
        "transactions": [
            {
                "transaction_reference": route_ref,
                "sender_account_reference": "SYN-MOMO-FRAUD-01",
                "receiver_account_reference": "SYN-TRACE-MULE-WALLET",
                "sender_partner_code": momo.partner_code,
                "receiver_partner_code": momo.partner_code,
                "amount": "470.00", "currency": "GHS",
                "timestamp": (TRACE_DAY + timedelta(hours=9, minutes=10)).isoformat(),
                "transaction_status": "successful",
            },
            {
                "transaction_reference": cashout_ref,
                "sender_account_reference": "SYN-TRACE-MULE-WALLET",
                "receiver_account_reference": "SYN-TRACE-CASHOUT-AGENT-WALLET",
                "sender_partner_code": momo.partner_code,
                "receiver_partner_code": momo.partner_code,
                "amount": "450.00", "currency": "GHS",
                "timestamp": (TRACE_DAY + timedelta(hours=9, minutes=20)).isoformat(),
                "transaction_status": "successful",
            },
        ],
    })
    await _seed_submission(db, momo, momo_batch, settings)

    reporter = await _ensure_user(db, victim_phone)
    prior = await db.scalar(select(CommunityReport.id).where(
        CommunityReport.reporter_id == reporter.id,
        CommunityReport.subject_value == suspect_phone,
        CommunityReport.category == SYNTHETIC_CATEGORY,
    ))
    if prior is None:
        service = CommunityIntelligenceService(db, settings.default_calling_code, settings)
        await service.submit(reporter, CommunityReportCreate(
            subject=suspect_phone,
            report_type=ReportType.OTHER,
            channel=CommunicationChannel.APP,
            category=SYNTHETIC_CATEGORY,
            description=(
                "SYNTHETIC TRAINING SCENARIO — not a real complaint. "
                f"I was deceived by someone using {suspect_phone}. I transferred GH₵500 "
                f"from my fictional bank account to their mobile-money wallet. "
                f"Transaction reference: {loss_ref}. The ledger also contains a later "
                "transfer through a fictional intermediary wallet and a final cash-out "
                "agent wallet. The allegation is unverified."
            ),
            evidence_reference=f"synthetic/nexus-training/cashout-{TRACE_DATE}.txt",
        ))
    fir = await db.scalar(select(FIRReportRecord).where(
        FIRReportRecord.reporter_id == reporter.id,
        FIRReportRecord.evidence_reference == f"synthetic/nexus-training/cashout-{TRACE_DATE}.txt",
    ))
    if fir is None:
        raise RuntimeError("Synthetic cash-out FIR was not created")
    return str(fir.id), [loss_ref, route_ref, cashout_ref]


async def main() -> None:
    settings = get_settings()
    url = make_url(settings.database_url)
    if settings.environment not in {"development", "test"}:
        raise PermissionDenied("Synthetic data seeding is limited to development or test environments.")
    if url.host not in {None, "localhost", "127.0.0.1", "::1"}:
        raise PermissionDenied("Synthetic data seeding is limited to a local database host.")

    engine = create_engine(settings)
    sessions = create_session_factory(engine)
    try:
        async with sessions() as db:
            admin_phone = os.getenv("SAFEGUARD_DEMO_ADMIN_PHONE", "+233200000001")
            admin = await _ensure_user(db, admin_phone, UserRole.ADMIN)
            if admin.role != UserRole.ADMIN:
                admin.role = UserRole.ADMIN
                await db.flush()

            momo = await _ensure_partner(db, admin.id, settings,
                "nexus_synthetic_momo", "NEXUS Synthetic Training MoMo", "momo")
            bank = await _ensure_partner(db, admin.id, settings,
                "nexus_synthetic_bank", "NEXUS Synthetic Training Bank", "bank")
            bank_batch, momo_batch, loss_transfers = _synthetic_data(momo.partner_code, bank.partner_code)

            # Submit the source identities, accounts, and payment ledger through
            # the same validated/encrypted PDR ingestion path used by partners.
            await _seed_submission(db, bank, PartnerDataSubmissionIn.model_validate(bank_batch), settings)
            await _seed_submission(db, momo, PartnerDataSubmissionIn.model_validate(momo_batch), settings)

            reports_created = 0
            service = CommunityIntelligenceService(db, settings.default_calling_code, settings)
            for index, transfer in enumerate(loss_transfers):
                victim_index = index % 5
                suspect_index = (victim_index + index // 5) % 5
                victim_phone = f"+233000000{victim_index + 1:03d}"
                suspect_phone = f"+233000000{200 + suspect_index + 1:03d}"
                amount = transfer["amount"]
                reporter = await _ensure_user(db, victim_phone)
                prior = await db.scalar(select(CommunityReport.id).where(
                    CommunityReport.reporter_id == reporter.id,
                    CommunityReport.subject_value == suspect_phone,
                    CommunityReport.category == SYNTHETIC_CATEGORY,
                ))
                report_body = CommunityReportCreate(
                    subject=suspect_phone, report_type=ReportType.OTHER,
                    channel=CommunicationChannel.APP,
                    category=SYNTHETIC_CATEGORY,
                    description=(
                        "SYNTHETIC TRAINING SCENARIO — not a real complaint. "
                        f"The fictional victim line {victim_phone} reports being deceived and transferring "
                        f"GH₵{amount} to suspected mobile-money account holder {suspect_phone}. "
                        f"Transaction reference: {transfer['transaction_reference']}. "
                        "This allegation is unverified and exists only for NEXUS graph training."
                    ),
                    evidence_reference=f"synthetic/nexus-training/loss-{index + 1:03d}.txt",
                )
                await service.submit(reporter, report_body)
                if prior is None:
                    reports_created += 1

            trace_report_id, trace_transaction_references = await _seed_cashout_trace(
                db, settings, momo, bank,
            )

            projection_counts = await IntelligenceLayers(db, settings).refresh_all()
            await db.commit()
            print({
                "synthetic_training_only": True,
                "pdr_identities": 13, "pdr_accounts": 13, "pdr_transactions": 23,
                "fir_reports_created_this_run": reports_created,
                "fir_report_total_in_dataset": 11,
                "cashout_trace_report_id": trace_report_id,
                "cashout_trace_transaction_references": trace_transaction_references,
                "core_records_total": 60,
                "partners": [momo.partner_code, bank.partner_code],
                "projection_counts": projection_counts,
            })
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
