"""Partner Data Repository submissions and response models."""
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

PartnerReference = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
PartnerCode = Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")]


class _PartnerModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PartnerIdentityIn(_PartnerModel):
    identity_reference: PartnerReference = Field(
        validation_alias=AliasChoices("identity_reference", "customer_reference", "customer_ref", "subscriber_ref")
    )
    national_id_reference: str | None = Field(default=None, min_length=1, max_length=256)
    phone_number: str | None = Field(default=None, min_length=7, max_length=32,
                                     validation_alias=AliasChoices("phone_number", "phone", "msisdn"))
    phone_number_reference: str | None = Field(default=None, min_length=8, max_length=64)
    verified_ownership: bool = False
    verification_status: Literal["verified", "pending", "unverified"] = "unverified"

    @model_validator(mode="after")
    def ownership_must_be_verified(self) -> "PartnerIdentityIn":
        if self.phone_number and self.phone_number_reference:
            raise ValueError("Send either phone_number or phone_number_reference, not both.")
        if self.verified_ownership and self.verification_status != "verified":
            raise ValueError("Verified ownership requires verification_status='verified'.")
        return self


class PartnerAccountIn(_PartnerModel):
    identity_reference: PartnerReference | None = None
    account_identifier: PartnerReference = Field(validation_alias=AliasChoices("account_identifier", "account_id", "wallet_id"))
    account_type: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    service_provider: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)] | None = None
    account_status: Literal["active", "suspended", "closed"] = Field(
        default="active", validation_alias=AliasChoices("account_status", "status")
    )
    ownership_reference: PartnerReference | None = None


class PartnerTransactionIn(_PartnerModel):
    transaction_reference: PartnerReference = Field(validation_alias=AliasChoices("transaction_reference", "transaction_id", "txn_ref"))
    sender_account_reference: PartnerReference = Field(
        validation_alias=AliasChoices("sender_account_reference", "sender_account", "sender_account_id")
    )
    receiver_account_reference: PartnerReference = Field(
        validation_alias=AliasChoices("receiver_account_reference", "receiver_account", "receiver_account_id")
    )
    sender_partner_code: PartnerCode | None = None
    receiver_partner_code: PartnerCode | None = None
    amount: Decimal = Field(gt=0, max_digits=20, decimal_places=4)
    currency: Annotated[str, StringConstraints(min_length=3, max_length=3, pattern=r"^[A-Za-z]{3}$")]
    balance: Decimal | None = Field(default=None, ge=0, max_digits=20, decimal_places=4)
    timestamp: datetime = Field(validation_alias=AliasChoices("timestamp", "transaction_datetime", "occurred_at"))
    transaction_status: Literal["successful", "pending", "failed"] = Field(
        validation_alias=AliasChoices("transaction_status", "status")
    )

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Transaction timestamp must include a timezone.")
        return value.astimezone(UTC)


class PartnerDataSubmissionIn(_PartnerModel):
    submission_reference: PartnerReference
    schema_version: Literal["1"] = "1"
    identities: list[PartnerIdentityIn] = Field(default_factory=list, max_length=5000)
    accounts: list[PartnerAccountIn] = Field(default_factory=list, max_length=10000)
    transactions: list[PartnerTransactionIn] = Field(default_factory=list, max_length=50000)

    @model_validator(mode="after")
    def require_records(self) -> "PartnerDataSubmissionIn":
        if not (self.identities or self.accounts or self.transactions):
            raise ValueError("At least one identity, account, or transaction record is required.")
        return self


class PartnerIdentitySubmissionIn(_PartnerModel):
    submission_reference: PartnerReference
    schema_version: Literal["1"] = "1"
    identities: list[PartnerIdentityIn] = Field(min_length=1, max_length=5000)


class PartnerAccountSubmissionIn(_PartnerModel):
    submission_reference: PartnerReference
    schema_version: Literal["1"] = "1"
    accounts: list[PartnerAccountIn] = Field(min_length=1, max_length=10000)


class PartnerTransactionSubmissionIn(_PartnerModel):
    submission_reference: PartnerReference
    schema_version: Literal["1"] = "1"
    transactions: list[PartnerTransactionIn] = Field(min_length=1, max_length=50000)


class PartnerSubmissionOut(_PartnerModel):
    submission_id: UUID
    submission_reference: str
    processing_status: Literal["accepted"]
    identity_count: int
    account_count: int
    transaction_count: int


class PartnerOut(_PartnerModel):
    id: UUID
    partner_code: str
    partner_name: str
    partner_type: Literal["telecom", "bank", "momo"]
    partner_status: Literal["active", "inactive"]
    registration_datetime: datetime


class PartnerCreated(PartnerOut):
    shared_secret: str


class PartnerCreate(_PartnerModel):
    partner_code: PartnerCode
    partner_name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=120)]
    partner_type: Literal["telecom", "bank", "momo"]
