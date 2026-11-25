"""Development-only HTTP API for simulated MoMo balance and transfers."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from app.api.deps import GatewayDep, SettingsDep
from app.core.exceptions import ValidationFailed
from app.core.phone import normalize_phone
from app.services.momo_sandbox import momo_sandbox

router = APIRouter(prefix="/sandbox/momo", tags=["MoMo sandbox"])


def _sandbox_enabled(settings) -> None:
    if settings.environment not in {"development", "test"}:
        from app.core.exceptions import PermissionDenied
        raise PermissionDenied("The simulated MoMo API is only available in development and test.",
                               code="momo_sandbox_unavailable")


class SimulatedTransferIn(BaseModel):
    msisdn: str = Field(min_length=7, max_length=20)
    recipient: str = Field(min_length=7, max_length=20)
    amount: str = Field(min_length=1, max_length=20)
    confirm: bool = False


@router.get("/balance")
async def simulated_balance(gateway: GatewayDep, settings: SettingsDep,
                            msisdn: Annotated[str, Query(min_length=7, max_length=20)]) -> dict:
    _sandbox_enabled(settings)
    number = normalize_phone(msisdn, settings.default_calling_code)
    return await momo_sandbox.balance(number)


@router.get("/received")
async def simulated_received(gateway: GatewayDep, settings: SettingsDep,
                             msisdn: Annotated[str, Query(min_length=7, max_length=20)],
                             limit: int = Query(default=5, ge=1, le=20)) -> dict:
    _sandbox_enabled(settings)
    number = normalize_phone(msisdn, settings.default_calling_code)
    return await momo_sandbox.received(number, limit)


@router.post("/transfers")
async def simulated_transfer(body: SimulatedTransferIn, gateway: GatewayDep,
                             settings: SettingsDep) -> dict:
    _sandbox_enabled(settings)
    sender = normalize_phone(body.msisdn, settings.default_calling_code)
    recipient = normalize_phone(body.recipient, settings.default_calling_code)
    try:
        if not body.confirm:
            return {"status": "awaiting_confirmation",
                    **await momo_sandbox.stage_transfer(sender, recipient, body.amount)}
        return await momo_sandbox.confirm_transfer(sender)
    except ValueError as exc:
        raise ValidationFailed(str(exc), code="momo_sandbox_transfer_invalid") from exc
