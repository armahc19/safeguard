from fastapi import APIRouter

from app.api.deps import CurrentUser, SettingsDep
from app.schemas.communication import (
    CommunicationContext,
    CommunicationInterpretRequest,
)
from app.services.communication import interpret

router = APIRouter(prefix="/communication", tags=["communication-intelligence"])


@router.post("/interpret", response_model=CommunicationContext)
async def interpret_communication(
    body: CommunicationInterpretRequest, user: CurrentUser, settings: SettingsDep,
) -> CommunicationContext:
    return interpret(
        channel=body.channel, text=body.text, phone_number=body.phone_number,
        default_calling_code=settings.default_calling_code,
    )
