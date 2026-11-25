from fastapi import APIRouter

from app.api.deps import CurrentUser, FraudServiceDep
from app.schemas.fraud import LookupOut, LookupRequest

router = APIRouter(prefix="/numbers", tags=["lookup"])


@router.post("/lookup", response_model=LookupOut)
async def lookup_number(body: LookupRequest, user: CurrentUser, fraud: FraudServiceDep) -> LookupOut:
    """Risk check for a phone number. POST (not GET) so the number stays out of URLs and access logs."""
    return await fraud.lookup(
        user,
        body.number,
        message=body.message_indicators,
        transaction=body.transaction_context,
        case_id=body.case_id,
        channel=body.channel,
    )
