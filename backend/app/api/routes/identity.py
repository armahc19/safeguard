from fastapi import APIRouter

from app.api.deps import CurrentUser
from app.schemas.identity import IdentityAnalyzeOut, IdentityAnalyzeRequest
from app.services.identity_intelligence import assess_identity

router = APIRouter(prefix="/identity", tags=["identity-intelligence"])


@router.post("/analyze", response_model=IdentityAnalyzeOut)
async def analyze_identity(body: IdentityAnalyzeRequest, user: CurrentUser) -> IdentityAnalyzeOut:
    analysis = assess_identity(body.text, phone_number=body.phone_number)
    return IdentityAnalyzeOut(**analysis.signals())
