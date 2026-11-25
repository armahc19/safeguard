"""User-facing liveness challenge creation."""
from fastapi import APIRouter

from app.api.deps import CurrentUser, DbDep, SettingsDep
from app.schemas.liveness import LivenessChallengeOut
from app.services.liveness_verification import create_challenge

router = APIRouter(prefix="/liveness", tags=["liveness-detection"])


@router.post("/challenges", response_model=LivenessChallengeOut)
async def create_liveness_challenge(db: DbDep, user: CurrentUser,
                                   settings: SettingsDep) -> LivenessChallengeOut:
    """Create a five-minute, single-use challenge for a trusted liveness verifier."""
    return await create_challenge(db, user, settings)
