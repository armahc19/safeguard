from fastapi import APIRouter

from app.api.deps import CurrentUser, DbDep, SettingsDep
from app.schemas.network import NetworkLookupOut, NetworkLookupRequest
from app.services.network_intelligence import NetworkService

router = APIRouter(prefix="/network", tags=["fraud-network-intelligence"])


@router.post("/number", response_model=NetworkLookupOut)
async def lookup_network(
    body: NetworkLookupRequest, user: CurrentUser, db: DbDep, settings: SettingsDep,
) -> NetworkLookupOut:
    snapshot = await NetworkService(db, settings.default_calling_code).snapshot(body.number)
    return NetworkLookupOut(
        number=snapshot.number, link_count=snapshot.link_count, network_score=snapshot.network_score,
        related_patterns=list(snapshot.related_patterns), campaigns=list(snapshot.campaigns),
        reasons=list(snapshot.reasons),
    )
