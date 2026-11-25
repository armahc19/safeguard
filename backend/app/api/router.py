from fastapi import APIRouter

from app.api.routes import (
    admin,
    auth,
    awareness,
    calls,
    cases,
    communication,
    community,
    conversation,
    fir,
    gateway,
    identity,
    intelligence,
    intelligence_layers,
    intervention,
    liveness,
    network,
    numbers,
    partners,
    patterns,
    reports,
    shield,
    threats,
    transactions,
)

api_router = APIRouter()
api_router.include_router(awareness.router)
api_router.include_router(cases.router)
api_router.include_router(community.router)
api_router.include_router(calls.router)
api_router.include_router(communication.router)
api_router.include_router(conversation.router)
api_router.include_router(auth.router)
api_router.include_router(reports.router)
api_router.include_router(numbers.router)
api_router.include_router(network.router)
api_router.include_router(patterns.router)
api_router.include_router(partners.router)
api_router.include_router(threats.router)
api_router.include_router(threats.categories_router)
api_router.include_router(gateway.router)
api_router.include_router(fir.router)
api_router.include_router(identity.router)
api_router.include_router(intelligence.router)
api_router.include_router(intelligence_layers.router)
api_router.include_router(liveness.router)
api_router.include_router(intervention.router)
api_router.include_router(shield.router)
api_router.include_router(transactions.router)
api_router.include_router(admin.router)
