import logging

from fastapi import APIRouter
from sqlalchemy import text

from app.api.deps import DbDep, RedisDep
from app.core.exceptions import ServiceUnavailableError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
async def live() -> dict:
    """Process is up. Used by the orchestrator's liveness probe."""
    return {"status": "ok"}


@router.get("/ready")
async def ready(db: DbDep, redis: RedisDep) -> dict:
    """Dependencies reachable. Used by the readiness probe / load balancer."""
    checks: dict[str, str] = {}
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        logger.exception("readiness_database_failed")
        checks["database"] = "down"
    try:
        await redis.ping()
        checks["redis"] = "ok"
    except Exception:
        logger.exception("readiness_redis_failed")
        checks["redis"] = "down"

    if "down" in checks.values():
        raise ServiceUnavailableError(details=checks)
    return {"status": "ok", "checks": checks}
