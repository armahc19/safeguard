"""FastAPI dependencies: settings, DB session, Redis, current user, role checks, gateway auth."""
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.core.config import Settings
from app.core.config import get_settings as _get_settings
from app.core.exceptions import AuthenticationError, PermissionDenied
from app.enums import AccountStatus, UserRole
from app.models import User
from app.services.auth_service import AuthService
from app.services.fraud_service import FraudService
from app.services.sms import SMSSender

_bearer = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return getattr(request.app.state, "settings", None) or _get_settings()


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_sms_sender(request: Request) -> SMSSender:
    return request.app.state.sms_sender


SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[AsyncSession, Depends(get_db)]
RedisDep = Annotated[Redis, Depends(get_redis)]


def get_auth_service(db: DbDep, redis: RedisDep, settings: SettingsDep,
                     sms: Annotated[SMSSender, Depends(get_sms_sender)]) -> AuthService:
    return AuthService(db, redis, settings, sms)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


# ---------------------------------------------------------------- end users (Bearer JWT)
async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: DbDep,
    settings: SettingsDep,
) -> User:
    if credentials is None:
        raise AuthenticationError()
    claims = security.decode_token(
        credentials.credentials, expected_type=security.ACCESS,
        secret=settings.secret_key.get_secret_value(), algorithm=settings.jwt_algorithm,
    )
    user = await db.get(User, uuid.UUID(claims["sub"]))
    if user is None:
        raise AuthenticationError("Invalid authentication token.", code="invalid_token")
    if user.account_status != AccountStatus.ACTIVE:
        raise PermissionDenied("This account is not active.", code="account_inactive")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: UserRole):
    allowed = set(roles) | {UserRole.ADMIN}

    async def checker(user: CurrentUser) -> User:
        if user.role not in allowed:
            raise PermissionDenied()
        return user

    return checker


# ---------------------------------------------------------------- USSD / SMS gateways (HMAC)
async def require_gateway(request: Request, settings: SettingsDep) -> str:
    """Verifies X-Gateway-Id / X-Timestamp / X-Signature. Returns the gateway id ("ussd", "sms", ...)."""
    gateway_id = request.headers.get("X-Gateway-Id", "")
    secret = settings.gateway_secrets.get(gateway_id)
    # Same error for unknown gateway and bad signature, so ids can't be enumerated.
    if secret is None or not security.verify_gateway_request(
        secret.get_secret_value(),
        request.headers.get("X-Timestamp", ""),
        await request.body(),
        request.headers.get("X-Signature", ""),
        tolerance_seconds=settings.gateway_timestamp_tolerance_seconds,
    ):
        raise AuthenticationError("Invalid gateway credentials.", code="invalid_gateway_signature")
    return gateway_id


GatewayDep = Annotated[str, Depends(require_gateway)]


# ---------------------------------------------------------------- shared route dependencies
ReviewerUser = Annotated[User, Depends(require_roles(UserRole.REVIEWER))]  # reviewer or admin
AdminUser = Annotated[User, Depends(require_roles())]  # admin only


def get_fraud_service(db: DbDep, redis: RedisDep, settings: SettingsDep) -> FraudService:
    return FraudService(db, redis, settings)


FraudServiceDep = Annotated[FraudService, Depends(get_fraud_service)]


@dataclass(frozen=True)
class PageParams:
    limit: int
    offset: int


def page_params(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)) -> PageParams:
    return PageParams(limit=limit, offset=offset)


PageDep = Annotated[PageParams, Depends(page_params)]
