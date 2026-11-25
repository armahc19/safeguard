"""Phone-number OTP login with short-lived access tokens and rotating refresh tokens.

Redis keys
  otp:{phone}          keyed hash of the active code          (TTL = otp_ttl_seconds)
  otp_attempts:{phone} wrong-guess counter for that code
  refresh:{jti}        user id; presence == refresh token is valid (allow-list, deleted on use/logout)
"""
import logging
import uuid
from datetime import timedelta

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.core.config import Settings
from app.core.exceptions import AuthenticationError, PermissionDenied
from app.core.phone import normalize_phone
from app.core.ratelimit import hit
from app.models import AccountStatus, User
from app.schemas.auth import TokenPair
from app.services.sms import SMSSender
from app.services.users import get_or_create_user

logger = logging.getLogger(__name__)


class AuthService:
    def __init__(self, db: AsyncSession, redis: Redis, settings: Settings, sms: SMSSender) -> None:
        self.db, self.redis, self.settings, self.sms = db, redis, settings, sms
        self._secret = settings.secret_key.get_secret_value()

    # ------------------------------------------------------------ OTP
    async def request_otp(self, raw_phone: str, client_ip: str | None) -> None:
        s = self.settings
        phone = normalize_phone(raw_phone, s.default_calling_code)

        await hit(self.redis, f"rl:otp:phone:{phone}", s.otp_requests_per_phone, 600)
        if client_ip:
            await hit(self.redis, f"rl:otp:ip:{client_ip}", s.otp_requests_per_ip, 3600)

        code = security.generate_otp(s.otp_length)
        await self.redis.set(f"otp:{phone}", security.hash_otp(code, phone, self._secret), ex=s.otp_ttl_seconds)
        await self.redis.delete(f"otp_attempts:{phone}")
        await self.sms.send(phone, f"Your SafeGuard code is {code}. It expires in {s.otp_ttl_seconds // 60} minutes.")

    async def verify_otp(self, raw_phone: str, code: str) -> TokenPair:
        s = self.settings
        phone = normalize_phone(raw_phone, s.default_calling_code)
        otp_key, attempts_key = f"otp:{phone}", f"otp_attempts:{phone}"

        stored = await self.redis.get(otp_key)
        if stored is None:
            raise AuthenticationError("The code is invalid or has expired.", code="invalid_otp")

        attempts = await self.redis.incr(attempts_key)
        if attempts == 1:
            await self.redis.expire(attempts_key, s.otp_ttl_seconds)
        if attempts > s.otp_max_attempts:
            await self.redis.delete(otp_key, attempts_key)
            raise AuthenticationError("Too many wrong attempts. Request a new code.", code="otp_locked")

        if not security.constant_time_equals(stored, security.hash_otp(code, phone, self._secret)):
            raise AuthenticationError("The code is invalid or has expired.", code="invalid_otp")

        await self.redis.delete(otp_key, attempts_key)  # single use
        user = await self._get_or_create_user(phone)
        self._ensure_active(user)
        return await self._issue_tokens(user)

    # ------------------------------------------------------------ tokens
    async def refresh(self, refresh_token: str) -> TokenPair:
        claims = security.decode_token(
            refresh_token, expected_type=security.REFRESH, secret=self._secret, algorithm=self.settings.jwt_algorithm
        )
        # GETDEL makes rotation atomic: a refresh token can be exchanged exactly once.
        user_id = await self.redis.getdel(f"refresh:{claims['jti']}")
        if user_id is None or user_id != claims["sub"]:
            logger.warning("refresh_token_rejected", extra={"user_id": claims["sub"]})
            raise AuthenticationError("Refresh token is no longer valid.", code="invalid_token")

        user = await self.db.get(User, uuid.UUID(claims["sub"]))
        if user is None:
            raise AuthenticationError("Refresh token is no longer valid.", code="invalid_token")
        self._ensure_active(user)
        return await self._issue_tokens(user)

    async def logout(self, refresh_token: str) -> None:
        try:
            claims = security.decode_token(
                refresh_token, expected_type=security.REFRESH, secret=self._secret,
                algorithm=self.settings.jwt_algorithm,
            )
        except AuthenticationError:
            return  # already expired/invalid: nothing to revoke
        await self.redis.delete(f"refresh:{claims['jti']}")

    async def _issue_tokens(self, user: User) -> TokenPair:
        s = self.settings
        access = security.create_token(
            subject=str(user.id), token_type=security.ACCESS, role=user.role.value, secret=self._secret,
            algorithm=s.jwt_algorithm, ttl=timedelta(minutes=s.access_token_ttl_minutes),
        )
        refresh = security.create_token(
            subject=str(user.id), token_type=security.REFRESH, secret=self._secret,
            algorithm=s.jwt_algorithm, ttl=timedelta(days=s.refresh_token_ttl_days),
        )
        await self.redis.set(f"refresh:{refresh.jti}", str(user.id), ex=int(timedelta(days=s.refresh_token_ttl_days).total_seconds()))
        return TokenPair(
            access_token=access.token, refresh_token=refresh.token, expires_in=s.access_token_ttl_minutes * 60
        )

    # ------------------------------------------------------------ users
    async def _get_or_create_user(self, phone: str) -> User:
        return await get_or_create_user(self.db, phone)

    @staticmethod
    def _ensure_active(user: User) -> None:
        if user.account_status != AccountStatus.ACTIVE:
            raise PermissionDenied("This account is not active.", code="account_inactive")
