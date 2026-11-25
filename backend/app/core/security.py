"""Token, OTP and gateway-signature primitives. No framework imports, so these are unit-testable on their own."""
import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from app.core.exceptions import AuthenticationError, ServiceUnavailableError

ACCESS = "access"
REFRESH = "refresh"


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime


def create_token(*, subject: str, token_type: str, ttl: timedelta, secret: str, algorithm: str = "HS256",
                 role: str | None = None) -> IssuedToken:
    if not secret or not secret.strip():
        raise ServiceUnavailableError("Authentication is not configured.", code="authentication_unavailable")
    now = datetime.now(UTC)
    jti = uuid.uuid4().hex
    exp = now + ttl
    claims = {"sub": subject, "type": token_type, "jti": jti, "iat": now, "exp": exp}
    if role:
        claims["role"] = role
    return IssuedToken(jwt.encode(claims, secret, algorithm=algorithm), jti, exp)


def decode_token(token: str, *, expected_type: str, secret: str, algorithm: str = "HS256") -> dict:
    if not secret or not secret.strip():
        raise ServiceUnavailableError("Authentication is not configured.", code="authentication_unavailable")
    try:
        claims = jwt.decode(
            token, secret, algorithms=[algorithm], options={"require": ["exp", "iat", "sub", "jti", "type"]}
        )
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Your session has expired.", code="token_expired")
    except jwt.InvalidTokenError:
        raise AuthenticationError("Invalid authentication token.", code="invalid_token")
    if claims["type"] != expected_type:
        raise AuthenticationError("Invalid authentication token.", code="invalid_token")
    return claims


# ---- one-time passwords
def generate_otp(length: int = 6) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def hash_otp(code: str, phone: str, secret: str) -> str:
    """Keyed hash so a Redis leak doesn't expose live codes. Bound to the phone number."""
    return hmac.new(secret.encode(), f"{phone}:{code}".encode(), hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ---- gateway (USSD / SMS) request signing: HMAC-SHA256 over "<timestamp>.<raw body>"
def sign_gateway_request(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify_gateway_request(secret: str, timestamp: str, body: bytes, signature: str, *,
                           tolerance_seconds: int = 300, now: float | None = None) -> bool:
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((now if now is not None else time.time()) - ts) > tolerance_seconds:
        return False  # stale or future-dated: blocks replay of captured requests
    return constant_time_equals(sign_gateway_request(secret, timestamp, body), signature or "")
