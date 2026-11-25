"""Fixed-window rate limiting on Redis."""
from redis.asyncio import Redis

from app.core.exceptions import RateLimitedError


async def hit(redis: Redis, key: str, limit: int, window_seconds: int) -> None:
    """Count one event against `key`; raise RateLimitedError once `limit` is exceeded within the window."""
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window_seconds)
    if count > limit:
        ttl = await redis.ttl(key)
        raise RateLimitedError(retry_after=ttl if ttl and ttl > 0 else window_seconds)
