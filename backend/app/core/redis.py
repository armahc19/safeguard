"""Redis client (caching, rate limits, OTPs, refresh-token allow-list)."""
from redis.asyncio import Redis

from app.core.config import Settings


def create_redis(settings: Settings) -> Redis:
    # decode_responses=True: every value we store is a plain string
    return Redis.from_url(settings.redis_url, decode_responses=True)
