"""Shared fixtures for the end-to-end tests (need TEST_DATABASE_URL; Redis is faked, SMS is captured)."""
import os
import re

import pytest

# Heavy imports (httpx, SQLAlchemy, the app) happen inside fixtures so the pure unit tests run without them.
DB_URL = os.environ.get("TEST_DATABASE_URL")


def pytest_collection_modifyitems(config, items):
    """Skip every test that needs the `client` fixture unless a test database is configured."""
    if DB_URL:
        return
    skip = pytest.mark.skip(reason="TEST_DATABASE_URL not set")
    for item in items:
        if "client" in getattr(item, "fixturenames", ()):
            item.add_marker(skip)


class FakeRedis:
    """The subset of redis.asyncio.Redis the app uses (no real expiry; TTLs are recorded only)."""

    def __init__(self):
        self.data, self.ttls = {}, {}

    async def get(self, k): return self.data.get(k)
    async def set(self, k, v, ex=None): self.data[k] = v; self.ttls[k] = ex
    async def delete(self, *ks): [self.data.pop(k, None) for k in ks]
    async def incr(self, k): self.data[k] = int(self.data.get(k, 0)) + 1; return self.data[k]
    async def expire(self, k, s): self.ttls[k] = s
    async def ttl(self, k): return self.ttls.get(k, -1)
    async def getdel(self, k): return self.data.pop(k, None)
    async def ping(self): return True
    async def aclose(self): pass


class CaptureSMS:
    def __init__(self): self.sent = []
    async def send(self, to, message): self.sent.append((to, message))


@pytest.fixture
async def client(monkeypatch):
    if not DB_URL:
        pytest.skip("TEST_DATABASE_URL not set")
    import httpx
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.core.config import Settings
    from app.models import Base

    engine = create_async_engine(DB_URL)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()

    from app import main
    fake, sms = FakeRedis(), CaptureSMS()
    monkeypatch.setattr(main, "create_redis", lambda settings: fake)
    settings = Settings(environment="test", database_url=DB_URL, secret_key="k" * 40, log_json=False,
                        gateway_secrets={"ussd": "ussd-secret"})
    application = main.create_app(settings)
    application.state.sms_sender = sms

    async with application.router.lifespan_context(application):
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            c.sms, c.redis, c.app = sms, fake, application
            yield c


async def login(client, phone="0241234567", role: str | None = None) -> dict:
    """Log in via OTP (creating the user) and return Authorization headers. `role` promotes the user in the DB."""
    assert (await client.post("/v1/auth/otp/request", json={"phone": phone})).status_code == 202
    code = re.search(r"code is (\d+)", client.sms.sent[-1][1]).group(1)
    r = await client.post("/v1/auth/otp/verify", json={"phone": phone, "code": code})
    assert r.status_code == 200, r.text
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    if role:
        from sqlalchemy import text

        # the user row is re-read on every request, so promoting after login takes effect immediately
        async with client.app.state.session_factory() as session:
            await session.execute(text("UPDATE users SET role = :r WHERE phone = :p"),
                                  {"r": role, "p": "+233" + phone[1:]})
            await session.commit()
    return headers
