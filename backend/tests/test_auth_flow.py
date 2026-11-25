"""End-to-end auth flow (needs TEST_DATABASE_URL; see conftest.py)."""
from tests.conftest import login


async def test_full_flow(client):
    headers = await login(client)

    me = await client.get("/v1/auth/me", headers=headers)
    assert me.status_code == 200 and me.json()["phone"] == "+233241234567" and me.json()["role"] == "user"


async def test_refresh_rotates_and_logout_revokes(client):
    await client.post("/v1/auth/otp/request", json={"phone": "0241234567"})
    import re
    code = re.search(r"code is (\d+)", client.sms.sent[-1][1]).group(1)
    tokens = (await client.post("/v1/auth/otp/verify", json={"phone": "0241234567", "code": code})).json()

    r1 = await client.post("/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r1.status_code == 200
    r2 = await client.post("/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r2.status_code == 401 and r2.json()["error"]["code"] == "invalid_token"

    assert (await client.post("/v1/auth/logout", json={"refresh_token": r1.json()["refresh_token"]})).status_code == 204
    r3 = await client.post("/v1/auth/refresh", json={"refresh_token": r1.json()["refresh_token"]})
    assert r3.status_code == 401


async def test_wrong_otp_and_lockout(client):
    await client.post("/v1/auth/otp/request", json={"phone": "0241234567"})
    for _ in range(5):
        r = await client.post("/v1/auth/otp/verify", json={"phone": "0241234567", "code": "000000"})
        assert r.status_code == 401
    r = await client.post("/v1/auth/otp/verify", json={"phone": "0241234567", "code": "000000"})
    assert r.json()["error"]["code"] == "otp_locked"


async def test_errors_share_one_shape_and_request_id(client):
    r = await client.get("/v1/auth/me", headers={"X-Request-ID": "trace-1"})
    body = r.json()["error"]
    assert r.status_code == 401 and body["code"] == "unauthenticated" and body["request_id"] == "trace-1"
    assert r.headers["X-Request-ID"] == "trace-1"

    bad = await client.post("/v1/auth/otp/verify", json={"phone": "0241234567", "code": "abc"})
    assert bad.status_code == 422 and "abc" not in bad.text  # submitted value is never echoed


async def test_otp_request_rate_limited(client):
    codes = [(await client.post("/v1/auth/otp/request", json={"phone": "0241234567"})).status_code for _ in range(4)]
    assert codes == [202, 202, 202, 429]


async def test_health(client):
    assert (await client.get("/health/live")).status_code == 200
    assert (await client.get("/health/ready")).status_code == 200
