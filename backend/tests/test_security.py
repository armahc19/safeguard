import time
from datetime import timedelta

import pytest

from app.core import security
from app.core.exceptions import AuthenticationError

SECRET = "x" * 40


def make(token_type=security.ACCESS, ttl=timedelta(minutes=5), secret=SECRET):
    return security.create_token(subject="user-1", token_type=token_type, ttl=ttl, secret=secret, role="user")


def test_token_round_trip():
    issued = make()
    claims = security.decode_token(issued.token, expected_type=security.ACCESS, secret=SECRET)
    assert claims["sub"] == "user-1" and claims["jti"] == issued.jti and claims["role"] == "user"


def test_expired_token_rejected():
    issued = make(ttl=timedelta(seconds=-1))
    with pytest.raises(AuthenticationError) as e:
        security.decode_token(issued.token, expected_type=security.ACCESS, secret=SECRET)
    assert e.value.code == "token_expired"


def test_wrong_type_rejected():
    refresh = make(token_type=security.REFRESH)
    with pytest.raises(AuthenticationError):
        security.decode_token(refresh.token, expected_type=security.ACCESS, secret=SECRET)


def test_wrong_secret_and_garbage_rejected():
    issued = make()
    for bad in (issued.token, "not.a.jwt"):
        with pytest.raises(AuthenticationError):
            security.decode_token(bad, expected_type=security.ACCESS, secret="y" * 40)


def test_otp_shape_and_hash_binding():
    code = security.generate_otp(6)
    assert len(code) == 6 and code.isdigit()
    h = security.hash_otp(code, "+233241234567", SECRET)
    assert security.constant_time_equals(h, security.hash_otp(code, "+233241234567", SECRET))
    assert not security.constant_time_equals(h, security.hash_otp(code, "+233241234568", SECRET))  # bound to phone


def test_gateway_signature():
    body, ts = b'{"msisdn":"+233241234567"}', str(int(time.time()))
    sig = security.sign_gateway_request("s3cret", ts, body)
    assert security.verify_gateway_request("s3cret", ts, body, sig)
    assert not security.verify_gateway_request("other", ts, body, sig)
    assert not security.verify_gateway_request("s3cret", ts, b"tampered", sig)
    assert not security.verify_gateway_request("s3cret", "abc", body, sig)


def test_gateway_replay_window():
    body = b"{}"
    old = str(int(time.time()) - 3600)
    sig = security.sign_gateway_request("s3cret", old, body)
    assert not security.verify_gateway_request("s3cret", old, body, sig, tolerance_seconds=300)


@pytest.mark.asyncio
async def test_campaign_studio_can_be_framed_only_from_configured_admin_origins():
    from app.core.security_headers import SecurityHeadersMiddleware

    async def response_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [
            (b"x-frame-options", b"DENY"),
            (b"content-security-policy", b"default-src 'self'; frame-ancestors 'none'"),
        ]})
        await send({"type": "http.response.body", "body": b"ok"})

    async def get_headers(path):
        sent = []
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        async def send(message):
            sent.append(message)
        middleware = SecurityHeadersMiddleware(
            response_app, frame_ancestors=["http://localhost:5173", "*"]
        )
        await middleware({"type": "http", "path": path, "headers": []}, receive, send)
        return {key.decode().lower(): value.decode()
                for key, value in sent[0]["headers"]}

    campaign_headers = await get_headers("/campaign-studio/")
    assert "x-frame-options" not in campaign_headers
    assert "default-src 'self'" in campaign_headers["content-security-policy"]
    assert "frame-ancestors 'self' http://localhost:5173" in campaign_headers["content-security-policy"]
    assert "*" not in campaign_headers["content-security-policy"]

    regular_headers = await get_headers("/v1/admin/intelligence")
    assert regular_headers["x-frame-options"] == "DENY"
