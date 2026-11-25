"""Outbound SMS providers.

The application depends on the small ``SMSSender`` protocol, so providers can
be changed without changing authentication or route code.
"""
import logging
from typing import Protocol

import httpx

from app.core.config import Settings

logger = logging.getLogger(__name__)


class SMSSender(Protocol):
    async def send(self, to: str, message: str) -> None: ...


class ConsoleSMSSender:
    """Development stand-in: logs the message instead of sending it. Never use in production (it logs OTPs)."""

    async def send(self, to: str, message: str) -> None:
        logger.warning("sms_not_sent_console_sender", extra={"to": to, "message_body": message})


class HttpSMSSender:
    """Generic provider sender using a JSON ``to/message/sender_id`` payload."""

    def __init__(self, *, url: str, token: str, sender_id: str | None = None) -> None:
        self.url = url
        self.token = token
        self.sender_id = sender_id

    async def send(self, to: str, message: str) -> None:
        payload = {"to": to, "message": message}
        if self.sender_id:
            payload["sender_id"] = self.sender_id
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                self.url,
                json=payload,
                headers={"Authorization": f"Bearer {self.token}"},
            )
            response.raise_for_status()


def create_sms_sender(settings: Settings) -> SMSSender:
    if settings.sms_provider == "http":
        assert settings.sms_api_url and settings.sms_api_token
        return HttpSMSSender(
            url=settings.sms_api_url,
            token=settings.sms_api_token.get_secret_value(),
            sender_id=settings.sms_sender_id,
        )
    return ConsoleSMSSender()
