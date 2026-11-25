"""Small ASGI middleware for baseline browser security headers."""
from urllib.parse import urlsplit

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, production: bool = False,
                 frame_ancestors: list[str] | None = None) -> None:
        self.app = app
        self.production = production
        configured = frame_ancestors or []
        self.frame_ancestors = tuple(dict.fromkeys(
            origin.rstrip("/") for origin in configured
            if urlsplit(origin).scheme in {"http", "https"}
            and urlsplit(origin).netloc
            and "*" not in origin
        ))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                if scope.get("path", "").startswith("/campaign-studio"):
                    # The Admin frontend embeds only this Gradio route. X-Frame-Options
                    # DENY blocks that embed even when the frontend origin is trusted.
                    if "X-Frame-Options" in headers:
                        del headers["X-Frame-Options"]
                    allowed = " ".join(("'self'", *self.frame_ancestors))
                    existing = headers.get("Content-Security-Policy", "")
                    directives = [part.strip() for part in existing.split(";") if part.strip()]
                    directives = [part for part in directives
                                  if part.split(None, 1)[0].lower() != "frame-ancestors"]
                    directives.append(f"frame-ancestors {allowed}")
                    headers["Content-Security-Policy"] = "; ".join(directives)
                if self.production:
                    headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            await send(message)

        await self.app(scope, receive, send_wrapper)
