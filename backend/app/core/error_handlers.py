"""Turns every failure into one JSON shape:

    {"error": {"code": "...", "message": "...", "details": ..., "request_id": "..."}}
"""
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import AppError

logger = logging.getLogger(__name__)


def _body(request: Request, code: str, message: str, details=None) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details,
            "request_id": getattr(request.state, "request_id", None),
        }
    }


def _response(request: Request, status: int, code: str, message: str, details=None, headers=None) -> JSONResponse:
    headers = dict(headers or {})
    rid = getattr(request.state, "request_id", None)
    if rid:
        headers.setdefault("X-Request-ID", rid)
    return JSONResponse(_body(request, code, message, details), status_code=status, headers=headers)


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    if exc.status_code >= 500:
        logger.error("app_error", extra={"code": exc.code}, exc_info=exc)
    return _response(request, exc.status_code, exc.code, exc.message, exc.details, exc.headers)


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Never echo the submitted value back: it may be an OTP or other secret.
    details = [
        {
            "field": ".".join(str(p) for p in err["loc"] if p not in ("body", "query", "path")),
            "message": err["msg"],
            "type": err["type"],
        }
        for err in exc.errors()
    ]
    return _response(request, 422, "validation_error", "Request validation failed.", details)


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
    return _response(request, exc.status_code, code, str(exc.detail), headers=getattr(exc, "headers", None))


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled_exception", exc_info=exc)
    return _response(request, 500, "internal_error", "An unexpected error occurred.")


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
