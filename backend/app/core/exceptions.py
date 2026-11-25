"""Application exception hierarchy. Pure Python: raise these from services; handlers turn them into JSON."""
from typing import Any


class AppError(Exception):
    status_code = 500
    code = "internal_error"
    message = "Something went wrong."

    def __init__(self, message: str | None = None, *, code: str | None = None, details: Any = None,
                 headers: dict[str, str] | None = None):
        self.message = message or self.message
        self.code = code or self.code
        self.details = details
        self.headers = headers
        super().__init__(self.message)


class BadRequestError(AppError):
    status_code = 400
    code = "bad_request"
    message = "The request is invalid."


class ValidationFailed(AppError):
    status_code = 422
    code = "validation_error"
    message = "Validation failed."


class AuthenticationError(AppError):
    status_code = 401
    code = "unauthenticated"
    message = "Authentication is required."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = self.headers or {"WWW-Authenticate": "Bearer"}


class PermissionDenied(AppError):
    status_code = 403
    code = "forbidden"
    message = "You do not have permission to do that."


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"
    message = "Resource not found."


class ConflictError(AppError):
    status_code = 409
    code = "conflict"
    message = "The request conflicts with the current state."


class RateLimitedError(AppError):
    status_code = 429
    code = "rate_limited"
    message = "Too many requests. Please try again later."

    def __init__(self, *args, retry_after: int | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        if retry_after is not None:
            self.headers = {"Retry-After": str(retry_after)}


class ServiceUnavailableError(AppError):
    status_code = 503
    code = "service_unavailable"
    message = "A required service is unavailable."
