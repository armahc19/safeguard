"""Structured logging. JSON in production, readable text in development. Every record carries the request id."""
import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)

# attributes present on every LogRecord; anything else came from `extra=` and is emitted as a field
_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime", "taskName"}


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and key != "request_id":
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<7} [{getattr(record, 'request_id', None) or '-'}] {record.name}: {record.getMessage()}"
        extras = {k: v for k, v in record.__dict__.items() if k not in _RESERVED and k != "request_id"}
        if extras:
            base += " " + " ".join(f"{k}={v}" for k, v in extras.items())
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(_RequestIdFilter())
    handler.setFormatter(JsonFormatter() if json_logs else _TextFormatter())

    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())

    # route uvicorn's loggers through our handler; our middleware writes the access log instead
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
    access = logging.getLogger("uvicorn.access")
    access.handlers[:] = []
    access.propagate = False
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
