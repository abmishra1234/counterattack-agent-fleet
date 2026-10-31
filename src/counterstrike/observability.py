"""Structured operational logging primitives with request correlation and redaction."""

from __future__ import annotations

import json
import logging
import re
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

request_id_context: ContextVar[str] = ContextVar("counterstrike_request_id", default="-")

_SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"(?i)(password\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
)
_SAFE_EXTRA_FIELDS = (
    "event",
    "service",
    "route",
    "method",
    "status_code",
    "duration_ms",
    "run_id",
    "job_id",
    "source_id",
    "advisory_id",
    "task",
    "error_code",
    "attempt",
    "client_host",
    "local_host_allowed",
    "local_client_allowed",
    "artifact_count",
)


def redact(value: str) -> str:
    """Redact common credentials before a message reaches a log handler."""
    result = value
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(
            lambda match: f"{match.group(1) if match.lastindex else ''}[REDACTED]", result
        )
    return result


class JsonFormatter(logging.Formatter):
    """Emit one compact JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact(record.getMessage()),
            "request_id": request_id_context.get(),
        }
        for field in _SAFE_EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exception_type"] = (
                record.exc_info[0].__name__ if record.exc_info[0] else "Exception"
            )
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str)


def configure_logging(level: str = "INFO") -> logging.Logger:
    """Configure the application logger without replacing host application handlers."""
    logger = logging.getLogger("counterstrike")
    logger.setLevel(level)
    logger.propagate = False
    if not any(getattr(handler, "_counterstrike_json", False) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler._counterstrike_json = True  # type: ignore[attr-defined]
        logger.addHandler(handler)
    for handler in logger.handlers:
        handler.setLevel(level)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.asgi"):
        runtime_logger = logging.getLogger(name)
        runtime_logger.handlers.clear()
        runtime_logger.addHandler(logger.handlers[0])
        runtime_logger.setLevel(level)
        runtime_logger.propagate = False
    # Middleware below is the single HTTP access log; Uvicorn's raw path log is redundant.
    logging.getLogger("uvicorn.access").disabled = True
    return logger
